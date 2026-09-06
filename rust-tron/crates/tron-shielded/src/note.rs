use ff::{Field, PrimeField};
use sapling_crypto::{
    bundle::{GrothProofBytes, OutputDescription},
    keys::{OutgoingViewingKey, SaplingIvk},
    note::ExtractedNoteCommitment,
    note_encryption::{
        sapling_note_encryption, try_sapling_note_decryption, try_sapling_output_recovery,
        PreparedIncomingViewingKey, SaplingDomain, Zip212Enforcement,
    },
    value::{NoteValue, ValueCommitment},
    zip32::ExtendedSpendingKey,
    PaymentAddress, Rseed,
};
use zip32::Scope;
use zcash_note_encryption::{Domain, EphemeralKeyBytes};
use zeroize::Zeroize;

use crate::{Result, ShieldedError};

pub const MEMO_BYTES: usize = 512;
pub const ENC_CIPHERTEXT_BYTES: usize = 580;
pub const OUT_CIPHERTEXT_BYTES: usize = 80;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EncryptedNoteWithEsk {
    pub encrypted_note: EncryptedNote,
    pub esk: [u8; 32],
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EncryptedNote {
    pub value_commitment: [u8; 32],
    pub note_commitment: [u8; 32],
    pub ephemeral_key: [u8; 32],
    pub enc_ciphertext: [u8; ENC_CIPHERTEXT_BYTES],
    pub out_ciphertext: [u8; OUT_CIPHERTEXT_BYTES],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DecryptedNote {
    pub diversifier: [u8; 11],
    pub pk_d: [u8; 32],
    pub value: u64,
    pub rcm: [u8; 32],
    pub memo: [u8; MEMO_BYTES],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExternalKeyPath {
    pub ask: [u8; 32],
    pub nsk: [u8; 32],
    pub ovk: [u8; 32],
    pub ak: [u8; 32],
    pub nk: [u8; 32],
    pub ivk: [u8; 32],
    pub diversifier_index: [u8; 11],
    pub diversifier: [u8; 11],
    pub payment_address: [u8; 43],
}

pub fn external_key_path(xsk: &[u8]) -> Result<ExternalKeyPath> {
    let xsk = ExtendedSpendingKey::from_bytes(xsk)
        .map_err(|_| ShieldedError::InvalidEncoding("extended spending key"))?;
    let dfvk = xsk.to_diversifiable_full_viewing_key();
    let dfvk_bytes = dfvk.to_bytes();
    let expsk_bytes = xsk.expsk.to_bytes();
    let (index, address) = dfvk.default_address();
    Ok(ExternalKeyPath {
        ask: expsk_bytes[..32].try_into().expect("fixed expanded-key field"),
        nsk: expsk_bytes[32..64].try_into().expect("fixed expanded-key field"),
        ovk: expsk_bytes[64..].try_into().expect("fixed expanded-key field"),
        ak: dfvk_bytes[..32].try_into().expect("fixed viewing-key field"),
        nk: dfvk_bytes[32..64].try_into().expect("fixed viewing-key field"),
        ivk: dfvk.to_ivk(Scope::External).to_repr(),
        diversifier_index: *index.as_bytes(),
        diversifier: address.diversifier().0,
        payment_address: address.to_bytes(),
    })
}

pub fn encrypt_pre_zip212_note(
    recipient: [u8; 43],
    value: u64,
    rcm: [u8; 32],
    ovk: Option<[u8; 32]>,
    value_commitment: [u8; 32],
    memo: [u8; MEMO_BYTES],
) -> Result<EncryptedNote> {
    Ok(encrypt_pre_zip212_note_returning_esk(
        recipient, value, rcm, ovk, value_commitment, memo,
    )?.encrypted_note)
}

pub fn encrypt_pre_zip212_note_returning_esk(
    recipient: [u8; 43],
    value: u64,
    rcm: [u8; 32],
    ovk: Option<[u8; 32]>,
    value_commitment: [u8; 32],
    memo: [u8; MEMO_BYTES],
) -> Result<EncryptedNoteWithEsk> {
    let esk = jubjub::Fr::random(&mut rand_core::OsRng).to_repr();
    let encrypted_note = encrypt_pre_zip212_note_with_esk(
        recipient, value, rcm, ovk, value_commitment, memo, esk,
    )?;
    Ok(EncryptedNoteWithEsk { encrypted_note, esk })
}

pub fn encrypt_pre_zip212_note_with_esk(
    recipient: [u8; 43],
    value: u64,
    rcm: [u8; 32],
    ovk: Option<[u8; 32]>,
    value_commitment: [u8; 32],
    memo: [u8; MEMO_BYTES],
    esk: [u8; 32],
) -> Result<EncryptedNote> {
    let recipient = PaymentAddress::from_bytes(&recipient)
        .ok_or(ShieldedError::InvalidEncoding("payment address"))?;
    let rcm = Option::<jubjub::Fr>::from(jubjub::Fr::from_repr(rcm))
        .ok_or(ShieldedError::InvalidEncoding("note commitment trapdoor"))?;
    let esk_scalar = Option::<jubjub::Fr>::from(jubjub::Fr::from_repr(esk))
        .ok_or(ShieldedError::InvalidEncoding("ephemeral secret key"))?;
    let cv = parse_cv(value_commitment)?;
    let note = recipient.create_note(NoteValue::from_raw(value), Rseed::BeforeZip212(rcm));
    let cmu = note.cmu();
    let mut rng = FixedEskRng::new(esk);
    let encryption = sapling_note_encryption(ovk.map(OutgoingViewingKey), note, memo, &mut rng);
    if rng.scalar != esk_scalar { return Err(ShieldedError::InvalidEncoding("ephemeral secret key")); }
    let ephemeral_key = <SaplingDomain as Domain>::epk_bytes(encryption.epk()).0;
    let enc_ciphertext = encryption.encrypt_note_plaintext();
    let out_ciphertext = encryption.encrypt_outgoing_plaintext(&cv, &cmu, &mut rand_core::OsRng);
    Ok(EncryptedNote {
        value_commitment,
        note_commitment: cmu.to_bytes(),
        ephemeral_key,
        enc_ciphertext,
        out_ciphertext,
    })
}
struct FixedEskRng { bytes: [u8; 64], offset: usize, scalar: jubjub::Fr }
impl FixedEskRng { fn new(esk:[u8;32])->Self{let mut bytes=[0u8;64];bytes[..32].copy_from_slice(&esk);let scalar=jubjub::Fr::from_bytes_wide(&bytes);Self{bytes,offset:0,scalar}} }
impl rand_core::RngCore for FixedEskRng {
    fn next_u32(&mut self)->u32{let mut b=[0;4];self.fill_bytes(&mut b);u32::from_le_bytes(b)}
    fn next_u64(&mut self)->u64{let mut b=[0;8];self.fill_bytes(&mut b);u64::from_le_bytes(b)}
    fn fill_bytes(&mut self,dest:&mut[u8]){self.try_fill_bytes(dest).expect("fixed RNG capacity")}
    fn try_fill_bytes(&mut self,dest:&mut[u8])->std::result::Result<(),rand_core::Error>{if self.offset+dest.len()>self.bytes.len(){return Err(rand_core::Error::new("fixed RNG exhausted"))}dest.copy_from_slice(&self.bytes[self.offset..self.offset+dest.len()]);self.offset+=dest.len();Ok(())}
}
impl rand_core::CryptoRng for FixedEskRng {}
pub const BURN_CIPHERTEXT_BYTES: usize = 80;
pub const BURN_RECORD_BYTES: usize = 96;
const BURN_V2_MARKER: [u8; 4] = [0, 0, 0, 1];
const BURN_NONCE_DOMAIN: &[u8] = b"TRON_SHIELDED_TRC20_BURN_V2";

pub fn burn_nonce(nullifier: [u8; 32], amount: [u8; 32], address: [u8; 21]) -> [u8; 12] {
    let mut tagged = Vec::with_capacity(BURN_NONCE_DOMAIN.len() + 85);
    tagged.extend_from_slice(BURN_NONCE_DOMAIN);
    tagged.extend_from_slice(&nullifier);
    tagged.extend_from_slice(&amount);
    tagged.extend_from_slice(&address);
    let digest = tron_crypto::keccak256(&tagged);
    digest[..12].try_into().expect("fixed nonce")
}

pub fn encrypt_burn_record(
    ovk: [u8; 32], amount: [u8; 32], address: [u8; 21], nullifier: [u8; 32],
) -> Result<[u8; BURN_RECORD_BYTES]> {
    let nonce = burn_nonce(nullifier, amount, address);
    let mut plaintext = [0u8; 64];
    plaintext[..32].copy_from_slice(&amount);
    plaintext[32..53].copy_from_slice(&address);
    let encrypted = crate::sodium::aead_encrypt(&plaintext, &[], &nonce, &ovk, BURN_CIPHERTEXT_BYTES);
    plaintext.zeroize();
    if encrypted.rc != crate::sodium::SUCCESS || encrypted.output.len() != BURN_CIPHERTEXT_BYTES {
        return Err(ShieldedError::InvalidParameter("burn encryption failed".into()));
    }
    let mut record = [0u8; BURN_RECORD_BYTES];
    record[..BURN_CIPHERTEXT_BYTES].copy_from_slice(&encrypted.output);
    record[80..92].copy_from_slice(&nonce);
    record[92..].copy_from_slice(&BURN_V2_MARKER);
    Ok(record)
}

pub fn recover_burn_record(
    ovk: [u8; 32], record: &[u8], nullifier: Option<[u8; 32]>,
    amount: Option<[u8; 32]>, address: Option<[u8; 21]>,
) -> Result<Option<([u8; 32], [u8; 21])>> {
    if record.len() != BURN_RECORD_BYTES { return Ok(None); }
    let nonce: [u8; 12] = record[80..92].try_into().expect("fixed nonce");
    let marker: [u8; 4] = record[92..].try_into().expect("fixed marker");
    if marker == BURN_V2_MARKER {
        let (Some(nf), Some(expected_amount), Some(expected_address)) = (nullifier, amount, address) else { return Ok(None); };
        if nonce != burn_nonce(nf, expected_amount, expected_address) { return Ok(None); }
    } else if marker != [0; 4] || nonce != [0; 12] { return Ok(None); }
    let decrypted = crate::sodium::aead_decrypt(&record[..80], &[], &nonce, &ovk, 64);
    if decrypted.rc != crate::sodium::SUCCESS || decrypted.output.len() != 64 { return Ok(None); }
    let recovered_amount = decrypted.output[..32].try_into().expect("fixed amount");
    let recovered_address = decrypted.output[32..53].try_into().expect("fixed address");
    if amount.is_some_and(|v| v != recovered_amount) || address.is_some_and(|v| v != recovered_address) { return Ok(None); }
    Ok(Some((recovered_amount, recovered_address)))
}

pub fn decrypt_pre_zip212_note(ivk: [u8; 32], output: &EncryptedNote) -> Result<Option<DecryptedNote>> {
    let ivk = Option::<jubjub::Fr>::from(jubjub::Fr::from_repr(ivk))
        .map(SaplingIvk)
        .ok_or(ShieldedError::InvalidEncoding("incoming viewing key"))?;
    let output = output_description(output)?;
    Ok(try_sapling_note_decryption(
        &PreparedIncomingViewingKey::new(&ivk),
        &output,
        Zip212Enforcement::Off,
    )
    .map(note_parts))
}

pub fn recover_pre_zip212_note(ovk: [u8; 32], output: &EncryptedNote) -> Result<Option<DecryptedNote>> {
    let output = output_description(output)?;
    Ok(try_sapling_output_recovery(
        &OutgoingViewingKey(ovk),
        &output,
        Zip212Enforcement::Off,
    )
    .map(note_parts))
}

fn output_description(output: &EncryptedNote) -> Result<OutputDescription<GrothProofBytes>> {
    let cv = parse_cv(output.value_commitment)?;
    let cmu = Option::<ExtractedNoteCommitment>::from(ExtractedNoteCommitment::from_bytes(&output.note_commitment))
        .ok_or(ShieldedError::InvalidEncoding("note commitment"))?;
    Ok(OutputDescription::from_parts(
        cv,
        cmu,
        EphemeralKeyBytes(output.ephemeral_key),
        output.enc_ciphertext,
        output.out_ciphertext,
        [0u8; 192],
    ))
}

fn parse_cv(bytes: [u8; 32]) -> Result<ValueCommitment> {
    Option::<ValueCommitment>::from(ValueCommitment::from_bytes_not_small_order(&bytes))
        .ok_or(ShieldedError::InvalidEncoding("value commitment"))
}

fn note_parts((note, address, memo): (sapling_crypto::Note, PaymentAddress, [u8; 512])) -> DecryptedNote {
    DecryptedNote {
        diversifier: address.diversifier().0,
        pk_d: address.to_bytes()[11..].try_into().expect("fixed transmission key"),
        value: note.value().inner(),
        rcm: note.rcm().to_repr(),
        memo,
    }
}
