use ff::PrimeField;
use sapling_crypto::{
    bundle::{GrothProofBytes, OutputDescription},
    keys::{OutgoingViewingKey, SaplingIvk},
    note::ExtractedNoteCommitment,
    note_encryption::{
        sapling_note_encryption, try_sapling_note_decryption, try_sapling_output_recovery,
        PreparedIncomingViewingKey, Zip212Enforcement,
    },
    value::{NoteValue, ValueCommitment},
    zip32::ExtendedSpendingKey,
    PaymentAddress, Rseed,
};
use zip32::Scope;
use zcash_note_encryption::{Domain, EphemeralKeyBytes};

use crate::{Result, ShieldedError};

pub const MEMO_BYTES: usize = 512;
pub const ENC_CIPHERTEXT_BYTES: usize = 580;
pub const OUT_CIPHERTEXT_BYTES: usize = 80;

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
    let recipient = PaymentAddress::from_bytes(&recipient)
        .ok_or(ShieldedError::InvalidEncoding("payment address"))?;
    let rcm = Option::<jubjub::Fr>::from(jubjub::Fr::from_repr(rcm))
        .ok_or(ShieldedError::InvalidEncoding("note commitment trapdoor"))?;
    let cv = parse_cv(value_commitment)?;
    let note = recipient.create_note(NoteValue::from_raw(value), Rseed::BeforeZip212(rcm));
    let cmu = note.cmu();
    let encryption = sapling_note_encryption(ovk.map(OutgoingViewingKey), note, memo, &mut rand_core::OsRng);
    let ephemeral_key = <sapling_crypto::note_encryption::SaplingDomain as Domain>::epk_bytes(encryption.epk()).0;
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
