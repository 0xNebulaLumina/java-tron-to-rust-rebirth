use blake2::{
    digest::{consts::U64, FixedOutput, Update},
    Blake2bMac,
};
use ff::Field;
use sapling_crypto::value::{NoteValue, ValueCommitTrapdoor, ValueCommitment};
use tron_shielded::{
    aead_decrypt, aead_encrypt, blake2b_salt_personal, decrypt_pre_zip212_note,
    encrypt_pre_zip212_note, external_key_path, generate_r, recover_pre_zip212_note,
    zip32_xsk_master, Black2bSaltPersonalParams, Chacha20Poly1305IetfEncryptParams,
    Chacha20poly1305IetfDecryptParams, ShieldedError, SodiumCompat, Validate, AEAD_TAG_BYTES,
    FAILURE, MAX_SODIUM_OUTPUT_BYTES, MEMO_BYTES, SUCCESS,
};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}


#[test]
fn pre_zip212_note_round_trips_through_external_keys_and_preserves_memo() {
    let xsk = zip32_xsk_master(b"C006 pre-ZIP212 external path fixture");
    let keys = external_key_path(&xsk).unwrap();
    let value = 9_876_543u64;
    let rcm = generate_r();
    let rcv = ValueCommitTrapdoor::random(&mut rand_core::OsRng);
    let cv = ValueCommitment::derive(NoteValue::from_raw(value), rcv).to_bytes();
    let mut memo = [0u8; MEMO_BYTES];
    for (index, byte) in memo.iter_mut().enumerate() {
        *byte = (index as u8).wrapping_mul(29).wrapping_add(7);
    }

    let encrypted = encrypt_pre_zip212_note(
        keys.payment_address,
        value,
        rcm,
        Some(keys.ovk),
        cv,
        memo,
    )
    .unwrap();
    let recipient = decrypt_pre_zip212_note(keys.ivk, &encrypted).unwrap().unwrap();
    let sender = recover_pre_zip212_note(keys.ovk, &encrypted).unwrap().unwrap();

    assert_eq!(recipient, sender);
    assert_eq!(recipient.value, value);
    assert_eq!(recipient.rcm, rcm);
    assert_eq!(recipient.memo, memo);
    assert_eq!(recipient.diversifier, keys.diversifier);
    assert_eq!(encrypted.note_commitment.len(), 32);
}

#[test]
fn wrong_incoming_or_outgoing_key_is_a_boolean_decryption_miss() {
    let xsk = zip32_xsk_master(b"C006 pre-ZIP212 wrong-key fixture");
    let keys = external_key_path(&xsk).unwrap();
    let rcm = jubjub::Fr::random(rand_core::OsRng).to_bytes();
    let rcv = ValueCommitTrapdoor::random(&mut rand_core::OsRng);
    let cv = ValueCommitment::derive(NoteValue::from_raw(1), rcv).to_bytes();
    let encrypted = encrypt_pre_zip212_note(
        keys.payment_address,
        1,
        rcm,
        Some(keys.ovk),
        cv,
        [0u8; MEMO_BYTES],
    )
    .unwrap();

    let other = external_key_path(&zip32_xsk_master(b"different external key")).unwrap();
    assert!(decrypt_pre_zip212_note(other.ivk, &encrypted).unwrap().is_none());
    assert!(recover_pre_zip212_note(other.ovk, &encrypted).unwrap().is_none());
}

#[test]
fn all_jlibsodium_state_one_shot_and_aead_operations_preserve_return_semantics() {
    let sodium = SodiumCompat::with_max_states(2).unwrap();
    let salt = [0x21; 16];
    let personal = [0x43; 16];
    let key = [0x65; 32];
    let input_a = [0x87; 33];
    let input_b = [0xa9; 34];

    let state = sodium.init_state().unwrap();
    assert_eq!(sodium.blake2b_update(state, &input_a), FAILURE);
    assert_eq!(
        sodium.blake2b_init(state, &key, key.len() - 1, 64, &salt, &personal),
        FAILURE
    );
    assert_eq!(
        sodium.blake2b_init(state, &key, key.len(), 64, &salt, &personal),
        SUCCESS
    );
    assert_eq!(sodium.blake2b_update(state, &input_a), SUCCESS);
    assert_eq!(sodium.blake2b_final(state, 32), Err(FAILURE));
    assert_eq!(
        sodium.blake2b_init(state, &key, key.len() - 1, 64, &salt, &personal),
        FAILURE
    );
    assert_eq!(sodium.blake2b_update(state, &input_b), SUCCESS);
    let digest = sodium.blake2b_final(state, 64).unwrap();
    let mut expected =
        Blake2bMac::<U64>::new_with_salt_and_personal(Some(&key), &salt, &personal).unwrap();
    expected.update(&input_a);
    expected.update(&input_b);
    assert_eq!(digest, expected.finalize_fixed().to_vec());
    assert_eq!(sodium.blake2b_final(state, 64), Err(FAILURE));
    assert_eq!(sodium.blake2b_update(state, &input_a), FAILURE);
    assert!(sodium.free_state(state));
    assert!(!sodium.free_state(state));
    assert_eq!(
        sodium.blake2b_init(state, &key, key.len(), 64, &salt, &personal),
        FAILURE
    );

    let short_state = sodium.init_state().unwrap();
    assert_eq!(
        sodium.blake2b_init(short_state, &[], 0, 64, &salt, &personal),
        SUCCESS
    );
    assert_eq!(sodium.blake2b_update(short_state, &input_a), SUCCESS);
    assert_eq!(sodium.blake2b_final(short_state, 11).unwrap().len(), 11);
    assert!(sodium.free_state(short_state));

    let first = sodium.init_state().unwrap();
    let second = sodium.init_state().unwrap();
    assert!(matches!(
        sodium.init_state(),
        Err(ShieldedError::ContextLimit { max: 2 })
    ));
    assert!(sodium.free_state(first));
    let replacement = sodium.init_state().unwrap();
    assert_ne!(replacement, first);
    assert!(sodium.free_state(second));
    assert!(sodium.free_state(replacement));

    assert!(blake2b_salt_personal(&input_a, &key, key.len() - 1, &salt, &personal, 32).is_err());
    assert!(blake2b_salt_personal(&input_a, &key, key.len(), &salt[..15], &personal, 32).is_err());

    let nonce = [0xbc; 12];
    let aad = b"C006 authenticated data";
    let message = b"bounded JLibsodium AEAD behavior";
    let encrypted = aead_encrypt(message, aad, &nonce, &key, message.len() + AEAD_TAG_BYTES);
    assert_eq!(encrypted.rc, SUCCESS);
    assert_eq!(encrypted.output_len as usize, message.len() + AEAD_TAG_BYTES);
    let decrypted = aead_decrypt(&encrypted.output, aad, &nonce, &key, message.len());
    assert_eq!(decrypted.rc, SUCCESS);
    assert_eq!(decrypted.output, message);
    assert_eq!(decrypted.output_len as usize, message.len());

    let too_small = aead_encrypt(message, aad, &nonce, &key, message.len() + AEAD_TAG_BYTES - 1);
    assert_eq!(too_small.rc, FAILURE);
    assert_eq!(too_small.output_len, 0);
    assert!(too_small.output.is_empty());

    let mut tampered = encrypted.output.clone();
    tampered[0] ^= 1;
    let rejected = aead_decrypt(&tampered, aad, &nonce, &key, message.len());
    assert_eq!(rejected.rc, FAILURE);
    assert_eq!(rejected.output_len, 0);
    assert!(rejected.output.is_empty());

    let undersized = aead_decrypt(&encrypted.output, aad, &nonce, &key, message.len() - 1);
    assert_eq!(undersized.rc, FAILURE);
    assert_eq!(undersized.output_len, 0);
    assert!(undersized.output.is_empty());
}

#[test]
fn fixed_blake2b_null_key_null_salt_note_derivation_vectors() {
    let sodium = SodiumCompat::new();
    let spending_key: Vec<u8> = (0..32).collect();
    let personal = b"Ztron_ExpandSeed";

    let prf_state = sodium.init_state().unwrap();
    assert_eq!(
        sodium.blake2b_init(prf_state, &[], 0, 64, &[], personal),
        SUCCESS
    );
    let mut prf_input = spending_key.clone();
    prf_input.push(2);
    assert_eq!(sodium.blake2b_update(prf_state, &[0; 35]), FAILURE);
    assert_eq!(sodium.blake2b_update(prf_state, &prf_input), SUCCESS);
    assert_eq!(
        hex(&sodium.blake2b_final(prf_state, 64).unwrap()),
        "9861efdc0ceb6ef279b3ac35529b04a62911c8977f1e0a3a6b69cd98a593dfa689a71e891034ea0d301d387a215ee9558188fb32a19f3ef617e0886452bfdf2a"
    );

    let diversifier_state = sodium.init_state().unwrap();
    assert_eq!(
        sodium.blake2b_init(diversifier_state, &[], 0, 64, &[], personal),
        SUCCESS
    );
    let mut diversifier_input = spending_key;
    diversifier_input.extend_from_slice(&[3, 0]);
    assert_eq!(
        sodium.blake2b_update(diversifier_state, &diversifier_input),
        SUCCESS
    );
    assert_eq!(
        hex(&sodium.blake2b_final(diversifier_state, 11).unwrap()),
        "91f635a6a1f25d5ce8839b"
    );

    let kdf_input: Vec<u8> = (0..64).collect();
    let kdf = blake2b_salt_personal(
        &kdf_input,
        &[],
        0,
        &[],
        b"Ztron_SaplingKDF",
        32,
    )
    .unwrap();
    assert_eq!(
        hex(&kdf),
        "fbf6c8018b43ea06a666fb1bda2fabaeebd07eeea6bc13c001315404a0b247bc"
    );
    assert_eq!(
        kdf,
        blake2b_salt_personal(&kdf_input, &[], 0, &[0; 16], b"Ztron_SaplingKDF", 32)
            .unwrap()
    );
    let ock_input: Vec<u8> = (0..128).collect();
    assert_eq!(
        hex(&blake2b_salt_personal(
            &ock_input,
            &[],
            0,
            &[],
            b"Ztron_Derive_ock",
            32,
        ).unwrap()),
        "5a3c64f54619d8a56a144ee54a5259a480c4050dcbd4bd32568dab585041e850"
    );

    assert!(blake2b_salt_personal(&kdf_input, &[], 0, &[0; 15], b"Ztron_SaplingKDF", 32).is_err());
}

#[test]
fn attacker_controlled_sodium_lengths_fail_without_proportional_allocation_or_panic() {
    let nonce = [0u8; 12];
    let key = [0u8; 32];

    for result in [
        aead_encrypt(b"x", &[], &nonce, &key, usize::MAX),
        aead_decrypt(&[0u8; AEAD_TAG_BYTES], &[], &nonce, &key, usize::MAX),
        aead_decrypt(&[], &[], &nonce, &key, usize::MAX),
    ] {
        assert_eq!(result.rc, FAILURE);
        assert_eq!(result.output_len, 0);
        assert!(result.output.is_empty());
        assert_eq!(result.output.capacity(), 0);
    }

    assert!(Black2bSaltPersonalParams {
        out_len: usize::MAX,
        input: vec![],
        in_len: 0,
        key: vec![],
        key_len: 0,
        salt: vec![],
        personal: vec![0; 16],
    }
    .validate()
    .is_err());

    assert!(Chacha20Poly1305IetfEncryptParams {
        output_len: usize::MAX,
        message: vec![],
        m_len: usize::MAX,
        aad: vec![],
        ad_len: 0,
        nonce,
        key,
    }
    .validate()
    .is_err());

    assert!(Chacha20poly1305IetfDecryptParams {
        output_len: MAX_SODIUM_OUTPUT_BYTES + 1,
        ciphertext: vec![],
        c_len: 0,
        aad: vec![],
        ad_len: usize::MAX,
        nonce,
        key,
    }
    .validate()
    .is_err());
}
