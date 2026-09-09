use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use ed25519_dalek::{Signer, SigningKey};
use serde_json::json;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use tron_crypto::artifact_auth::{
    Algorithm, AuthError, AuthLimits, DsseEnvelope, DsseSignature, KeyId, RoleName,
    TRUST_STORE_PAYLOAD_TYPE, dsse_pae, parse_trust_store, verify_dsse,
    verify_dsse_scoped, verify_trust_store_update,
};

const PAYLOAD_TYPE: &str = "application/vnd.tron.test.v1+json";
const NOW_TEXT: &str = "2026-09-08T12:00:00Z";
const BEFORE: &str = "2026-01-01T00:00:00Z";
const AFTER: &str = "2027-01-01T00:00:00Z";

fn now() -> OffsetDateTime { OffsetDateTime::parse(NOW_TEXT, &Rfc3339).unwrap() }
fn signing_keys(first: u8) -> Vec<SigningKey> {
    (first..first + 3).map(|seed| SigningKey::from_bytes(&[seed; 32])).collect()
}
fn key_json(key: &SigningKey, revoked: bool) -> serde_json::Value {
    let public = key.verifying_key().to_bytes();
    json!({
        "key_id": KeyId::for_ed25519(&public).as_str(),
        "algorithm": "ed25519-v1",
        "public_key_base64": BASE64.encode(public),
        "not_before": BEFORE,
        "not_after": AFTER,
        "revoked": revoked
    })
}
fn store_json(version: u64, keys: &[SigningKey]) -> Vec<u8> {
    let ids: Vec<_> = keys.iter().map(|key| KeyId::for_ed25519(&key.verifying_key().to_bytes()).as_str().to_owned()).collect();
    serde_json::to_vec(&json!({
        "schema": "tron-trust-store-v1",
        "version": version,
        "expires": AFTER,
        "keys": keys.iter().map(|key| key_json(key, false)).collect::<Vec<_>>(),
        "roles": [
            {"name": "root", "key_ids": ids.clone(), "threshold": 2, "scope": "trust-store"},
            {"name": "release:stable", "key_ids": ids, "threshold": 2, "scope": "release:stable"}
        ]
    })).unwrap()
}
fn signed(payload_type: &str, payload: &[u8], keys: &[&SigningKey]) -> DsseEnvelope {
    let pae = dsse_pae(payload_type, payload);
    DsseEnvelope {
        payload_type: payload_type.to_owned(),
        payload: BASE64.encode(payload),
        signatures: keys.iter().map(|key| DsseSignature {
            key_id: KeyId::for_ed25519(&key.verifying_key().to_bytes()),
            algorithm: Algorithm::Ed25519V1,
            signature: BASE64.encode(key.sign(&pae).to_bytes()),
        }).collect(),
    }
}

#[test]
fn dsse_pae_is_domain_separated_and_verifies_two_of_three_unique_keys() {
    assert_eq!(dsse_pae("text/plain", b"hello"), b"DSSEv1 10 text/plain 5 hello");
    let keys = signing_keys(1);
    let store = parse_trust_store(&store_json(1, &keys), AuthLimits::default()).unwrap();
    let payload = br#"{"answer":42}"#;
    let envelope = signed(PAYLOAD_TYPE, payload, &[&keys[0], &keys[2]]);
    let verified = verify_dsse_scoped(&envelope, PAYLOAD_TYPE, &store, &RoleName::release("stable").unwrap(), "release:stable", now(), AuthLimits::default()).unwrap();
    assert_eq!(verified.payload, payload);
    assert_eq!(verified.signing_key_ids.len(), 2);

    let one = signed(PAYLOAD_TYPE, payload, &[&keys[0]]);
    assert_eq!(verify_dsse(&one, PAYLOAD_TYPE, &store, &RoleName::release("stable").unwrap(), now(), AuthLimits::default()), Err(AuthError::ThresholdNotMet));

    let mut duplicate = envelope.clone();
    duplicate.signatures.push(duplicate.signatures[0].clone());
    assert_eq!(verify_dsse(&duplicate, PAYLOAD_TYPE, &store, &RoleName::release("stable").unwrap(), now(), AuthLimits::default()), Err(AuthError::DuplicateSignature));
}

#[test]
fn release_authorization_is_bound_to_exact_canonical_channel_scope() {
    let keys = signing_keys(7);
    let store = parse_trust_store(&store_json(1, &keys), AuthLimits::default()).unwrap();
    let envelope = signed(PAYLOAD_TYPE, b"stable", &[&keys[0], &keys[1]]);
    let stable = RoleName::release("stable").unwrap();
    assert!(verify_dsse_scoped(&envelope, PAYLOAD_TYPE, &store, &stable, "release:stable", now(), AuthLimits::default()).is_ok());
    assert_eq!(verify_dsse_scoped(&envelope, PAYLOAD_TYPE, &store, &stable, "release:beta", now(), AuthLimits::default()), Err(AuthError::ScopeMismatch));
    assert_eq!(verify_dsse_scoped(&envelope, PAYLOAD_TYPE, &store, &RoleName::release("beta").unwrap(), "release:beta", now(), AuthLimits::default()), Err(AuthError::RoleMissing));
    assert!(RoleName::release("bad/channel").is_err());
}

#[test]
fn bounded_strict_parsing_rejects_unknown_fields_algorithms_and_oversize() {
    let keys = signing_keys(10);
    let mut value: serde_json::Value = serde_json::from_slice(&store_json(1, &keys)).unwrap();
    value.as_object_mut().unwrap().insert("unexpected".into(), json!(true));
    assert_eq!(parse_trust_store(&serde_json::to_vec(&value).unwrap(), AuthLimits::default()), Err(AuthError::Malformed));

    let mut value: serde_json::Value = serde_json::from_slice(&store_json(1, &keys)).unwrap();
    value["keys"][0]["algorithm"] = json!("ed448-v1");
    assert_eq!(parse_trust_store(&serde_json::to_vec(&value).unwrap(), AuthLimits::default()), Err(AuthError::UnknownAlgorithm));

    let envelope_json = br#"{"payload_type":"x","payload":"","signatures":[],"extra":1}"#;
    assert_eq!(DsseEnvelope::parse(envelope_json, AuthLimits::default()), Err(AuthError::Malformed));
    let tight = AuthLimits { max_envelope_bytes: 4, ..AuthLimits::default() };
    assert_eq!(DsseEnvelope::parse(envelope_json, tight), Err(AuthError::Limit));
}

#[test]
fn revocation_and_clock_windows_fail_closed() {
    let keys = signing_keys(20);
    let mut value: serde_json::Value = serde_json::from_slice(&store_json(1, &keys)).unwrap();
    value["keys"][0]["revoked"] = json!(true);
    let store = parse_trust_store(&serde_json::to_vec(&value).unwrap(), AuthLimits::default()).unwrap();
    let envelope = signed(PAYLOAD_TYPE, b"x", &[&keys[0], &keys[1]]);
    assert_eq!(verify_dsse(&envelope, PAYLOAD_TYPE, &store, &RoleName::release("stable").unwrap(), now(), AuthLimits::default()), Err(AuthError::RevokedKey));

    let valid_store = parse_trust_store(&store_json(1, &keys), AuthLimits::default()).unwrap();
    let too_early = OffsetDateTime::parse("2025-12-31T23:59:59Z", &Rfc3339).unwrap();
    assert_eq!(verify_dsse(&envelope, PAYLOAD_TYPE, &valid_store, &RoleName::release("stable").unwrap(), too_early, AuthLimits::default()), Err(AuthError::KeyNotYetValid));
    let expired = OffsetDateTime::parse(AFTER, &Rfc3339).unwrap();
    assert_eq!(verify_dsse(&envelope, PAYLOAD_TYPE, &valid_store, &RoleName::release("stable").unwrap(), expired, AuthLimits::default()), Err(AuthError::TrustStoreExpired));
}

#[test]
fn root_rotation_requires_exact_next_version_and_both_thresholds() {
    let old = signing_keys(30);
    let new = signing_keys(40);
    let current = parse_trust_store(&store_json(7, &old), AuthLimits::default()).unwrap();
    let candidate_bytes = store_json(8, &new);
    let envelope = signed(TRUST_STORE_PAYLOAD_TYPE, &candidate_bytes, &[&old[0], &old[1], &new[0], &new[2]]);
    let verified = verify_trust_store_update(&current, &envelope, now(), AuthLimits::default()).unwrap();
    assert_eq!(verified.trust_store.version, 8);

    let only_old = signed(TRUST_STORE_PAYLOAD_TYPE, &candidate_bytes, &[&old[0], &old[1]]);
    assert_eq!(verify_trust_store_update(&current, &only_old, now(), AuthLimits::default()), Err(AuthError::RotationNewThreshold));
    let only_new = signed(TRUST_STORE_PAYLOAD_TYPE, &candidate_bytes, &[&new[0], &new[1]]);
    assert_eq!(verify_trust_store_update(&current, &only_new, now(), AuthLimits::default()), Err(AuthError::RotationOldThreshold));

    let skipped_bytes = store_json(9, &new);
    let skipped = signed(TRUST_STORE_PAYLOAD_TYPE, &skipped_bytes, &[&old[0], &old[1], &new[0], &new[1]]);
    assert_eq!(verify_trust_store_update(&current, &skipped, now(), AuthLimits::default()), Err(AuthError::RotationVersion));
}
