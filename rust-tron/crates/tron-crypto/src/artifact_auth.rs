//! Domain-separated authentication for release and snapshot artifacts.
//!
//! This module deliberately does not accept TRON transaction signatures or a
//! transaction [`crate::CryptoEngine`]. Artifact signatures are Ed25519-v1
//! signatures over DSSE PAE bytes.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

pub const TRUST_STORE_SCHEMA: &str = "tron-trust-store-v1";
pub const TRUST_STORE_PAYLOAD_TYPE: &str = "application/vnd.tron.trust-store.v1+json";
const ED25519_V1: &str = "ed25519-v1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthLimits {
    pub max_envelope_bytes: usize,
    pub max_payload_bytes: usize,
    pub max_signatures: usize,
    pub max_keys: usize,
    pub max_roles: usize,
}

impl Default for AuthLimits {
    fn default() -> Self {
        Self {
            max_envelope_bytes: 1024 * 1024,
            max_payload_bytes: 768 * 1024,
            max_signatures: 32,
            max_keys: 128,
            max_roles: 32,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AuthError {
    Malformed,
    Limit,
    UnknownVersion,
    UnknownAlgorithm,
    UnknownKey,
    RevokedKey,
    KeyNotYetValid,
    KeyExpired,
    TrustStoreExpired,
    RoleMissing,
    ThresholdNotMet,
    ScopeMismatch,
    DuplicateSignature,
    BadSignature,
    RotationVersion,
    RotationOldThreshold,
    RotationNewThreshold,
}

impl fmt::Display for AuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", match self {
            Self::Malformed => "malformed artifact authentication data",
            Self::Limit => "artifact authentication limit exceeded",
            Self::UnknownVersion => "unknown authentication version",
            Self::UnknownAlgorithm => "unknown signature algorithm",
            Self::UnknownKey => "unknown signing key",
            Self::RevokedKey => "revoked signing key",
            Self::KeyNotYetValid => "signing key is not yet valid",
            Self::KeyExpired => "signing key has expired",
            Self::TrustStoreExpired => "trust store has expired",
            Self::ScopeMismatch => "trust role scope does not match artifact scope",
            Self::RoleMissing => "trust role is missing",
            Self::ThresholdNotMet => "signature threshold not met",
            Self::DuplicateSignature => "duplicate signature",
            Self::BadSignature => "bad signature",
            Self::RotationVersion => "trust-store rotation version is not sequential",
            Self::RotationOldThreshold => "current root threshold not met",
            Self::RotationNewThreshold => "candidate root threshold not met",
        })
    }
}
impl std::error::Error for AuthError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum Algorithm {
    #[serde(rename = "ed25519-v1")]
    Ed25519V1,
}

impl Algorithm {
    pub const fn as_str(self) -> &'static str { ED25519_V1 }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct KeyId(String);

impl KeyId {
    pub fn new(value: impl Into<String>) -> Result<Self, AuthError> {
        let value = value.into();
        if value.len() != 64 || !value.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()) {
            return Err(AuthError::Malformed);
        }
        Ok(Self(value))
    }
    pub fn for_ed25519(public_key: &[u8; 32]) -> Self {
        let mut digest = Sha256::new();
        digest.update(ED25519_V1.as_bytes());
        digest.update([0]);
        digest.update(public_key);
        Self(hex_lower(&digest.finalize()))
    }
    pub fn as_str(&self) -> &str { &self.0 }
}

impl fmt::Display for KeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { f.write_str(&self.0) }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RoleName(String);

impl RoleName {
    pub fn new(value: impl Into<String>) -> Result<Self, AuthError> {
        let value = value.into();
        if value.is_empty() || value.len() > 128 || !value.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b':' | b'-' | b'_' | b'.')) {
            return Err(AuthError::Malformed);
        }
        Ok(Self(value))
    }
    pub fn root() -> Self { Self("root".to_owned()) }
    pub fn release(channel: &str) -> Result<Self, AuthError> { Self::new(format!("release:{channel}")) }
    pub fn snapshot(network: &str) -> Result<Self, AuthError> { Self::new(format!("snapshot:{network}")) }
    pub fn as_str(&self) -> &str { &self.0 }
}

impl fmt::Display for RoleName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { f.write_str(&self.0) }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrustedKey {
    pub key_id: KeyId,
    pub algorithm: Algorithm,
    pub public_key: [u8; 32],
    pub not_before: OffsetDateTime,
    pub not_after: OffsetDateTime,
    pub revoked: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrustRole {
    pub name: RoleName,
    pub key_ids: Vec<KeyId>,
    pub threshold: usize,
    pub scope: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrustStoreV1 {
    pub version: u64,
    pub expires: OffsetDateTime,
    pub keys: Vec<TrustedKey>,
    pub roles: Vec<TrustRole>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DsseSignature {
    pub key_id: KeyId,
    pub algorithm: Algorithm,
    pub signature: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DsseEnvelope {
    pub payload_type: String,
    pub payload: String,
    pub signatures: Vec<DsseSignature>,
}

impl DsseEnvelope {
    pub fn parse(bytes: &[u8], limits: AuthLimits) -> Result<Self, AuthError> {
        if bytes.len() > limits.max_envelope_bytes { return Err(AuthError::Limit); }
        let envelope: Self = serde_json::from_slice(bytes).map_err(classify_json_error)?;
        envelope.validate_limits(limits)?;
        Ok(envelope)
    }

    pub fn payload_bytes(&self, limits: AuthLimits) -> Result<Vec<u8>, AuthError> {
        let estimated = self.payload.len().saturating_mul(3) / 4;
        if estimated > limits.max_payload_bytes { return Err(AuthError::Limit); }
        let payload = decode_canonical_base64(&self.payload)?;
        if payload.len() > limits.max_payload_bytes { return Err(AuthError::Limit); }
        Ok(payload)
    }

    fn validate_limits(&self, limits: AuthLimits) -> Result<(), AuthError> {
        if self.payload_type.is_empty() || self.payload_type.len() > 256 || self.signatures.len() > limits.max_signatures {
            return Err(AuthError::Limit);
        }
        let mut ids = HashSet::with_capacity(self.signatures.len());
        for signature in &self.signatures {
            if !ids.insert(&signature.key_id) { return Err(AuthError::DuplicateSignature); }
            if signature.signature.len() > 128 { return Err(AuthError::Limit); }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedPayload {
    pub payload_type: String,
    pub payload: Vec<u8>,
    pub signing_key_ids: Vec<KeyId>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedTrustStore {
    pub trust_store: TrustStoreV1,
    pub payload: VerifiedPayload,
}

pub trait AuthClock {
    fn now(&self) -> OffsetDateTime;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct SystemAuthClock;
impl AuthClock for SystemAuthClock {
    fn now(&self) -> OffsetDateTime {
        let duration = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
        OffsetDateTime::from_unix_timestamp_nanos(duration.as_nanos() as i128).unwrap_or(OffsetDateTime::UNIX_EPOCH)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FixedAuthClock(pub OffsetDateTime);
impl AuthClock for FixedAuthClock { fn now(&self) -> OffsetDateTime { self.0 } }

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TrustStoreWire {
    schema: String,
    version: u64,
    expires: String,
    keys: Vec<TrustedKeyWire>,
    roles: Vec<TrustRoleWire>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TrustedKeyWire {
    key_id: KeyId,
    algorithm: Algorithm,
    #[serde(rename = "public_key_base64")]
    public_key: String,
    not_before: String,
    not_after: String,
    revoked: bool,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TrustRoleWire {
    name: RoleName,
    key_ids: Vec<KeyId>,
    threshold: usize,
    scope: String,
}

pub fn parse_trust_store(bytes: &[u8], limits: AuthLimits) -> Result<TrustStoreV1, AuthError> {
    if bytes.len() > limits.max_payload_bytes { return Err(AuthError::Limit); }
    let wire: TrustStoreWire = serde_json::from_slice(bytes).map_err(classify_json_error)?;
    if wire.schema != TRUST_STORE_SCHEMA || wire.version == 0 { return Err(AuthError::UnknownVersion); }
    if wire.keys.len() > limits.max_keys || wire.roles.len() > limits.max_roles { return Err(AuthError::Limit); }
    let expires = parse_time(&wire.expires)?;
    let mut key_ids = HashSet::with_capacity(wire.keys.len());
    let mut keys = Vec::with_capacity(wire.keys.len());
    for key in wire.keys {
        if !key_ids.insert(key.key_id.clone()) { return Err(AuthError::Malformed); }
        let raw = decode_canonical_base64(&key.public_key)?;
        let public_key: [u8; 32] = raw.try_into().map_err(|_| AuthError::Malformed)?;
        if KeyId::for_ed25519(&public_key) != key.key_id { return Err(AuthError::Malformed); }
        let not_before = parse_time(&key.not_before)?;
        let not_after = parse_time(&key.not_after)?;
        if not_before >= not_after { return Err(AuthError::Malformed); }
        keys.push(TrustedKey { key_id: key.key_id, algorithm: key.algorithm, public_key, not_before, not_after, revoked: key.revoked });
    }
    let mut role_names = HashSet::with_capacity(wire.roles.len());
    let mut roles = Vec::with_capacity(wire.roles.len());
    for role in wire.roles {
        if !role_names.insert(role.name.clone()) || role.threshold == 0 || role.threshold > role.key_ids.len() || role.scope.is_empty() || role.scope.len() > 256 {
            return Err(AuthError::Malformed);
        }
        let mut members = HashSet::with_capacity(role.key_ids.len());
        for key_id in &role.key_ids {
            if !members.insert(key_id) || !key_ids.contains(key_id) { return Err(AuthError::Malformed); }
        }
        roles.push(TrustRole { name: role.name, key_ids: role.key_ids, threshold: role.threshold, scope: role.scope });
    }
    if !role_names.contains(&RoleName::root()) { return Err(AuthError::RoleMissing); }
    Ok(TrustStoreV1 { version: wire.version, expires, keys, roles })
}

pub fn verify_dsse(
    envelope: &DsseEnvelope,
    expected_payload_type: &str,
    trust_store: &TrustStoreV1,
    role: &RoleName,
    now: OffsetDateTime,
    limits: AuthLimits,
) -> Result<VerifiedPayload, AuthError> {
    envelope.validate_limits(limits)?;
    if envelope.payload_type != expected_payload_type { return Err(AuthError::Malformed); }
    let payload = envelope.payload_bytes(limits)?;
    let valid = verify_threshold(envelope, &payload, trust_store, role, now, limits)?;
    Ok(VerifiedPayload { payload_type: envelope.payload_type.clone(), payload, signing_key_ids: valid })
}

pub fn verify_dsse_scoped(
    envelope: &DsseEnvelope,
    expected_payload_type: &str,
    trust_store: &TrustStoreV1,
    role: &RoleName,
    expected_scope: &str,
    now: OffsetDateTime,
    limits: AuthLimits,
) -> Result<VerifiedPayload, AuthError> {
    let trust_role = trust_store.roles.iter().find(|candidate| &candidate.name == role).ok_or(AuthError::RoleMissing)?;
    if trust_role.scope != expected_scope { return Err(AuthError::ScopeMismatch); }
    verify_dsse(envelope, expected_payload_type, trust_store, role, now, limits)
}

pub fn verify_trust_store_update(
    current: &TrustStoreV1,
    candidate_envelope: &DsseEnvelope,
    now: OffsetDateTime,
    limits: AuthLimits,
) -> Result<VerifiedTrustStore, AuthError> {
    candidate_envelope.validate_limits(limits)?;
    if candidate_envelope.payload_type != TRUST_STORE_PAYLOAD_TYPE { return Err(AuthError::Malformed); }
    let bytes = candidate_envelope.payload_bytes(limits)?;
    let candidate = parse_trust_store(&bytes, limits)?;
    if candidate.version != current.version.checked_add(1).ok_or(AuthError::RotationVersion)? {
        return Err(AuthError::RotationVersion);
    }
    let (old_valid, new_valid) = verify_rotation_signatures(
        candidate_envelope, &bytes, current, &candidate, now, limits,
    )?;
    if old_valid.len() < root_role(current).map_err(|_| AuthError::RotationOldThreshold)?.threshold {
        return Err(AuthError::RotationOldThreshold);
    }
    if new_valid.len() < root_role(&candidate).map_err(|_| AuthError::RotationNewThreshold)?.threshold {
        return Err(AuthError::RotationNewThreshold);
    }
    let candidate_keys = new_valid;
    Ok(VerifiedTrustStore {
        trust_store: candidate,
        payload: VerifiedPayload { payload_type: TRUST_STORE_PAYLOAD_TYPE.to_owned(), payload: bytes, signing_key_ids: candidate_keys },
    })
}

pub fn dsse_pae(payload_type: &str, payload: &[u8]) -> Vec<u8> {
    let type_len = decimal(payload_type.len());
    let payload_len = decimal(payload.len());
    let mut out = Vec::with_capacity(6 + type_len.len() + payload_type.len() + payload_len.len() + payload.len() + 3);
    out.extend_from_slice(b"DSSEv1 ");
    out.extend_from_slice(type_len.as_bytes());
    out.push(b' ');
    out.extend_from_slice(payload_type.as_bytes());
    out.push(b' ');
    out.extend_from_slice(payload_len.as_bytes());
    out.push(b' ');
    out.extend_from_slice(payload);
    out
}

fn verify_threshold(
    envelope: &DsseEnvelope,
    payload: &[u8],
    store: &TrustStoreV1,
    role_name: &RoleName,
    now: OffsetDateTime,
    limits: AuthLimits,
) -> Result<Vec<KeyId>, AuthError> {
    if store.expires <= now { return Err(AuthError::TrustStoreExpired); }
    if store.keys.len() > limits.max_keys || store.roles.len() > limits.max_roles { return Err(AuthError::Limit); }
    let role = store.roles.iter().find(|role| &role.name == role_name).ok_or(AuthError::RoleMissing)?;
    let members: HashSet<&KeyId> = role.key_ids.iter().collect();
    let keys: HashMap<&KeyId, &TrustedKey> = store.keys.iter().map(|key| (&key.key_id, key)).collect();
    let pae = dsse_pae(&envelope.payload_type, payload);
    let mut valid = Vec::with_capacity(role.threshold);
    let mut seen = HashSet::with_capacity(envelope.signatures.len());
    for signed in &envelope.signatures {
        if !seen.insert(&signed.key_id) { return Err(AuthError::DuplicateSignature); }
        let key = keys.get(&signed.key_id).copied().ok_or(AuthError::UnknownKey)?;
        if key.algorithm != Algorithm::Ed25519V1 || signed.algorithm != Algorithm::Ed25519V1 { return Err(AuthError::UnknownAlgorithm); }
        if key.revoked { return Err(AuthError::RevokedKey); }
        if now < key.not_before { return Err(AuthError::KeyNotYetValid); }
        if now >= key.not_after { return Err(AuthError::KeyExpired); }
        let signature_bytes = decode_canonical_base64(&signed.signature)?;
        let signature = Signature::from_slice(&signature_bytes).map_err(|_| AuthError::BadSignature)?;
        let verifying_key = VerifyingKey::from_bytes(&key.public_key).map_err(|_| AuthError::Malformed)?;
        verifying_key.verify(&pae, &signature).map_err(|_| AuthError::BadSignature)?;
        if members.contains(&signed.key_id) { valid.push(key.key_id.clone()); }
    }
    if valid.len() < role.threshold { return Err(AuthError::ThresholdNotMet); }
    Ok(valid)
}

fn root_role(store: &TrustStoreV1) -> Result<&TrustRole, AuthError> {
    store.roles.iter().find(|role| role.name == RoleName::root()).ok_or(AuthError::RoleMissing)
}

fn verify_rotation_signatures(
    envelope: &DsseEnvelope,
    payload: &[u8],
    current: &TrustStoreV1,
    candidate: &TrustStoreV1,
    now: OffsetDateTime,
    limits: AuthLimits,
) -> Result<(Vec<KeyId>, Vec<KeyId>), AuthError> {
    if current.expires <= now || candidate.expires <= now { return Err(AuthError::TrustStoreExpired); }
    if current.keys.len() > limits.max_keys || candidate.keys.len() > limits.max_keys { return Err(AuthError::Limit); }
    let old_role = root_role(current).map_err(|_| AuthError::RotationOldThreshold)?;
    let new_role = root_role(candidate).map_err(|_| AuthError::RotationNewThreshold)?;
    let old_members: HashSet<&KeyId> = old_role.key_ids.iter().collect();
    let new_members: HashSet<&KeyId> = new_role.key_ids.iter().collect();
    let old_keys: HashMap<&KeyId, &TrustedKey> = current.keys.iter().map(|key| (&key.key_id, key)).collect();
    let new_keys: HashMap<&KeyId, &TrustedKey> = candidate.keys.iter().map(|key| (&key.key_id, key)).collect();
    let pae = dsse_pae(&envelope.payload_type, payload);
    let mut old_valid = Vec::new();
    let mut new_valid = Vec::new();
    let mut seen = HashSet::with_capacity(envelope.signatures.len());
    for signed in &envelope.signatures {
        if !seen.insert(&signed.key_id) { return Err(AuthError::DuplicateSignature); }
        let old_key = old_keys.get(&signed.key_id).copied();
        let new_key = new_keys.get(&signed.key_id).copied();
        let key = new_key.or(old_key).ok_or(AuthError::UnknownKey)?;
        if old_key.is_some_and(|key| key.revoked) || new_key.is_some_and(|key| key.revoked) { return Err(AuthError::RevokedKey); }
        if key.algorithm != Algorithm::Ed25519V1 || signed.algorithm != Algorithm::Ed25519V1 { return Err(AuthError::UnknownAlgorithm); }
        if now < key.not_before { return Err(AuthError::KeyNotYetValid); }
        if now >= key.not_after { return Err(AuthError::KeyExpired); }
        let signature_bytes = decode_canonical_base64(&signed.signature)?;
        let signature = Signature::from_slice(&signature_bytes).map_err(|_| AuthError::BadSignature)?;
        let verifying_key = VerifyingKey::from_bytes(&key.public_key).map_err(|_| AuthError::Malformed)?;
        verifying_key.verify(&pae, &signature).map_err(|_| AuthError::BadSignature)?;
        if old_members.contains(&signed.key_id) { old_valid.push(signed.key_id.clone()); }
        if new_members.contains(&signed.key_id) { new_valid.push(signed.key_id.clone()); }
    }
    Ok((old_valid, new_valid))
}

fn decode_canonical_base64(value: &str) -> Result<Vec<u8>, AuthError> {
    let decoded = BASE64.decode(value).map_err(|_| AuthError::Malformed)?;
    if BASE64.encode(&decoded) != value { return Err(AuthError::Malformed); }
    Ok(decoded)
}

fn parse_time(value: &str) -> Result<OffsetDateTime, AuthError> {
    let time = OffsetDateTime::parse(value, &Rfc3339).map_err(|_| AuthError::Malformed)?;
    if time.format(&Rfc3339).map_err(|_| AuthError::Malformed)? != value { return Err(AuthError::Malformed); }
    Ok(time)
}

fn classify_json_error(error: serde_json::Error) -> AuthError {
    let message = error.to_string();
    if message.contains("unknown variant") && message.contains(ED25519_V1) { AuthError::UnknownAlgorithm }
    else { AuthError::Malformed }
}

fn decimal(value: usize) -> String { value.to_string() }

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &byte in bytes { out.push(HEX[(byte >> 4) as usize] as char); out.push(HEX[(byte & 15) as usize] as char); }
    out
}
