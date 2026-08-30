use crate::{CryptoEngine, PrivateKey, derive_address, encode_address_base58check};
use aes::Aes128;
use ctr::cipher::{KeyIvInit, StreamCipher};
use hmac::Hmac;
use pbkdf2::pbkdf2;
use rand_core::{CryptoRng, OsRng, RngCore};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::Sha256;
use std::{fmt, io::Read, path::Path};
use subtle::ConstantTimeEq;
use uuid::Uuid;
use zeroize::{ZeroizeOnDrop, Zeroizing};

type Aes128Ctr = ctr::Ctr128BE<Aes128>;
const _: () = {
    fn assert_zeroizing_drop<T: ZeroizeOnDrop>() {}
    let _ = assert_zeroizing_drop::<Aes128Ctr>;
};

pub const KEYSTORE_VERSION: i32 = 3;
pub const KEYSTORE_CIPHER: &str = "aes-128-ctr";
pub const SCRYPT_STANDARD_N: u32 = 1 << 18;
pub const SCRYPT_STANDARD_P: u32 = 1;
pub const SCRYPT_LIGHT_N: u32 = 1 << 12;
pub const SCRYPT_LIGHT_P: u32 = 6;
pub const SCRYPT_R: u32 = 8;
pub const DERIVED_KEY_LENGTH: u32 = 32;
pub const MAX_PASSWORD_FILE_BYTES: usize = 1024;

// Reviewed safe deviation from Java's unbounded inputs. These limits include every
// generated standard/light file and historical compatibility vector while preventing
// attacker-controlled JSON from requesting unbounded CPU, memory, or allocations.
const MAX_SCRYPT_N: u32 = 1 << 20;
const MAX_SCRYPT_R: u32 = 32;
const MAX_SCRYPT_P: u32 = 32;
const MAX_SCRYPT_MEMORY: u64 = 256 * 1024 * 1024;
const MAX_SCRYPT_WORK: u64 = 32 * 1024 * 1024;
const MAX_PBKDF2_ITERATIONS: u32 = 10_000_000;
const MAX_DECODED_FIELD_BYTES: usize = 1024 * 1024;
const MAX_SALT_BYTES: usize = 1024;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CipherParams {
    pub iv: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScryptKdfParams {
    pub dklen: i64,
    pub n: i64,
    pub p: i64,
    pub r: i64,
    pub salt: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Pbkdf2KdfParams {
    #[serde(default)]
    pub dklen: i64,
    pub c: i64,
    pub prf: Option<String>,
    pub salt: Option<String>,
}

/// The PBKDF2 representation historically called `Aes128CtrKdfParams` in Java.
pub type Aes128CtrKdfParams = Pbkdf2KdfParams;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KdfParams {
    Scrypt(ScryptKdfParams),
    Pbkdf2(Pbkdf2KdfParams),
    MissingOrUnknown(Value),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeystoreCrypto {
    pub cipher: Option<String>,
    pub ciphertext: Option<String>,
    pub cipherparams: Option<CipherParams>,
    pub kdf: Option<String>,
    pub kdfparams: KdfParams,
    pub mac: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WalletFile {
    pub address: Option<String>,
    pub crypto: Option<KeystoreCrypto>,
    pub id: Option<String>,
    pub version: i32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScryptProfile { Standard, Light }

pub trait KeystoreRandom: RngCore + CryptoRng {
    fn uuid_v4(&mut self) -> Uuid {
        let mut bytes = [0u8; 16];
        self.fill_bytes(&mut bytes);
        uuid::Builder::from_random_bytes(bytes).into_uuid()
    }
}

impl<T: RngCore + CryptoRng> KeystoreRandom for T {}

#[derive(Debug)]
pub enum KeystoreError {
    Json(serde_json::Error),
    Io(std::io::Error),
    Message(String),
}

impl fmt::Display for KeystoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Json(error) => write!(f, "{error}"),
            Self::Io(error) => write!(f, "{error}"),
            Self::Message(message) => f.write_str(message),
        }
    }
}
impl std::error::Error for KeystoreError {}
impl From<serde_json::Error> for KeystoreError { fn from(value: serde_json::Error) -> Self { Self::Json(value) } }
impl From<std::io::Error> for KeystoreError { fn from(value: std::io::Error) -> Self { Self::Io(value) } }

impl WalletFile {
    pub fn parse(json: &str) -> Result<Self, KeystoreError> { parse_wallet_file(json, true) }
    pub fn parse_strict(json: &str) -> Result<Self, KeystoreError> { parse_wallet_file(json, false) }
    pub fn to_json(&self) -> Result<String, KeystoreError> { Ok(serde_json::to_string(self)?) }
    pub fn is_valid_discovery_file(&self) -> bool {
        self.address.is_some() && validation_error(self).is_none()
    }
}

impl Serialize for WalletFile {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = Map::new();
        if let Some(address) = &self.address { map.insert("address".into(), Value::String(address.clone())); }
        if let Some(crypto) = &self.crypto { map.insert("crypto".into(), crypto_value(crypto).map_err(serde::ser::Error::custom)?); }
        if let Some(id) = &self.id { map.insert("id".into(), Value::String(id.clone())); }
        map.insert("version".into(), Value::from(self.version));
        Value::Object(map).serialize(serializer)
    }
}

fn crypto_value(crypto: &KeystoreCrypto) -> Result<Value, serde_json::Error> {
    let mut map = Map::new();
    if let Some(v) = &crypto.cipher { map.insert("cipher".into(), Value::String(v.clone())); }
    if let Some(v) = &crypto.ciphertext { map.insert("ciphertext".into(), Value::String(v.clone())); }
    if let Some(v) = &crypto.cipherparams { map.insert("cipherparams".into(), serde_json::to_value(v)?); }
    if let Some(v) = &crypto.kdf { map.insert("kdf".into(), Value::String(v.clone())); }
    map.insert("kdfparams".into(), match &crypto.kdfparams {
        KdfParams::Scrypt(v) => serde_json::to_value(v)?,
        KdfParams::Pbkdf2(v) => serde_json::to_value(v)?,
        KdfParams::MissingOrUnknown(v) => v.clone(),
    });
    if let Some(v) = &crypto.mac { map.insert("mac".into(), Value::String(v.clone())); }
    Ok(Value::Object(map))
}

fn parse_wallet_file(json: &str, allow_unquoted: bool) -> Result<WalletFile, KeystoreError> {
    let normalized;
    let input = if allow_unquoted { normalized = quote_unquoted_field_names(json); &normalized } else { json };
    let value: Value = serde_json::from_str(input)?;
    let object = value.as_object().ok_or_else(|| message("expected keystore JSON object"))?;
    // Jackson invokes both setters in document order; later `crypto`/`Crypto` wins.
    let crypto_value = object.iter().filter(|(key, _)| *key == "crypto" || *key == "Crypto").last().map(|(_, value)| value);
    Ok(WalletFile {
        address: string_field(object, "address"),
        crypto: crypto_value.and_then(Value::as_object).map(parse_crypto).transpose()?,
        id: string_field(object, "id"),
        version: parse_version(object)?,
    })
}
fn parse_version(object: &Map<String, Value>) -> Result<i32, KeystoreError> {
    match object.get("version") {
        Some(value @ Value::Number(_)) => Ok(serde_json::from_value(value.clone())?),
        _ => Ok(0),
    }
}


fn parse_crypto(object: &Map<String, Value>) -> Result<KeystoreCrypto, KeystoreError> {
    let kdf = string_field(object, "kdf");
    let raw = object.get("kdfparams").cloned().unwrap_or(Value::Null);
    let kdfparams = match kdf.as_deref() {
        Some("scrypt") => serde_json::from_value(raw.clone()).map(KdfParams::Scrypt).unwrap_or(KdfParams::MissingOrUnknown(raw)),
        Some("pbkdf2") => serde_json::from_value(raw.clone()).map(KdfParams::Pbkdf2).unwrap_or(KdfParams::MissingOrUnknown(raw)),
        _ => KdfParams::MissingOrUnknown(raw),
    };
    Ok(KeystoreCrypto {
        cipher: string_field(object, "cipher"), ciphertext: string_field(object, "ciphertext"),
        cipherparams: object.get("cipherparams").cloned().and_then(|v| serde_json::from_value(v).ok()),
        kdf, kdfparams, mac: string_field(object, "mac"),
    })
}

fn string_field(object: &Map<String, Value>, key: &str) -> Option<String> {
    object.get(key).and_then(Value::as_str).map(str::to_owned)
}

/// Quotes bare object keys only; values and quoted strings are left byte-for-byte intact.
fn quote_unquoted_field_names(input: &str) -> String {
    let bytes = input.as_bytes(); let mut out = String::with_capacity(input.len());
    let mut i = 0; let mut in_string = false; let mut escaped = false; let mut expecting_key = false;
    while i < bytes.len() {
        let ch = bytes[i] as char;
        if in_string {
            out.push(ch); if escaped { escaped = false; } else if ch == '\\' { escaped = true; } else if ch == '"' { in_string = false; }
            i += 1; continue;
        }
        if ch == '"' { in_string = true; out.push(ch); i += 1; continue; }
        if ch == '{' || ch == ',' { expecting_key = true; out.push(ch); i += 1; continue; }
        if expecting_key && ch.is_ascii_whitespace() { out.push(ch); i += 1; continue; }
        if expecting_key && (ch.is_ascii_alphabetic() || ch == '_' || ch == '$') {
            let start = i; i += 1;
            while i < bytes.len() && ((bytes[i] as char).is_ascii_alphanumeric() || bytes[i] == b'_' || bytes[i] == b'$') { i += 1; }
            let mut j = i; while j < bytes.len() && (bytes[j] as char).is_ascii_whitespace() { j += 1; }
            if j < bytes.len() && bytes[j] == b':' { out.push('"'); out.push_str(&input[start..i]); out.push('"'); expecting_key = false; continue; }
            out.push_str(&input[start..i]); continue;
        }
        if !ch.is_ascii_whitespace() { expecting_key = false; }
        out.push(ch); i += 1;
    }
    out
}

pub fn validation_error(wallet: &WalletFile) -> Option<&'static str> {
    if wallet.version != KEYSTORE_VERSION { return Some("Wallet version is not supported"); }
    let Some(crypto) = wallet.crypto.as_ref() else { return Some("Missing crypto section"); };
    if crypto.cipher.as_deref() != Some(KEYSTORE_CIPHER) { return Some("Wallet cipher is not supported"); }
    if !matches!(crypto.kdf.as_deref(), Some("pbkdf2" | "scrypt")) { return Some("KDF type is not supported"); }
    None
}

pub fn validate(wallet: &WalletFile) -> Result<(), KeystoreError> {
    if wallet.version != KEYSTORE_VERSION { return Err(message("Wallet version is not supported")); }
    let Some(crypto) = &wallet.crypto else { return Err(message("Missing crypto section")); };
    if crypto.cipher.as_deref() != Some(KEYSTORE_CIPHER) { return Err(message("Wallet cipher is not supported")); }
    if !matches!(crypto.kdf.as_deref(), Some("pbkdf2" | "scrypt")) { return Err(message("KDF type is not supported")); }
    Ok(())
}

pub fn create_standard(password: &str, key: &PrivateKey, checksum_engine: CryptoEngine) -> Result<WalletFile, KeystoreError> {
    create(password, key, checksum_engine, ScryptProfile::Standard)
}
pub fn create_light(password: &str, key: &PrivateKey, checksum_engine: CryptoEngine) -> Result<WalletFile, KeystoreError> {
    create(password, key, checksum_engine, ScryptProfile::Light)
}
pub fn create(password: &str, key: &PrivateKey, checksum_engine: CryptoEngine, profile: ScryptProfile) -> Result<WalletFile, KeystoreError> {
    create_with_random(password, key, checksum_engine, profile, &mut OsRng)
}

pub fn create_with_random<R: KeystoreRandom>(password: &str, key: &PrivateKey, checksum_engine: CryptoEngine, profile: ScryptProfile, random: &mut R) -> Result<WalletFile, KeystoreError> {
    let (n, p) = match profile { ScryptProfile::Standard => (SCRYPT_STANDARD_N, SCRYPT_STANDARD_P), ScryptProfile::Light => (SCRYPT_LIGHT_N, SCRYPT_LIGHT_P) };
    let mut salt = [0u8; 32]; random.fill_bytes(&mut salt);
    let params = ScryptKdfParams { dklen: 32, n: i64::from(n), p: i64::from(p), r: 8, salt: Some(hex_encode(&salt)) };
    create_with_scrypt_params_and_random(password, key, checksum_engine, params, random)
}

pub fn create_with_scrypt_params_and_random<R: KeystoreRandom>(password: &str, key: &PrivateKey, checksum_engine: CryptoEngine, params: ScryptKdfParams, random: &mut R) -> Result<WalletFile, KeystoreError> {
    let salt = decode_hex(params.salt.as_deref(), "salt")?;
    let mut iv = [0u8; 16]; random.fill_bytes(&mut iv);
    let derived = derive_scrypt(password.as_bytes(), &salt, &params)?;
    let mut ciphertext = with_private_bytes(key, |private_bytes| {
        let mut ciphertext = Zeroizing::new([0u8; 32]);
        ciphertext.copy_from_slice(private_bytes);
        ciphertext
    });
    apply_aes_ctr(&derived[..16], &iv, ciphertext.as_mut_slice())?;
    let mac = compute_mac(&derived, ciphertext.as_slice());
    let address = encode_address_base58check(checksum_engine, &derive_address(&key.public_key()));
    Ok(WalletFile { address: Some(address), id: Some(random.uuid_v4().to_string()), version: 3, crypto: Some(KeystoreCrypto {
        cipher: Some(KEYSTORE_CIPHER.into()), ciphertext: Some(hex_encode(ciphertext.as_slice())), cipherparams: Some(CipherParams { iv: Some(hex_encode(&iv)) }),
        kdf: Some("scrypt".into()), kdfparams: KdfParams::Scrypt(params), mac: Some(hex_encode(&mac)),
    }) })
}

pub fn decrypt(password: &str, wallet: &WalletFile, key_engine: CryptoEngine, checksum_engine: CryptoEngine) -> Result<PrivateKey, KeystoreError> {
    validate(wallet)?;
    let crypto = wallet.crypto.as_ref().expect("validated");
    let mac = decode_hex(crypto.mac.as_deref(), "mac")?;
    let iv = decode_hex(crypto.cipherparams.as_ref().and_then(|v| v.iv.as_deref()), "iv")?;
    let mut ciphertext = Zeroizing::new(decode_hex(crypto.ciphertext.as_deref(), "ciphertext")?);
    let derived = match &crypto.kdfparams {
        KdfParams::Scrypt(params) => { let salt = decode_hex(params.salt.as_deref(), "salt")?; derive_scrypt(password.as_bytes(), &salt, params)? }
        KdfParams::Pbkdf2(params) => { let salt = decode_hex(params.salt.as_deref(), "salt")?; derive_pbkdf2(password.as_bytes(), &salt, params)? }
        KdfParams::MissingOrUnknown(_) => return Err(message(format!("Unable to deserialize params: {}", crypto.kdf.as_deref().unwrap_or("null")))),
    };
    let expected = compute_mac(&derived, &ciphertext);
    if mac.len() != expected.len() || !bool::from(mac.ct_eq(&expected)) { return Err(message("Invalid password provided")); }
    apply_aes_ctr(&derived[..16], &iv, &mut ciphertext)?;
    let key = PrivateKey::from_bytes(key_engine, &ciphertext).map_err(|e| message(e.to_string()))?;
    if let Some(declared) = wallet.address.as_deref().filter(|v| !v.is_empty()) {
        let derived_address = encode_address_base58check(checksum_engine, &derive_address(&key.public_key()));
        if declared != derived_address { return Err(message(format!("Keystore address mismatch: file declares {declared} but private key derives {derived_address}"))); }
    }
    Ok(key)
}

fn derive_scrypt(password: &[u8], salt: &[u8], params: &ScryptKdfParams) -> Result<Zeroizing<Vec<u8>>, KeystoreError> {
    let n = positive_u32(params.n, "scrypt n")?; let r = positive_u32(params.r, "scrypt r")?; let p = positive_u32(params.p, "scrypt p")?;
    let dklen = positive_usize(params.dklen, "scrypt dklen")?;
    if !n.is_power_of_two() || n > MAX_SCRYPT_N || r > MAX_SCRYPT_R || p > MAX_SCRYPT_P || dklen < 32 || dklen > 64 || salt.len() > MAX_SALT_BYTES || 128u64.saturating_mul(n as u64).saturating_mul(r as u64) > MAX_SCRYPT_MEMORY || (n as u64).saturating_mul(r as u64).saturating_mul(p as u64) > MAX_SCRYPT_WORK {
        return Err(message("KDF parameters exceed safe compatibility limits"));
    }
    let log_n = n.trailing_zeros() as u8;
    let config = scrypt::Params::new(log_n, r, p, dklen).map_err(|_| message("KDF parameters exceed safe compatibility limits"))?;
    let mut output = Zeroizing::new(vec![0; dklen]); scrypt::scrypt(password, salt, &config, &mut output).map_err(|_| message("KDF operation failed"))?; Ok(output)
}

fn derive_pbkdf2(password: &[u8], salt: &[u8], params: &Pbkdf2KdfParams) -> Result<Zeroizing<Vec<u8>>, KeystoreError> {
    if params.prf.as_deref() != Some("hmac-sha256") { return Err(message(format!("Unsupported prf:{}", params.prf.as_deref().unwrap_or("null")))); }
    let rounds = positive_u32(params.c, "pbkdf2 c")?;
    if rounds > MAX_PBKDF2_ITERATIONS || salt.len() > MAX_SALT_BYTES { return Err(message("KDF parameters exceed safe compatibility limits")); }
    // Java ignores JSON dklen and always calls generateDerivedParameters(256).
    let mut output = Zeroizing::new(vec![0u8; 32]); pbkdf2::<Hmac<Sha256>>(password, salt, rounds, &mut output).map_err(|_| message("KDF operation failed"))?; Ok(output)
}

fn apply_aes_ctr(key: &[u8], iv: &[u8], text: &mut [u8]) -> Result<(), KeystoreError> {
    let mut cipher = Aes128Ctr::new_from_slices(key, iv).map_err(|_| message("Error performing cipher operation"))?; cipher.apply_keystream(text); Ok(())
}
fn with_private_bytes<T>(key: &PrivateKey, use_bytes: impl FnOnce(&[u8]) -> T) -> T {
    match key {
        PrivateKey::Secp256k1(key) => key.with_private_bytes(use_bytes),
        PrivateKey::Sm2(key) => key.with_private_bytes(use_bytes),
    }
}

fn compute_mac(derived: &[u8], ciphertext: &[u8]) -> [u8; 32] {
    let mut input = Zeroizing::new(Vec::with_capacity(16 + ciphertext.len()));
    input.extend_from_slice(&derived[16..32]);
    input.extend_from_slice(ciphertext);
    crate::keccak256(&input)
}

/// Java-compatible hex: null is empty, lowercase `0x` only, odd length is zero-padded.
fn decode_hex(value: Option<&str>, field: &str) -> Result<Vec<u8>, KeystoreError> {
    let mut text = value.unwrap_or(""); if let Some(rest) = text.strip_prefix("0x") { text = rest; }
    if text.len() > MAX_DECODED_FIELD_BYTES * 2 { return Err(message(format!("{field} exceeds safe size limit"))); }
    let padded; if text.len() % 2 != 0 { padded = format!("0{text}"); text = &padded; }
    let mut out = Vec::with_capacity(text.len() / 2);
    for pair in text.as_bytes().chunks_exact(2) { let s = std::str::from_utf8(pair).expect("ASCII slice"); out.push(u8::from_str_radix(s, 16).map_err(|_| message(format!("invalid hexadecimal {field}")))?); }
    Ok(out)
}
fn hex_encode(bytes: &[u8]) -> String { bytes.iter().map(|b| format!("{b:02x}")).collect() }
fn positive_u32(value: i64, name: &str) -> Result<u32, KeystoreError> { u32::try_from(value).ok().filter(|v| *v > 0).ok_or_else(|| message(format!("invalid {name}"))) }
fn positive_usize(value: i64, name: &str) -> Result<usize, KeystoreError> { usize::try_from(value).ok().filter(|v| *v > 0).ok_or_else(|| message(format!("invalid {name}"))) }
fn message(value: impl Into<String>) -> KeystoreError { KeystoreError::Message(value.into()) }

pub fn strip_password_line(input: Option<&str>) -> Option<String> {
    input.map(|value| value.strip_prefix('\u{feff}').unwrap_or(value).trim_end_matches(['\r', '\n']).to_owned())
}

/// Java `String.length()` counts UTF-16 code units, not Unicode scalar values.
pub fn password_valid(password: Option<&str>) -> bool {
    password.is_some_and(|value| !value.is_empty() && value.encode_utf16().count() >= 6)
}

#[derive(Debug)]
pub enum PasswordFileError {
    Io(std::io::Error),
    Symlink,
    NotRegularFile,
    TooLarge,
    InsecurePermissions { mode: u32 },
    WrongOwner { owner: u32, effective_user: u32 },
    MultipleLines,
    WrongLineCount,
    InvalidPassword,
}
impl fmt::Display for PasswordFileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(_) => f.write_str("unable to read password file"),
            Self::Symlink => f.write_str("refusing to follow symbolic link"),
            Self::NotRegularFile => f.write_str("not a regular file"),
            Self::TooLarge => write!(f, "password file too large (max {MAX_PASSWORD_FILE_BYTES} bytes)"),
            Self::InsecurePermissions { mode } => write!(f, "password file must be POSIX 0600 (found {:04o})", mode & 0o7777),
            Self::WrongOwner { owner, effective_user } => write!(f, "password file owner {owner} does not match effective user {effective_user}"),
            Self::MultipleLines => f.write_str("password file contains multiple lines"),
            Self::WrongLineCount => f.write_str("password file must contain exactly two lines"),
            Self::InvalidPassword => f.write_str("invalid password: must be at least 6 characters"),
        }
    }
}
impl std::error::Error for PasswordFileError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self { Self::Io(error) => Some(error), _ => None }
    }
}

pub fn read_password_file(path: impl AsRef<Path>) -> Result<String, PasswordFileError> {
    let bytes = read_bounded_nofollow(path.as_ref())?;
    let decoded = Zeroizing::new(String::from_utf8_lossy(&bytes).into_owned()); // Java decoder replaces malformed UTF-8.
    let password = Zeroizing::new(strip_password_line(Some(&decoded)).expect("present"));
    if password.contains(['\r', '\n']) { return Err(PasswordFileError::MultipleLines); }
    if !password_valid(Some(&password)) { return Err(PasswordFileError::InvalidPassword); }
    Ok(password.to_string())
}

pub fn read_update_password_file(path: impl AsRef<Path>) -> Result<(String, String), PasswordFileError> {
    let bytes = read_bounded_nofollow(path.as_ref())?;
    let decoded = Zeroizing::new(String::from_utf8_lossy(&bytes).into_owned());
    let content = decoded.strip_prefix('\u{feff}').unwrap_or(&decoded);
    let mut lines = split_java_lines(content);
    // Java String.split(regex) drops all trailing empty fields.
    while lines.last() == Some(&"") { lines.pop(); }
    if lines.len() != 2 { return Err(PasswordFileError::WrongLineCount); }
    let old = Zeroizing::new(strip_password_line(Some(lines[0])).expect("present"));
    let new = Zeroizing::new(strip_password_line(Some(lines[1])).expect("present"));
    if !password_valid(Some(&new)) { return Err(PasswordFileError::InvalidPassword); }
    Ok((old.to_string(), new.to_string()))
}

fn split_java_lines(content: &str) -> Vec<&str> {
    let bytes = content.as_bytes();
    let mut lines = Vec::new();
    let mut start = 0;
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'\r' || bytes[index] == b'\n' {
            lines.push(&content[start..index]);
            if bytes[index] == b'\r' && bytes.get(index + 1) == Some(&b'\n') { index += 1; }
            index += 1;
            start = index;
        } else {
            index += 1;
        }
    }
    lines.push(&content[start..]);
    lines
}

fn read_bounded_nofollow(path: &Path) -> Result<Zeroizing<Vec<u8>>, PasswordFileError> {
    #[cfg(unix)]
    let file = {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK).open(path).map_err(|error| {
            if error.raw_os_error() == Some(libc::ELOOP) { PasswordFileError::Symlink } else { PasswordFileError::Io(error) }
        })?
    };
    #[cfg(not(unix))]
    let file = std::fs::File::open(path).map_err(PasswordFileError::Io)?;
    let metadata = file.metadata().map_err(PasswordFileError::Io)?;
    if !metadata.is_file() { return Err(PasswordFileError::NotRegularFile); }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let mode = metadata.mode() & 0o7777;
        if mode != 0o600 { return Err(PasswordFileError::InsecurePermissions { mode }); }
        let effective_user = rustix::process::geteuid().as_raw();
        if metadata.uid() != effective_user {
            return Err(PasswordFileError::WrongOwner { owner: metadata.uid(), effective_user });
        }
    }
    if metadata.len() > MAX_PASSWORD_FILE_BYTES as u64 { return Err(PasswordFileError::TooLarge); }
    let mut bytes = Zeroizing::new(Vec::with_capacity(MAX_PASSWORD_FILE_BYTES + 1));
    file.take((MAX_PASSWORD_FILE_BYTES + 1) as u64).read_to_end(&mut bytes).map_err(PasswordFileError::Io)?;
    if bytes.len() > MAX_PASSWORD_FILE_BYTES { return Err(PasswordFileError::TooLarge); }
    Ok(bytes)
}
