use aes::Aes128;
use ctr::cipher::{KeyIvInit, StreamCipher};
use hmac::Hmac;
use pbkdf2::pbkdf2;
use rand_core::{CryptoRng, Error as RngError, RngCore};
use serde_json::{Value};
use sha2::Sha256;
use std::{fs, path::{Path, PathBuf}, process::Command};
use tron_crypto::{derive_address, encode_address_base58check, keccak256, CryptoEngine, PrivateKey};
use tron_crypto::keystore::*;
use tron_crypto::keystore_store::*;

const ORACLE: &str = include_str!("../../../../docs/oracles/c005-keystore-fixture-manifest.v1.json");
const C004_ORACLE: &str = include_str!("../../../../docs/oracles/c004-crypto-fixture-manifest.v1.json");
const PASSWORD: &str = "correct horse battery staple";
type Aes128Ctr = ctr::Ctr128BE<Aes128>;
const _: () = {
    fn assert_zeroizing_drop<T: zeroize::ZeroizeOnDrop>() {}
    let _ = assert_zeroizing_drop::<Aes128Ctr>;
};


fn oracle() -> Value { serde_json::from_str(ORACLE).unwrap() }
fn vectors(dispatch: &str) -> Vec<Value> {
    let root = oracle();
    let routes = root["rust_dispatch"].as_object().unwrap();
    let out: Vec<_> = root["vectors"].as_array().unwrap().iter().filter(|v| routes[v["id"].as_str().unwrap()] == dispatch).cloned().collect();
    assert!(!out.is_empty(), "empty C005 dispatch {dispatch}");
    out
}
fn vector(id: &str) -> Value { oracle()["vectors"].as_array().unwrap().iter().find(|v| v["id"] == id).unwrap().clone() }
fn c004_sm2_address() -> String {
    let root: Value = serde_json::from_str(C004_ORACLE).unwrap();
    root["vectors"].as_array().unwrap().iter().find(|v| v["id"] == "C004.KEY.SM2").unwrap()["address_base58check"].as_str().unwrap().into()
}
fn decrypt_error(password: &str, wallet: &WalletFile, key_engine: CryptoEngine, checksum_engine: CryptoEngine) -> String { match decrypt(password, wallet, key_engine, checksum_engine) { Ok(_) => panic!("expected decrypt error"), Err(error) => error.to_string() } }
fn hex(text: &str) -> Vec<u8> { (0..text.len()).step_by(2).map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap()).collect() }
fn hex_string(bytes: &[u8]) -> String { bytes.iter().map(|b| format!("{b:02x}")).collect() }

struct BytesRng { bytes: Vec<u8>, at: usize }
impl BytesRng { fn new(bytes: Vec<u8>) -> Self { Self { bytes, at: 0 } } }
impl RngCore for BytesRng {
    fn next_u32(&mut self) -> u32 { let mut b = [0; 4]; self.fill_bytes(&mut b); u32::from_le_bytes(b) }
    fn next_u64(&mut self) -> u64 { let mut b = [0; 8]; self.fill_bytes(&mut b); u64::from_le_bytes(b) }
    fn fill_bytes(&mut self, out: &mut [u8]) { out.copy_from_slice(&self.bytes[self.at..self.at + out.len()]); self.at += out.len(); }
    fn try_fill_bytes(&mut self, out: &mut [u8]) -> Result<(), RngError> { self.fill_bytes(out); Ok(()) }
}
impl CryptoRng for BytesRng {}

struct ZeroRng;
impl RngCore for ZeroRng {
    fn next_u32(&mut self) -> u32 { 0 }
    fn next_u64(&mut self) -> u64 { 0 }
    fn fill_bytes(&mut self, out: &mut [u8]) { out.fill(0); }
    fn try_fill_bytes(&mut self, out: &mut [u8]) -> Result<(), RngError> { self.fill_bytes(out); Ok(()) }
}
impl CryptoRng for ZeroRng {}

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self { let path = temp_path(); fs::create_dir(&path).unwrap(); set_0700(&path); Self(path) }
    fn path(&self, name: &str) -> PathBuf { self.0.join(name) }
}
impl Drop for Fixture { fn drop(&mut self) { let _ = fs::remove_dir_all(&self.0); } }

fn deterministic_key(engine: CryptoEngine) -> PrivateKey { PrivateKey::from_bytes(engine, &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]).unwrap() }
fn deterministic_random() -> BytesRng {
    let input = &oracle()["deterministic_inputs"];
    let mut bytes = hex(input["iv_hex"].as_str().unwrap());
    let uuid_hex: String = input["uuid"].as_str().unwrap().chars().filter(|c| *c != '-').collect();
    bytes.extend(hex(&uuid_hex));
    BytesRng::new(bytes)
}
fn sample_wallet() -> WalletFile { WalletFile::parse_strict(vector("C005.CROSS.SCRYPT.EC")["wallet_json"].as_str().unwrap()).unwrap() }
fn write_wallet(path: &Path, wallet: &WalletFile) { fs::write(path, wallet.to_json().unwrap()).unwrap(); set_0600(path); }

fn deterministic_pbkdf2_wallet(engine: CryptoEngine) -> WalletFile {
    let input = &oracle()["deterministic_inputs"];
    let key = deterministic_key(engine);
    let salt = hex(input["salt_hex"].as_str().unwrap());
    let iv = hex(input["iv_hex"].as_str().unwrap());
    let mut derived = [0u8; 32];
    pbkdf2::<Hmac<Sha256>>(PASSWORD.as_bytes(), &salt, 4096, &mut derived).unwrap();
    let mut ciphertext = key.private_bytes().to_vec();
    Aes128Ctr::new_from_slices(&derived[..16], &iv).unwrap().apply_keystream(&mut ciphertext);
    let mut mac_input = Vec::with_capacity(16 + ciphertext.len());
    mac_input.extend_from_slice(&derived[16..]); mac_input.extend_from_slice(&ciphertext);
    WalletFile {
        address: Some(encode_address_base58check(engine, &derive_address(&key.public_key()))),
        id: Some(input["uuid"].as_str().unwrap().into()), version: 3,
        crypto: Some(KeystoreCrypto { cipher: Some(KEYSTORE_CIPHER.into()), ciphertext: Some(hex_string(&ciphertext)), cipherparams: Some(CipherParams { iv: Some(hex_string(&iv)) }), kdf: Some("pbkdf2".into()), kdfparams: KdfParams::Pbkdf2(Pbkdf2KdfParams { dklen: 32, c: 4096, prf: Some("hmac-sha256".into()), salt: Some(hex_string(&salt)) }), mac: Some(hex_string(&keccak256(&mac_input))) }),
    }
}

fn invoke_java(flag: &str, engine: &str, wallet: Option<&WalletFile>) -> Value {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..");
    let mut command = Command::new("python3");
    command.current_dir(&root).arg("tools/keystore/c005_oracle.py").arg(flag).arg(engine);
    if let Some(wallet) = wallet { command.arg("--wallet-json").arg(wallet.to_json().unwrap()); }
    let output = command.output().unwrap();
    assert!(output.status.success(), "Java oracle failed: {}", String::from_utf8_lossy(&output.stderr));
    let stdout = String::from_utf8(output.stdout).unwrap();
    serde_json::from_str(stdout.lines().last().unwrap()).unwrap()
}

#[test]
fn java_rust_cross_open_vectors() {
    for row in vectors("java_rust_cross_open_vectors") {
        let id = row["id"].as_str().unwrap();
        match id {
            "C005.CROSS.SCRYPT.EC" => cross_scrypt(CryptoEngine::Secp256k1, "ec", &row),
            "C005.CROSS.SCRYPT.SM2" => cross_scrypt(CryptoEngine::Sm2, "sm2", &row),
            "C005.CROSS.PBKDF2.EC" => cross_pbkdf2(CryptoEngine::Secp256k1, "ec", &row),
            "C005.CROSS.PBKDF2.SM2" => cross_pbkdf2(CryptoEngine::Sm2, "sm2", &row),
            "C005.CROSS.PBKDF2.MISSING_DKLEN.EC" => cross_pbkdf2_missing_dklen(&row),
            _ => panic!("unhandled {id}"),
        }
    }
}
fn cross_scrypt(key_engine: CryptoEngine, java_engine: &str, row: &Value) {
    open_java_wallet_in_rust(key_engine, java_engine);
    let params = match WalletFile::parse_strict(row["wallet_json"].as_str().unwrap()).unwrap().crypto.unwrap().kdfparams { KdfParams::Scrypt(p) => p, _ => unreachable!() };
    let wallet = create_with_scrypt_params_and_random(PASSWORD, &deterministic_key(key_engine), key_engine, params, &mut deterministic_random()).unwrap();
    assert_eq!(serde_json::from_str::<Value>(&wallet.to_json().unwrap()).unwrap(), serde_json::from_str::<Value>(row["wallet_json"].as_str().unwrap()).unwrap());
    java_open_assert(java_engine, &wallet);
}
fn cross_pbkdf2(key_engine: CryptoEngine, java_engine: &str, row: &Value) {
    open_java_wallet_in_rust(key_engine, java_engine);
    let wallet = deterministic_pbkdf2_wallet(key_engine);
    assert_eq!(serde_json::from_str::<Value>(&wallet.to_json().unwrap()).unwrap(), serde_json::from_str::<Value>(row["wallet_json"].as_str().unwrap()).unwrap());
    java_open_assert(java_engine, &wallet);
}
fn cross_pbkdf2_missing_dklen(row: &Value) {
    assert_eq!(row["java_default_dklen"], 0);
    let wallet_json = row["wallet_json"].as_str().unwrap();
    assert!(!wallet_json.contains("\"dklen\""));
    let wallet = WalletFile::parse_strict(wallet_json).unwrap();
    let params = match &wallet.crypto.as_ref().unwrap().kdfparams { KdfParams::Pbkdf2(params) => params, _ => unreachable!() };
    assert_eq!(params.dklen, 0);
    let key = decrypt(PASSWORD, &wallet, CryptoEngine::Secp256k1, CryptoEngine::Secp256k1).unwrap();
    assert_eq!(hex_string(&key.private_bytes()), row["private_key_hex"]);
}
fn open_java_wallet_in_rust(key_engine: CryptoEngine, java_engine: &str) {
    let result = invoke_java("--java-create", java_engine, None);
    let wallet = WalletFile::parse_strict(result["wallet_json"].as_str().unwrap()).unwrap();
    let key = decrypt(PASSWORD, &wallet, key_engine, key_engine).unwrap();
    assert_eq!(hex_string(&key.private_bytes()), result["private_key_hex"]);
    assert_eq!(wallet.address.as_deref().unwrap(), result["address"]);
    if key_engine == CryptoEngine::Sm2 { assert_eq!(wallet.address.as_deref().unwrap(), c004_sm2_address()); }
}
fn java_open_assert(java_engine: &str, wallet: &WalletFile) {
    let result = invoke_java("--java-open", java_engine, Some(wallet));
    assert_eq!(result["private_key_hex"], hex_string(&deterministic_key(if java_engine == "sm2" { CryptoEngine::Sm2 } else { CryptoEngine::Secp256k1 }).private_bytes()));
    assert_eq!(result["address"], wallet.address.as_deref().unwrap());
}

#[test]
fn schema_and_decrypt_error_vectors() {
    let base = sample_wallet();
    for row in vectors("schema_and_decrypt_error_vectors") {
        let id = row["id"].as_str().unwrap(); let mut wallet = base.clone();
        let actual = match id {
            "C005.ERROR.WRONG_PASSWORD" => decrypt_error("incorrect", &wallet, CryptoEngine::Secp256k1, CryptoEngine::Secp256k1),
            "C005.ERROR.VERSION" => { wallet.version = 2; validate(&wallet).unwrap_err().to_string() },
            "C005.ERROR.VERSION_INT_OVERFLOW" => version_integer_overflow(&row),
            "C005.ERROR.MISSING_CRYPTO" => { wallet.crypto = None; validate(&wallet).unwrap_err().to_string() },
            "C005.ERROR.CIPHER" => { wallet.crypto.as_mut().unwrap().cipher = Some("aes-256-gcm".into()); validate(&wallet).unwrap_err().to_string() },
            "C005.ERROR.KDF" => { wallet.crypto.as_mut().unwrap().kdf = Some("argon2".into()); validate(&wallet).unwrap_err().to_string() },
            "C005.ERROR.PRF" => { let crypto = wallet.crypto.as_mut().unwrap(); crypto.kdf = Some("pbkdf2".into()); crypto.kdfparams = KdfParams::Pbkdf2(Pbkdf2KdfParams { dklen: 32, c: 1, prf: Some("hmac-sha1".into()), salt: Some("00".into()) }); decrypt_error(PASSWORD, &wallet, CryptoEngine::Secp256k1, CryptoEngine::Secp256k1) },
            _ => panic!("unhandled {id}"),
        };
        assert_eq!(actual, row["expected"], "vector {id}");
    }
}
fn version_integer_overflow(row: &Value) -> String {
    let json = row["wallet_json"].as_str().unwrap();
    for result in [WalletFile::parse_strict(json), WalletFile::parse(json)] {
        assert!(matches!(result, Err(KeystoreError::Json(_))), "overflow must remain a typed JSON error");
    }
    let error = WalletFile::parse_strict(json).unwrap_err();
    assert!(error.to_string().contains("4294967299"));
    row["expected"].as_str().unwrap().to_owned()
}


#[test]
fn password_vectors() {
    for row in vectors("password_vectors") {
        let id = row["id"].as_str().unwrap();
        match id {
            "C005.PASSWORD.WHITESPACE" => assert_password_row(&row),
            "C005.PASSWORD.BOM" => assert_password_row(&row),
            "C005.PASSWORD.EMPTY" => assert_password_row(&row),
            "C005.PASSWORD.SHORT" => assert_password_row(&row),
            "C005.PASSWORD.MULTILINE" => with_file(b"secret\nsecond\n", |p| assert!(matches!(read_password_file(p), Err(PasswordFileError::MultipleLines)))),
            "C005.PASSWORD.MALFORMED_UTF8" => with_file(b"secret\xff", |p| assert!(read_password_file(p).unwrap().contains('\u{fffd}'))),
            _ => panic!("unhandled {id}"),
        }
    }
}
fn assert_password_row(row: &Value) { let normalized = strip_password_line(Some(row["input"].as_str().unwrap())).unwrap(); assert_eq!(normalized, row["normalized"]); assert_eq!(password_valid(Some(&normalized)), row["valid"].as_bool().unwrap()); }

#[cfg(unix)]
#[test]
fn password_file_fifo_regressions() {
    use std::{sync::mpsc, time::Duration};

    let fixture = Fixture::new();
    let fifo = fixture.path("password-fifo");
    assert!(Command::new("mkfifo").arg(&fifo).status().unwrap().success());

    for read in [
        read_password_file as fn(PathBuf) -> Result<String, PasswordFileError>,
        |path| read_update_password_file(path).map(|_| String::new()),
    ] {
        let path = fifo.clone();
        let (sender, receiver) = mpsc::channel();
        std::thread::spawn(move || sender.send(read(path)).unwrap());
        let error = receiver
            .recv_timeout(Duration::from_secs(1))
            .expect("password FIFO read blocked without a writer")
            .unwrap_err();
        assert!(matches!(error, PasswordFileError::NotRegularFile));
    }
}

#[test]
fn filesystem_and_atomic_vectors() {
    for row in vectors("filesystem_and_atomic_vectors") {
        let id = row["id"].as_str().unwrap();
        match id {
            "C005.NEW.INJECTED" => fs_new_injected(),
            "C005.IMPORT.DUPLICATE" => fs_import_duplicate(),
            "C005.IMPORT.OVERWRITE" => fs_import_overwrite(),
            "C005.LIST.CORRUPT" => fs_list_invalid(b"{"),
            "C005.LIST.BOM" => fs_list_invalid(format!("\u{feff}{}", sample_wallet().to_json().unwrap()).as_bytes()),
            "C005.LIST.MULTILINE" => fs_list_multiline(),
            "C005.LIST.SYMLINK" => fs_list_symlink(),
            "C005.LIST.PERMISSIONS" => fs_list_permissions(),
            "C005.LIST.OWNERSHIP" => fs_list_ownership(),
            "C005.DIRECT.SYMLINK" => fs_direct_symlink(),
            "C005.DIRECT.UNQUOTED" => fs_direct_unquoted(),
            "C005.DIRECT.CORRUPT" => fs_direct_corrupt(),
            "C005.UPDATE.PASSWORD" => fs_update_password(),
            "C005.UPDATE.WRONG_PASSWORD" => fs_update_wrong_password(),
            "C005.UPDATE.DUPLICATE" => fs_update_duplicate(),
            "C005.UPDATE.SYMLINK_SWAP" => fs_update_inode_swap(),
            "C005.WRITE.CLEANUP" => fs_write_cleanup(),
            "C005.WRITE.MODE" => fs_write_mode(),
            "C005.WINDOWS.LIMIT" => fs_windows_decision(),
            _ => panic!("unhandled {id}"),
        }
    }
}

fn fs_new_injected() { let f = Fixture::new(); let path = f.path("new.json"); let wallet = new_keystore(&path, PASSWORD, &deterministic_key(CryptoEngine::Secp256k1), CryptoEngine::Secp256k1, false, &mut ZeroRng).unwrap(); assert_eq!(load_keystore_direct(path).unwrap().wallet, wallet); }
fn fs_import_duplicate() { let f = Fixture::new(); let wallet = sample_wallet(); write_wallet(&f.path("first.json"), &wallet); let error = import_keystore(&f.0, f.path("second.json"), PASSWORD, &deterministic_key(CryptoEngine::Secp256k1), CryptoEngine::Secp256k1, false, false, &mut ZeroRng).unwrap_err(); assert!(matches!(error, StoreError::DuplicateAddress { .. })); assert!(!f.path("second.json").exists()); }
fn fs_import_overwrite() {
    let f = Fixture::new();
    let target = f.path("target.json");
    fs::write(&target, b"{}").unwrap();
    set_0600(&target);

    let error = import_keystore(&f.0, &target, PASSWORD, &deterministic_key(CryptoEngine::Secp256k1), CryptoEngine::Secp256k1, false, false, &mut ZeroRng).unwrap_err();
    assert!(matches!(error, StoreError::TargetExists(path) if path == target));

    let overwritten = import_keystore(&f.0, &target, PASSWORD, &deterministic_key(CryptoEngine::Secp256k1), CryptoEngine::Secp256k1, false, true, &mut ZeroRng).unwrap();
    assert_eq!(load_keystore_direct(&target).unwrap().wallet, overwritten);

    let fresh = f.path("fresh.json");
    let duplicate = import_keystore(&f.0, &fresh, PASSWORD, &deterministic_key(CryptoEngine::Secp256k1), CryptoEngine::Secp256k1, false, true, &mut ZeroRng).unwrap_err();
    assert!(matches!(duplicate, StoreError::DuplicateAddress { .. }));
    assert!(!fresh.exists());

    let forced = import_keystore(&f.0, &fresh, PASSWORD, &deterministic_key(CryptoEngine::Secp256k1), CryptoEngine::Secp256k1, true, false, &mut ZeroRng).unwrap();
    assert_eq!(load_keystore_direct(&fresh).unwrap().wallet, forced);
}
fn fs_list_invalid(bytes: &[u8]) { let f = Fixture::new(); let path = f.path("bad.json"); fs::write(&path, bytes).unwrap(); set_0600(&path); let report = list_keystores(&f.0).unwrap(); assert!(report.keystores.is_empty()); assert_eq!(report.warnings, vec![StoreWarning::SkippedInvalidJson { path }]); }
fn fs_list_multiline() { let f = Fixture::new(); let path = f.path("wallet.json"); let wallet = sample_wallet(); let text = serde_json::to_string_pretty(&wallet).unwrap(); assert!(text.lines().count() > 1); fs::write(&path, text).unwrap(); set_0600(&path); let report = list_keystores(&f.0).unwrap(); assert_eq!(report.keystores.len(), 1); assert_eq!(report.keystores[0].path, path); assert_eq!(report.keystores[0].address, wallet.address.unwrap()); assert!(report.warnings.is_empty()); }
#[cfg(unix)] fn fs_list_symlink() { use std::os::unix::fs::symlink; let f = Fixture::new(); let real = f.path("real"); fs::create_dir(&real).unwrap(); let target = real.join("wallet"); write_wallet(&target, &sample_wallet()); let link = f.path("linked.json"); symlink(target, &link).unwrap(); assert_eq!(list_keystores(&f.0).unwrap().warnings, vec![StoreWarning::SkippedSymlink { path: link }]); }
#[cfg(not(unix))] fn fs_list_symlink() { assert!(!cfg!(unix)); }
#[cfg(unix)] fn fs_list_permissions() { use std::os::unix::fs::PermissionsExt; let f = Fixture::new(); let path = f.path("wallet.json"); write_wallet(&path, &sample_wallet()); fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap(); assert!(matches!(list_keystores(&f.0), Err(StoreError::InsecurePermissions { mode: 0o644, .. }))); }
#[cfg(not(unix))] fn fs_list_permissions() { assert!(!cfg!(unix)); }
#[cfg(unix)] fn fs_list_ownership() { let f = Fixture::new(); let path = f.path("wallet.json"); write_wallet(&path, &sample_wallet()); let uid = rustix::process::geteuid().as_raw(); if uid == 0 { rustix::fs::chown(&path, Some(rustix::process::Uid::from_raw(1)), None).unwrap(); assert!(matches!(list_keystores(&f.0), Err(StoreError::WrongOwner { owner: 1, effective_user: 0, .. }))); } else { assert_eq!(list_keystores(&f.0).unwrap().keystores.len(), 1); } }
#[cfg(not(unix))] fn fs_list_ownership() { assert!(!cfg!(unix)); }
#[cfg(unix)] fn fs_direct_symlink() { use std::os::unix::fs::symlink; let f = Fixture::new(); let real = f.path("real.json"); write_wallet(&real, &sample_wallet()); let link = f.path("link.json"); symlink(&real, &link).unwrap(); let result = load_keystore_direct(&link).unwrap(); assert_eq!(result.wallet, sample_wallet()); assert_eq!(result.warnings, vec![StoreWarning::DirectLoadFollowedSymlink { path: link }]); }
#[cfg(not(unix))] fn fs_direct_symlink() { assert!(!cfg!(unix)); }
fn fs_direct_unquoted() { let f = Fixture::new(); let path = f.path("wallet.json"); let wallet = sample_wallet(); let text = wallet.to_json().unwrap().replacen("\"address\"", "address", 1); fs::write(&path, text).unwrap(); set_0600(&path); assert_eq!(load_keystore_direct(&path).unwrap().wallet, wallet); let report = list_keystores(&f.0).unwrap(); assert!(report.keystores.is_empty()); assert_eq!(report.warnings, vec![StoreWarning::SkippedInvalidJson { path }]); }
fn fs_direct_corrupt() { let f = Fixture::new(); let path = f.path("wallet.json"); fs::write(&path, b"{").unwrap(); set_0600(&path); assert!(matches!(load_keystore_direct(path), Err(StoreError::Keystore(_)))); }
fn fs_update_password() { let f = Fixture::new(); let path = f.path("wallet.json"); let wallet = sample_wallet(); let address = wallet.address.clone().unwrap(); write_wallet(&path, &wallet); update_keystore(&f.0, &address, PASSWORD, "replacement password", CryptoEngine::Secp256k1, CryptoEngine::Secp256k1, &mut ZeroRng).unwrap(); let changed = load_keystore_direct(path).unwrap().wallet; assert!(decrypt(PASSWORD, &changed, CryptoEngine::Secp256k1, CryptoEngine::Secp256k1).is_err()); assert_eq!(decrypt("replacement password", &changed, CryptoEngine::Secp256k1, CryptoEngine::Secp256k1).unwrap().private_bytes(), deterministic_key(CryptoEngine::Secp256k1).private_bytes()); }
fn fs_update_wrong_password() { let f = Fixture::new(); let path = f.path("wallet.json"); let wallet = sample_wallet(); let original = wallet.to_json().unwrap(); write_wallet(&path, &wallet); let error = update_keystore(&f.0, wallet.address.as_deref().unwrap(), "wrong", "replacement password", CryptoEngine::Secp256k1, CryptoEngine::Secp256k1, &mut ZeroRng).unwrap_err(); assert!(matches!(error, StoreError::Keystore(_))); assert_eq!(fs::read_to_string(path).unwrap(), original); }
fn fs_update_duplicate() { let f = Fixture::new(); let wallet = sample_wallet(); write_wallet(&f.path("one.json"), &wallet); write_wallet(&f.path("two.json"), &wallet); let error = update_keystore(&f.0, wallet.address.as_deref().unwrap(), PASSWORD, "replacement password", CryptoEngine::Secp256k1, CryptoEngine::Secp256k1, &mut ZeroRng).unwrap_err(); assert!(matches!(error, StoreError::DuplicateAddress { files, .. } if files.len() == 2)); }

struct SwapRng { calls: usize, path: PathBuf, replacement: PathBuf }
impl RngCore for SwapRng {
    fn next_u32(&mut self) -> u32 { 0 } fn next_u64(&mut self) -> u64 { 0 }
    fn fill_bytes(&mut self, out: &mut [u8]) { self.calls += 1; if self.calls == 4 { fs::rename(&self.replacement, &self.path).unwrap(); } out.fill(0); }
    fn try_fill_bytes(&mut self, out: &mut [u8]) -> Result<(), RngError> { self.fill_bytes(out); Ok(()) }
}
impl CryptoRng for SwapRng {}
fn fs_update_inode_swap() { let f = Fixture::new(); let path = f.path("wallet.json"); let replacement = f.path("replacement"); let wallet = sample_wallet(); write_wallet(&path, &wallet); write_wallet(&replacement, &wallet); let mut rng = SwapRng { calls: 0, path: path.clone(), replacement }; let error = update_keystore(&f.0, wallet.address.as_deref().unwrap(), PASSWORD, "replacement password", CryptoEngine::Secp256k1, CryptoEngine::Secp256k1, &mut rng).unwrap_err(); assert!(matches!(error, StoreError::InodeChanged(p) if p == path)); }
fn fs_write_cleanup() {
    let pre_publication_stages = [AtomicWriteStage::Serialization, AtomicWriteStage::Write, AtomicWriteStage::FileFsync, AtomicWriteStage::Rename];
    for stage in pre_publication_stages {
        let f = Fixture::new();
        let destination = f.path("target.json");
        let original = b"original destination";
        fs::write(&destination, original).unwrap();
        set_0600(&destination);
        let error = atomic_write_wallet_with_failure(&sample_wallet(), &destination, true, &mut ZeroRng, stage).unwrap_err();
        assert!(matches!(error, StoreError::AtomicWriteFailure(actual) if actual == stage));
        assert_eq!(fs::read(&destination).unwrap(), original);
        assert!(!f.path(".keystore-0000000000000000.tmp").exists());
    }

    let f = Fixture::new();
    let destination = f.path("target.json");
    fs::write(&destination, b"original destination").unwrap();
    set_0600(&destination);
    let wallet = sample_wallet();
    let original = b"original destination";
    let error = atomic_write_wallet_with_failure(&wallet, &destination, true, &mut ZeroRng, AtomicWriteStage::DirectoryFsync).unwrap_err();
    assert!(matches!(error, StoreError::AtomicWriteFailure(AtomicWriteStage::DirectoryFsync)));
    assert_eq!(fs::read(&destination).unwrap(), original);
    assert!(!f.path(".keystore-0000000000000000.tmp").exists());
    assert!(!f.path(".keystore-0000000000000000.backup").exists());
    fs_write_symlinked_parent();
    fs_write_parent_swap();
    fs_write_fifo_parent();
    fs_insecure_directory();
    fs_direct_parent_symlink();
}


#[cfg(unix)]
fn fs_write_symlinked_parent() {
    use std::os::unix::fs::symlink;
    let f = Fixture::new();
    let real = f.path("real");
    fs::create_dir(&real).unwrap();
    set_0700(&real);
    let linked = f.path("linked");
    symlink(&real, &linked).unwrap();
    let destination = linked.join("wallet.json");
    let error = atomic_write_wallet_with_random(&sample_wallet(), &destination, false, &mut ZeroRng).unwrap_err();
    assert!(matches!(error, StoreError::ParentSymlink(path) if path == linked));
    assert!(!real.join("wallet.json").exists());
    assert!(!real.join(".keystore-0000000000000000.tmp").exists());
}

#[cfg(not(unix))]
fn fs_write_symlinked_parent() { assert!(!cfg!(unix)); }

#[cfg(unix)]
fn fs_write_fifo_parent() {
    use std::{sync::mpsc, time::Duration};
    let f = Fixture::new();
    let fifo = f.path("fifo-parent");
    assert!(Command::new("mkfifo").arg(&fifo).status().unwrap().success());
    let destination = fifo.join("wallet.json");
    let worker_destination = destination.clone();
    let (sender, receiver) = mpsc::channel();
    std::thread::spawn(move || {
        let result = atomic_write_wallet_with_random(&sample_wallet(), &worker_destination, false, &mut ZeroRng);
        sender.send(result).unwrap();
    });
    let error = receiver.recv_timeout(Duration::from_secs(1)).expect("FIFO parent traversal blocked").unwrap_err();
    assert!(matches!(error, StoreError::ParentNotDirectory(path) if path == fifo));
    assert!(!destination.exists());
    assert!(!f.path(".keystore-0000000000000000.tmp").exists());
}

#[cfg(not(unix))]
fn fs_write_fifo_parent() { assert!(!cfg!(unix)); }

#[cfg(unix)]
fn fs_write_parent_swap() {
    let f = Fixture::new();
    let parent = f.path("parent");
    let displaced = f.path("displaced");
    let replacement = f.path("replacement");
    fs::create_dir(&parent).unwrap();
    fs::create_dir(&replacement).unwrap();
    set_0700(&parent);
    set_0700(&replacement);
    let original = b"original destination";
    fs::write(parent.join("wallet.json"), original).unwrap();
    set_0600(&parent.join("wallet.json"));
    let destination = parent.join("wallet.json");
    let error = atomic_write_wallet_with_hook(&sample_wallet(), &destination, true, &mut ZeroRng, || {
        fs::rename(&parent, &displaced).unwrap();
        fs::rename(&replacement, &parent).unwrap();
    }).unwrap_err();
    assert!(matches!(error, StoreError::ParentChanged(path) if path == parent));
    assert!(!destination.exists());
    assert!(!parent.join(".keystore-0000000000000000.tmp").exists());
    assert_eq!(fs::read(displaced.join("wallet.json")).unwrap(), original);
    assert!(!displaced.join(".keystore-0000000000000000.tmp").exists());
    assert!(!displaced.join(".keystore-0000000000000000.backup").exists());
}

#[cfg(not(unix))]
fn fs_write_parent_swap() { assert!(!cfg!(unix)); }
#[cfg(unix)]
fn fs_insecure_directory() {
    use std::os::unix::fs::PermissionsExt;
    let f = Fixture::new();
    fs::set_permissions(&f.0, fs::Permissions::from_mode(0o770)).unwrap();
    let error = list_keystores(&f.0).unwrap_err();
    assert!(matches!(error, StoreError::InsecureDirectory { mode: 0o770, .. }));
}

#[cfg(not(unix))]
fn fs_insecure_directory() { assert!(!cfg!(unix)); }

#[cfg(unix)]
fn fs_direct_parent_symlink() {
    use std::os::unix::fs::symlink;
    let f = Fixture::new();
    let real = f.path("real");
    fs::create_dir(&real).unwrap();
    set_0700(&real);
    write_wallet(&real.join("wallet.json"), &sample_wallet());
    let linked = f.path("linked");
    symlink(&real, &linked).unwrap();
    let error = load_keystore_direct(linked.join("wallet.json")).unwrap_err();
    assert!(matches!(error, StoreError::ParentSymlink(path) if path == linked));
}

#[cfg(not(unix))]
fn fs_direct_parent_symlink() { assert!(!cfg!(unix)); }

fn fs_write_mode() { let f = Fixture::new(); let path = f.path("wallet.json"); atomic_write_wallet(&sample_wallet(), &path, false).unwrap(); #[cfg(unix)] { use std::os::unix::fs::PermissionsExt; assert_eq!(fs::metadata(path).unwrap().permissions().mode() & 0o777, 0o600); } }
fn fs_windows_decision() { let f = Fixture::new(); let path = f.path("wallet.json"); #[cfg(windows)] { let error = atomic_write_wallet(&sample_wallet(), &path, false).unwrap_err(); assert!(matches!(error, StoreError::UnsupportedPlatform(WINDOWS_PERMISSION_LIMITATION))); assert!(!path.exists()); } #[cfg(not(windows))] { assert!(atomic_write_wallet(&sample_wallet(), &path, false).unwrap().is_empty()); assert_eq!(WINDOWS_PERMISSION_LIMITATION, "descriptor-anchored keystore publication is unsupported on Windows"); } }

fn temp_path() -> PathBuf { let mut p = std::env::temp_dir(); p.push(format!("tron-c005-{}-{}", std::process::id(), std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos())); p }
fn with_file(bytes: &[u8], f: impl FnOnce(&Path)) { let fixture = Fixture::new(); let path = fixture.path("password"); fs::write(&path, bytes).unwrap(); set_0600(&path); f(&path); }
fn set_0600(path: &Path) { #[cfg(unix)] { use std::os::unix::fs::PermissionsExt; fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap(); } }
fn set_0700(path: &Path) { #[cfg(unix)] { use std::os::unix::fs::PermissionsExt; fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap(); } }
