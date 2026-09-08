use rand_core::{CryptoRng, Error as RngError, RngCore};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{fs, path::{Path, PathBuf}, process::Command, sync::atomic::{AtomicU64, Ordering}};
use tron_crypto::{CryptoEngine, PrivateKey};
use tron_crypto::keystore::{create_with_random, decrypt, read_private_key_file, PasswordFileError, ScryptProfile, WalletFile};
use tron_crypto::keystore_store::{
    atomic_write_wallet_with_failure, atomic_write_wallet_with_stage_hook, import_keystore_reporting,
    list_keystores, load_keystore_direct, new_keystore, new_keystore_reporting, update_keystore_reporting,
    AtomicWriteHookStage, AtomicWriteStage, StoreError, StoreWarning,
};

const PASSWORD: &str = "correct horse battery staple";
const NEW_PASSWORD: &str = "replacement password";
static FIXTURE_SEQUENCE: AtomicU64 = AtomicU64::new(0);

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
    fn new() -> Self {
        loop {
            let sequence = FIXTURE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!("tron-c027-keystore-{}-{sequence}", std::process::id()));
            match fs::create_dir(&path) {
                Ok(()) => {
                    set_mode(&path, 0o700);
                    return Self(path);
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => panic!("create fixture {}: {error}", path.display()),
            }
        }
    }
    fn path(&self, name: &str) -> PathBuf { self.0.join(name) }
}
impl Drop for Fixture { fn drop(&mut self) { let _ = fs::remove_dir_all(&self.0); } }

fn key() -> PrivateKey {
    let mut bytes = [0u8; 32];
    bytes[31] = 1;
    PrivateKey::from_bytes(CryptoEngine::Secp256k1, &bytes).unwrap()
}

fn set_mode(path: &Path, mode: u32) {
    #[cfg(unix)] {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
    }
    #[cfg(not(unix))] let _ = (path, mode);
}

#[test]
fn reporting_results_include_the_published_wallet_and_path() {
    let fixture = Fixture::new();
    let path = fixture.path("wallet.json");
    let stored = new_keystore_reporting(&path, PASSWORD, &key(), CryptoEngine::Secp256k1, false, &mut ZeroRng, |_| {}).unwrap();
    assert_eq!(stored.path, path);
    assert_eq!(load_keystore_direct(&stored.path).unwrap().wallet, stored.wallet);
}

#[test]
fn import_reports_scan_warnings_even_when_duplicate_rejection_follows() {
    let fixture = Fixture::new();
    let existing = fixture.path("b.json");
    new_keystore(&existing, PASSWORD, &key(), CryptoEngine::Secp256k1, false, &mut ZeroRng).unwrap();
    let corrupt = fixture.path("a.json");
    fs::write(&corrupt, b"{").unwrap();
    set_mode(&corrupt, 0o600);
    let mut warnings = Vec::new();
    let error = import_keystore_reporting(
        &fixture.0, fixture.path("new.json"), PASSWORD, &key(), CryptoEngine::Secp256k1,
        false, false, &mut ZeroRng, |warning| warnings.push(warning.clone()),
    ).unwrap_err();
    assert!(matches!(error, StoreError::DuplicateAddress { .. }));
    assert_eq!(warnings, vec![StoreWarning::SkippedInvalidJson { path: corrupt }]);
}

#[test]
fn update_reports_scan_warnings_before_password_failure() {
    let fixture = Fixture::new();
    let existing = fixture.path("b.json");
    let wallet = new_keystore(&existing, PASSWORD, &key(), CryptoEngine::Secp256k1, false, &mut ZeroRng).unwrap();
    let corrupt = fixture.path("a.json");
    fs::write(&corrupt, b"{").unwrap();
    set_mode(&corrupt, 0o600);
    let mut warnings = Vec::new();
    let error = update_keystore_reporting(
        &fixture.0, wallet.address.as_deref().unwrap(), "wrong", NEW_PASSWORD,
        CryptoEngine::Secp256k1, CryptoEngine::Secp256k1, &mut ZeroRng,
        |warning| warnings.push(warning.clone()),
    ).unwrap_err();
    assert!(matches!(error, StoreError::Keystore(_)));
    assert_eq!(warnings, vec![StoreWarning::SkippedInvalidJson { path: corrupt }]);
}

#[test]
fn missing_or_non_directory_update_root_is_address_not_found() {
    let fixture = Fixture::new();
    let missing = fixture.path("missing");
    let missing_error = update_keystore_reporting(
        &missing, "address", PASSWORD, NEW_PASSWORD, CryptoEngine::Secp256k1,
        CryptoEngine::Secp256k1, &mut ZeroRng, |_| {},
    ).unwrap_err();
    assert!(matches!(missing_error, StoreError::AddressNotFound(address) if address == "address"));

    let file = fixture.path("file");
    fs::write(&file, b"not a directory").unwrap();
    set_mode(&file, 0o600);
    let file_error = update_keystore_reporting(
        &file, "address", PASSWORD, NEW_PASSWORD, CryptoEngine::Secp256k1,
        CryptoEngine::Secp256k1, &mut ZeroRng, |_| {},
    ).unwrap_err();
    assert!(matches!(file_error, StoreError::AddressNotFound(address) if address == "address"));
}

#[test]
fn private_key_file_reader_is_bounded_nofollow_and_zeroizing() {
    fn assert_zeroizing<T: zeroize::ZeroizeOnDrop>() {}
    let _ = assert_zeroizing::<zeroize::Zeroizing<Vec<u8>>>;

    let fixture = Fixture::new();
    let path = fixture.path("key");
    fs::write(&path, b"  0X01  \n").unwrap();
    set_mode(&path, 0o600);
    assert_eq!(&*read_private_key_file(&path).unwrap(), b"  0X01  \n");

    #[cfg(unix)] {
        use std::os::unix::fs::symlink;
        let link = fixture.path("key-link");
        symlink(&path, &link).unwrap();
        assert!(matches!(read_private_key_file(link), Err(PasswordFileError::Symlink)));
    }

    let oversized = fixture.path("oversized");
    fs::write(&oversized, vec![b'x'; 1025]).unwrap();
    set_mode(&oversized, 0o600);
    assert!(matches!(read_private_key_file(oversized), Err(PasswordFileError::TooLarge)));
}

#[cfg(unix)]
#[derive(Serialize)]
struct TestIdentity { dev: u64, ino: u64 }
#[derive(Serialize)]
struct TestJournalPayload<'a> {
    version: u8,
    phase: &'a str,
    destination: &'a str,
    temporary: &'a str,
    backup: &'a str,
    original_sha256: Option<String>,
    original_address: Option<String>,
    original_identity: Option<TestIdentity>,
    replacement_sha256: String,
    replacement_address: String,
    replacement_identity: TestIdentity,
}

#[cfg(unix)]
#[derive(Serialize)]
struct TestJournal<'a> { payload: &'a TestJournalPayload<'a>, checksum: String }

#[cfg(unix)]
fn digest(bytes: &[u8]) -> String { Sha256::digest(bytes).iter().map(|byte| format!("{byte:02x}")).collect() }

#[cfg(unix)]
#[test]
fn abrupt_replacement_child() {
    use std::os::unix::fs::MetadataExt;
    let Ok(phase) = std::env::var("TRON_KEYSTORE_TEST_PHASE") else { return; };
    let directory = PathBuf::from(std::env::var_os("TRON_KEYSTORE_TEST_DIR").unwrap());
    let original = std::env::var("TRON_KEYSTORE_TEST_ORIGINAL").unwrap();
    let replacement = std::env::var("TRON_KEYSTORE_TEST_REPLACEMENT").unwrap();
    let original_wallet = WalletFile::parse_strict(&original).unwrap();
    let replacement_wallet = WalletFile::parse_strict(&replacement).unwrap();
    let write = |name: &str, bytes: &[u8]| { let path = directory.join(name); fs::write(&path, bytes).unwrap(); set_mode(&path, 0o600); };
    let temporary = ".keystore-0000000000000001.tmp";
    let backup = ".keystore-0000000000000001.backup";
    let _ = fs::remove_file(directory.join("wallet.json"));
    match phase.as_str() {
        "before-backup" => { write("wallet.json", original.as_bytes()); write(temporary, replacement.as_bytes()); }
        "after-backup" => { write(backup, original.as_bytes()); write(temporary, replacement.as_bytes()); }
        "after-publish" => { write(backup, original.as_bytes()); write("wallet.json", replacement.as_bytes()); }
        "cleanup" => write("wallet.json", replacement.as_bytes()),
        _ => panic!("unknown phase"),
    }
    let identity = |name: &str| { let metadata = fs::metadata(directory.join(name)).unwrap(); TestIdentity { dev: metadata.dev(), ino: metadata.ino() } };
    let original_identity = if phase == "before-backup" { Some(identity("wallet.json")) } else if phase == "after-backup" || phase == "after-publish" { Some(identity(backup)) } else { None };
    let replacement_identity = if phase == "after-publish" || phase == "cleanup" { identity("wallet.json") } else { identity(temporary) };
    let payload = TestJournalPayload {
        version: 1, phase: "prepared", destination: "wallet.json", temporary, backup,
        original_sha256: if phase == "cleanup" { None } else { Some(digest(original.as_bytes())) },
        original_address: if phase == "cleanup" { None } else { original_wallet.address },
        original_identity,
        replacement_sha256: digest(replacement.as_bytes()), replacement_address: replacement_wallet.address.unwrap(), replacement_identity,
    };
    let encoded = serde_json::to_vec(&payload).unwrap();
    let journal = serde_json::to_vec(&TestJournal { payload: &payload, checksum: digest(&encoded) }).unwrap();
    write(".keystore-replace.journal", &journal);
    std::process::exit(91);
}
#[test]
fn abrupt_process_replacement_phase_matrix_recovers_a_decryptable_wallet() {
    for (phase, replacement_wins) in [("before-backup", false), ("after-backup", false), ("after-publish", true), ("cleanup", true)] {
        let fixture = Fixture::new();
        let original = create_with_random(PASSWORD, &key(), CryptoEngine::Secp256k1, ScryptProfile::Standard, &mut ZeroRng).unwrap();
        let replacement = create_with_random(NEW_PASSWORD, &key(), CryptoEngine::Secp256k1, ScryptProfile::Standard, &mut ZeroRng).unwrap();
        let original_json = original.to_json().unwrap();
        let replacement_json = replacement.to_json().unwrap();
        let status = Command::new(std::env::current_exe().unwrap())
            .arg("--exact").arg("abrupt_replacement_child").arg("--nocapture")
            .env("TRON_KEYSTORE_TEST_PHASE", phase)
            .env("TRON_KEYSTORE_TEST_DIR", &fixture.0)
            .env("TRON_KEYSTORE_TEST_ORIGINAL", &original_json)
            .env("TRON_KEYSTORE_TEST_REPLACEMENT", &replacement_json)
            .status().unwrap();
        assert_eq!(status.code(), Some(91));
        let report = list_keystores(&fixture.0).unwrap();
        assert_eq!(report.keystores.len(), 1);
        assert!(report.warnings.is_empty());
        let recovered = load_keystore_direct(fixture.path("wallet.json")).unwrap().wallet;
        let password = if replacement_wins { NEW_PASSWORD } else { PASSWORD };
        assert_eq!(decrypt(password, &recovered, CryptoEngine::Secp256k1, CryptoEngine::Secp256k1).unwrap().private_bytes(), key().private_bytes());
        assert!(!fixture.path(".keystore-replace.journal").exists());
        assert!(!fixture.path(".keystore-0000000000000001.tmp").exists());
        assert!(!fixture.path(".keystore-0000000000000001.backup").exists());
    }
}

#[cfg(unix)]
#[test]
fn tampered_recovery_journal_is_rejected_without_writes() {
    let fixture = Fixture::new();
    let journal = fixture.path(".keystore-replace.journal");
    fs::write(&journal, br#"{"payload":{},"checksum":"bad"}"#).unwrap();
    set_mode(&journal, 0o600);
    let before = fs::read(&journal).unwrap();
    assert!(matches!(list_keystores(&fixture.0), Err(StoreError::RecoveryRefused { .. })));
    assert_eq!(fs::read(&journal).unwrap(), before);
}

#[cfg(unix)]
#[test]
fn symlinked_recovery_journal_is_rejected_without_target_writes() {
    use std::os::unix::fs::symlink;
    let fixture = Fixture::new();
    let target = fixture.path("outside");
    fs::write(&target, b"outside sentinel").unwrap();
    set_mode(&target, 0o600);
    symlink(&target, fixture.path(".keystore-replace.journal")).unwrap();
    assert!(matches!(list_keystores(&fixture.0), Err(StoreError::RecoveryRefused { .. })));
    assert_eq!(fs::read(&target).unwrap(), b"outside sentinel");
}

#[cfg(unix)]
#[test]
fn rollback_rename_failure_retains_recovery_metadata_and_recovers_replacement() {
    let fixture = Fixture::new();
    let destination = fixture.path("wallet.json");
    let original = create_with_random(PASSWORD, &key(), CryptoEngine::Secp256k1, ScryptProfile::Standard, &mut ZeroRng).unwrap();
    let replacement = create_with_random(NEW_PASSWORD, &key(), CryptoEngine::Secp256k1, ScryptProfile::Standard, &mut ZeroRng).unwrap();
    fs::write(&destination, original.to_json().unwrap()).unwrap();
    set_mode(&destination, 0o600);

    let error = atomic_write_wallet_with_failure(&replacement, &destination, true, &mut ZeroRng, AtomicWriteStage::RollbackRename).unwrap_err();
    assert!(matches!(error, StoreError::RollbackFailed { rollback, .. } if matches!(*rollback, StoreError::AtomicWriteFailure(AtomicWriteStage::RollbackRename))));
    assert!(fixture.path(".keystore-replace.journal").exists());
    assert!(fixture.path(".keystore-0000000000000000.backup").exists());

    let report = list_keystores(&fixture.0).unwrap();
    assert_eq!(report.keystores.len(), 1);
    let recovered = load_keystore_direct(&destination).unwrap().wallet;
    assert_eq!(decrypt(NEW_PASSWORD, &recovered, CryptoEngine::Secp256k1, CryptoEngine::Secp256k1).unwrap().private_bytes(), key().private_bytes());
    assert!(!fixture.path(".keystore-replace.journal").exists());
    assert!(!fixture.path(".keystore-0000000000000000.backup").exists());
}

#[cfg(unix)]
#[test]
fn rollback_fsync_failure_retains_journal_and_recovers_original() {
    let fixture = Fixture::new();
    let destination = fixture.path("wallet.json");
    let original = create_with_random(PASSWORD, &key(), CryptoEngine::Secp256k1, ScryptProfile::Standard, &mut ZeroRng).unwrap();
    let replacement = create_with_random(NEW_PASSWORD, &key(), CryptoEngine::Secp256k1, ScryptProfile::Standard, &mut ZeroRng).unwrap();
    fs::write(&destination, original.to_json().unwrap()).unwrap();
    set_mode(&destination, 0o600);

    let error = atomic_write_wallet_with_failure(&replacement, &destination, true, &mut ZeroRng, AtomicWriteStage::RollbackFsync).unwrap_err();
    assert!(matches!(error, StoreError::RollbackFailed { rollback, .. } if matches!(*rollback, StoreError::AtomicWriteFailure(AtomicWriteStage::RollbackFsync))));
    assert!(fixture.path(".keystore-replace.journal").exists());
    assert!(fixture.path(".keystore-0000000000000000.backup").exists());

    list_keystores(&fixture.0).unwrap();
    let recovered = load_keystore_direct(&destination).unwrap().wallet;
    assert_eq!(decrypt(PASSWORD, &recovered, CryptoEngine::Secp256k1, CryptoEngine::Secp256k1).unwrap().private_bytes(), key().private_bytes());
    assert!(!fixture.path(".keystore-replace.journal").exists());
    assert!(!fixture.path(".keystore-0000000000000000.backup").exists());
}

#[cfg(unix)]
#[test]
fn tampered_rollback_artifact_is_refused_without_erasing_journal_or_wallet() {
    let fixture = Fixture::new();
    let destination = fixture.path("wallet.json");
    let original = create_with_random(PASSWORD, &key(), CryptoEngine::Secp256k1, ScryptProfile::Standard, &mut ZeroRng).unwrap();
    let replacement = create_with_random(NEW_PASSWORD, &key(), CryptoEngine::Secp256k1, ScryptProfile::Standard, &mut ZeroRng).unwrap();
    fs::write(&destination, original.to_json().unwrap()).unwrap();
    set_mode(&destination, 0o600);
    let _ = atomic_write_wallet_with_failure(&replacement, &destination, true, &mut ZeroRng, AtomicWriteStage::RollbackRename).unwrap_err();
    let journal = fixture.path(".keystore-replace.journal");
    let journal_before = fs::read(&journal).unwrap();
    let wallet_before = fs::read(&destination).unwrap();
    let backup = fixture.path(".keystore-0000000000000000.backup");
    fs::write(&backup, b"tampered").unwrap();
    set_mode(&backup, 0o600);

    assert!(matches!(list_keystores(&fixture.0), Err(StoreError::RecoveryRefused { .. })));
    assert_eq!(fs::read(&journal).unwrap(), journal_before);
    assert_eq!(fs::read(&destination).unwrap(), wallet_before);
    assert_eq!(fs::read(&backup).unwrap(), b"tampered");
}

#[cfg(unix)]
#[test]
fn destination_interference_refuses_recovery_without_deleting_either_wallet() {
    let fixture = Fixture::new();
    let destination = fixture.path("wallet.json");
    let original = create_with_random(PASSWORD, &key(), CryptoEngine::Secp256k1, ScryptProfile::Standard, &mut ZeroRng).unwrap();
    let replacement = create_with_random(NEW_PASSWORD, &key(), CryptoEngine::Secp256k1, ScryptProfile::Standard, &mut ZeroRng).unwrap();
    fs::write(&destination, original.to_json().unwrap()).unwrap();
    set_mode(&destination, 0o600);
    let _ = atomic_write_wallet_with_failure(&replacement, &destination, true, &mut ZeroRng, AtomicWriteStage::RollbackRename).unwrap_err();

    let mut other_bytes = [0u8; 32];
    other_bytes[31] = 2;
    let other_key = PrivateKey::from_bytes(CryptoEngine::Secp256k1, &other_bytes).unwrap();
    let other = create_with_random(PASSWORD, &other_key, CryptoEngine::Secp256k1, ScryptProfile::Standard, &mut ZeroRng).unwrap().to_json().unwrap();
    fs::write(&destination, &other).unwrap();
    set_mode(&destination, 0o600);
    let journal = fixture.path(".keystore-replace.journal");
    let journal_before = fs::read(&journal).unwrap();
    let backup = fixture.path(".keystore-0000000000000000.backup");
    let backup_before = fs::read(&backup).unwrap();

    assert!(matches!(list_keystores(&fixture.0), Err(StoreError::RecoveryRefused { .. })));
    assert_eq!(fs::read_to_string(&destination).unwrap(), other);
    assert_eq!(fs::read(&backup).unwrap(), backup_before);
    assert_eq!(fs::read(&journal).unwrap(), journal_before);
}

#[cfg(unix)]
#[test]
fn same_uid_substitution_at_each_overwrite_boundary_is_never_unlinked() {
    for stage in [
        AtomicWriteHookStage::DestinationValidated,
        AtomicWriteHookStage::BackupRenamed,
        AtomicWriteHookStage::Published,
        AtomicWriteHookStage::BeforeCleanup,
    ] {
        let fixture = Fixture::new();
        let destination = fixture.path("wallet.json");
        let original = create_with_random(PASSWORD, &key(), CryptoEngine::Secp256k1, ScryptProfile::Standard, &mut ZeroRng).unwrap();
        let replacement = create_with_random(NEW_PASSWORD, &key(), CryptoEngine::Secp256k1, ScryptProfile::Standard, &mut ZeroRng).unwrap();
        let mut other_bytes = [0u8; 32];
        other_bytes[31] = 2;
        let other_key = PrivateKey::from_bytes(CryptoEngine::Secp256k1, &other_bytes).unwrap();
        let substitute = create_with_random(PASSWORD, &other_key, CryptoEngine::Secp256k1, ScryptProfile::Standard, &mut ZeroRng).unwrap().to_json().unwrap();
        fs::write(&destination, original.to_json().unwrap()).unwrap();
        set_mode(&destination, 0o600);
        let saved_name = format!("saved-{stage:?}.json");
        let saved = fixture.path(&saved_name);
        let backup = fixture.path(".keystore-0000000000000000.backup");
        let error = atomic_write_wallet_with_stage_hook(&replacement, &destination, true, &mut ZeroRng, |current| {
            if current != stage { return; }
            let victim = if current == AtomicWriteHookStage::DestinationValidated { &destination }
                else if current == AtomicWriteHookStage::Published { &destination }
                else { &backup };
            fs::rename(victim, &saved).unwrap();
            fs::write(victim, &substitute).unwrap();
            set_mode(victim, 0o600);
        }).unwrap_err();
        assert!(matches!(error, StoreError::RecoveryRefused { .. } | StoreError::RollbackFailed { .. }), "{stage:?}: {error:?}");
        assert_eq!(fs::read_to_string(&saved).unwrap(), if stage == AtomicWriteHookStage::Published { replacement.to_json().unwrap() } else { original.to_json().unwrap() });
        let substitute_survives = fs::read_to_string(&destination).ok().as_deref() == Some(&substitute)
            || fs::read_to_string(&backup).ok().as_deref() == Some(&substitute);
        assert!(substitute_survives, "substitute disappeared at {stage:?}");
        assert!(fixture.path(".keystore-replace.journal").exists(), "journal disappeared at {stage:?}");
    }
}
