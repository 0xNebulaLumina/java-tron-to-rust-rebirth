use std::cell::Cell;
use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use ed25519_dalek::{Signer, SigningKey};
use serde_json::json;
use sha2::{Digest, Sha256};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use tron_crypto::artifact_auth::{AuthLimits, KeyId, dsse_pae};
use tron_toolkit::release::{FixedReleaseClock, InstallFault, InstallPhase, InstallReceiptV1, InstallRequest, LocalReleaseFs, ReceiptFile, ReleaseError, ReleaseFs, RetainedReleaseInput, StagePublicationRequest, VerifyBundleRequest, install_verified, install_verified_with_fault, stage_verified_publication, verify_bundle, verify_install};

fn temp(name: &str) -> PathBuf {
    let nonce = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
    let path = std::env::temp_dir().join(format!("tron-c028-{name}-{}-{nonce}", std::process::id()));
    fs::create_dir(&path).unwrap();
    path
}
fn digest(bytes: &[u8]) -> String { let mut h=Sha256::new(); h.update(bytes); h.finalize().iter().map(|b|format!("{b:02x}")).collect() }
fn receipt(bytes: &[u8], current: &std::path::Path, config_root: &std::path::Path, receipt_path: &std::path::Path) -> InstallReceiptV1 {
    let config_current=config_root.join("current");
    fs::create_dir_all(&config_current).unwrap();
    fs::write(config_current.join("fullnode.conf"),bytes).unwrap();
    fs::set_permissions(config_current.join("fullnode.conf"),fs::Permissions::from_mode(0o600)).unwrap();
    InstallReceiptV1 { schema:"tron-install-receipt-v1".into(), release_id:"r1".into(), release_sequence:1, platform_id:"P-LINUX-X64".into(), manifest_sha256:"00".repeat(32), install_prefix:current.parent().unwrap().to_path_buf(), current_target:current.to_path_buf(), config_root:config_root.to_path_buf(), config_current_target:config_current, receipt_path:receipt_path.to_path_buf(), installed_at:"2026-01-01T00:00:00Z".into(), files:vec![ReceiptFile { path:"bin/tron-fullnode".into(), sha256:digest(bytes), size:bytes.len() as u64, mode:0o755 }], config_files:vec![ReceiptFile { path:"fullnode.conf".into(), sha256:digest(bytes), size:bytes.len() as u64, mode:0o600 }] }
}


#[test]
fn inventory_rejects_symlinks_before_content_is_read() {
    let root=temp("symlink");
    fs::write(root.join("outside"),b"secret").unwrap();
    symlink(root.join("outside"),root.join("member")).unwrap();
    assert!(matches!(LocalReleaseFs.inventory(&root,16),Err(ReleaseError::Filesystem(_))));
    fs::remove_dir_all(root).unwrap();
}


const RELEASE_TYPE: &str = "application/vnd.tron.release-manifest.v1+json";

fn try_verified_release_with_identity(channel: &str, signer_count: usize, corrupt_second: bool, source_revision: &str, release_id: &str) -> Result<(tron_toolkit::release::VerifiedRelease, PathBuf), ReleaseError> {
    let root = temp("bundle");
    let bundle = root.join("bundle");
    fs::create_dir(&bundle).unwrap();
    let entries = [
        ("tron-fullnode", "artifacts/tron-fullnode"), ("tron-solidity", "artifacts/tron-solidity"),
        ("tron-toolkit", "artifacts/tron-toolkit"), ("tron-release-verify", "artifacts/tron-release-verify"),
        ("native-archive", "artifacts/native-archive"), ("config-archive", "artifacts/config-archive"),
        ("oci-image", "artifacts/oci-image"), ("sbom", "artifacts/sbom"), ("provenance", "artifacts/provenance"),
        ("config-fullnode", "config/fullnode.conf"), ("config-fullnode-deployment", "config/fullnode.deployment.json"),
        ("config-solidity", "config/solidity.conf"), ("config-solidity-deployment", "config/solidity.deployment.json"),
    ];
    let artifacts = entries.iter().map(|(name,path)| {
        if let Some(parent)=bundle.join(path).parent(){fs::create_dir_all(parent).unwrap();}
        let bytes = name.as_bytes();
        fs::write(bundle.join(path), bytes).unwrap();
        fs::set_permissions(bundle.join(path), fs::Permissions::from_mode(0o644)).unwrap();
        json!({"logical_name":name,"path":path,"kind":if path.starts_with("config/"){"configuration"}else{"archive"},"platform_id":"P-LINUX-X64","sha256":digest(bytes),"size":bytes.len(),"mode":420,"media_type":"application/octet-stream","release_id":release_id})
    }).collect::<Vec<_>>();
    let manifest = serde_json::to_vec(&json!({
        "schema":"tron-release-manifest-v1","release_id":release_id,"version":"2.0.0","release_sequence":2,"channel":channel,
        "source_revision":source_revision,"source_date_epoch":1,
        "install_prefix":root.join("install"),"current_target":root.join("install/current"),"config_root":root.join("config"),"receipt_path":root.join("receipt.json"),
        "production_materials":[{"name":"busybox","sha256":"22".repeat(32),"version":"v1.36.1","license":"GPL-2.0-only","provenance":"fixture:busybox"}],
        "platforms":[{"platform_id":"P-LINUX-X64","os":"linux","architecture":"x86_64","target":"x86_64-unknown-linux-gnu","backend":"rustlog","backend_format":"rustlog-v1","features":[],"enabled":true}],
        "artifacts":artifacts,"operator_inputs":[],"compatibility":{"minimum_sequence":1,"native_resources":[]}
    })).unwrap();
    let keys = [SigningKey::from_bytes(&[91; 32]), SigningKey::from_bytes(&[92; 32]), SigningKey::from_bytes(&[93; 32])];
    let publics = keys.iter().map(|key| key.verifying_key().to_bytes()).collect::<Vec<_>>();
    let key_ids = publics.iter().map(|public| KeyId::for_ed25519(public)).collect::<Vec<_>>();
    let trust_keys = publics.iter().zip(&key_ids).map(|(public,key_id)|json!({"key_id":key_id.as_str(),"algorithm":"ed25519-v1","public_key_base64":BASE64.encode(public),"not_before":"2026-01-01T00:00:00Z","not_after":"2027-01-01T00:00:00Z","revoked":false})).collect::<Vec<_>>();
    let ids = key_ids.iter().map(KeyId::as_str).collect::<Vec<_>>();
    let trust = serde_json::to_vec(&json!({"schema":"tron-trust-store-v1","version":1,"expires":"2027-01-01T00:00:00Z","keys":trust_keys,"roles":[{"name":"root","key_ids":ids,"threshold":2,"scope":"trust-store"},{"name":"release:stable","key_ids":ids,"threshold":2,"scope":"release:stable"}]})).unwrap();
    let pae = dsse_pae(RELEASE_TYPE, &manifest);
    let signatures = keys.iter().zip(&key_ids).take(signer_count).enumerate().map(|(index,(key,key_id))| { let mut signature=key.sign(&pae).to_bytes(); if corrupt_second && index==1 { signature[0]^=1; } json!({"key_id":key_id.as_str(),"algorithm":"ed25519-v1","signature":BASE64.encode(signature)}) }).collect::<Vec<_>>();
    let envelope = serde_json::to_vec(&json!({"payload_type":RELEASE_TYPE,"payload":BASE64.encode(&manifest),"signatures":signatures})).unwrap();
    fs::write(root.join("release-manifest.dsse.json"), &envelope).unwrap();
    let clock = FixedReleaseClock(OffsetDateTime::parse("2026-09-08T12:00:00Z", &Rfc3339).unwrap());
    let verified = verify_bundle(VerifyBundleRequest { trust_store:&trust, manifest_envelope:&envelope, bundle:&bundle, platform_id:"P-LINUX-X64", minimum_sequence:0, channel, fs:&LocalReleaseFs, clock:&clock, limits:AuthLimits::default() })?;
    Ok((verified, root))
}

fn try_verified_release_with_source_revision(channel: &str, signer_count: usize, corrupt_second: bool, source_revision: &str) -> Result<(tron_toolkit::release::VerifiedRelease, PathBuf), ReleaseError> { try_verified_release_with_identity(channel,signer_count,corrupt_second,source_revision,"r2") }
fn try_verified_release_with_signers(channel: &str, signer_count: usize, corrupt_second: bool) -> Result<(tron_toolkit::release::VerifiedRelease, PathBuf), ReleaseError> { try_verified_release_with_source_revision(channel,signer_count,corrupt_second,&"11".repeat(20)) }
fn try_verified_release(channel: &str) -> Result<(tron_toolkit::release::VerifiedRelease, PathBuf), ReleaseError> { try_verified_release_with_signers(channel,2,false) }
fn verified_release(channel: &str) -> (tron_toolkit::release::VerifiedRelease, PathBuf) { try_verified_release(channel).unwrap() }
#[test]
fn authenticated_restart_rejects_matching_receipt_and_binary_substitution() {
    let (verified, root) = verified_release("stable");
    let prefix = root.join("install");
    let config = root.join("config");
    let receipt_path = root.join("receipt.json");
    let clock = FixedReleaseClock(OffsetDateTime::parse("2026-09-08T12:00:00Z", &Rfc3339).unwrap());
    let mut receipt = install_verified(&verified, InstallRequest { prefix:&prefix, config_root:&config, receipt:&receipt_path, retained_slots:2 }, &clock).unwrap();
    verify_install(&verified, &receipt, &receipt_path, &prefix.join("current"), &LocalReleaseFs).unwrap();

    let replacement = b"same uid attacker replacement";
    let installed = prefix.join("current/artifacts/tron-fullnode");
    fs::write(&installed, replacement).unwrap();
    fs::set_permissions(&installed, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(matches!(verify_install(&verified, &receipt, &receipt_path, &prefix.join("current"), &LocalReleaseFs), Err(ReleaseError::Digest(_))));
    let row = receipt.files.iter_mut().find(|row| row.path == "artifacts/tron-fullnode").unwrap();
    row.sha256 = digest(replacement);
    row.size = replacement.len() as u64;
    fs::write(&receipt_path, serde_json::to_vec(&receipt).unwrap()).unwrap();

    assert!(matches!(verify_install(&verified, &receipt, &receipt_path, &prefix.join("current"), &LocalReleaseFs), Err(ReleaseError::Authentication(_))));
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn release_verification_requires_the_requested_channel() {
    assert!(matches!(try_verified_release("stable"), Ok(_)));
    let (verified, root) = verified_release("stable");
    assert_eq!(verified.manifest().channel, "stable");
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn release_verification_rejects_cross_channel_and_unknown_channel() {
    assert!(matches!(try_verified_release("beta"), Err(ReleaseError::Authentication(_))), "beta manifest must not be authorized by stable role");
    assert!(matches!(try_verified_release("bad/channel"), Err(ReleaseError::Malformed("release channel is not canonical"))), "non-canonical channel must be rejected");
}

#[test]
fn release_threshold_requires_two_independent_valid_signers() {
    assert!(try_verified_release_with_signers("stable",2,false).is_ok());
    assert!(matches!(try_verified_release_with_signers("stable",1,false),Err(ReleaseError::Authentication(_))));
    assert!(matches!(try_verified_release_with_signers("stable",2,true),Err(ReleaseError::Authentication(_))));
}

#[test]
fn release_verification_rejects_noncanonical_source_revision() {
    for revision in ["11".repeat(32), "A1".repeat(20), "1".repeat(39), "g1".repeat(20)] {
        assert!(matches!(try_verified_release_with_source_revision("stable",2,false,&revision),Err(ReleaseError::Malformed("source revision is not a canonical Git SHA-1"))));
    }
}

#[test]
fn release_id_enforces_canonical_ascii_boundaries_before_filesystem_use() {
    for release_id in ["", "../escape", "/absolute", "dir/name", "dir\\name", ".hidden", "é", &"a".repeat(129)] {
        let result = try_verified_release_with_identity("stable", 2, false, &"11".repeat(20), release_id);
        assert!(matches!(result, Err(ReleaseError::Malformed("malformed release manifest"))), "accepted invalid release ID {release_id:?}");
    }
    for release_id in ["a".to_owned(), "a".repeat(128)] {
        let (verified, root) = try_verified_release_with_identity("stable", 2, false, &"11".repeat(20), &release_id).unwrap();
        assert_eq!(verified.manifest().release_id.as_str(), release_id);
        fs::remove_dir_all(root).unwrap();
    }
}

#[test]
fn invalid_release_id_verify_and_install_leave_install_topology_absent() {
    for release_id in ["../escape", "/absolute", "dir/name", "é", &"a".repeat(129)] {
        let result = try_verified_release_with_identity("stable", 2, false, &"11".repeat(20), release_id);
        assert!(matches!(result, Err(ReleaseError::Malformed("malformed release manifest"))));
        let escaped_root = std::env::temp_dir().join("escape");
        assert!(!escaped_root.exists(), "invalid release ID escaped the fixture topology");
    }
}

#[test]
fn install_rejects_post_verify_path_replacement() {
    let (verified, root) = verified_release("stable");
    let member = root.join("bundle/artifacts/tron-fullnode");
    fs::remove_file(&member).unwrap();
    fs::write(&member, b"tron-fullnode").unwrap();
    fs::set_permissions(&member, fs::Permissions::from_mode(0o644)).unwrap();
    let prefix = root.join("install");
    let config = root.join("config");
    let receipt = root.join("receipt.json");
    let clock = FixedReleaseClock(OffsetDateTime::parse("2026-09-08T12:00:00Z", &Rfc3339).unwrap());
    let error = install_verified(&verified, InstallRequest { prefix:&prefix, config_root:&config, receipt:&receipt, retained_slots:2 }, &clock).unwrap_err();
    assert!(matches!(error, ReleaseError::Filesystem("verified bundle member was replaced or changed")));
    assert!(!prefix.join("current").exists());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn install_rejects_prefix_not_authorized_by_signed_manifest() {
    let (verified, root) = verified_release("stable");
    let wrong = root.join("wrong-install");
    let clock = FixedReleaseClock(OffsetDateTime::parse("2026-09-08T12:00:00Z", &Rfc3339).unwrap());
    let error = install_verified(&verified, InstallRequest { prefix:&wrong, config_root:&root.join("config"), receipt:&root.join("receipt.json"), retained_slots:2 }, &clock).unwrap_err();
    assert!(matches!(error, ReleaseError::Filesystem("install request differs from signed topology")));
    assert!(!wrong.exists());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn staged_publication_uses_retained_verified_bytes_after_candidate_substitution() {
    let (verified, root) = verified_release("stable");
    let manifest_path = root.join("release-manifest.dsse.json");
    let retained_manifest = RetainedReleaseInput::open(&manifest_path, 1024 * 1024).unwrap();
    let member = root.join("bundle/artifacts/tron-fullnode");
    let verified_bytes = fs::read(&member).unwrap();
    fs::remove_file(&member).unwrap();
    fs::write(&member, b"attacker replacement").unwrap();
    fs::remove_file(&manifest_path).unwrap();
    fs::write(&manifest_path, b"attacker envelope").unwrap();
    let staging = root.join("private-publication");
    let inventory = stage_verified_publication(&verified, StagePublicationRequest {
        staging: &staging,
        manifest_name: "release-manifest.dsse.json",
        manifest_envelope: &retained_manifest,
        trust_update_name: None,
        trust_update: None,
    }).unwrap();
    assert_eq!(fs::read(staging.join("bundle/artifacts/tron-fullnode")).unwrap(), verified_bytes);
    assert_ne!(fs::read(staging.join("bundle/artifacts/tron-fullnode")).unwrap(), fs::read(member).unwrap());
    assert_ne!(fs::read(staging.join("release-manifest.dsse.json")).unwrap(), fs::read(manifest_path).unwrap());
    assert_eq!(inventory.schema, "tron-publication-inventory-v1");
    assert_eq!(inventory.release_id, "r2");
    assert_eq!(inventory.channel, "stable");
    assert_eq!(inventory.source_revision, "11".repeat(20));
    assert!(inventory.objects.iter().any(|object| object.path == "release-manifest.dsse.json"));
    assert!(inventory.objects.iter().any(|object| object.path == "bundle/artifacts/tron-fullnode"));
    assert_eq!(fs::metadata(&staging).unwrap().permissions().mode() & 0o777, 0o700);
    fs::remove_dir_all(root).unwrap();
}

struct FailOnce { phase: InstallPhase, fired: Cell<bool> }
impl InstallFault for FailOnce {
    fn after(&self, phase: InstallPhase) -> Result<(), ReleaseError> {
        if phase == self.phase && !self.fired.replace(true) { Err(ReleaseError::Io("injected disk full".into())) } else { Ok(()) }
    }
}

struct TamperPublishedSlot { slot: PathBuf, fired: Cell<bool> }
impl InstallFault for TamperPublishedSlot {
    fn after(&self, phase: InstallPhase) -> Result<(), ReleaseError> {
        if phase == InstallPhase::Staged && !self.fired.replace(true) {
            fs::write(self.slot.join("artifacts/tron-fullnode"), b"tampered").unwrap();
            return Err(ReleaseError::Io("simulated crash after slot rename".into()));
        }
        Ok(())
    }
}

struct ReplaceConfigSelector { selector: PathBuf, replacement: PathBuf, fired: Cell<bool> }
impl InstallFault for ReplaceConfigSelector {
    fn after(&self, phase: InstallPhase) -> Result<(), ReleaseError> {
        if phase == InstallPhase::ConfigSlotPublished && !self.fired.replace(true) {
            fs::remove_file(&self.selector).unwrap();
            symlink(&self.replacement, &self.selector).unwrap();
            return Err(ReleaseError::Io("simulated crash after config switch".into()));
        }
        Ok(())
    }
}

#[test]
fn every_install_phase_fault_recovers_matching_current_and_receipt() {
    for phase in [InstallPhase::Staged, InstallPhase::SlotPublished, InstallPhase::ConfigSlotPublished, InstallPhase::ConfigCurrentPublished, InstallPhase::ReceiptPublished, InstallPhase::CurrentPublished, InstallPhase::Pruned] {
        let (verified, root) = verified_release("stable");
        let prefix = root.join("install");
        let config = root.join("config");
        let receipt_path = root.join("receipt.json");
        let old_slot = prefix.join("releases/r1");
        fs::create_dir_all(old_slot.join("bin")).unwrap();
        fs::write(old_slot.join("bin/tron-fullnode"), b"old").unwrap();
        fs::set_permissions(old_slot.join("bin/tron-fullnode"), fs::Permissions::from_mode(0o755)).unwrap();
        let older_slot = prefix.join("releases/r0");
        fs::create_dir_all(older_slot.join("bin")).unwrap();
        fs::write(older_slot.join("bin/tron-fullnode"), b"older").unwrap();
        fs::create_dir_all(&prefix).unwrap();
        symlink(&old_slot, prefix.join("current")).unwrap();
        let old_config_slot = config.join("releases/r1");
        fs::create_dir_all(&old_config_slot).unwrap();
        let older_config_slot = config.join("releases/r0");
        fs::create_dir_all(&older_config_slot).unwrap();
        fs::create_dir_all(&config).unwrap();
        symlink(&old_config_slot, config.join("current")).unwrap();
        fs::write(&receipt_path, serde_json::to_vec(&receipt(b"old",&prefix.join("current"),&config,&receipt_path)).unwrap()).unwrap();
        let clock = FixedReleaseClock(OffsetDateTime::parse("2026-09-08T12:00:00Z", &Rfc3339).unwrap());
        let fault = FailOnce { phase, fired: Cell::new(false) };
        assert!(install_verified_with_fault(&verified, InstallRequest { prefix:&prefix, config_root:&config, receipt:&receipt_path, retained_slots:2 }, &clock, &fault).is_err());
        let persisted: InstallReceiptV1 = serde_json::from_slice(&fs::read(&receipt_path).unwrap()).unwrap();
        verify_install(&verified, &persisted, &receipt_path, &prefix.join("current"), &LocalReleaseFs).unwrap();
        assert_eq!(fs::read_link(prefix.join("current")).unwrap(), prefix.join("releases/r2"), "phase {phase:?}");
        assert_eq!(fs::read_link(config.join("current")).unwrap(), config.join("releases/r2"));
        assert_eq!(persisted.config_current_target, config.join("current"));
        assert!(!persisted.config_files.is_empty());
        let binary_slots = fs::read_dir(prefix.join("releases")).unwrap().filter_map(Result::ok).filter(|entry| entry.path().is_dir()).count();
        let config_slots = fs::read_dir(config.join("releases")).unwrap().filter_map(Result::ok).filter(|entry| entry.path().is_dir()).count();
        assert_eq!(binary_slots, 2, "phase {phase:?}");
        assert_eq!(config_slots, 2, "phase {phase:?}");
        assert!(!prefix.join(".install-journal.json").exists());
        fs::remove_dir_all(root).unwrap();
    }
}

#[test]
fn recovery_rejects_tampered_completed_effect_and_preserves_journal() {
    let (verified, root) = verified_release("stable");
    let prefix = root.join("install");
    let config = root.join("config");
    let receipt_path = root.join("receipt.json");
    let clock = FixedReleaseClock(OffsetDateTime::parse("2026-09-08T12:00:00Z", &Rfc3339).unwrap());
    let fault = TamperPublishedSlot { slot: prefix.join("releases/r2"), fired: Cell::new(false) };
    let error = install_verified_with_fault(&verified, InstallRequest { prefix:&prefix, config_root:&config, receipt:&receipt_path, retained_slots:2 }, &clock, &fault).unwrap_err();
    assert!(matches!(error, ReleaseError::Digest(_)));
    assert!(prefix.join(".install-journal.json").exists());
    assert!(!prefix.join("current").exists());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn recovery_rejects_ambiguous_selector_and_preserves_journal() {
    let (verified, root) = verified_release("stable");
    let prefix = root.join("install");
    let config = root.join("config");
    let receipt_path = root.join("receipt.json");
    let attacker = root.join("attacker-config");
    fs::create_dir(&attacker).unwrap();
    let clock = FixedReleaseClock(OffsetDateTime::parse("2026-09-08T12:00:00Z", &Rfc3339).unwrap());
    let fault = ReplaceConfigSelector { selector: config.join("current"), replacement: attacker.clone(), fired: Cell::new(false) };
    let error = install_verified_with_fault(&verified, InstallRequest { prefix:&prefix, config_root:&config, receipt:&receipt_path, retained_slots:2 }, &clock, &fault).unwrap_err();
    assert!(matches!(error, ReleaseError::Filesystem("current selector changed during activation")));
    assert_eq!(fs::read_link(config.join("current")).unwrap(), attacker);
    assert!(prefix.join(".install-journal.json").exists());
    assert!(!prefix.join("current").exists());
    fs::remove_dir_all(root).unwrap();
}
