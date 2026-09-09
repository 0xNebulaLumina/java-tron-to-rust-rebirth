use std::collections::BTreeMap;
use std::env;
use std::path::{Path, PathBuf};

use serde_json::json;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use tron_crypto::artifact_auth::{AuthLimits, DsseEnvelope};
use tron_toolkit::release::{self, FixedReleaseClock, InstallReceiptV1, InstallRequest, LocalReleaseFs, ReleaseError, ReleaseFs, RetainedReleaseInput, StagePublicationRequest, VerifyBundleRequest};

fn main() {
    let result = run(env::args().skip(1).collect());
    match result {
        Ok(value) => { println!("{}", value); }
        Err(error) => { eprintln!("error: {error}"); std::process::exit(error.exit_code()); }
    }
}

fn run(args: Vec<String>) -> Result<serde_json::Value, ReleaseError> {
    let (command, options) = parse(args)?;
    let time = parse_time(required(&options, "verification-time")?)?;
    let clock = FixedReleaseClock(time);
    let fs = LocalReleaseFs;
    let limits = AuthLimits::default();
    match command.as_str() {
        "stage-publish" => {
            let candidate = Path::new(required(&options, "candidate")?);
            let staging = Path::new(required(&options, "staging")?);
            let trust = read(&fs, required(&options, "trust-store")?, limits.max_payload_bytes as u64)?;
            let manifest_name = "release-manifest.dsse.json";
            let manifest = RetainedReleaseInput::open(&candidate.join(manifest_name), limits.max_envelope_bytes as u64)?;
            let manifest_bytes = manifest.read(limits.max_envelope_bytes as u64)?;
            let update_path = candidate.join("release-trust-update.dsse.json");
            let update = if update_path.exists() { Some(RetainedReleaseInput::open(&update_path, limits.max_envelope_bytes as u64)?) } else { None };
            let effective_trust = if let Some(input) = &update {
                let bytes = input.read(limits.max_envelope_bytes as u64)?;
                release::verify_trust_update(&trust, &bytes, &clock, limits)?;
                DsseEnvelope::parse(&bytes, limits).map_err(|error| ReleaseError::Authentication(error.to_string()))?.payload_bytes(limits).map_err(|error| ReleaseError::Authentication(error.to_string()))?
            } else { trust };
            let platform = required(&options, "platform")?;
            let channel = required(&options, "channel")?;
            let minimum_sequence = options.get("minimum-sequence").map(|s| s.parse().map_err(|_| ReleaseError::Usage("invalid --minimum-sequence"))).transpose()?.unwrap_or(0);
            let verified = release::verify_bundle(VerifyBundleRequest { trust_store: &effective_trust, manifest_envelope: &manifest_bytes, bundle: &candidate.join("bundle"), platform_id: platform, minimum_sequence, channel, fs: &fs, clock: &clock, limits })?;
            let inventory = release::stage_verified_publication(&verified, StagePublicationRequest { staging, manifest_name, manifest_envelope: &manifest, trust_update_name: update.as_ref().map(|_| "release-trust-update.dsse.json"), trust_update: update.as_ref() })?;
            Ok(json!({"status":"staged","staging":staging,"inventory":inventory}))
        }
        "verify" | "install" => {
            let trust = read(&fs, required(&options, "trust-store")?, limits.max_payload_bytes as u64)?;
            let manifest = read(&fs, required(&options, "manifest")?, limits.max_envelope_bytes as u64)?;
            let platform = required(&options, "platform")?;
            let channel = required(&options, "channel")?;
            let minimum_sequence = options.get("minimum-sequence").map(|s| s.parse().map_err(|_| ReleaseError::Usage("invalid --minimum-sequence"))).transpose()?.unwrap_or(0);
            let verified = release::verify_bundle(VerifyBundleRequest { trust_store: &trust, manifest_envelope: &manifest, bundle: Path::new(required(&options, "bundle")?), platform_id: platform, minimum_sequence, channel, fs: &fs, clock: &clock, limits })?;
            if command == "install" {
                let receipt = release::install_verified(&verified, InstallRequest { prefix: Path::new(required(&options, "prefix")?), config_root: Path::new(required(&options, "config-root")?), receipt: Path::new(required(&options, "receipt")?), retained_slots: options.get("retained-slots").map(|s| s.parse().map_err(|_| ReleaseError::Usage("invalid --retained-slots"))).transpose()?.unwrap_or(2) }, &clock)?;
                Ok(json!({"status":"installed","receipt":receipt}))
            } else {
                Ok(json!({"status":"verified","release_id":verified.manifest().release_id,"release_sequence":verified.manifest().release_sequence,"manifest_sha256":verified.manifest_digest()}))
            }
        }
        "verify-install" => {
            let trust = read(&fs, required(&options, "trust-store")?, limits.max_payload_bytes as u64)?;
            let manifest = read(&fs, required(&options, "manifest")?, limits.max_envelope_bytes as u64)?;
            let verified = release::verify_bundle(VerifyBundleRequest {
                trust_store: &trust,
                manifest_envelope: &manifest,
                bundle: Path::new(required(&options, "bundle")?),
                platform_id: required(&options, "platform")?,
                minimum_sequence: required(&options, "minimum-sequence")?.parse().map_err(|_| ReleaseError::Usage("invalid --minimum-sequence"))?,
                channel: required(&options, "channel")?,
                fs: &fs,
                clock: &clock,
                limits,
            })?;
            let bytes = read(&fs, required(&options, "receipt")?, 1024 * 1024)?;
            let receipt: InstallReceiptV1 = serde_json::from_slice(&bytes).map_err(|_| ReleaseError::Malformed("malformed install receipt"))?;
            release::verify_install(&verified, &receipt, Path::new(required(&options, "receipt")?), Path::new(required(&options, "prefix")?), &fs)?;
            Ok(json!({"status":"verified","release_id":receipt.release_id,"manifest_sha256":receipt.manifest_sha256}))
        }
        "verify-trust-update" => {
            let current = read(&fs, required(&options, "current")?, limits.max_payload_bytes as u64)?;
            let candidate = read(&fs, required(&options, "candidate")?, limits.max_envelope_bytes as u64)?;
            let trust = release::verify_trust_update(&current, &candidate, &clock, limits)?;
            Ok(json!({"status":"verified","trust_store_version":trust.version}))
        }
        _ => Err(ReleaseError::Usage("command must be verify, stage-publish, install, verify-install, or verify-trust-update")),
    }
}

fn parse(args: Vec<String>) -> Result<(String, BTreeMap<String, String>), ReleaseError> {
    let mut iter = args.into_iter();
    let command = iter.next().ok_or(ReleaseError::Usage("missing command"))?;
    let mut options = BTreeMap::new();
    while let Some(flag) = iter.next() {
        if flag == "--json" { continue; }
        let name = flag.strip_prefix("--").ok_or(ReleaseError::Usage("arguments must be --name value"))?;
        if name.contains("url") || name.contains("host") { return Err(ReleaseError::Usage("network options are forbidden")); }
        let value = iter.next().ok_or(ReleaseError::Usage("missing option value"))?;
        if options.insert(name.to_owned(), value).is_some() { return Err(ReleaseError::Usage("duplicate option")); }
    }
    Ok((command, options))
}
fn required<'a>(options: &'a BTreeMap<String,String>, name: &str) -> Result<&'a str, ReleaseError> { options.get(name).map(String::as_str).ok_or(ReleaseError::Usage("missing required option")) }
fn read(fs: &dyn ReleaseFs, value: &str, max: u64) -> Result<Vec<u8>, ReleaseError> { fs.read_bounded(&PathBuf::from(value), max) }
fn parse_time(value: &str) -> Result<OffsetDateTime, ReleaseError> { OffsetDateTime::parse(value, &Rfc3339).map_err(|_| ReleaseError::Usage("invalid --verification-time")) }
