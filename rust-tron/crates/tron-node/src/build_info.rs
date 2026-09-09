use serde::Serialize;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct BuildIdentity {
    pub release_id: &'static str,
    pub release_version: &'static str,
    pub release_sequence: u64,
    pub source_revision: &'static str,
    pub source_date_epoch: &'static str,
    pub platform_id: &'static str,
    pub target: &'static str,
    pub backend: &'static str,
    pub backend_format: &'static str,
    pub features: &'static [&'static str],
    pub cargo_lock_sha256: &'static str,
    pub rust_toolchain_sha256: &'static str,
}

const fn parse_sequence(value: Option<&str>) -> u64 {
    let bytes = match value { Some(value) => value.as_bytes(), None => return 0 };
    let mut value = 0_u64;
    let mut i = 0;
    while i < bytes.len() {
        let digit = bytes[i];
        if digit < b'0' || digit > b'9' { return 0; }
        if value > (u64::MAX - (digit - b'0') as u64) / 10 { return 0; }
        value = value * 10 + (digit - b'0') as u64;
        i += 1;
    }
    value
}

pub const BUILD_IDENTITY: BuildIdentity = BuildIdentity {
    release_id: match option_env!("TRON_RELEASE_ID") { Some(v) => v, None => "development" },
    release_version: match option_env!("TRON_RELEASE_VERSION") { Some(v) => v, None => env!("CARGO_PKG_VERSION") },
    release_sequence: parse_sequence(option_env!("TRON_RELEASE_SEQUENCE")),
    source_revision: match option_env!("TRON_SOURCE_REVISION") { Some(v) => v, None => "development" },
    source_date_epoch: match option_env!("SOURCE_DATE_EPOCH") { Some(v) => v, None => "0" },
    platform_id: match option_env!("TRON_PLATFORM_ID") { Some(v) => v, None => "P-LINUX-X64" },
    target: match option_env!("TRON_BUILD_TARGET") { Some(v) => v, None => "x86_64-unknown-linux-gnu" },
    backend: "rustlog",
    backend_format: "rustlog-v1",
    features: &["rustlog-v1"],
    cargo_lock_sha256: match option_env!("TRON_CARGO_LOCK_SHA256") { Some(v) => v, None => "development" },
    rust_toolchain_sha256: match option_env!("TRON_RUST_TOOLCHAIN_SHA256") { Some(v) => v, None => "development" },
};

impl BuildIdentity {
    #[must_use] pub fn is_development(self) -> bool { self.release_id == "development" || self.source_revision == "development" }
}
