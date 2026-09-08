use std::str::FromStr;

use tron_config::toolkit::{
    BackendIdentity, CapabilityState, PlatformFacts, ToolkitBackend, ToolkitCapabilityError,
    P_LINUX_ARM64, P_LINUX_X64, P_MACOS_ARM64, P_MACOS_X64, P_UNSUPPORTED,
    toolkit_capabilities, validate_toolkit_backend,
};

fn facts(os: &str, architecture: &str, target: &str) -> PlatformFacts {
    PlatformFacts::new(os, architecture, target)
}

#[test]
fn only_linux_x64_rustlog_is_readable_and_writable() {
    let capabilities = toolkit_capabilities(facts("linux", "x86_64", "x86_64-unknown-linux-gnu"));
    assert_eq!(capabilities.platform_id, P_LINUX_X64);
    assert_eq!(capabilities.state, CapabilityState::Enabled);
    assert_eq!(capabilities.reason, None);
    assert_eq!(capabilities.backends.len(), 3);

    let rustlog = &capabilities.backends[0];
    assert_eq!(rustlog.backend, ToolkitBackend::RustlogV1);
    assert_eq!(rustlog.state, CapabilityState::Enabled);
    assert!(rustlog.readable);
    assert!(rustlog.writable);
    assert_eq!(rustlog.reason, None);
    assert_eq!(
        validate_toolkit_backend(&capabilities, ToolkitBackend::RustlogV1).unwrap(),
        BackendIdentity { backend: "rustlog", backend_format: "rustlog-v1", required_feature: "rustlog-v1" }
    );
}

#[test]
fn reserved_arm_and_macos_rows_are_future() {
    for (input, expected_id) in [
        (facts("linux", "aarch64", "aarch64-unknown-linux-gnu"), P_LINUX_ARM64),
        (facts("macos", "x86_64", "x86_64-apple-darwin"), P_MACOS_X64),
        (facts("macos", "aarch64", "aarch64-apple-darwin"), P_MACOS_ARM64),
    ] {
        let capabilities = toolkit_capabilities(input);
        assert_eq!(capabilities.platform_id, expected_id);
        assert_eq!(capabilities.state, CapabilityState::Future);
        assert!(capabilities.reason.is_some());
        let rustlog = &capabilities.backends[0];
        assert_eq!(rustlog.state, CapabilityState::Future);
        assert!(!rustlog.readable);
        assert!(!rustlog.writable);
        assert_eq!(
            validate_toolkit_backend(&capabilities, ToolkitBackend::RustlogV1),
            Err(ToolkitCapabilityError::FuturePlatform { id: expected_id.to_owned() })
        );
    }
}

#[test]
fn mismatched_or_unreserved_platform_facts_are_unsupported() {
    for input in [
        facts("linux", "x86_64", "aarch64-unknown-linux-gnu"),
        facts("windows", "x86_64", "x86_64-pc-windows-msvc"),
        facts("linux", "x86", "i686-unknown-linux-gnu"),
    ] {
        let expected = ToolkitCapabilityError::UnsupportedPlatform {
            os: input.os.clone(), architecture: input.architecture.clone(), target: input.target.clone(),
        };
        let capabilities = toolkit_capabilities(input);
        assert_eq!(capabilities.platform_id, P_UNSUPPORTED);
        assert_eq!(capabilities.state, CapabilityState::Unsupported);
        assert_eq!(validate_toolkit_backend(&capabilities, ToolkitBackend::RustlogV1), Err(expected));
    }
}

#[test]
fn java_backends_are_recognized_but_always_reference_only() {
    let capabilities = toolkit_capabilities(facts("linux", "x86_64", "x86_64-unknown-linux-gnu"));
    for (spelling, expected, canonical) in [
        ("LEVELDB", ToolkitBackend::JavaLevelDb, "LEVELDB"),
        ("leveldb", ToolkitBackend::JavaLevelDb, "LEVELDB"),
        ("java-leveldb", ToolkitBackend::JavaLevelDb, "LEVELDB"),
        ("ROCKSDB", ToolkitBackend::JavaRocksDb, "ROCKSDB"),
        ("rocksdb", ToolkitBackend::JavaRocksDb, "ROCKSDB"),
        ("java-rocksdb", ToolkitBackend::JavaRocksDb, "ROCKSDB"),
    ] {
        let backend = ToolkitBackend::from_str(spelling).unwrap();
        assert_eq!(backend, expected);
        assert_eq!(backend.cli_name(), canonical);
        assert_eq!(
            validate_toolkit_backend(&capabilities, backend),
            Err(ToolkitCapabilityError::JavaReferenceOnly { backend: canonical })
        );
        let row = capabilities.backends.iter().find(|row| row.backend == backend).unwrap();
        assert_eq!(row.state, CapabilityState::ReferenceOnly);
        assert!(!row.readable);
        assert!(!row.writable);
    }
}

#[test]
fn backend_parser_never_substitutes_unknown_values() {
    assert_eq!("RUSTLOG-V1".parse(), Ok(ToolkitBackend::RustlogV1));
    for value in ["rustlog", "LevelDB-v1", ""] {
        assert_eq!(
            ToolkitBackend::from_str(value),
            Err(ToolkitCapabilityError::UnknownBackend(value.to_owned()))
        );
    }
}
