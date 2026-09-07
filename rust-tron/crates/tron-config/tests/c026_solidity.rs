use tron_config::{Config, NodeMode};

#[test]
fn solidity_requires_nonblank_valid_trust_node_before_services() {
    for invalid in [
        "", "   ", "host", ":50051", "host:0", "host:65536", "bad host:50051",
        "[::1]", "[]:50051", "::1:50051", "host:1:50051", "host/path:50051",
        "http://host:50051", "user@host:50051", "host:50051?query", "host:50051#fragment",
        "-host:50051", "host-:50051", "host..example:50051", "999.1.1.1:50051",
    ] {
        let mut config = Config::default();
        config.node.trust_node = invalid.into();
        assert!(config.validate_for_mode(NodeMode::Solidity).is_err(), "accepted {invalid:?}");
    }
    for valid in ["127.0.0.1:50051", "trust.example:50051", "[::1]:50051"] {
        let mut config = Config::default();
        config.node.trust_node = valid.into();
        config.validate_for_mode(NodeMode::Solidity).unwrap();
    }
}

#[test]
fn full_and_keystore_modes_do_not_require_trust_node() {
    let config = Config::default();
    config.validate_for_mode(NodeMode::Full).unwrap();
    config.validate_for_mode(NodeMode::KeystoreFactory).unwrap();
}
