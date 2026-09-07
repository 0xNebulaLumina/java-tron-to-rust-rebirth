use std::{collections::BTreeSet, fs, path::PathBuf};
use tron_apis::{ApiCursor, GrpcServerPlan, ServerMode, TonicDatabaseSource, http_routes::{HttpSurface, routes_for}};
use tron_config::Config;

fn root() -> PathBuf { PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../..") }
fn manifest() -> serde_json::Value {
    serde_json::from_str(&fs::read_to_string(root().join("docs/oracles/c026-solidity-exposure.v1.json")).unwrap()).unwrap()
}

#[test]
fn standalone_solidity_grpc_service_matrix_is_exact() {
    let config = Config::default();
    let base = GrpcServerPlan::from_config(ServerMode::StandaloneSolidity, &config.node.rpc, false, false).unwrap();
    assert_eq!(base.listen.port(), 50051);
    assert_eq!(format!("{:?}", base.services), "{WalletSolidity, Database}");
    let optional = GrpcServerPlan::from_config(ServerMode::StandaloneSolidity, &config.node.rpc, true, true).unwrap();
    assert_eq!(format!("{:?}", optional.services), "{WalletSolidity, WalletExtension, Database, Monitor}");
    assert!(!format!("{:?}", optional.services).contains("Wallet,"));
    assert!(!format!("{:?}", optional.services).contains("Network"));
}

#[test]
fn standalone_solidity_grpc_method_matrix_is_exact() {
    let value = manifest();
    let rows = value["rows"].as_array().unwrap();
    let counts = rows.iter().filter(|row| row["kind"] == "grpc_method").fold(std::collections::BTreeMap::new(), |mut out, row| {
        *out.entry(row["service"].as_str().unwrap()).or_insert(0usize) += 1; out
    });
    assert_eq!(counts, std::collections::BTreeMap::from([("Database",4), ("Monitor",1), ("Wallet",147), ("WalletExtension",4), ("WalletSolidity",47)]));
    assert!(rows.iter().filter(|row| row["kind"] == "grpc_method").all(|row| row.get("exposure").and_then(|v| v.as_str()).is_some()));
}

#[test]
fn standalone_solidity_http_routes_are_exact_and_executable() {
    let rust: BTreeSet<_> = routes_for(HttpSurface::Solidity).map(|route| (route.path, route.rpc_api, route.rpc_method)).collect();
    assert_eq!(rust.len(), 45);
    assert!(routes_for(HttpSurface::Solidity).all(|route| route.cursor == ApiCursor::Solidity));
    let value = manifest();
    let pinned: BTreeSet<_> = value["rows"].as_array().unwrap().iter().filter(|row| row["kind"] == "http_route").map(|row| (
        row["path"].as_str().unwrap(), row["rpc_api"].as_str().unwrap(), row["rpc_method"].as_str().unwrap()
    )).collect();
    assert_eq!(rust, pinned);
}

#[test]
fn standalone_solidity_ports_and_absences_are_exact() {
    let config = Config::default();
    let standalone = GrpcServerPlan::from_config(ServerMode::StandaloneSolidity, &config.node.rpc, false, false).unwrap();
    let secondary = GrpcServerPlan::from_config(ServerMode::Solidity, &config.node.rpc, false, false).unwrap();
    assert_eq!(standalone.listen.port(), 50051);
    assert_eq!(secondary.listen.port(), 50061);
    assert_ne!(standalone.mode, ServerMode::Full);
    assert_ne!(standalone.mode, ServerMode::Pbft);
}

#[tokio::test]
async fn tonic_database_source_uses_strict_config_authority_grammar() {
    for valid in ["127.0.0.1:50051", "trust.example:50051", "[::1]:50051"] {
        assert!(TonicDatabaseSource::from_host_port(valid).is_ok(), "rejected {valid:?}");
    }
    for invalid in [
        "", "host", ":50051", "host:0", "host:65536", "::1:50051", "host:1:50051",
        "host/path:50051", "http://host:50051", "user@host:50051", "host:50051?query",
        "host:50051#fragment", "[]:50051",
    ] {
        assert!(TonicDatabaseSource::from_host_port(invalid).is_err(), "accepted {invalid:?}");
    }
}
