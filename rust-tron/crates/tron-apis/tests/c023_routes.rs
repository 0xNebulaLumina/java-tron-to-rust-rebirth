use std::{collections::BTreeSet, fs, path::PathBuf};
use tron_apis::{ApiCursor, http_routes::{HTTP_ROUTES, HttpSurface, find_route, routes_for}};

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../..")
}

#[test]
fn servlet_inventory_is_exact_and_excludes_commented_registrations() {
    let oracle: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(root().join("docs/oracles/c023-routes.v1.json")).unwrap(),
    ).unwrap();
    assert_eq!(oracle["counts"]["TOTAL"], 215);
    assert_eq!(routes_for(HttpSurface::Full).count(), 123);
    assert_eq!(routes_for(HttpSurface::Solidity).count(), 45);
    assert_eq!(routes_for(HttpSurface::Pbft).count(), 47);
    assert_eq!(oracle["routes"].as_array().unwrap().len(), HTTP_ROUTES.len());

    let rust: BTreeSet<_> = HTTP_ROUTES.iter().map(|r| (
        format!("{:?}", r.surface).to_uppercase(), r.path, r.servlet,
        r.get, r.post, r.rpc_method, r.request_type, r.response_type,
    )).collect();
    let pinned: BTreeSet<_> = oracle["routes"].as_array().unwrap().iter().map(|r| (
        r["surface"].as_str().unwrap().to_owned(),
        r["path"].as_str().unwrap(), r["servlet"].as_str().unwrap(),
        r["methods"].as_array().unwrap().iter().any(|m| m == "GET"),
        r["methods"].as_array().unwrap().iter().any(|m| m == "POST"),
        r["rpc_method"].as_str().unwrap(), r["request_type"].as_str().unwrap(),
        r["response_type"].as_str().unwrap(),
    )).collect();
    assert_eq!(rust, pinned);

    for excluded in [
        "/wallet/createshieldedtransaction", "/wallet/scannotebyivk",
        "/wallet/getmerkletreevoucherinfo", "/walletsolidity/scannotebyivk",
        "/walletsolidity/isspend",
    ] {
        assert!(!HTTP_ROUTES.iter().any(|route| route.path == excluded));
    }
}

#[test]
fn pinned_java_route_vectors_cover_aliases_verbs_and_cursors() {
    let create = find_route(HttpSurface::Full, "/wallet/createtransaction").unwrap();
    assert!(!create.get && create.post);
    assert_eq!(create.rpc_method, "create_transaction");
    assert_eq!(create.request_type, "protocol.TransferContract");
    assert_eq!(create.cursor, ApiCursor::Head);

    let receipt = find_route(HttpSurface::Full, "/wallet/gettransactionreceiptbyid").unwrap();
    assert!(receipt.get && receipt.post);
    assert_eq!(receipt.rpc_method, "get_transaction_info_by_id");
    assert_eq!(receipt.response_type, "protocol.TransactionInfo");

    let broadcast_hex = find_route(HttpSurface::Full, "/wallet/broadcasthex").unwrap();
    assert_eq!(broadcast_hex.rpc_method, "broadcast_transaction");
    assert_eq!(broadcast_hex.request_type, "protocol.Transaction");

    let solidity = find_route(HttpSurface::Solidity, "/walletsolidity/getaccount").unwrap();
    assert_eq!(solidity.cursor, ApiCursor::Solidity);
    let pbft = find_route(HttpSurface::Pbft, "/walletpbft/getaccount").unwrap();
    assert_eq!(pbft.cursor, ApiCursor::Pbft);

    assert!(find_route(HttpSurface::Solidity, "/walletsolidity/getpaginatednowwitnesslist").is_some());
    assert!(find_route(HttpSurface::Pbft, "/walletpbft/getpaginatednowwitnesslist").is_none());
    assert!(find_route(HttpSurface::Solidity, "/walletsolidity/getmerkletreevoucherinfo").is_none());
    assert!(find_route(HttpSurface::Pbft, "/walletpbft/getmerkletreevoucherinfo").is_some());

    let net = find_route(HttpSurface::Full, "/net/listnodes").unwrap();
    assert_eq!(net.rpc_method, "list_nodes");
    let monitor = find_route(HttpSurface::Full, "/monitor/getstatsinfo").unwrap();
    assert_eq!(monitor.rpc_api, "Monitor");
    assert_eq!(monitor.rpc_method, "get_stats_info");
}
