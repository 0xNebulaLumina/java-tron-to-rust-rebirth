use tron_apis::server::{
    ApiService, GrpcServerPlan, ServerConfigError, ServerMode, validate_unique_enabled_ports,
};
use tron_config::RpcConfig;

#[test]
fn full_solidity_pbft_plans_use_plaintext_ports_and_exact_services() {
    let mut rpc = RpcConfig::default();
    rpc.reflection_service = true;
    let full = GrpcServerPlan::from_config(ServerMode::Full, &rpc, true, true).unwrap();
    assert_eq!(full.listen.port(), 50051);
    assert!(full.plaintext);
    assert_eq!(
        full.services.into_iter().collect::<Vec<_>>(),
        [
            ApiService::Wallet,
            ApiService::WalletExtension,
            ApiService::Database,
            ApiService::Monitor,
            ApiService::Network,
            ApiService::TronZksnark,
            ApiService::Reflection
        ]
    );
    let solidity = GrpcServerPlan::from_config(ServerMode::Solidity, &rpc, true, true).unwrap();
    assert_eq!(solidity.listen.port(), 50061);
    assert_eq!(
        solidity.services.into_iter().collect::<Vec<_>>(),
        [
            ApiService::WalletSolidity,
            ApiService::Database,
            ApiService::Reflection
        ]
    );
    let pbft = GrpcServerPlan::from_config(ServerMode::Pbft, &rpc, true, true).unwrap();
    assert_eq!(pbft.listen.port(), 50071);
    assert_eq!(
        pbft.services.into_iter().collect::<Vec<_>>(),
        [
            ApiService::WalletSolidity,
            ApiService::Database,
            ApiService::Reflection
        ]
    );
}

#[test]
fn ports_and_transport_limits_are_rejected_before_binding() {
    let mut rpc = RpcConfig::default();
    rpc.solidity_port = rpc.port;
    assert_eq!(
        validate_unique_enabled_ports(&rpc),
        Err(ServerConfigError::DuplicatePort(50051))
    );
    rpc.solidity_enable = false;
    rpc.port = 0;
    assert_eq!(
        GrpcServerPlan::from_config(ServerMode::Full, &rpc, false, false).unwrap_err(),
        ServerConfigError::InvalidPort(0)
    );
    rpc.port = 50051;
    rpc.max_message_size = 0;
    assert_eq!(
        GrpcServerPlan::from_config(ServerMode::Full, &rpc, false, false).unwrap_err(),
        ServerConfigError::InvalidLimit("max message size", 0)
    );
}

#[test]
fn message_boundaries_are_inclusive() {
    let rpc = RpcConfig::default();
    let plan = GrpcServerPlan::from_config(ServerMode::Full, &rpc, false, false).unwrap();
    assert!(plan.request_within_limit(4_194_304));
    assert!(!plan.request_within_limit(4_194_305));
    assert!(plan.response_within_limit(4_194_304));
    assert!(!plan.response_within_limit(4_194_305));
}
