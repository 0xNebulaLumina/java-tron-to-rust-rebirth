use std::{
    collections::BTreeSet,
    future::Future,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    time::Duration,
};
use crate::{
    RpcApiServices, database, extension,
    interceptors::{IngressLayer, RawUnaryCaptureLayer}, monitor, network, solidity, wallet, zksnark,
};
use tron_config::RpcConfig;
use tokio::net::TcpListener;
use tokio_stream::wrappers::TcpListenerStream;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ApiService {
    Wallet,
    WalletSolidity,
    WalletExtension,
    Database,
    Monitor,
    Network,
    TronZksnark,
    Reflection,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServerMode {
    Full,
    /// Dedicated SolidityNode process: primary 50051 listener, no Full/PBFT services.
    StandaloneSolidity,
    Solidity,
    Pbft,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransportLimits {
    pub max_request_bytes: usize,
    pub max_response_bytes: usize,
    pub max_concurrent_streams: u32,
    pub max_header_list_bytes: u32,
    pub initial_connection_window_bytes: u32,
    pub connection_idle: Option<Duration>,
    pub connection_age: Option<Duration>,
    pub request_deadline: Option<Duration>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GrpcServerPlan {
    pub mode: ServerMode,
    pub listen: SocketAddr,
    /// java-tron gRPC uses plaintext unless deployment infrastructure terminates TLS.
    pub plaintext: bool,
    pub services: BTreeSet<ApiService>,
    pub limits: TransportLimits,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ServerConfigError {
    Disabled,
    InvalidPort(i32),
    InvalidLimit(&'static str, i64),
    DuplicatePort(u16),
}
impl std::fmt::Display for ServerConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Disabled => f.write_str("gRPC server is disabled"),
            Self::InvalidPort(port) => write!(f, "invalid gRPC port {port}"),
            Self::InvalidLimit(name, value) => write!(f, "invalid gRPC {name} {value}"),
            Self::DuplicatePort(port) => write!(f, "duplicate gRPC port {port}"),
        }
    }
}
impl std::error::Error for ServerConfigError {}

impl GrpcServerPlan {
    pub fn from_config(
        mode: ServerMode,
        rpc: &RpcConfig,
        wallet_extension: bool,
        metrics: bool,
    ) -> Result<Self, ServerConfigError> {
        let (enabled, port) = match mode {
            ServerMode::Full | ServerMode::StandaloneSolidity => (rpc.enable, rpc.port),
            ServerMode::Solidity => (rpc.solidity_enable, rpc.solidity_port),
            ServerMode::Pbft => (rpc.pbft_enable, rpc.pbft_port),
        };
        if !enabled {
            return Err(ServerConfigError::Disabled);
        }
        let port = checked_port(port)?;
        let positive = |name, value: i64| {
            if value > 0 {
                Ok(value)
            } else {
                Err(ServerConfigError::InvalidLimit(name, value))
            }
        };
        let message = usize::try_from(positive(
            "max message size",
            i64::from(rpc.max_message_size),
        )?)
        .map_err(|_| {
            ServerConfigError::InvalidLimit("max message size", i64::from(rpc.max_message_size))
        })?;
        let streams = u32::try_from(positive(
            "max concurrent calls",
            i64::from(rpc.max_concurrent_calls_per_connection),
        )?)
        .map_err(|_| {
            ServerConfigError::InvalidLimit(
                "max concurrent calls",
                i64::from(rpc.max_concurrent_calls_per_connection),
            )
        })?;
        let headers = u32::try_from(positive(
            "max header list size",
            i64::from(rpc.max_header_list_size),
        )?)
        .map_err(|_| {
            ServerConfigError::InvalidLimit(
                "max header list size",
                i64::from(rpc.max_header_list_size),
            )
        })?;
        let window = u32::try_from(positive(
            "flow control window",
            i64::from(rpc.flow_control_window),
        )?)
        .map_err(|_| {
            ServerConfigError::InvalidLimit(
                "flow control window",
                i64::from(rpc.flow_control_window),
            )
        })?;
        let mut services = BTreeSet::from([ApiService::Database]);
        match mode {
            ServerMode::Full => {
                services.extend([
                    ApiService::Wallet,
                    ApiService::Network,
                    ApiService::TronZksnark,
                ]);
                if wallet_extension {
                    services.insert(ApiService::WalletExtension);
                }
                if metrics {
                    services.insert(ApiService::Monitor);
                }
            }
            ServerMode::StandaloneSolidity => {
                services.insert(ApiService::WalletSolidity);
                if wallet_extension {
                    services.insert(ApiService::WalletExtension);
                }
                if metrics {
                    services.insert(ApiService::Monitor);
                }
            }
            ServerMode::Solidity | ServerMode::Pbft => {
                services.insert(ApiService::WalletSolidity);
            }
        }
        if rpc.reflection_service {
            services.insert(ApiService::Reflection);
        }
        Ok(Self {
            mode,
            listen: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port),
            plaintext: true,
            services,
            limits: TransportLimits {
                max_request_bytes: message,
                max_response_bytes: message,
                max_concurrent_streams: streams,
                max_header_list_bytes: headers,
                initial_connection_window_bytes: window,
                connection_idle: duration_or_none(
                    rpc.max_connection_idle_in_millis,
                    "max connection idle",
                )?,
                connection_age: duration_or_none(
                    rpc.max_connection_age_in_millis,
                    "max connection age",
                )?,
                request_deadline: Some(Duration::from_secs(30)),
            },
        })
    }

    #[must_use]
    pub fn with_request_deadline(mut self, deadline: Option<Duration>) -> Self {
        self.limits.request_deadline = deadline;
        self
    }

    /// Applies transport controls. Kept private so production callers cannot assemble an
    /// uncontrolled tonic server; `serve_grpc` is the sole production entry point.
    fn tonic_builder(&self) -> tonic::transport::Server {
        let mut builder = tonic::transport::Server::builder()
            .max_concurrent_streams(Some(self.limits.max_concurrent_streams))
            .initial_stream_window_size(Some(self.limits.initial_connection_window_bytes))
            .initial_connection_window_size(Some(self.limits.initial_connection_window_bytes))
            .http2_max_header_list_size(Some(self.limits.max_header_list_bytes));
        if let Some(deadline) = self.limits.request_deadline {
            builder = builder.timeout(deadline);
        }
        if let Some(idle) = self.limits.connection_idle {
            builder = builder
                .tcp_keepalive(Some(idle))
                .http2_keepalive_interval(Some(idle))
                .http2_keepalive_timeout(Some(idle));
        }
        if let Some(age) = self.limits.connection_age {
            builder = builder.max_connection_age(age);
        }
        builder
    }

    #[must_use]
    pub fn request_within_limit(&self, encoded_len: usize) -> bool {
        encoded_len <= self.limits.max_request_bytes
    }
    #[must_use]
    pub fn response_within_limit(&self, encoded_len: usize) -> bool {
        encoded_len <= self.limits.max_response_bytes
    }
}
/// Binds and gracefully drains a production gRPC server with mandatory ingress controls.
pub async fn serve_grpc<F>(plan: GrpcServerPlan, controls: IngressLayer, services: RpcApiServices, shutdown: F) -> std::io::Result<()>
where F: Future<Output = ()> + Send + 'static {
    let listener=TcpListener::bind(plan.listen).await?;
    serve_grpc_with_listener(plan,listener,controls,services,shutdown).await
}

/// Starts a gRPC plan from an already-bound listener. Binding can therefore be completed
/// transactionally across every API surface before runtime readiness is reported.
pub async fn serve_grpc_with_listener<F>(
    plan: GrpcServerPlan,
    listener: TcpListener,
    controls: IngressLayer,
    services: RpcApiServices,
    shutdown: F,
) -> std::io::Result<()>
where
    F: Future<Output = ()> + Send + 'static,
{
    let actual=listener.local_addr()?;if actual.ip()!=plan.listen.ip() || (plan.listen.port()!=0 && actual.port()!=plan.listen.port()){return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput,"prebound gRPC listener does not match server plan"));}
    let request_limit = plan.limits.max_request_bytes;
    let response_limit = plan.limits.max_response_bytes;
    let configured = |service| plan.services.contains(&service);

    let database = database::database_server::DatabaseServer::new(services.clone())
        .max_decoding_message_size(request_limit)
        .max_encoding_message_size(response_limit);
    let reflection = configured(ApiService::Reflection).then(|| {
        tonic_reflection::server::Builder::configure()
            .register_encoded_file_descriptor_set(tron_protocol::FILE_DESCRIPTOR_SET)
            .build_v1()
            .expect("the embedded protocol descriptor is build-validated")
    });
    let mut builder = plan.tonic_builder()
        .layer(controls)
        .layer(RawUnaryCaptureLayer::new(request_limit));

    match plan.mode {
        ServerMode::Full => {
            let wallet = wallet::wallet_server::WalletServer::new(services.clone())
                .max_decoding_message_size(request_limit)
                .max_encoding_message_size(response_limit);
            let extension = configured(ApiService::WalletExtension).then(||
                extension::wallet_extension_server::WalletExtensionServer::new(services.clone())
                    .max_decoding_message_size(request_limit)
                    .max_encoding_message_size(response_limit));
            let monitor = configured(ApiService::Monitor).then(||
                monitor::monitor_server::MonitorServer::new(services.clone())
                    .max_decoding_message_size(request_limit)
                    .max_encoding_message_size(response_limit));
            let network = network::network_server::NetworkServer::new(services.clone())
                .max_decoding_message_size(request_limit)
                .max_encoding_message_size(response_limit);
            let zksnark = zksnark::tron_zksnark_server::TronZksnarkServer::new(services)
                .max_decoding_message_size(request_limit)
                .max_encoding_message_size(response_limit);
            builder
                .add_service(wallet)
                .add_optional_service(extension)
                .add_service(database)
                .add_optional_service(monitor)
                .add_service(network)
                .add_service(zksnark)
                .add_optional_service(reflection)
                .serve_with_incoming_shutdown(TcpListenerStream::new(listener), shutdown)
                .await.map_err(std::io::Error::other)
        }
        ServerMode::StandaloneSolidity => {
            let solidity = solidity::wallet_solidity_server::WalletSolidityServer::new(services.clone())
                .max_decoding_message_size(request_limit)
                .max_encoding_message_size(response_limit);
            let extension = configured(ApiService::WalletExtension).then(||
                extension::wallet_extension_server::WalletExtensionServer::new(services.clone())
                    .max_decoding_message_size(request_limit)
                    .max_encoding_message_size(response_limit));
            let monitor = configured(ApiService::Monitor).then(||
                monitor::monitor_server::MonitorServer::new(services)
                    .max_decoding_message_size(request_limit)
                    .max_encoding_message_size(response_limit));
            builder
                .add_service(solidity)
                .add_service(database)
                .add_optional_service(extension)
                .add_optional_service(monitor)
                .add_optional_service(reflection)
                .serve_with_incoming_shutdown(TcpListenerStream::new(listener), shutdown)
                .await.map_err(std::io::Error::other)
        }
        ServerMode::Solidity | ServerMode::Pbft => {
            let solidity = solidity::wallet_solidity_server::WalletSolidityServer::new(services)
                .max_decoding_message_size(request_limit)
                .max_encoding_message_size(response_limit);
            builder
                .add_service(solidity)
                .add_service(database)
                .add_optional_service(reflection)
                .serve_with_incoming_shutdown(TcpListenerStream::new(listener), shutdown)
                .await.map_err(std::io::Error::other)
        }
    }
}

pub fn validate_unique_enabled_ports(rpc: &RpcConfig) -> Result<(), ServerConfigError> {
    let enabled = [
        (rpc.enable, rpc.port),
        (rpc.solidity_enable, rpc.solidity_port),
        (rpc.pbft_enable, rpc.pbft_port),
    ];
    let mut ports = BTreeSet::new();
    for (on, port) in enabled {
        if on {
            let port = checked_port(port)?;
            if !ports.insert(port) {
                return Err(ServerConfigError::DuplicatePort(port));
            }
        }
    }
    Ok(())
}
fn checked_port(port: i32) -> Result<u16, ServerConfigError> {
    u16::try_from(port)
        .ok()
        .filter(|port| *port != 0)
        .ok_or(ServerConfigError::InvalidPort(port))
}
fn duration_or_none(value: i64, name: &'static str) -> Result<Option<Duration>, ServerConfigError> {
    if value < 0 {
        Err(ServerConfigError::InvalidLimit(name, value))
    } else if value == 0 {
        Ok(None)
    } else {
        Ok(Some(Duration::from_millis(
            u64::try_from(value).expect("positive i64 fits u64"),
        )))
    }
}
