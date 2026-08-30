use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use prost::Message;
use tokio::sync::Semaphore;
use tonic::Code;
use tonic::transport::{Channel, Endpoint};
use tron_protocol::protocol::tron_zksnark_client::TronZksnarkClient as ProtocolClient;
use tron_protocol::protocol::{ZksnarkRequest, ZksnarkResponse};

pub const DEFAULT_ZKSNARK_ENDPOINT: &str = "http://127.0.0.1:60051";
pub const ZKSNARK_CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
pub const ZKSNARK_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
pub const MAX_ZKSNARK_REQUEST_BYTES: usize = 4 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ZksnarkClientError {
    Unavailable(String),
    Failed(String),
}

impl fmt::Display for ZksnarkClientError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unavailable(message) => write!(formatter, "TronZksnark unavailable: {message}"),
            Self::Failed(message) => write!(formatter, "TronZksnark request failed: {message}"),
        }
    }
}

#[derive(Clone, Debug)]

pub struct TronZksnarkGrpcClient {
    channel: Channel,
    in_flight: Arc<Semaphore>,
}

impl TronZksnarkGrpcClient {
    pub async fn connect_default() -> Result<Self, ZksnarkClientError> {
        Self::connect(DEFAULT_ZKSNARK_ENDPOINT).await
    }

    pub async fn connect(endpoint: impl AsRef<str>) -> Result<Self, ZksnarkClientError> {
        let endpoint = validated_endpoint(endpoint.as_ref())?;
        let channel = endpoint
            .connect()
            .await
            .map_err(|error| ZksnarkClientError::Unavailable(error.to_string()))?;
        Ok(Self {
            channel,
            in_flight: Arc::new(Semaphore::new(1)),
        })
    }

    pub async fn check_zksnark_proof(
        &self,
        request: ZksnarkRequest,
    ) -> Result<ZksnarkResponse, ZksnarkClientError> {
        let encoded_len = request.encoded_len();
        if encoded_len > MAX_ZKSNARK_REQUEST_BYTES {
            return Err(ZksnarkClientError::Failed(format!(
                "encoded request is {encoded_len} bytes; limit is {MAX_ZKSNARK_REQUEST_BYTES}"
            )));
        }
        let _permit = Arc::clone(&self.in_flight).try_acquire_owned().map_err(|_| {
            ZksnarkClientError::Failed("another TronZksnark request is already in flight".to_owned())
        })?;
        let mut client = ProtocolClient::new(self.channel.clone())
            .max_encoding_message_size(MAX_ZKSNARK_REQUEST_BYTES);
        let response = tokio::time::timeout(
            ZKSNARK_REQUEST_TIMEOUT,
            client.check_zksnark_proof(request),
        )
        .await
        .map_err(|_| ZksnarkClientError::Unavailable("request timed out".to_owned()))?
        .map_err(map_status)?;
        Ok(response.into_inner())
    }
}

fn validated_endpoint(value: &str) -> Result<Endpoint, ZksnarkClientError> {
    let endpoint = Endpoint::from_shared(value.to_owned())
        .map_err(|error| ZksnarkClientError::Failed(format!("invalid endpoint: {error}")))?;
    let uri = endpoint.uri();
    if uri.scheme_str() != Some("http") {
        return Err(ZksnarkClientError::Failed(
            "endpoint must use plaintext http on loopback".to_owned(),
        ));
    }
    let host = uri.host().ok_or_else(|| {
        ZksnarkClientError::Failed("endpoint must contain a loopback IP address".to_owned())
    })?;
    let loopback = host.parse::<std::net::IpAddr>().is_ok_and(|address| {
        address == std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
            || address == std::net::IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)
    });
    if !loopback {
        return Err(ZksnarkClientError::Failed(
            "endpoint host must be 127.0.0.1 or ::1".to_owned(),
        ));
    }
    if uri.port_u16().is_none() {
        return Err(ZksnarkClientError::Failed(
            "endpoint must include an explicit port".to_owned(),
        ));
    }
    Ok(endpoint
        .connect_timeout(ZKSNARK_CONNECT_TIMEOUT)
        .timeout(ZKSNARK_REQUEST_TIMEOUT))
}

fn map_status(status: tonic::Status) -> ZksnarkClientError {
    match status.code() {
        Code::Unavailable | Code::DeadlineExceeded => {
            ZksnarkClientError::Unavailable(status.to_string())
        }
        _ => ZksnarkClientError::Failed(status.to_string()),
    }
}
