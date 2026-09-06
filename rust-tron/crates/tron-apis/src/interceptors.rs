use std::{
    collections::BTreeSet,
    future::Future,
    io::Read,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::{Duration, Instant},
};
use bytes::Bytes;
use flate2::read::GzDecoder;
use http_body_util::{BodyExt, Full, Limited};
use tonic::{Code, Status, body::BoxBody, codegen::http};
use tower::{Layer, Service};

use crate::rate_limit::ApiRateLimiter;

pub const DISABLED_API_MESSAGE: &str = "this API is unavailable due to config";
pub const LITE_API_MESSAGE: &str = "this API is closed because this node is a lite fullnode";

pub const LITE_FILTER_METHODS: &[&str] = &[
    "protocol.Wallet/GetBlockById",
    "protocol.Wallet/GetBlockByLatestNum",
    "protocol.Wallet/GetBlockByLatestNum2",
    "protocol.Wallet/GetBlockByLimitNext",
    "protocol.Wallet/GetBlockByLimitNext2",
    "protocol.Wallet/GetBlockByNum",
    "protocol.Wallet/GetBlockByNum2",
    "protocol.Wallet/GetMerkleTreeVoucherInfo",
    "protocol.Wallet/GetTransactionById",
    "protocol.Wallet/GetTransactionCountByBlockNum",
    "protocol.Wallet/GetTransactionInfoById",
    "protocol.Wallet/IsSpend",
    "protocol.Wallet/ScanAndMarkNoteByIvk",
    "protocol.Wallet/ScanNoteByIvk",
    "protocol.Wallet/ScanNoteByOvk",
    "protocol.Wallet/TotalTransaction",
    "protocol.Wallet/GetMarketOrderByAccount",
    "protocol.Wallet/GetMarketOrderById",
    "protocol.Wallet/GetMarketPriceByPair",
    "protocol.Wallet/GetMarketOrderListByPair",
    "protocol.Wallet/GetMarketPairList",
    "protocol.Wallet/ScanShieldedTRC20NotesByIvk",
    "protocol.Wallet/ScanShieldedTRC20NotesByOvk",
    "protocol.Wallet/IsShieldedTRC20ContractNoteSpent",
    "protocol.WalletSolidity/GetBlockByNum",
    "protocol.WalletSolidity/GetBlockByNum2",
    "protocol.WalletSolidity/GetMerkleTreeVoucherInfo",
    "protocol.WalletSolidity/GetTransactionById",
    "protocol.WalletSolidity/GetTransactionCountByBlockNum",
    "protocol.WalletSolidity/GetTransactionInfoById",
    "protocol.WalletSolidity/IsSpend",
    "protocol.WalletSolidity/ScanAndMarkNoteByIvk",
    "protocol.WalletSolidity/ScanNoteByIvk",
    "protocol.WalletSolidity/ScanNoteByOvk",
    "protocol.WalletSolidity/GetMarketOrderByAccount",
    "protocol.WalletSolidity/GetMarketOrderById",
    "protocol.WalletSolidity/GetMarketPriceByPair",
    "protocol.WalletSolidity/GetMarketOrderListByPair",
    "protocol.WalletSolidity/GetMarketPairList",
    "protocol.WalletSolidity/ScanShieldedTRC20NotesByIvk",
    "protocol.WalletSolidity/ScanShieldedTRC20NotesByOvk",
    "protocol.WalletSolidity/IsShieldedTRC20ContractNoteSpent",
    "protocol.Database/GetBlockByNum",
];

#[derive(Clone, Debug)]
pub struct ApiInterceptors {
    disabled_methods: BTreeSet<String>,
    lite_node: bool,
    open_history_query_when_lite: bool,
}

impl ApiInterceptors {
    pub fn new(
        disabled_methods: impl IntoIterator<Item = String>,
        lite_node: bool,
        open_history_query_when_lite: bool,
    ) -> Self {
        Self {
            disabled_methods: disabled_methods
                .into_iter()
                .map(|method| method.to_lowercase())
                .collect(),
            lite_node,
            open_history_query_when_lite,
        }
    }

    /// Applies Java's interceptor order after rate limiting: disabled API, then lite-node history.
    pub fn check(&self, full_method_name: &str) -> Result<(), Status> {
        let method = full_method_name
            .split_once('/')
            .map_or(full_method_name, |(_, method)| method);
        if self.disabled_methods.contains(&method.to_lowercase()) {
            return Err(Status::new(Code::Unavailable, DISABLED_API_MESSAGE));
        }
        if self.lite_node
            && !self.open_history_query_when_lite
            && LITE_FILTER_METHODS.contains(&full_method_name)
        {
            return Err(Status::new(Code::Unavailable, LITE_API_MESSAGE));
        }
        Ok(())
    }

    /// Tonic interceptors are installed per generated service/method, so bind the canonical
    /// descriptor name during registration rather than trusting caller metadata.
    #[must_use]
    pub fn tonic_interceptor_for(
        self,
        full_method_name: impl Into<String>,
    ) -> impl FnMut(tonic::Request<()>) -> Result<tonic::Request<()>, Status> + Clone {
        let full_method_name = full_method_name.into();
        move |request| {
            self.check(&full_method_name)?;
            Ok(request)
        }
    }
}

/// Exact uncompressed protobuf bytes captured before tonic/prost decoding.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreservedRawGrpcMessage(pub Bytes);

/// Mandatory production layer for bounded unary gRPC envelope validation and wire preservation.
#[derive(Clone, Copy, Debug)]
pub struct RawUnaryCaptureLayer {
    max_request_bytes: usize,
}

impl RawUnaryCaptureLayer {
    #[must_use]
    pub fn new(max_request_bytes: usize) -> Self { Self { max_request_bytes } }
}

impl<S> Layer<S> for RawUnaryCaptureLayer {
    type Service = RawUnaryCaptureService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        RawUnaryCaptureService { inner, max_request_bytes: self.max_request_bytes }
    }
}

#[derive(Clone, Debug)]
pub struct RawUnaryCaptureService<S> {
    inner: S,
    max_request_bytes: usize,
}

impl<S> Service<http::Request<BoxBody>> for RawUnaryCaptureService<S>
where
    S: Service<http::Request<BoxBody>, Response = http::Response<BoxBody>> + Clone + Send + 'static,
    S::Future: Send + 'static,
    S::Error: Send + 'static,
{
    type Response = http::Response<BoxBody>;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, request: http::Request<BoxBody>) -> Self::Future {
        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);
        if request.uri().path() != "/protocol.Wallet/BroadcastTransaction" {
            return Box::pin(async move { inner.call(request).await });
        }
        let max_request_bytes = self.max_request_bytes;
        Box::pin(async move {
            let encoding = request.headers().get("grpc-encoding")
                .and_then(|value| value.to_str().ok())
                .unwrap_or("identity")
                .trim()
                .to_ascii_lowercase();
            let (mut parts, body) = request.into_parts();
            let collected = match Limited::new(body, max_request_bytes.saturating_add(5)).collect().await {
                Ok(body) => body.to_bytes(),
                Err(_) => return Ok(Status::resource_exhausted("gRPC request exceeds configured message limit").into_http()),
            };
            let raw = match decode_unary_grpc_message(&collected, &encoding, max_request_bytes) {
                Ok(raw) => raw,
                Err(status) => return Ok(status.into_http()),
            };
            parts.extensions.insert(PreservedRawGrpcMessage(raw.clone()));
            parts.headers.remove("grpc-encoding");
            let mut envelope = Vec::with_capacity(raw.len() + 5);
            envelope.push(0);
            envelope.extend_from_slice(&(raw.len() as u32).to_be_bytes());
            envelope.extend_from_slice(&raw);
            let body = Full::new(Bytes::from(envelope)).map_err(|never| match never {}).boxed_unsync();
            inner.call(http::Request::from_parts(parts, body)).await
        })
    }
}

fn decode_unary_grpc_message(envelope: &[u8], encoding: &str, limit: usize) -> Result<Bytes, Status> {
    if envelope.len() < 5 {
        return Err(Status::invalid_argument("malformed gRPC unary envelope"));
    }
    let compressed = envelope[0];
    if compressed > 1 {
        return Err(Status::invalid_argument("invalid gRPC compression flag"));
    }
    let declared = u32::from_be_bytes(envelope[1..5].try_into().expect("five-byte envelope")) as usize;
    if envelope.len() - 5 != declared {
        return Err(Status::invalid_argument("gRPC unary envelope length mismatch"));
    }
    if declared > limit {
        return Err(Status::resource_exhausted("gRPC request exceeds configured message limit"));
    }
    let message = &envelope[5..];
    if compressed == 0 {
        return Ok(Bytes::copy_from_slice(message));
    }
    if encoding != "gzip" {
        return Err(Status::unimplemented("unsupported gRPC request compression"));
    }
    let mut take = GzDecoder::new(message).take(limit.saturating_add(1) as u64);
    let mut decoded = Vec::new();
    take.read_to_end(&mut decoded).map_err(|_| Status::invalid_argument("invalid compressed gRPC request"))?;
    if decoded.len() > limit {
        return Err(Status::resource_exhausted("decompressed gRPC request exceeds configured message limit"));
    }
    Ok(Bytes::from(decoded))
}

#[cfg(test)]
mod raw_capture_tests {
    use super::decode_unary_grpc_message;
    use flate2::{Compression, write::GzEncoder};
    use std::io::Write;

    fn envelope(flag: u8, message: &[u8]) -> Vec<u8> {
        let mut value = vec![flag];
        value.extend_from_slice(&(message.len() as u32).to_be_bytes());
        value.extend_from_slice(message);
        value
    }

    #[test]
    fn validates_exact_unary_envelope() {
        assert_eq!(decode_unary_grpc_message(&envelope(0, b"wire"), "identity", 4).unwrap(), &b"wire"[..]);
        assert!(decode_unary_grpc_message(&[0, 0, 0, 0], "identity", 4).is_err());
        assert!(decode_unary_grpc_message(&[0, 0, 0, 0, 2, 1], "identity", 4).is_err());
        assert!(decode_unary_grpc_message(&envelope(2, b""), "identity", 4).is_err());
        assert_eq!(decode_unary_grpc_message(&envelope(0, b"12345"), "identity", 4).unwrap_err().code(), tonic::Code::ResourceExhausted);
    }

    #[test]
    fn gzip_is_bounded_after_decompression() {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(b"wire").unwrap();
        let compressed = encoder.finish().unwrap();
        assert_eq!(decode_unary_grpc_message(&envelope(1, &compressed), "gzip", compressed.len()).unwrap(), &b"wire"[..]);

        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&[0; 128]).unwrap();
        let compressed = encoder.finish().unwrap();
        assert_eq!(decode_unary_grpc_message(&envelope(1, &compressed), "gzip", 64).unwrap_err().code(), tonic::Code::ResourceExhausted);
        assert_eq!(decode_unary_grpc_message(&envelope(1, &compressed), "br", 256).unwrap_err().code(), tonic::Code::Unimplemented);
    }
}

/// HTTP/2 ingress controls run before tonic dispatch, so rejected calls never reach handlers.
#[derive(Clone, Debug)]
pub struct IngressLayer {
    interceptors: ApiInterceptors,
    limiter: Arc<ApiRateLimiter>,
    request_deadline: Option<Duration>,
}

impl IngressLayer {
    #[must_use]
    pub fn new(
        interceptors: ApiInterceptors,
        limiter: Arc<ApiRateLimiter>,
        request_deadline: Option<Duration>,
    ) -> Self {
        Self { interceptors, limiter, request_deadline }
    }
}

impl<S> Layer<S> for IngressLayer {
    type Service = IngressService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        IngressService { inner, controls: self.clone() }
    }
}

#[derive(Clone, Debug)]
pub struct IngressService<S> {
    inner: S,
    controls: IngressLayer,
}

impl<S, B> Service<http::Request<B>> for IngressService<S>
where
    S: Service<http::Request<B>, Response = http::Response<BoxBody>> + Clone + Send + 'static,
    S::Future: Send + 'static,
    S::Error: Send + 'static,
    B: Send + 'static,
{
    type Response = http::Response<BoxBody>;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, request: http::Request<B>) -> Self::Future {
        let method = request.uri().path().trim_start_matches('/').to_owned();
        let remote_ip = request
            .extensions()
            .get::<tonic::transport::server::TcpConnectInfo>()
            .and_then(tonic::transport::server::TcpConnectInfo::remote_addr)
            .map(|address| address.ip().to_string());
        let deadline = self.controls.request_deadline
            .and_then(|duration| Instant::now().checked_add(duration));
        let controls = self.controls.clone();
        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);
        Box::pin(async move {
            let permit = match controls.limiter.acquire(&method, remote_ip.as_deref(), deadline).await
                .and_then(|permit| controls.interceptors.check(&method).map(|()| permit))
            {
                Ok(permit) => permit,
                Err(status) => return Ok(status.into_http()),
            };
            let response = inner.call(request).await;
            drop(permit);
            response
        })
    }
}
