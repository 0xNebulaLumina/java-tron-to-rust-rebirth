use std::net::SocketAddr;
use std::sync::Arc;

use tokio::net::TcpListener;
use tokio::sync::{Mutex, Notify, oneshot};
use tokio_stream::wrappers::TcpListenerStream;
use tonic::{Request, Response, Status, transport::Server};
use tron_protocol::protocol::tron_zksnark_server::{TronZksnark, TronZksnarkServer};
use tron_protocol::protocol::{Transaction, ZksnarkRequest, ZksnarkResponse, zksnark_response};
use tron_shielded::{MAX_ZKSNARK_REQUEST_BYTES, TronZksnarkGrpcClient, ZksnarkClientError};

#[derive(Clone)]
struct RecordingService {
    request: Arc<Mutex<Option<ZksnarkRequest>>>,
    code: i32,
    started: Option<Arc<Notify>>,
    release: Option<Arc<Notify>>,
}

#[tonic::async_trait]
impl TronZksnark for RecordingService {
    async fn check_zksnark_proof(
        &self,
        request: Request<ZksnarkRequest>,
    ) -> Result<Response<ZksnarkResponse>, Status> {
        *self.request.lock().await = Some(request.into_inner());
        if let Some(started) = &self.started {
            started.notify_one();
        }
        if let Some(release) = &self.release {
            release.notified().await;
        }
        Ok(Response::new(ZksnarkResponse { code: self.code }))
    }
}

async fn local_server(
    started: Option<Arc<Notify>>,
    release: Option<Arc<Notify>>,
) -> (
    SocketAddr,
    Arc<Mutex<Option<ZksnarkRequest>>>,
    oneshot::Sender<()>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let request = Arc::new(Mutex::new(None));
    let service = RecordingService {
        request: Arc::clone(&request),
        code: zksnark_response::Code::Success as i32,
        started,
        release,
    };
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    tokio::spawn(async move {
        Server::builder()
            .add_service(TronZksnarkServer::new(service))
            .serve_with_incoming_shutdown(TcpListenerStream::new(listener), async {
                let _ = shutdown_rx.await;
            })
            .await
            .unwrap();
    });
    (address, request, shutdown_tx)
}

fn canonical_request() -> ZksnarkRequest {
    ZksnarkRequest {
        transaction: Some(Transaction::default()),
        sighash: hex::decode("ded9c2181fd7ea468a7a7b1475defe90bb0fc0ca8d0f2096b0617465cea6568c")
            .unwrap(),
        value_balance: 10_000,
        tx_id: "deterministic-local-boundary".to_owned(),
    }
}

#[tokio::test]
async fn check_zksnark_proof_preserves_the_local_grpc_boundary() {
    let (address, recorded, shutdown) = local_server(None, None).await;
    let client = TronZksnarkGrpcClient::connect(format!("http://{address}"))
        .await
        .unwrap();
    let request = canonical_request();

    let response = client.check_zksnark_proof(request.clone()).await.unwrap();

    assert_eq!(response.code, zksnark_response::Code::Success as i32);
    assert_eq!(recorded.lock().await.as_ref(), Some(&request));
    let _ = shutdown.send(());
}

#[tokio::test]
async fn check_zksnark_proof_reports_an_unavailable_endpoint() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);

    let error = TronZksnarkGrpcClient::connect(format!("http://{address}"))
        .await
        .expect_err("a released localhost endpoint must be unavailable");
    assert!(matches!(error, ZksnarkClientError::Unavailable(_)));
}

#[tokio::test]
async fn client_rejects_non_loopback_endpoints() {
    let error = TronZksnarkGrpcClient::connect("http://192.0.2.1:60051")
        .await
        .expect_err("non-loopback endpoints must be rejected before connecting");
    assert!(matches!(error, ZksnarkClientError::Failed(_)));
}

#[tokio::test]
async fn client_rejects_oversize_requests_before_transport() {
    let (address, recorded, shutdown) = local_server(None, None).await;
    let client = TronZksnarkGrpcClient::connect(format!("http://{address}"))
        .await
        .unwrap();
    let mut request = canonical_request();
    request.tx_id = "x".repeat(MAX_ZKSNARK_REQUEST_BYTES);

    let error = client.check_zksnark_proof(request).await.unwrap_err();
    assert!(matches!(error, ZksnarkClientError::Failed(_)));
    assert!(recorded.lock().await.is_none());
    let _ = shutdown.send(());
}

#[tokio::test]
async fn client_applies_one_inflight_backpressure() {
    let started = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let (address, _, shutdown) =
        local_server(Some(Arc::clone(&started)), Some(Arc::clone(&release))).await;
    let client = TronZksnarkGrpcClient::connect(format!("http://{address}"))
        .await
        .unwrap();
    let first_client = client.clone();
    let first = tokio::spawn(async move {
        first_client.check_zksnark_proof(canonical_request()).await
    });
    started.notified().await;

    let error = client
        .check_zksnark_proof(canonical_request())
        .await
        .expect_err("a second concurrent request must receive backpressure");
    assert!(matches!(error, ZksnarkClientError::Failed(_)));

    release.notify_one();
    assert!(first.await.unwrap().is_ok());
    let _ = shutdown.send(());
}
