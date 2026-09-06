use std::{future::Future, io, net::SocketAddr, pin::Pin, task::{Context, Poll}, time::Duration};

use axum::{Extension, Router, error_handling::HandleErrorLayer, http::StatusCode, response::IntoResponse};
use hyper::{Request, body::Incoming, server::conn::http1, service::service_fn};
use hyper_util::{rt::TokioIo, service::TowerToHyperService};
use tokio::{io::{AsyncRead, AsyncWrite, ReadBuf}, net::{TcpListener, TcpStream}, sync::watch, time::{Instant, Sleep}};
use tower::{BoxError, ServiceBuilder, timeout::TimeoutLayer};

use crate::http_filters::{ConnectionCap, HttpControls, process_error};

#[derive(Clone, Debug)]
pub struct HttpServerConfig {
    pub bind: SocketAddr,
    pub request_deadline: Duration,
    pub first_request_timeout: Duration,
    pub connection_idle_timeout: Duration,
    pub connection_max_age: Duration,
    pub controls: HttpControls,
}

impl HttpServerConfig {
    #[must_use]
    pub fn new(bind: SocketAddr) -> Self {
        Self {
            bind,
            request_deadline: Duration::from_secs(30),
            first_request_timeout: Duration::from_secs(10),
            connection_idle_timeout: Duration::from_secs(30),
            connection_max_age: Duration::from_secs(300),
            controls: HttpControls::default(),
        }
    }
}

pub struct HttpServerPlan {
    config: HttpServerConfig,
    router: Router,
    connection_cap: ConnectionCap,
}

impl HttpServerPlan {
    #[must_use]
    pub fn new(config: HttpServerConfig, router: Router) -> Self {
        assert!(!config.first_request_timeout.is_zero(), "first-request timeout must be positive");
        assert!(!config.connection_idle_timeout.is_zero(), "connection idle timeout must be positive");
        assert!(!config.connection_max_age.is_zero(), "connection max age must be positive");
        let connection_cap = ConnectionCap::new(config.controls.max_connections);
        Self { config, router, connection_cap }
    }

    #[must_use]
    pub fn configured_router(&self) -> Router {
        let deadline = self.config.request_deadline;
        self.router.clone().layer(ServiceBuilder::new()
            .layer(HandleErrorLayer::new(|error: BoxError| async move {
                if error.is::<tower::timeout::error::Elapsed>() { (StatusCode::GATEWAY_TIMEOUT, "request deadline exceeded").into_response() }
                else { process_error("java.lang.RuntimeException", &error.to_string()).into_response() }
            }))
            .layer(TimeoutLayer::new(deadline)))
    }

    pub async fn serve(self, mut cancellation: watch::Receiver<bool>) -> io::Result<()> {
        let listener = TcpListener::bind(self.config.bind).await?;
        let router = self.configured_router();
        loop {
            tokio::select! {
                changed = cancellation.changed() => { if changed.is_err() || *cancellation.borrow() { break; } },
                accepted = listener.accept() => {
                    let (stream, remote_addr) = accepted?;
                    let Some(permit) = self.connection_cap.try_acquire() else { drop(stream); continue; };
                    let service = TowerToHyperService::new(router.clone().layer(Extension(remote_addr)));
                    let first_timeout = self.config.first_request_timeout;
                    let idle_timeout = self.config.connection_idle_timeout;
                    let max_age = self.config.connection_max_age;
                    let mut connection_cancellation = cancellation.clone();
                    tokio::spawn(async move {
                        let _permit = permit;
                        let (first_tx, mut first_rx) = watch::channel(false);
                        let service = service_fn(move |request: Request<Incoming>| {
                            let _ = first_tx.send(true);
                            hyper::service::Service::call(&service, request)
                        });
                        let connection = http1::Builder::new().serve_connection(TokioIo::new(TimeoutIo::new(stream, idle_timeout)), service);
                        tokio::pin!(connection);
                        let first_deadline = tokio::time::sleep(first_timeout);
                        let max_deadline = tokio::time::sleep(max_age);
                        tokio::pin!(first_deadline, max_deadline);
                        loop {
                            tokio::select! {
                                _ = &mut connection => break,
                                _ = &mut first_deadline, if !*first_rx.borrow() => break,
                                _ = &mut max_deadline => break,
                                changed = connection_cancellation.changed() => {
                                    if changed.is_err() || *connection_cancellation.borrow() { break; }
                                },
                                changed = first_rx.changed(), if !*first_rx.borrow() => {
                                    if changed.is_err() { break; }
                                },
                            }
                        }
                    });
                }
            }
        }
        Ok(())
    }

    #[must_use]
    pub fn connection_cap(&self) -> ConnectionCap { self.connection_cap.clone() }
}

struct TimeoutIo {
    stream: TcpStream,
    timeout: Duration,
    read_deadline: Pin<Box<Sleep>>,
    write_deadline: Pin<Box<Sleep>>,
}

impl TimeoutIo {
    fn new(stream: TcpStream, timeout: Duration) -> Self {
        Self {
            stream,
            timeout,
            read_deadline: Box::pin(tokio::time::sleep(timeout)),
            write_deadline: Box::pin(tokio::time::sleep(timeout)),
        }
    }
}

impl AsyncRead for TimeoutIo {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buffer: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let before = buffer.filled().len();
        match Pin::new(&mut self.stream).poll_read(cx, buffer) {
            Poll::Ready(Ok(())) => {
                if buffer.filled().len() > before { let timeout = self.timeout; self.read_deadline.as_mut().reset(Instant::now() + timeout); }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(error) => Poll::Ready(error),
            Poll::Pending => match self.read_deadline.as_mut().poll(cx) {
                Poll::Ready(()) => Poll::Ready(Err(io::Error::new(io::ErrorKind::TimedOut, "HTTP connection read idle timeout"))),
                Poll::Pending => Poll::Pending,
            },
        }
    }
}

impl AsyncWrite for TimeoutIo {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, bytes: &[u8]) -> Poll<io::Result<usize>> {
        match Pin::new(&mut self.stream).poll_write(cx, bytes) {
            Poll::Ready(Ok(written)) => {
                if written != 0 { let timeout = self.timeout; self.write_deadline.as_mut().reset(Instant::now() + timeout); }
                Poll::Ready(Ok(written))
            }
            Poll::Ready(error) => Poll::Ready(error),
            Poll::Pending => match self.write_deadline.as_mut().poll(cx) {
                Poll::Ready(()) => Poll::Ready(Err(io::Error::new(io::ErrorKind::TimedOut, "HTTP connection write idle timeout"))),
                Poll::Pending => Poll::Pending,
            },
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> { Pin::new(&mut self.stream).poll_flush(cx) }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> { Pin::new(&mut self.stream).poll_shutdown(cx) }
}

pub async fn with_deadline<T>(duration: Duration, cancellation: impl Future<Output=()>, action: impl Future<Output=T>) -> Result<T, HttpAbort> {
    tokio::select! { result = tokio::time::timeout(duration, action) => result.map_err(|_| HttpAbort::Deadline), _ = cancellation => Err(HttpAbort::Cancelled) }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HttpAbort { Deadline, Cancelled }
