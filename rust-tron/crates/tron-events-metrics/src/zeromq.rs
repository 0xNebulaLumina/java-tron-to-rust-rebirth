use std::time::Duration;

use bytes::Bytes;
use tokio::{sync::{mpsc::{self, error::TrySendError, Sender}, watch}, task::JoinHandle};
use tokio_util::sync::CancellationToken;
use zeromq::{PubSocket, Socket, SocketSend, ZmqMessage};

pub const DEFAULT_BIND_PORT: u16 = 5555;
pub const DEFAULT_SEND_HWM: usize = 1000;
pub const SEND_TIMEOUT: Duration = Duration::from_secs(2);
pub const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(3);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ZeroMqConfig { pub bind_port: u16, pub send_hwm: usize }
impl Default for ZeroMqConfig { fn default() -> Self { Self { bind_port: DEFAULT_BIND_PORT, send_hwm: DEFAULT_SEND_HWM } } }
impl ZeroMqConfig {
    pub fn normalized(self) -> Self { Self { bind_port: if self.bind_port == 0 { DEFAULT_BIND_PORT } else { self.bind_port }, send_hwm: if self.send_hwm == 0 { DEFAULT_SEND_HWM } else { self.send_hwm } } }
    pub fn bind_address(self) -> String { format!("tcp://*:{}", self.normalized().bind_port) }
}

#[derive(Debug, thiserror::Error)]
pub enum ZeroMqError {
    #[error("ZeroMQ bind failed: {0}")] Bind(String),
    #[error("ZeroMQ publisher is shut down")] Shutdown,
    #[error("ZeroMQ send queue is full (HWM {0})")] Full(usize),
    #[error("ZeroMQ publisher worker failed: {0}")] Worker(String),
    #[error("ZeroMQ publisher operation timed out")]
    Timeout,
}

enum WorkerCommand { Publish { topic: String, json: String } }

pub struct ZeroMqPublisher {
    tx: Sender<WorkerCommand>,
    cancel: CancellationToken,
    outcome: watch::Receiver<Option<Result<(), String>>>,
    join: Option<JoinHandle<Result<(), String>>>,
    config: ZeroMqConfig,
}

impl ZeroMqPublisher {
    pub async fn bind(config: ZeroMqConfig) -> Result<Self, ZeroMqError> {
        let config = config.normalized();
        let (tx, mut rx) = mpsc::channel(config.send_hwm);
        let cancel = CancellationToken::new();
        let worker_cancel = cancel.clone();
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
        let (outcome_tx, outcome) = watch::channel(None);
        let join = tokio::spawn(async move {
            let mut socket = PubSocket::new();
            let address = format!("tcp://0.0.0.0:{}", config.bind_port);
            let bind = tokio::time::timeout(SEND_TIMEOUT, socket.bind(&address)).await;
            match bind {
                Ok(Ok(_)) => { let _ = ready_tx.send(Ok(())); }
                Ok(Err(error)) => { let message = error.to_string(); let _ = ready_tx.send(Err(message.clone())); let _ = outcome_tx.send(Some(Err(message.clone()))); return Err(message); }
                Err(_) => { let message = "bind timed out".to_owned(); let _ = ready_tx.send(Err(message.clone())); let _ = outcome_tx.send(Some(Err(message.clone()))); return Err(message); }
            }
            let result = loop {
                tokio::select! {
                    biased;
                    () = worker_cancel.cancelled() => break Ok(()),
                    command = rx.recv() => match command {
                        Some(WorkerCommand::Publish { topic, json }) => {
                            let message = ZmqMessage::try_from(vec![Bytes::from(topic), Bytes::from(json)]).expect("two frames");
                            match tokio::time::timeout(SEND_TIMEOUT, socket.send(message)).await {
                                Ok(Ok(())) => {}
                                Ok(Err(error)) => break Err(error.to_string()),
                                Err(_) => break Err("send timed out".to_owned()),
                            }
                        }
                        None => break Ok(()),
                    }
                }
            };
            let _ = outcome_tx.send(Some(result.clone()));
            result
        });
        match tokio::time::timeout(SEND_TIMEOUT, ready_rx).await {
            Ok(Ok(Ok(()))) => Ok(Self { tx, cancel, outcome, join: Some(join), config }),
            Ok(Ok(Err(error))) => { let _ = join.await; Err(ZeroMqError::Bind(error)) }
            Ok(Err(_)) => { let result = join.await; Err(ZeroMqError::Worker(join_error(result))) }
            Err(_) => { cancel.cancel(); join.abort(); let _ = join.await; Err(ZeroMqError::Timeout) }
        }
    }

    pub fn publish(&self, topic: impl Into<String>, json: impl Into<String>) -> Result<(), ZeroMqError> {
        if let Some(result) = self.outcome.borrow().as_ref() {
            return match result { Ok(()) => Err(ZeroMqError::Shutdown), Err(error) => Err(ZeroMqError::Worker(error.clone())) };
        }
        match self.tx.try_send(WorkerCommand::Publish { topic: topic.into(), json: json.into() }) {
            Ok(()) => Ok(()),
            Err(TrySendError::Full(_)) => Err(ZeroMqError::Full(self.config.send_hwm)),
            Err(TrySendError::Closed(_)) => Err(ZeroMqError::Shutdown),
        }
    }

    pub fn publish_trigger(&self, event: &crate::events::EventTrigger) -> Result<(), ZeroMqError> {
        let json = event.to_json().map_err(|error| ZeroMqError::Worker(error.to_string()))?;
        self.publish(event.topic(), json)
    }

    pub fn config(&self) -> ZeroMqConfig { self.config }

    pub async fn shutdown(&mut self) -> Result<(), ZeroMqError> {
        let Some(mut join) = self.join.take() else { return Ok(()); };
        self.cancel.cancel();
        match tokio::time::timeout(SHUTDOWN_TIMEOUT, &mut join).await {
            Ok(Ok(Ok(()))) => Ok(()),
            Ok(Ok(Err(error))) => Err(ZeroMqError::Worker(error)),
            Ok(Err(error)) => Err(ZeroMqError::Worker(error.to_string())),
            Err(_) => { join.abort(); let _ = join.await; Err(ZeroMqError::Timeout) }
        }
    }
}

impl Drop for ZeroMqPublisher {
    fn drop(&mut self) {
        self.cancel.cancel();
        if let Some(join) = self.join.take() { join.abort(); }
    }
}

fn join_error(result: Result<Result<(), String>, tokio::task::JoinError>) -> String {
    match result { Ok(Ok(())) => "worker exited during bind".to_owned(), Ok(Err(error)) => error, Err(error) => error.to_string() }
}
