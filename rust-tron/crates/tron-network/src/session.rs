use bytes::Bytes;
use prost::Message;
use std::{io, net::SocketAddr, ops::Deref, sync::{Arc, Mutex}, time::{Duration, Instant, SystemTime, UNIX_EPOCH}};
use tokio::{io::{AsyncRead, AsyncWrite}, sync::{mpsc, OwnedSemaphorePermit, Semaphore}, time::{interval, timeout, MissedTickBehavior}};
use tokio_util::sync::CancellationToken;

use crate::{
    compression::{self, CompressMessage, CompressType},
    connection::{ConnectionPool, Direction, Peer, PoolConfig},
    handshake::{Admission, AdmissionConfig, Control, DisconnectReason, HelloMessage, KeepAliveMessage, P2pDisconnectMessage, StatusMessage},
    tcp::FramedIo,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionState { New, HelloSent, HelloReceived, Negotiating, Connected, Draining, Closed }

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SessionEvent { State(SessionState), Message(Vec<u8>), Ping(i64), Pong(i64), Disconnected(DisconnectReason) }

impl SessionEvent {
    /// Parses an opaque connected-session payload at the positive application boundary.
    pub fn app_message(&self) -> Result<Option<crate::app_message::AppMessage>, crate::app_message::AppMessageError> {
        match self {
            Self::Message(frame) => crate::app_message::AppMessage::parse(frame.clone()).map(Some),
            _ => Ok(None),
        }
    }
}

#[derive(Clone)]
pub struct SessionEventSender {
    tx: mpsc::Sender<QueuedSessionEvent>,
    bytes: Arc<Semaphore>,
    byte_limit: usize,
    enqueue_timeout: Duration,
}

pub struct SessionEventReceiver { rx: mpsc::Receiver<QueuedSessionEvent> }

pub struct QueuedSessionEvent { event: SessionEvent, _bytes: Option<OwnedSemaphorePermit> }

impl QueuedSessionEvent {
    pub fn into_event(self) -> SessionEvent { self.event }
}
impl Deref for QueuedSessionEvent { type Target = SessionEvent; fn deref(&self) -> &Self::Target { &self.event } }

impl SessionEventReceiver {
    pub async fn recv(&mut self) -> Option<QueuedSessionEvent> { self.rx.recv().await }
    pub fn try_recv(&mut self) -> Result<QueuedSessionEvent, mpsc::error::TryRecvError> { self.rx.try_recv() }
}

pub fn session_event_channel(max_events: usize, max_payload_bytes: usize, enqueue_timeout: Duration) -> (SessionEventSender, SessionEventReceiver) {
    let (tx, rx) = mpsc::channel(max_events.max(1));
    (SessionEventSender { tx, bytes: Arc::new(Semaphore::new(max_payload_bytes.max(1))), byte_limit: max_payload_bytes.max(1), enqueue_timeout }, SessionEventReceiver { rx })
}

#[derive(Debug, thiserror::Error)]
#[error("session event queue unavailable")]
struct EventQueueError;

impl SessionEventSender {
    async fn send(&self, event: SessionEvent) -> Result<(), EventQueueError> {
        let bytes = match &event { SessionEvent::Message(payload) => payload.len(), _ => 0 };
        if bytes > self.byte_limit || bytes > u32::MAX as usize { return Err(EventQueueError); }
        timeout(self.enqueue_timeout, async {
            let permit = if bytes == 0 { None } else {
                Some(self.bytes.clone().acquire_many_owned(bytes as u32).await.map_err(|_| EventQueueError)?)
            };
            self.tx.send(QueuedSessionEvent { event, _bytes: permit }).await.map_err(|_| EventQueueError)
        }).await.map_err(|_| EventQueueError)?
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SessionCommand {
    Send(Vec<u8>),
    Disconnect(DisconnectReason),
}

#[derive(Clone)]
pub struct SessionCommandSender {
    tx: mpsc::Sender<QueuedSessionCommand>,
    bytes: Arc<Semaphore>,
    byte_limit: usize,
    enqueue_timeout: Duration,
}

pub struct SessionCommandReceiver { rx: mpsc::Receiver<QueuedSessionCommand> }
struct QueuedSessionCommand { command: SessionCommand, _bytes: Option<OwnedSemaphorePermit> }

pub fn session_command_channel(max_commands: usize, max_payload_bytes: usize, enqueue_timeout: Duration) -> (SessionCommandSender, SessionCommandReceiver) {
    let (tx, rx) = mpsc::channel(max_commands.max(1));
    (SessionCommandSender { tx, bytes: Arc::new(Semaphore::new(max_payload_bytes.max(1))), byte_limit: max_payload_bytes.max(1), enqueue_timeout }, SessionCommandReceiver { rx })
}

impl SessionCommandSender {
    pub async fn send(&self, command: SessionCommand) -> Result<(), SessionError> {
        let bytes = match &command { SessionCommand::Send(payload) => payload.len(), SessionCommand::Disconnect(_) => 0 };
        if bytes > self.byte_limit || bytes > u32::MAX as usize { return Err(SessionError::Backpressure); }
        timeout(self.enqueue_timeout, async {
            let permit = if bytes == 0 { None } else { Some(self.bytes.clone().acquire_many_owned(bytes as u32).await.map_err(|_| SessionError::Backpressure)?) };
            self.tx.send(QueuedSessionCommand { command, _bytes: permit }).await.map_err(|_| SessionError::Closed)
        }).await.map_err(|_| SessionError::Backpressure)?
    }
    pub fn try_send(&self, command: SessionCommand) -> Result<(), SessionError> {
        let bytes = match &command { SessionCommand::Send(payload) => payload.len(), SessionCommand::Disconnect(_) => 0 };
        if bytes > self.byte_limit || bytes > u32::MAX as usize { return Err(SessionError::Backpressure); }
        let permit = if bytes == 0 { None } else { Some(self.bytes.clone().try_acquire_many_owned(bytes as u32).map_err(|_| SessionError::Backpressure)?) };
        self.tx.try_send(QueuedSessionCommand { command, _bytes: permit }).map_err(|error| match error {
            mpsc::error::TrySendError::Full(_) => SessionError::Backpressure,
            mpsc::error::TrySendError::Closed(_) => SessionError::Closed,
        })
    }
}

pub trait SessionClock: Send + Sync {
    fn unix_millis(&self) -> i64;
}

#[derive(Default)]
pub struct SystemSessionClock;
impl SessionClock for SystemSessionClock {
    fn unix_millis(&self) -> i64 { SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis().min(i64::MAX as u128) as i64 }
}

#[derive(Clone, Debug)]
pub struct SessionConfig {
    pub local_hello: HelloMessage,
    pub direction: Direction,
    pub admission: AdmissionConfig,
    pub pool: PoolConfig,
    pub keepalive_interval: Duration,
    pub pong_timeout: Duration,
    pub write_timeout: Duration,
    pub compression: bool,
}

#[derive(Clone, Default)]
pub struct SessionRegistry {
    pub admission: Arc<Mutex<Admission>>,
    pub pool: Arc<Mutex<ConnectionPool>>,
}

#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    #[error("transport: {0}")] Io(#[from] io::Error),
    #[error("whole frame write deadline elapsed")]
    WriteTimeout,
    #[error("invalid protobuf: {0}")] Decode(#[from] prost::DecodeError),
    #[error("compression: {0}")] Compression(#[from] compression::CompressionError),
    #[error("peer rejected: {0:?}")] Rejected(DisconnectReason),
    #[error("unexpected session message: {0}")] Protocol(&'static str),
    #[error("session event backpressure")]
    Backpressure,
    #[error("authenticated peer misconduct: {0:?}")]
    PeerMisconduct(tron_protocol::protocol::ReasonCode),
    #[error("session command channel closed")]
    Closed,
}
impl SessionError {
    /// Returns the Java peer-misconduct reason that warrants an IP ban.
    /// Transport failures and local resource/cancellation failures never ban.
    pub fn ban_reason(&self) -> Option<tron_protocol::protocol::ReasonCode> {
        use tron_protocol::protocol::ReasonCode;
        match self {
            Self::Protocol(_) | Self::Decode(_) | Self::Rejected(DisconnectReason::BadProtocol) => Some(ReasonCode::BadProtocol),
            Self::PeerMisconduct(reason) if matches!(reason, ReasonCode::BadProtocol | ReasonCode::BadBlock | ReasonCode::BadTx) => Some(*reason),
            _ => None,
        }
    }

    pub fn should_backoff(&self) -> bool {
        !matches!(self, Self::Backpressure)
    }
}

pub struct TransportSession<T> {
    io: FramedIo<T>, remote: SocketAddr, config: SessionConfig, registry: SessionRegistry,
    state: SessionState, remote_id: Option<Vec<u8>>, compressed: bool, awaiting_pong: Option<(i64, Instant)>,
    events: Option<SessionEventSender>, commands: Option<SessionCommandReceiver>, clock: Arc<dyn SessionClock>,
}

impl<T: AsyncRead + AsyncWrite + Unpin> TransportSession<T> {
    pub fn new(mut io: FramedIo<T>, remote: SocketAddr, config: SessionConfig, registry: SessionRegistry) -> Self {
        io.set_write_timeout(config.write_timeout);
        Self { io, remote, config, registry, state: SessionState::New, remote_id: None, compressed: false, awaiting_pong: None, events: None, commands: None, clock: Arc::new(SystemSessionClock) }
    }
    pub fn with_events(mut self, events: SessionEventSender) -> Self { self.events = Some(events); self }
    pub fn with_commands(mut self, commands: SessionCommandReceiver) -> Self { self.commands = Some(commands); self }
    pub fn with_clock(mut self, clock: Arc<dyn SessionClock>) -> Self { self.clock = clock; self }
    pub fn state(&self) -> SessionState { self.state }
    pub fn traffic(&self) -> crate::framing::Traffic { *self.io.traffic() }
    async fn emit(&self, event: SessionEvent) -> Result<(), SessionError> { if let Some(tx) = &self.events { tx.send(event).await.map_err(|_| SessionError::Backpressure)?; } Ok(()) }
    async fn transition(&mut self, state: SessionState) -> Result<(), SessionError> { self.state = state; self.emit(SessionEvent::State(state)).await }
    fn now_ms(&self) -> i64 { self.clock.unix_millis() }
    fn map_write_error(error: io::Error) -> SessionError {
        if crate::tcp::is_write_timeout(&error) { SessionError::WriteTimeout } else { SessionError::Io(error) }
    }
    async fn send_control<M: Message>(&mut self, control: Control, message: &M) -> Result<(), SessionError> {
        let body = message.encode_to_vec(); let mut frame = Vec::with_capacity(body.len()+1); frame.push(control.byte()); frame.extend_from_slice(&body);
        self.io.write_frame(Bytes::from(frame)).await.map_err(Self::map_write_error)?; Ok(())
    }
    async fn send_hello(&mut self) -> Result<(), SessionError> { let hello=self.config.local_hello.clone(); self.send_control(Control::HandshakeHello, &hello).await?; self.transition(SessionState::HelloSent).await?; Ok(()) }
    async fn receive_hello(&mut self) -> Result<HelloMessage, SessionError> {
        let frame=self.io.read_frame().await?; if frame.first().and_then(|b|Control::parse(*b))!=Some(Control::HandshakeHello){return Err(SessionError::Protocol("expected hello"))}
        let hello=crate::handshake::decode_hello(&frame[1..]).map_err(|_|SessionError::Protocol("invalid hello"))?; self.transition(SessionState::HelloReceived).await?; Ok(hello)
    }
    async fn reject(&mut self, reason: DisconnectReason) -> Result<(), SessionError> { let _=self.send_control(Control::Disconnect,&P2pDisconnectMessage{reason:reason as i32}).await; let _=self.emit(SessionEvent::Disconnected(reason)).await; Err(SessionError::Rejected(reason)) }
    async fn establish(&mut self) -> Result<(), SessionError> {
        let hello = match self.config.direction { Direction::Active => { self.send_hello().await?; self.receive_hello().await? }, Direction::Passive => { let h=self.receive_hello().await?; self.send_hello().await?; h } };
        let reason={self.registry.admission.lock().expect("admission poisoned").admit(&hello,self.remote.ip(),self.config.local_hello.from.as_ref().map_or(&[][..],|e|e.node_id.as_slice()),&self.config.admission,Instant::now()).err()};
        if let Some(reason)=reason{return self.reject(reason).await}
        let endpoint=hello.from.as_ref().expect("admitted hello has endpoint"); self.remote_id=Some(endpoint.node_id.clone());
        let peer=Peer{node_id:endpoint.node_id.clone(),address:self.remote,direction:self.config.direction,trusted:self.config.admission.trusted.contains(&self.remote.ip()),connected_at:Instant::now(),last_seen:Instant::now()};
        let pool_reason=self.registry.pool.lock().expect("pool poisoned").insert(peer,&self.config.pool).err().map(|e|match e { crate::connection::PoolError::Duplicate=>DisconnectReason::DuplicatePeer,crate::connection::PoolError::Full=>DisconnectReason::TooManyPeers,crate::connection::PoolError::SameIp=>DisconnectReason::TooManyPeersWithSameIp,crate::connection::PoolError::InvalidIdentity=>DisconnectReason::BadProtocol });
        if let Some(reason)=pool_reason { self.registry.admission.lock().expect("admission poisoned").remove(&endpoint.node_id); return self.reject(reason).await }
        self.transition(SessionState::Negotiating).await?;
        let status=StatusMessage{from:self.config.local_hello.from.clone(),version:self.config.local_hello.version,network_id:self.config.local_hello.network_id,max_connections:self.config.pool.max_connections.min(i32::MAX as usize) as i32,current_connections:self.registry.pool.lock().expect("pool poisoned").len().min(i32::MAX as usize) as i32,timestamp:self.now_ms()};
        self.send_control(Control::Status,&status).await?;
        let frame=self.io.read_frame().await?; if frame.first().and_then(|b|Control::parse(*b))!=Some(Control::Status){return Err(SessionError::Protocol("expected status"))}
        let remote_status=crate::handshake::decode_status(&frame[1..]).map_err(|_|SessionError::Protocol("invalid status"))?;
        if remote_status.network_id!=self.config.admission.network_id{return self.reject(DisconnectReason::BadProtocol).await} if remote_status.version!=self.config.admission.version{return self.reject(DisconnectReason::DifferentVersion).await}
        let local_compression = if self.config.compression { CompressType::Snappy } else { CompressType::Uncompress };
        self.io.write_frame(Bytes::from(vec![0xfa, local_compression as u8])).await.map_err(Self::map_write_error)?;
        let upgrade=self.io.read_frame().await?; if upgrade.len()!=2||upgrade[0]!=0xfa{return Err(SessionError::Protocol("expected compression upgrade"))}
        let remote_compression=CompressType::try_from(i32::from(upgrade[1])).map_err(|_|SessionError::Protocol("unknown compression upgrade"))?;
        self.compressed=local_compression==CompressType::Snappy&&remote_compression==CompressType::Snappy;
        self.transition(SessionState::Connected).await?; Ok(())
    }
    pub async fn send_message(&mut self, message: &[u8]) -> Result<(), SessionError> { let frame=if self.compressed { compression::envelope(message,true)?.encode_to_vec() } else { message.to_vec() }; self.io.write_frame(Bytes::from(frame)).await.map_err(Self::map_write_error)?; Ok(()) }
    /// Sends a validated positive application message through the established C020 framing layer.
    pub async fn send_app_message(&mut self, message: &crate::app_message::AppMessage) -> Result<(), SessionError> {
        self.send_message(&message.send_bytes()).await
    }
    async fn handle_frame(&mut self, frame: Bytes) -> Result<bool,SessionError> {
        if let Some(control)=frame.first().and_then(|b|Control::parse(*b)) { match control {
            Control::KeepAlivePing=>{let ping=KeepAliveMessage::decode(&frame[1..])?;self.send_control(Control::KeepAlivePong,&ping).await?;self.emit(SessionEvent::Ping(ping.timestamp)).await?;}
            Control::KeepAlivePong=>{let pong=KeepAliveMessage::decode(&frame[1..])?;if self.awaiting_pong.is_some_and(|(timestamp,_)|timestamp==pong.timestamp){self.awaiting_pong=None;}self.emit(SessionEvent::Pong(pong.timestamp)).await?;}
            Control::Disconnect=>{let msg=P2pDisconnectMessage::decode(&frame[1..])?;let reason=DisconnectReason::try_from(msg.reason).unwrap_or(DisconnectReason::Unknown);self.emit(SessionEvent::Disconnected(reason)).await?;return Ok(false)}
            Control::HandshakeHello=>return self.reject(DisconnectReason::DupHandshake).await.map(|_|false),
            Control::Status=>return Err(SessionError::Protocol("duplicate status")),
        }} else if frame.first()==Some(&0xfa) { return Err(SessionError::Protocol("duplicate upgrade")); }
        else { let data=if self.compressed { let envelope=CompressMessage::decode(frame.as_ref())?;compression::open(&envelope)? } else {frame.to_vec()};self.emit(SessionEvent::Message(data)).await?; }
        Ok(true)
    }
    pub async fn run(mut self, cancel: CancellationToken) -> Result<crate::framing::Traffic,SessionError> {
        let result=async {
            tokio::select! {
                biased;
                _=cancel.cancelled()=>{
                    self.transition(SessionState::Draining).await?;
                    let _=self.send_control(Control::Disconnect,&P2pDisconnectMessage{reason:DisconnectReason::PeerQuiting as i32}).await;
                }
                established=self.establish()=>{
                    established?;
                    let mut ticker=interval(self.config.keepalive_interval);ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);ticker.tick().await;
                    loop { tokio::select! { biased;
                        _=cancel.cancelled()=>{self.transition(SessionState::Draining).await?;let _=self.send_control(Control::Disconnect,&P2pDisconnectMessage{reason:DisconnectReason::PeerQuiting as i32}).await;break;}
                        command=async { match &mut self.commands { Some(rx) => rx.rx.recv().await, None => std::future::pending().await } }=>{match command.map(|queued|queued.command){Some(SessionCommand::Send(payload))=>self.send_message(&payload).await?,Some(SessionCommand::Disconnect(reason))=>{self.transition(SessionState::Draining).await?;let _=self.send_control(Control::Disconnect,&P2pDisconnectMessage{reason:reason as i32}).await;break},None=>self.commands=None}}
                        _=ticker.tick()=>{if self.awaiting_pong.is_some_and(|(_,t)|t.elapsed()>=self.config.pong_timeout){let _=self.send_control(Control::Disconnect,&P2pDisconnectMessage{reason:DisconnectReason::PingTimeout as i32}).await;return Err(SessionError::Rejected(DisconnectReason::PingTimeout))}if self.awaiting_pong.is_none(){let timestamp=self.now_ms();self.send_control(Control::KeepAlivePing,&KeepAliveMessage{timestamp}).await?;self.awaiting_pong=Some((timestamp,Instant::now()));}}
                        frame=self.io.read_frame()=>{if !self.handle_frame(frame?).await?{break}}
                    }}
                }
            }
            Ok(())
        }.await;
        if matches!(result, Err(SessionError::Backpressure | SessionError::WriteTimeout)) {
            let _ = self.send_control(Control::Disconnect, &P2pDisconnectMessage { reason: DisconnectReason::TooManyPeers as i32 }).await;
        }
        if let Some(id)=self.remote_id.take(){self.registry.admission.lock().expect("admission poisoned").remove(&id);self.registry.pool.lock().expect("pool poisoned").remove(&id);}
        if let Err(error) = &result {
            let trusted = self.config.admission.trusted.contains(&self.remote.ip());
            if !trusted && error.ban_reason().is_some() {
                self.registry.admission.lock().expect("admission poisoned").ban(self.remote.ip(), Instant::now() + self.config.admission.ban_duration);
            }
            if self.config.direction == Direction::Active && error.should_backoff() {
                self.registry.pool.lock().expect("pool poisoned").record_failure(self.remote, &self.config.pool, Instant::now());
            }
        }
        self.state = SessionState::Closed; let _ = self.emit(SessionEvent::State(SessionState::Closed)).await; let traffic=*self.io.traffic(); result.map(|_|traffic)
    }
}
