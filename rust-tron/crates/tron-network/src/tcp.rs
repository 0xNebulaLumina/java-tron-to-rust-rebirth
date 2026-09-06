use bytes::{Buf, Bytes, BytesMut};
use std::{collections::{HashMap, VecDeque}, error::Error, fmt, future::Future, io, net::{IpAddr, SocketAddr}, pin::Pin, sync::{Arc, Mutex}, time::Duration};
use tokio::{io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt}, net::{TcpListener, TcpStream}, sync::{OwnedSemaphorePermit, Semaphore}, task::JoinSet, time::timeout};
use tokio_util::{codec::{Decoder, Encoder}, sync::CancellationToken};
use crate::framing::VarintFrameCodec;

pub use tokio_util::sync::CancellationToken as Cancellation;

const READ_CHUNK_SIZE: usize = 8 * 1024;
#[derive(Debug)]
pub struct WriteTimeout;

impl fmt::Display for WriteTimeout {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { f.write_str("whole frame write deadline elapsed") }
}

impl Error for WriteTimeout {}

pub fn is_write_timeout(error: &io::Error) -> bool { error.get_ref().is_some_and(|source| source.is::<WriteTimeout>()) }


#[derive(Clone)]
pub struct BufferBudget(Arc<Semaphore>);

impl BufferBudget {
    pub fn new(bytes: usize) -> Self { Self(Arc::new(Semaphore::new(bytes.max(1))) ) }
    pub fn available(&self) -> usize { self.0.available_permits() }
}

struct BufferedPermit { permit: OwnedSemaphorePermit, bytes: usize }

pub struct FramedIo<T> {
    io: T,
    codec: VarintFrameCodec,
    buffer: BytesMut,
    read_timeout: Duration,
    write_timeout: Duration,
    budget: Option<BufferBudget>,
    buffered_permits: VecDeque<BufferedPermit>,
}

impl<T: AsyncRead + AsyncWrite + Unpin> FramedIo<T> {
    pub fn new(io: T, read_timeout: Duration) -> Self { Self::with_timeouts(io, read_timeout, read_timeout) }
    pub fn with_timeouts(io: T, read_timeout: Duration, write_timeout: Duration) -> Self { Self::with_optional_budget(io, read_timeout, write_timeout, None) }
    pub fn with_budget(io: T, read_timeout: Duration, budget: BufferBudget) -> Self { Self::with_budget_and_timeouts(io, read_timeout, read_timeout, budget) }
    pub fn with_budget_and_timeouts(io: T, read_timeout: Duration, write_timeout: Duration, budget: BufferBudget) -> Self { Self::with_optional_budget(io, read_timeout, write_timeout, Some(budget)) }
    fn with_optional_budget(io: T, read_timeout: Duration, write_timeout: Duration, budget: Option<BufferBudget>) -> Self {
        Self { io, codec: Default::default(), buffer: BytesMut::new(), read_timeout, write_timeout, budget, buffered_permits: VecDeque::new() }
    }
    pub fn set_write_timeout(&mut self, write_timeout: Duration) { self.write_timeout = write_timeout; }
    fn release_consumed(&mut self, mut bytes: usize) {
        while bytes > 0 {
            let Some(front) = self.buffered_permits.front_mut() else { break };
            let releasing = bytes.min(front.bytes);
            let released = front.permit.split(releasing).expect("tracked permit count");
            drop(released);
            front.bytes -= releasing;
            bytes -= releasing;
            if front.bytes == 0 { self.buffered_permits.pop_front(); }
        }
    }
    pub async fn read_frame(&mut self) -> io::Result<Bytes> {
        loop {
            let before = self.buffer.len();
            if let Some(frame) = self.codec.decode(&mut self.buffer)? {
                self.release_consumed(before - self.buffer.len());
                if self.buffer.is_empty() {
                    self.buffer = BytesMut::new();
                } else if self.buffer.capacity() > self.buffer.len().saturating_add(READ_CHUNK_SIZE) {
                    let remaining = self.buffer.len();
                    let copy_permit = if let Some(budget) = &self.budget {
                        Some(budget.0.clone().try_acquire_many_owned(remaining as u32).map_err(|_| io::Error::new(io::ErrorKind::OutOfMemory, "aggregate frame buffer budget exhausted while compacting"))?)
                    } else { None };
                    self.buffer = BytesMut::from(&self.buffer[..]);
                    drop(copy_permit);
                }
                return Ok(frame);
            }
            if let Some(budget) = &self.budget {
                let desired = (budget.available() / 2).min(READ_CHUNK_SIZE);
                if desired == 0 { return Err(io::Error::new(io::ErrorKind::OutOfMemory, "aggregate frame buffer budget exhausted")); }
                let reserved = desired * 2;
                let mut permit = budget.0.clone().try_acquire_many_owned(reserved as u32).map_err(|_| io::Error::new(io::ErrorKind::OutOfMemory, "aggregate frame buffer budget exhausted"))?;
                let mut chunk = vec![0u8; desired];
                let n = timeout(self.read_timeout, self.io.read(&mut chunk)).await.map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "peer read timeout"))??;
                if n == 0 { return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "peer closed")); }
                self.buffer.extend_from_slice(&chunk[..n]);
                drop(chunk);
                if reserved > n { drop(permit.split(reserved - n)); }
                self.buffered_permits.push_back(BufferedPermit { permit, bytes: n });
            }
            else {
                self.buffer.reserve(READ_CHUNK_SIZE);
                let n = timeout(self.read_timeout, self.io.read_buf(&mut self.buffer)).await.map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "peer read timeout"))??;
                if n == 0 { return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "peer closed")); }
            }
        }
    }
    pub async fn write_frame(&mut self, frame: Bytes) -> io::Result<()> {
        let payload_len = frame.len();
        let mut encoded = BytesMut::new();
        self.codec.encode(frame, &mut encoded)?;
        let result = timeout(self.write_timeout, async {
            while !encoded.is_empty() {
                let written = self.io.write(&encoded).await?;
                if written == 0 { return Err(io::Error::new(io::ErrorKind::WriteZero, "failed to write framed payload")); }
                encoded.advance(written);
                self.codec.record_sent_wire(written);
            }
            Ok(())
        }).await;
        match result {
            Ok(result) => result?,
            Err(_) => return Err(io::Error::new(io::ErrorKind::TimedOut, WriteTimeout)),
        }
        self.codec.record_sent_payload(payload_len);
        Ok(())
    }
    pub fn traffic(&self) -> &crate::framing::Traffic { self.codec.traffic() }
    pub fn buffered_len(&self) -> usize { self.buffer.len() }
    pub fn buffer_capacity(&self) -> usize { self.buffer.capacity() }
}

#[derive(Clone, Debug)]
pub struct ServeConfig {
    pub max_connections: usize,
    pub max_connections_per_ip: usize,
    pub handshake_timeout: Duration,
    pub aggregate_buffer_bytes: usize,
    pub write_timeout: Duration,
}

impl Default for ServeConfig {
    fn default() -> Self { Self { max_connections: 256, max_connections_per_ip: 8, handshake_timeout: Duration::from_secs(10), write_timeout: Duration::from_secs(10), aggregate_buffer_bytes: 64 * 1024 * 1024 } }
}

struct AdmissionGuard { ip: IpAddr, counts: Arc<Mutex<HashMap<IpAddr, usize>>>, _permit: OwnedSemaphorePermit }
impl Drop for AdmissionGuard {
    fn drop(&mut self) {
        let mut counts = self.counts.lock().expect("TCP admission counts poisoned");
        if let Some(count) = counts.get_mut(&self.ip) { *count -= 1; if *count == 0 { counts.remove(&self.ip); } }
    }
}

pub type ConnectionSession = Pin<Box<dyn Future<Output = ()> + Send + 'static>>;

pub trait IntoConnectionSession { fn into_session(self) -> Option<ConnectionSession>; }
impl IntoConnectionSession for () { fn into_session(self) -> Option<ConnectionSession> { None } }
impl IntoConnectionSession for ConnectionSession { fn into_session(self) -> Option<ConnectionSession> { Some(self) } }

pub async fn serve<F, Fut, S>(listener: TcpListener, cancel: CancellationToken, handshake: F) -> io::Result<()>
where F: Fn(FramedIo<TcpStream>, SocketAddr) -> Fut + Send + Sync + 'static, Fut: Future<Output = S> + Send + 'static, S: IntoConnectionSession + Send + 'static {
    serve_with_config(listener, cancel, ServeConfig::default(), handshake).await
}

pub async fn serve_with_config<F, Fut, S>(listener: TcpListener, cancel: CancellationToken, config: ServeConfig, handshake: F) -> io::Result<()>
where F: Fn(FramedIo<TcpStream>, SocketAddr) -> Fut + Send + Sync + 'static, Fut: Future<Output = S> + Send + 'static, S: IntoConnectionSession + Send + 'static {
    if config.max_connections == 0 || config.max_connections_per_ip == 0 || config.aggregate_buffer_bytes == 0 {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "TCP limits must be positive"));
    }
    let handshake = Arc::new(handshake);
    let global = Arc::new(Semaphore::new(config.max_connections));
    let counts = Arc::new(Mutex::new(HashMap::<IpAddr, usize>::new()));
    let budget = BufferBudget::new(config.aggregate_buffer_bytes);
    let mut tasks = JoinSet::new();
    loop {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => { tasks.abort_all(); while tasks.join_next().await.is_some() {} return Ok(()); }
            Some(_) = tasks.join_next(), if !tasks.is_empty() => {}
            accepted = listener.accept() => {
                let (stream, address) = accepted?;
                let Ok(permit) = global.clone().try_acquire_owned() else { drop(stream); continue };
                let admitted = {
                    let mut values = counts.lock().expect("TCP admission counts poisoned");
                    let count = values.entry(address.ip()).or_default();
                    if *count >= config.max_connections_per_ip { false } else { *count += 1; true }
                };
                if !admitted { drop(permit); drop(stream); continue; }
                let guard = AdmissionGuard { ip: address.ip(), counts: counts.clone(), _permit: permit };
                let establish = handshake.clone();
                let framed = FramedIo::with_budget_and_timeouts(stream, config.handshake_timeout, config.write_timeout, budget.clone());
                let handshake_timeout = config.handshake_timeout;
                tasks.spawn(async move {
                    let _guard = guard;
                    if let Ok(session) = timeout(handshake_timeout, establish(framed, address)).await {
                        if let Some(session) = session.into_session() { session.await; }
                    }
                });
            }
        }
    }
}
