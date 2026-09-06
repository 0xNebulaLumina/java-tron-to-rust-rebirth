//! Java-compatible witness backup election over UDP.

use prost::Message;
use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};
use tron_config::NodeBackupConfig;
use tron_protocol::protocol::BackupMessage;

pub const BACKUP_KEEP_ALIVE: u8 = 0x05;
pub const MAX_DATAGRAM_SIZE: usize = 2048;
pub const DEFAULT_KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(3);
pub const DNS_REFRESH_INTERVAL: Duration = Duration::from_secs(60);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BackupStatus {
    INIT,
    SLAVER,
    MASTER,
}

#[derive(Clone, Debug)]
pub struct BackupConfig {
    pub bind: SocketAddr,
    pub local_ip: IpAddr,
    pub members: Vec<String>,
    pub priority: i32,
    pub keep_alive_interval: Duration,
    pub dns_refresh_interval: Duration,
}

impl BackupConfig {
    pub fn new(bind: SocketAddr, local_ip: IpAddr, members: Vec<String>, priority: i32) -> Self {
        Self {
            bind,
            local_ip,
            members,
            priority,
            keep_alive_interval: DEFAULT_KEEP_ALIVE_INTERVAL,
            dns_refresh_interval: DNS_REFRESH_INTERVAL,
        }
    }

    pub fn from_node_config(bind_ip: IpAddr, local_ip: IpAddr, node: &NodeBackupConfig) -> io::Result<Self> {
        let port = u16::try_from(node.port).ok().filter(|port| *port != 0)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "backup port must be in 1..=65535"))?;
        let keep_alive_millis = u64::try_from(node.keep_alive_interval).ok().filter(|millis| *millis != 0)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "backup keep-alive interval must be positive"))?;
        Ok(Self {
            bind: SocketAddr::new(bind_ip, port),
            local_ip,
            members: node.members.clone(),
            priority: node.priority,
            keep_alive_interval: Duration::from_millis(keep_alive_millis),
            dns_refresh_interval: DNS_REFRESH_INTERVAL,
        })
    }
}

pub trait BackupClock: Send + Sync + 'static {
    fn now(&self) -> Duration;
    fn sleep(&self, duration: Duration);
}

pub struct MonotonicClock(Instant);

impl Default for MonotonicClock {
    fn default() -> Self {
        Self(Instant::now())
    }
}

impl BackupClock for MonotonicClock {
    fn now(&self) -> Duration {
        self.0.elapsed()
    }

    fn sleep(&self, duration: Duration) {
        thread::sleep(duration);
    }
}

pub trait DnsResolver: Send + Sync + 'static {
    fn resolve(&self, member: &str) -> io::Result<Vec<IpAddr>>;
}

pub struct SystemDnsResolver;

impl DnsResolver for SystemDnsResolver {
    fn resolve(&self, member: &str) -> io::Result<Vec<IpAddr>> {
        if let Ok(ip) = member.parse() {
            return Ok(vec![ip]);
        }
        Ok((member, 0).to_socket_addrs()?.map(|address| address.ip()).collect())
    }
}
/// Packet supplied by a transport that has already authenticated the remote peer.
///
/// `payload` is the exact UDP application payload. Secure adapters (for example
/// WireGuard/IPsec/DTLS or a P2P-bound receiver) must attest the peer identity,
/// monotonically increasing session, and sequence before constructing this value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticatedDatagram {
    pub payload: Vec<u8>,
    pub source: SocketAddr,
    pub peer_identity: IpAddr,
    pub session: u64,
    pub sequence: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReceivedDatagram {
    Authenticated(AuthenticatedDatagram),
    /// Java-compatible plain UDP. It may be observed for wire compatibility but
    /// can never update election state or make this process a producing witness.
    Unauthenticated { payload: Vec<u8>, source: SocketAddr },
}

pub trait DatagramSocket: Send + Sync + 'static {
    fn send_to(&self, bytes: &[u8], address: SocketAddr) -> io::Result<usize>;
    fn recv_datagram(&self) -> io::Result<ReceivedDatagram>;
    fn local_addr(&self) -> io::Result<SocketAddr>;
}

impl DatagramSocket for UdpSocket {
    fn send_to(&self, bytes: &[u8], address: SocketAddr) -> io::Result<usize> {
        UdpSocket::send_to(self, bytes, address)
    }

    fn recv_datagram(&self) -> io::Result<ReceivedDatagram> {
        let mut bytes = [0u8; MAX_DATAGRAM_SIZE];
        let (size, source) = UdpSocket::recv_from(self, &mut bytes)?;
        Ok(ReceivedDatagram::Unauthenticated { payload: bytes[..size].to_vec(), source })
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        UdpSocket::local_addr(self)
    }
}

pub trait SocketFactory: Send + Sync + 'static {
    fn bind(&self, address: SocketAddr) -> io::Result<Arc<dyn DatagramSocket>>;
    fn supplies_authenticated_datagrams(&self) -> bool { false }
}

pub struct SystemSocketFactory;

impl SocketFactory for SystemSocketFactory {
    fn bind(&self, address: SocketAddr) -> io::Result<Arc<dyn DatagramSocket>> {
        let socket = UdpSocket::bind(address)?;
        socket.set_nonblocking(true)?;
        Ok(Arc::new(socket))
    }
}

#[derive(Debug)]
pub struct BackupManager {
    local_ip: IpAddr,
    priority: i32,
    status: BackupStatus,
    last_keep_alive: Duration,
    timeout: Duration,
}

impl BackupManager {
    pub fn new(local_ip: IpAddr, priority: i32, interval: Duration, now: Duration) -> Self {
        Self {
            local_ip,
            priority,
            status: BackupStatus::INIT,
            last_keep_alive: now,
            timeout: interval.saturating_mul(6),
        }
    }

    pub fn status(&self) -> BackupStatus {
        self.status
    }

    pub fn timeout(&self) -> Duration {
        self.timeout
    }

    pub fn on_keep_alive(&mut self, sender: IpAddr, message: &BackupMessage, now: Duration) {
        self.last_keep_alive = now;
        if self.status == BackupStatus::INIT && (message.flag || message.priority > self.priority) {
            self.status = BackupStatus::SLAVER;
            return;
        }
        if self.status == BackupStatus::MASTER && message.flag {
            if message.priority > self.priority
                || (message.priority == self.priority
                    && self.local_ip.to_string() < sender.to_string())
            {
                self.status = BackupStatus::SLAVER;
            }
        }
    }

    pub fn tick(&mut self, now: Duration) {
        if self.status != BackupStatus::MASTER
            && now.saturating_sub(self.last_keep_alive) > self.timeout
        {
            if self.status == BackupStatus::SLAVER {
                self.status = BackupStatus::INIT;
                self.last_keep_alive = now;
            } else {
                self.status = BackupStatus::MASTER;
            }
        }
    }

    fn outbound(&self) -> Option<BackupMessage> {
        (self.status != BackupStatus::SLAVER).then_some(BackupMessage {
            flag: self.status == BackupStatus::MASTER,
            priority: self.priority,
        })
    }
}

pub fn encode_keep_alive(message: &BackupMessage) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::with_capacity(1 + message.encoded_len());
    bytes.push(BACKUP_KEEP_ALIVE);
    message.encode(&mut bytes).map_err(io::Error::other)?;
    if bytes.len() >= MAX_DATAGRAM_SIZE {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "backup datagram must be smaller than 2048 bytes"));
    }
    Ok(bytes)
}

pub fn decode_keep_alive(bytes: &[u8]) -> io::Result<BackupMessage> {
    if bytes.len() >= MAX_DATAGRAM_SIZE || bytes.first() != Some(&BACKUP_KEEP_ALIVE) {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid backup datagram"));
    }
    BackupMessage::decode(&bytes[1..]).map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
}

#[derive(Default)]
struct Membership {
    allowed: BTreeSet<IpAddr>,
    domains: BTreeMap<String, Option<IpAddr>>,
}

fn first_remote_address(addresses: Vec<IpAddr>, local_ip: IpAddr) -> Option<IpAddr> {
    addresses.into_iter().next().filter(|address| *address != local_ip)
}

fn resolve_members(config: &BackupConfig, dns: &dyn DnsResolver) -> Membership {
    let mut membership = Membership::default();
    for member in &config.members {
        let Ok(addresses) = dns.resolve(member) else { continue };
        let address = first_remote_address(addresses, config.local_ip);
        if let Some(address) = address { membership.allowed.insert(address); }
        if member.parse::<IpAddr>().is_err() {
            membership.domains.insert(member.clone(), address);
        }
    }
    membership
}

fn refresh_domains(membership: &mut Membership, config: &BackupConfig, dns: &dyn DnsResolver) {
    let names: Vec<_> = membership.domains.keys().cloned().collect();
    for name in names {
        let Ok(addresses) = dns.resolve(&name) else { continue };
        membership.domains.insert(name, first_remote_address(addresses, config.local_ip));
    }
    let mut allowed = BTreeSet::new();
    for member in &config.members {
        if let Ok(ip) = member.parse::<IpAddr>() {
            if ip != config.local_ip { allowed.insert(ip); }
        }
    }
    allowed.extend(membership.domains.values().filter_map(|address| *address));
    membership.allowed = allowed;
}

pub struct BackupService {
    config: BackupConfig,
    clock: Arc<dyn BackupClock>,
    dns: Arc<dyn DnsResolver>,
    sockets: Arc<dyn SocketFactory>,
    producing: bool,
    manager: Arc<Mutex<BackupManager>>,
    cancelled: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
    bound: Arc<Mutex<Option<SocketAddr>>>,
}

impl BackupService {
    /// Production constructor. The supplied factory must receive packet-level
    /// transport attestations; unauthenticated packets are always ignored.
    pub fn production(config: BackupConfig, sockets: Arc<dyn SocketFactory>) -> Self {
        Self::new(config, Arc::new(MonotonicClock::default()), Arc::new(SystemDnsResolver), sockets)
    }

    /// Java wire-compatible plain UDP mode. It sends and receives the exact 0x05
    /// payload, but is deliberately non-producing and cannot change witness role.
    pub fn system_legacy_java(config: BackupConfig) -> Self {
        Self::with_mode(config, Arc::new(MonotonicClock::default()), Arc::new(SystemDnsResolver), Arc::new(SystemSocketFactory), false)
    }

    pub fn new(config: BackupConfig, clock: Arc<dyn BackupClock>, dns: Arc<dyn DnsResolver>, sockets: Arc<dyn SocketFactory>) -> Self {
        Self::with_mode(config, clock, dns, sockets, true)
    }

    fn with_mode(config: BackupConfig, clock: Arc<dyn BackupClock>, dns: Arc<dyn DnsResolver>, sockets: Arc<dyn SocketFactory>, producing: bool) -> Self {
        let manager = Arc::new(Mutex::new(BackupManager::new(config.local_ip, config.priority, config.keep_alive_interval, clock.now())));
        Self { config, clock, dns, sockets, producing, manager, cancelled: Arc::new(AtomicBool::new(false)), worker: None, bound: Arc::new(Mutex::new(None)) }
    }

    pub fn status(&self) -> BackupStatus {
        self.manager.lock().expect("backup manager poisoned").status()
    }

    pub fn local_addr(&self) -> Option<SocketAddr> {
        *self.bound.lock().expect("backup bound address poisoned")
    }

    pub fn is_producing(&self) -> bool { self.producing }

    pub fn start(&mut self) -> io::Result<bool> {
        if self.worker.is_some() { return Ok(false); }
        if self.producing && !self.sockets.supplies_authenticated_datagrams() {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "production backup requires an authenticated datagram transport"));
        }
        if self.config.bind.port() == 0 || self.config.members.is_empty() { return Ok(false); }
        let first = self.sockets.bind(self.config.bind)?;
        *self.bound.lock().expect("backup bound address poisoned") = Some(first.local_addr()?);
        self.cancelled.store(false, Ordering::Release);
        let config = self.config.clone();
        let clock = Arc::clone(&self.clock);
        let dns = Arc::clone(&self.dns);
        let sockets = Arc::clone(&self.sockets);
        let manager = Arc::clone(&self.manager);
        let cancelled = Arc::clone(&self.cancelled);
        let bound = Arc::clone(&self.bound);
        let producing = self.producing;
        self.worker = Some(thread::spawn(move || run_loop(first, config, clock, dns, sockets, producing, manager, cancelled, bound)));
        Ok(true)
    }

    pub fn close(&mut self) {
        self.cancelled.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() { let _ = worker.join(); }
        *self.bound.lock().expect("backup bound address poisoned") = None;
    }
}

impl Drop for BackupService {
    fn drop(&mut self) { self.close(); }
}

fn run_loop(mut socket: Arc<dyn DatagramSocket>, config: BackupConfig, clock: Arc<dyn BackupClock>, dns: Arc<dyn DnsResolver>, sockets: Arc<dyn SocketFactory>, producing: bool, manager: Arc<Mutex<BackupManager>>, cancelled: Arc<AtomicBool>, bound: Arc<Mutex<Option<SocketAddr>>>) {
    let mut membership = resolve_members(&config, dns.as_ref());
    let mut replay = BTreeMap::<IpAddr, (u64, u64)>::new();
    let mut next_send = clock.now() + Duration::from_secs(1);
    let mut next_dns = clock.now() + config.dns_refresh_interval;
    while !cancelled.load(Ordering::Acquire) {
        let now = clock.now();
        if now >= next_dns {
            refresh_domains(&mut membership, &config, dns.as_ref());
            next_dns = now + config.dns_refresh_interval;
        }
        if producing {
            let mut state = manager.lock().expect("backup manager poisoned");
            state.tick(now);
            if now >= next_send {
                if let Some(message) = state.outbound() {
                    if let Ok(bytes) = encode_keep_alive(&message) {
                        for ip in &membership.allowed { let _ = socket.send_to(&bytes, SocketAddr::new(*ip, config.bind.port())); }
                    }
                }
                next_send = now + config.keep_alive_interval;
            }
        }
        match socket.recv_datagram() {
            Ok(ReceivedDatagram::Authenticated(packet))
                if producing
                    && packet.source.port() == config.bind.port()
                    && packet.source.ip() == packet.peer_identity
                    && membership.allowed.contains(&packet.peer_identity)
                    && accept_attestation(&mut replay, packet.peer_identity, packet.session, packet.sequence) =>
            {
                if let Ok(message) = decode_keep_alive(&packet.payload) {
                    manager.lock().expect("backup manager poisoned").on_keep_alive(packet.peer_identity, &message, clock.now());
                }
            }
            Ok(_) => {}
            Err(error) if matches!(error.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut) => clock.sleep(Duration::from_millis(10)),
            Err(_) => {
                if cancelled.load(Ordering::Acquire) { break; }
                match sockets.bind(config.bind) {
                    Ok(replacement) => {
                        if let Ok(address) = replacement.local_addr() { *bound.lock().expect("backup bound address poisoned") = Some(address); }
                        socket = replacement;
                    }
                    Err(_) => clock.sleep(Duration::from_millis(10)),
                }
            }
        }
    }
}

fn accept_attestation(replay: &mut BTreeMap<IpAddr, (u64, u64)>, identity: IpAddr, session: u64, sequence: u64) -> bool {
    match replay.get_mut(&identity) {
        None => { replay.insert(identity, (session, sequence)); true }
        Some((current_session, current_sequence)) if session > *current_session => {
            *current_session = session;
            *current_sequence = sequence;
            true
        }
        Some((current_session, current_sequence)) if session == *current_session && sequence > *current_sequence => {
            *current_sequence = sequence;
            true
        }
        Some(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attestation_window_rejects_replay_and_retired_sessions() {
        let identity: IpAddr = "192.0.2.7".parse().unwrap();
        let mut window = BTreeMap::new();
        assert!(accept_attestation(&mut window, identity, 7, 10));
        assert!(!accept_attestation(&mut window, identity, 7, 10));
        assert!(!accept_attestation(&mut window, identity, 7, 9));
        assert!(accept_attestation(&mut window, identity, 7, 11));
        assert!(accept_attestation(&mut window, identity, 8, 1));
        assert!(!accept_attestation(&mut window, identity, 7, u64::MAX));
        assert!(!accept_attestation(&mut window, identity, 8, 1));
    }
}
