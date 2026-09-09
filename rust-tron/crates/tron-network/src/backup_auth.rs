use std::{collections::BTreeMap, net::{IpAddr, SocketAddr}, sync::Mutex};

use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::discovery::{AuthenticatedDatagram, DatagramAuthenticator};

pub const BACKUP_AUTH_MAGIC: [u8; 4] = *b"TBA1";
pub const BACKUP_AUTH_VERSION: u8 = 1;
pub const BACKUP_AUTH_MAX_PAYLOAD: usize = 2048;
const TAG_LEN: usize = 32;
const HEADER_LEN: usize = 4 + 1 + 1 + 16 + 2 + 1 + 16 + 2 + 1 + 16 + 1 + 16 + 8 + 8 + 2;

type HmacSha256 = Hmac<Sha256>;

#[derive(Clone, Debug)]
pub struct BackupPeerKey {
    pub identity: IpAddr,
    pub endpoint: SocketAddr,
    key: Zeroizing<Vec<u8>>,
}

#[derive(Clone, Debug)]
pub struct BackupPeerKeyring {
    pub local_identity: IpAddr,
    pub local_endpoint: SocketAddr,
    peers: BTreeMap<IpAddr, BackupPeerKey>,
}

impl BackupPeerKeyring {
    pub fn new(local_identity: IpAddr, local_endpoint: SocketAddr) -> Self {
        Self { local_identity, local_endpoint, peers: BTreeMap::new() }
    }

    pub fn insert(&mut self, identity: IpAddr, endpoint: SocketAddr, key: [u8; 32]) -> Result<(), String> {
        if identity != endpoint.ip() { return Err("backup peer identity must equal its source IP".into()); }
        if self.peers.insert(identity, BackupPeerKey { identity, endpoint, key: Zeroizing::new(key.to_vec()) }).is_some() {
            return Err(format!("duplicate backup peer identity {identity}"));
        }
        Ok(())
    }
}

/// Parses `identity endpoint 64-hex-byte-key` records, one per nonempty line.
pub fn parse_keyring(local_identity: IpAddr, local_endpoint: SocketAddr, input: &str) -> Result<BackupPeerKeyring, String> {
    let mut ring = BackupPeerKeyring::new(local_identity, local_endpoint);
    for (index, line) in input.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') { continue; }
        let fields: Vec<_> = line.split_whitespace().collect();
        if fields.len() != 3 { return Err(format!("backup keyring line {} must contain identity endpoint key", index + 1)); }
        let identity = fields[0].parse::<IpAddr>().map_err(|_| format!("invalid identity on backup keyring line {}", index + 1))?;
        let endpoint = fields[1].parse::<SocketAddr>().map_err(|_| format!("invalid endpoint on backup keyring line {}", index + 1))?;
        let key = decode_hex_32(fields[2]).ok_or_else(|| format!("backup key on line {} must be exactly 64 hexadecimal characters", index + 1))?;
        ring.insert(identity, endpoint, key)?;
    }
    if ring.peers.is_empty() { return Err("backup keyring contains no peers".into()); }
    Ok(ring)
}

#[derive(Debug)]
pub struct HmacSha256DatagramAuthenticator { keyring: BackupPeerKeyring, inbound: Mutex<BTreeMap<IpAddr,(u64,u64)>> }

impl HmacSha256DatagramAuthenticator {
    pub fn new(keyring: BackupPeerKeyring) -> Result<Self, String> {
        if keyring.local_identity != keyring.local_endpoint.ip() { return Err("local backup identity must equal bind IP".into()); }
        if keyring.peers.is_empty() { return Err("backup keyring contains no peers".into()); }
        Ok(Self { keyring, inbound: Mutex::new(BTreeMap::new()) })
    }
}

impl DatagramAuthenticator for HmacSha256DatagramAuthenticator {
    fn authenticate(&self, source: SocketAddr, packet: &[u8]) -> Option<AuthenticatedDatagram> {
        if packet.len() < HEADER_LEN + TAG_LEN || packet[..4] != BACKUP_AUTH_MAGIC || packet[4] != BACKUP_AUTH_VERSION { return None; }
        let mut offset = 5;
        let source_identity = take_ip(packet, &mut offset)?;
        let enclosed_source = take_socket(packet, &mut offset)?;
        let destination_identity = take_ip(packet, &mut offset)?;
        let destination = take_socket(packet, &mut offset)?;
        let session = take_u64(packet, &mut offset)?;
        let sequence = take_u64(packet, &mut offset)?;
        let payload_len = take_u16(packet, &mut offset)? as usize;
        if payload_len > BACKUP_AUTH_MAX_PAYLOAD || offset.checked_add(payload_len + TAG_LEN)? != packet.len() { return None; }
        let peer = self.keyring.peers.get(&source_identity)?;
        if source_identity != source.ip() || enclosed_source != source || peer.endpoint != source || destination_identity != self.keyring.local_identity || destination != self.keyring.local_endpoint { return None; }
        let signed_len = offset + payload_len;
        let mut mac = HmacSha256::new_from_slice(&peer.key).ok()?;
        mac.update(&packet[..signed_len]);
        mac.verify_slice(&packet[signed_len..]).ok()?;
        let mut inbound=self.inbound.lock().ok()?;
        match inbound.get(&source_identity){Some(&(old_session,old_sequence)) if session<old_session || (session==old_session && sequence<=old_sequence)=>return None,_=>{inbound.insert(source_identity,(session,sequence));}}
        let mut peer_id=vec![0u8;64];peer_id[..16].copy_from_slice(&canonical_ip(source_identity));
        Some(AuthenticatedDatagram { peer_id, peer_identity: source_identity, session, sequence, source, payload: packet[offset..signed_len].to_vec() })
    }

    fn seal(&self, destination_identity: IpAddr, destination: SocketAddr, local_identity: IpAddr, source: SocketAddr, session: u64, sequence: u64, payload: &[u8]) -> Option<Vec<u8>> {
        if payload.len() > BACKUP_AUTH_MAX_PAYLOAD || session == 0 || sequence == 0 || local_identity != self.keyring.local_identity || source != self.keyring.local_endpoint { return None; }
        let peer = self.keyring.peers.get(&destination_identity)?;
        if peer.endpoint != destination || destination.ip() != destination_identity { return None; }
        let mut out = Vec::with_capacity(HEADER_LEN + payload.len() + TAG_LEN);
        out.extend_from_slice(&BACKUP_AUTH_MAGIC); out.push(BACKUP_AUTH_VERSION);
        put_ip(&mut out, local_identity); put_socket(&mut out, source);
        put_ip(&mut out, destination_identity); put_socket(&mut out, destination);
        out.extend_from_slice(&session.to_be_bytes()); out.extend_from_slice(&sequence.to_be_bytes());
        out.extend_from_slice(&(payload.len() as u16).to_be_bytes()); out.extend_from_slice(payload);
        let mut mac = HmacSha256::new_from_slice(&peer.key).ok()?; mac.update(&out); out.extend_from_slice(&mac.finalize().into_bytes()); Some(out)
    }
}

fn canonical_ip(ip: IpAddr) -> [u8; 16] { match ip { IpAddr::V4(v)=>{let mut out=[0;16];out[10]=0xff;out[11]=0xff;out[12..].copy_from_slice(&v.octets());out},IpAddr::V6(v)=>v.octets()} }
fn put_ip(out:&mut Vec<u8>,ip:IpAddr){out.push(if ip.is_ipv4(){4}else{6});out.extend_from_slice(&canonical_ip(ip));}
fn put_socket(out:&mut Vec<u8>,socket:SocketAddr){put_ip(out,socket.ip());out.extend_from_slice(&socket.port().to_be_bytes());}
fn take_ip(packet:&[u8],offset:&mut usize)->Option<IpAddr>{let family=*packet.get(*offset)?;*offset+=1;let bytes=<[u8;16]>::try_from(packet.get(*offset..*offset+16)?).ok()?;*offset+=16;match family{4 if bytes[..12]==[0,0,0,0,0,0,0,0,0,0,0xff,0xff]=>Some(IpAddr::V4(std::net::Ipv4Addr::new(bytes[12],bytes[13],bytes[14],bytes[15]))),6=>Some(IpAddr::V6(std::net::Ipv6Addr::from(bytes))),_=>None}}
fn take_socket(packet:&[u8],offset:&mut usize)->Option<SocketAddr>{let ip=take_ip(packet,offset)?;let port=take_u16(packet,offset)?;Some(SocketAddr::new(ip,port))}
fn take_u16(packet:&[u8],offset:&mut usize)->Option<u16>{let value=u16::from_be_bytes(packet.get(*offset..*offset+2)?.try_into().ok()?);*offset+=2;Some(value)}
fn take_u64(packet:&[u8],offset:&mut usize)->Option<u64>{let value=u64::from_be_bytes(packet.get(*offset..*offset+8)?.try_into().ok()?);*offset+=8;Some(value)}
fn decode_hex_32(value:&str)->Option<[u8;32]>{if value.len()!=64{return None}let mut out=[0;32];for(i,slot)in out.iter_mut().enumerate(){let hi=value.as_bytes()[i*2];let lo=value.as_bytes()[i*2+1];*slot=(hex_nibble(hi)?<<4)|hex_nibble(lo)?;}Some(out)}
fn hex_nibble(value:u8)->Option<u8>{match value{b'0'..=b'9'=>Some(value-b'0'),b'a'..=b'f'=>Some(value-b'a'+10),b'A'..=b'F'=>Some(value-b'A'+10),_=>None}}
