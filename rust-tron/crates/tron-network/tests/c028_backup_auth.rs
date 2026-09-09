use std::net::SocketAddr;
use tron_network::{backup_auth::{BackupPeerKeyring, HmacSha256DatagramAuthenticator, BACKUP_AUTH_MAX_PAYLOAD}, discovery::DatagramAuthenticator};

fn pair() -> (HmacSha256DatagramAuthenticator, HmacSha256DatagramAuthenticator, SocketAddr, SocketAddr) {
    let a: SocketAddr = "127.0.0.1:10001".parse().unwrap();
    let b: SocketAddr = "127.0.0.2:10002".parse().unwrap();
    let key = [0x5a; 32];
    let mut ar = BackupPeerKeyring::new(a.ip(), a); ar.insert(b.ip(), b, key).unwrap();
    let mut br = BackupPeerKeyring::new(b.ip(), b); br.insert(a.ip(), a, key).unwrap();
    (HmacSha256DatagramAuthenticator::new(ar).unwrap(), HmacSha256DatagramAuthenticator::new(br).unwrap(), a, b)
}

#[test]
fn authenticates_exact_identity_endpoints_session_sequence_and_payload() {
    let (a, b, source, destination) = pair();
    let payload = b"java backup protobuf bytes";
    let packet = a.seal(destination.ip(), destination, source.ip(), source, 7, 11, payload).unwrap();
    let opened = b.authenticate(source, &packet).unwrap();
    assert_eq!(opened.peer_identity, source.ip());
    assert_eq!(opened.source, source);
    assert_eq!(opened.session, 7);
    assert_eq!(opened.sequence, 11);
    assert_eq!(opened.payload, payload);
    assert!(b.authenticate(source, &packet).is_none(), "same session/sequence must be rejected as replay");
}

#[test]
fn rejects_wrong_source_destination_truncation_tampering_and_oversize() {
    let (a, b, source, destination) = pair();
    let packet = a.seal(destination.ip(), destination, source.ip(), source, 1, 1, b"payload").unwrap();
    assert!(b.authenticate("127.0.0.1:10003".parse().unwrap(), &packet).is_none());
    assert!(b.authenticate(source, &packet[..packet.len()-1]).is_none());
    let mut tampered=packet.clone(); tampered[30]^=1; assert!(b.authenticate(source,&tampered).is_none());
    let wrong_destination: std::net::IpAddr = "127.0.0.3".parse().unwrap();
    assert!(a.seal(wrong_destination, destination, source.ip(), source, 1, 2, b"payload").is_none());
    assert!(a.seal(destination.ip(), destination, source.ip(), source, 1, 2, &vec![0;BACKUP_AUTH_MAX_PAYLOAD+1]).is_none());
}

#[test]
fn refuses_zero_session_or_sequence_and_plaintext() {
    let (a,b,source,destination)=pair();
    assert!(a.seal(destination.ip(),destination,source.ip(),source,0,1,b"x").is_none());
    assert!(a.seal(destination.ip(),destination,source.ip(),source,1,0,b"x").is_none());
    assert!(b.authenticate(source,b"plain java udp").is_none());
}
