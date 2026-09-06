use std::{cell::RefCell, collections::BTreeMap, io, net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket}, sync::Arc, thread, time::Duration};

use tron_consensus::{
    backup::{encode_keep_alive, AuthenticatedDatagram, BackupConfig, BackupService, BackupStatus, DatagramSocket, ReceivedDatagram, SocketFactory},
    pbft::{persist_commit, preprepare_block, CommitData, DataType, LocalSigner, PbftBounds, PbftContext, PbftPersistence, PbftSidecar, LATEST_PBFT_BLOCK_NUM_KEY},
};
use tron_crypto::{derive_address, PublicKey, Secp256k1Key};
use tron_protocol::protocol::BackupMessage;
use tron_state::StoreKind;

#[derive(Default)]
struct Memory(RefCell<BTreeMap<(StoreKind, Vec<u8>), Vec<u8>>>);
impl PbftPersistence for Memory {
    type Error = ();
    fn persist_atomic(&self, key: &[u8], value: &[u8], candidate: Option<i64>) -> Result<Option<i64>, Self::Error> {
        let mut rows = self.0.borrow_mut();
        let previous = rows.get(&(StoreKind::Common, LATEST_PBFT_BLOCK_NUM_KEY.to_vec())).and_then(|bytes| bytes.as_slice().try_into().ok()).map(i64::from_be_bytes).unwrap_or(0);
        let advanced = candidate.filter(|number| *number > previous);
        rows.insert((StoreKind::Pbft, key.to_vec()), value.to_vec());
        if let Some(number) = advanced { rows.insert((StoreKind::Common, LATEST_PBFT_BLOCK_NUM_KEY.to_vec()), number.to_be_bytes().to_vec()); }
        Ok(advanced)
    }
}

fn key(n: u8) -> Secp256k1Key { let mut bytes=[0;32]; bytes[31]=n; Secp256k1Key::from_private_bytes(&bytes).unwrap() }
fn address(key: &Secp256k1Key) -> Vec<u8> { derive_address(&PublicKey::Secp256k1(key.public_key())).as_bytes().to_vec() }
fn available_port() -> u16 { UdpSocket::bind((Ipv4Addr::LOCALHOST,0)).unwrap().local_addr().unwrap().port() }
struct ScenarioSocket(UdpSocket, IpAddr);
impl DatagramSocket for ScenarioSocket {
    fn send_to(&self, bytes: &[u8], address: SocketAddr) -> io::Result<usize> { self.0.send_to(bytes, address) }
    fn recv_datagram(&self) -> io::Result<ReceivedDatagram> {
        let mut bytes = [0u8; 2048];
        let (size, source) = self.0.recv_from(&mut bytes)?;
        Ok(ReceivedDatagram::Authenticated(AuthenticatedDatagram { payload: bytes[..size].to_vec(), source, peer_identity: self.1, session: 1, sequence: 1 }))
    }
    fn local_addr(&self) -> io::Result<SocketAddr> { self.0.local_addr() }
}
struct ScenarioTransport(IpAddr);
impl SocketFactory for ScenarioTransport {
    fn bind(&self, address: SocketAddr) -> io::Result<Arc<dyn DatagramSocket>> {
        let socket = UdpSocket::bind(address)?;
        socket.set_nonblocking(true)?;
        Ok(Arc::new(ScenarioSocket(socket, self.0)))
    }
    fn supplies_authenticated_datagrams(&self) -> bool { true }
}

#[test]
fn auxiliary_pbft_and_localhost_backup_run_together_without_block_authority() {
    let keys=[key(1),key(2),key(3)];
    let witnesses=keys.iter().map(address).collect::<Vec<_>>();
    let context=PbftContext {
        now_millis: 1_000,
        syncing: false,
        chain_switch: false,
        current_witnesses: witnesses.clone(),
        before_witnesses: witnesses,
        before_maintenance_time: 0,
        local_signers: keys.iter().cloned().map(|key| LocalSigner { witness: address(&key), key }).collect(),
        expected_proposals: vec![tron_consensus::pbft::ExpectedProposal { data_type: DataType::Block, view_n: 123, epoch: 5, proposer: address(&keys[0]), data: vec![0xab; 32] }],
    };
    let mut sidecar=PbftSidecar::new(Some(3),PbftBounds::default());
    let effects=sidecar.handle(preprepare_block(vec![0xab;32],123,5,Some(&keys[0])).unwrap(),context).unwrap();
    let commit=effects.iter().find_map(|effect| match effect { tron_consensus::pbft::Effect::Commit(data)=>Some(data.clone()), _=>None }).expect("PBFT quorum must produce an auxiliary commit effect");
    let store=Memory::default();
    let saved=persist_commit(&store,&CommitData { raw:commit.raw, data_type:DataType::Block, number:commit.number, epoch:commit.epoch, signatures:commit.signatures }).unwrap();
    assert_eq!(saved.key,b"BLOCK123");
    assert_eq!(saved.latest_pbft_block,Some(123));

    let port=available_port();
    let source=SocketAddr::from(([127,0,0,2],port));
    let config=BackupConfig::new(SocketAddr::from(([127,0,0,1],port)),"127.0.0.1".parse::<IpAddr>().unwrap(),vec!["127.0.0.2".into()],6);
    let mut backup=BackupService::production(config,Arc::new(ScenarioTransport(source.ip())));
    assert!(backup.start().unwrap());
    let client=UdpSocket::bind(source).unwrap();
    client.send_to(&encode_keep_alive(&BackupMessage { flag:true, priority:6 }).unwrap(),(Ipv4Addr::LOCALHOST,port)).unwrap();
    for _ in 0..100 { if backup.status()==BackupStatus::SLAVER { break; } thread::sleep(Duration::from_millis(5)); }
    assert_eq!(backup.status(),BackupStatus::SLAVER);
    backup.close();

    // The integration surface ends in a PBFT persistence effect and a backup role.
    // Neither API accepts or returns a DPoS schedule, fork choice, or selected block.
    assert_eq!(saved.latest_pbft_block,Some(123));
}
