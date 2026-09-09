use std::{collections::HashSet, net::SocketAddr, sync::{Arc, atomic::{AtomicUsize, Ordering}}, time::Duration};
use prost::Message;
use tokio::net::{TcpListener, UdpSocket};
use tron_crypto::CryptoEngine;
use tron_execution::RawBlock;
use tron_network::{
    app_hello::AppHello,
    connection::{Direction, PoolConfig},
    gossip::{InventoryKey, InventoryType, Payload},
    handlers::{transaction_id_from_wire, BlockSink, TransactionSink},
    handshake::{AdmissionConfig, Endpoint as TransportEndpoint, HelloMessage as TransportHello},
    peer::PeerConnection,
    production::{ProductionDiscoveryConfig, ProductionNetwork, ProductionNetworkConfig},
    session::{SessionConfig, SystemSessionClock},
    sync::SyncBlockId,
};
use tron_protocol::protocol::{self, hello_message::BlockId, transaction::{self, Contract}, Transaction};

struct TxSink(Arc<AtomicUsize>);
impl TransactionSink for TxSink {
    fn known_transaction(&self, _: &[u8;32]) -> bool { false }
    fn process_transaction(&mut self, _: Vec<u8>, _: i64) -> Result<(),String> { self.0.fetch_add(1, Ordering::SeqCst); Ok(()) }
    fn broadcast_transaction(&mut self, _: &[u8], _: &PeerConnection) {}
}
struct Blocks;
impl BlockSink for Blocks {
    fn validate_block(&mut self, _: &RawBlock)->Result<(),String>{Ok(())}
    fn has_parent(&self, _: &RawBlock)->bool{true}
    fn head_number(&self)->i64{0}
    fn broadcast_block(&mut self, _: &[u8], _: &PeerConnection){}
    fn process_block(&mut self, _: RawBlock, _: i64)->Result<(),String>{Ok(())}
    fn start_sync(&mut self, _: &PeerConnection){}
}
fn sid(number:i64)->SyncBlockId{SyncBlockId::new([number as u8;32],number)}
fn app_hello(id:u8,port:u16)->AppHello{AppHello::constructed(protocol::HelloMessage{from:Some(protocol::Endpoint{address:vec![127,0,0,1],port:i32::from(port),node_id:vec![id;64],address_ipv6:vec![]}),version:2,timestamp:1,genesis_block_id:Some(BlockId{hash:vec![0;32],number:0}),solid_block_id:Some(BlockId{hash:vec![0;32],number:0}),head_block_id:Some(BlockId{hash:vec![0;32],number:0}),..Default::default()})}
fn session(id:u8,port:u16)->SessionConfig{SessionConfig{local_hello:TransportHello{from:Some(TransportEndpoint{address:b"127.0.0.1".to_vec(),port:i32::from(port),node_id:vec![id;64],address_ipv6:vec![]}),network_id:7,code:0,timestamp:1,version:2},direction:Direction::Passive,admission:AdmissionConfig{network_id:7,version:2,max_connections:8,max_same_ip:8,trusted:HashSet::new(),ban_duration:Duration::from_secs(1)},pool:PoolConfig{min_connections:0,max_connections:8,min_active:0,max_same_ip:8,initial_backoff:Duration::from_millis(10),max_backoff:Duration::from_secs(1)},keepalive_interval:Duration::from_secs(30),pong_timeout:Duration::from_secs(30),write_timeout:Duration::from_secs(2),compression:true}}
async fn network(id:u8,active_nodes:Vec<SocketAddr>,accepted:Arc<AtomicUsize>)->Arc<ProductionNetwork>{let listener=TcpListener::bind("127.0.0.1:0").await.unwrap();let port=listener.local_addr().unwrap().port();let udp=UdpSocket::bind(SocketAddr::from(([127,0,0,1],port))).await.unwrap();ProductionNetwork::new(ProductionNetworkConfig{listener,discovery:Some(ProductionDiscoveryConfig{socket:udp,persist:None,refresh_interval:Duration::from_millis(50)}),active_nodes,session:session(id,port),app_hello:app_hello(id,port),transaction_sink:Box::new(TxSink(accepted)),block_sink:Box::new(Blocks),sync_head:Arc::new(||0),sync_id_at:Arc::new(|n|(n==0).then(||sid(0))),sync_on_main:Arc::new(|id|id==&sid(0)),pbft:None,clock:Arc::new(SystemSessionClock),engine:CryptoEngine::Secp256k1}).unwrap()}

#[tokio::test]
async fn two_production_owners_handshake_sync_fetch_admit_and_join() {
    let accepted_a=Arc::new(AtomicUsize::new(0));let accepted_b=Arc::new(AtomicUsize::new(0));
    let passive=network(2,vec![],accepted_b.clone()).await;let passive_addr=passive.local_addr().unwrap();passive.start().unwrap();
    let active=network(1,vec![passive_addr],accepted_a).await;active.start().unwrap();
    tokio::time::timeout(Duration::from_secs(3),async{loop{if active.snapshot().active==1&&passive.snapshot().passive==1{break}tokio::time::sleep(Duration::from_millis(10)).await}}).await.unwrap();
    let tx=Transaction{raw_data:Some(transaction::Raw{contract:vec![Contract::default()],..Default::default()}),signature:vec![vec![7;65]],..Default::default()};let bytes=tx.encode_to_vec();let hash=transaction_id_from_wire(&bytes).unwrap();
    active.publish(Payload{key:InventoryKey{hash,kind:InventoryType::Transaction},bytes,block:None,produced_at_ms:0}).unwrap();
    tokio::time::timeout(Duration::from_secs(3),async{while accepted_b.load(Ordering::SeqCst)==0{tokio::time::sleep(Duration::from_millis(10)).await}}).await.unwrap();
    active.send_to(passive_addr,tron_network::app_message::AppMessage::from_payload(tron_network::app_message::AppMessageType::SyncBlockChain,tron_network::production::encode_sync_block_chain(&tron_network::sync::SyncBlockChain{ids:vec![sid(0)]})).unwrap()).await.unwrap();
    tokio::time::sleep(Duration::from_millis(20)).await;
    let passive_port=passive_addr.port();
    let started=tokio::time::Instant::now();
    let (active_result,passive_result)=tokio::join!(active.shutdown_with_timeout(Duration::from_secs(1)),passive.shutdown_with_timeout(Duration::from_secs(1)));
    active_result.unwrap();passive_result.unwrap();assert!(started.elapsed()<Duration::from_secs(1));assert_eq!(accepted_b.load(Ordering::SeqCst),1);assert!(active.snapshot().peers.is_empty()&&passive.snapshot().peers.is_empty());
    let tcp=TcpListener::bind(SocketAddr::from(([127,0,0,1],passive_port))).await.unwrap();drop(tcp);
    let udp=UdpSocket::bind(SocketAddr::from(([127,0,0,1],passive_port))).await.unwrap();drop(udp);
}

#[tokio::test]
async fn shutdown_cancels_a_session_blocked_in_handshake_and_releases_the_listener() {
    let accepted=Arc::new(AtomicUsize::new(0));
    let owner=network(3,vec![],accepted).await;
    let address=owner.local_addr().unwrap();
    owner.start().unwrap();
    let silent_peer=tokio::net::TcpStream::connect(address).await.unwrap();
    tokio::time::timeout(Duration::from_secs(1),async{loop{if owner.snapshot().peers.len()==1{break}tokio::task::yield_now().await}}).await.unwrap();
    let started=tokio::time::Instant::now();
    owner.shutdown_with_timeout(Duration::from_millis(500)).await.unwrap();
    assert!(started.elapsed()<Duration::from_millis(500));
    assert!(owner.snapshot().peers.is_empty());
    drop(silent_peer);
    let tcp=TcpListener::bind(address).await.unwrap();drop(tcp);
    let udp=UdpSocket::bind(address).await.unwrap();drop(udp);
}
