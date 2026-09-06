use prost::Message;
use tron_network::{app_hello::{apply_policy, validate_structure, AppHello, HelloPolicy, LocalHello}, app_message::{AppMessage, AppMessageError, AppMessageType}, stats::{MessageCount, ProtocolStats}};
use tron_protocol::protocol::{hello_message::BlockId, ReasonCode};

fn bid(byte:u8,n:i64)->BlockId{BlockId{hash:vec![byte;32],number:n}}
fn local()->LocalHello{LocalHello{node_id:vec![7;64],address_v4:b"127.0.0.1".to_vec(),address_v6:vec![],port:18888,version:1,timestamp:1_700_000_000_000,genesis:bid(1,0),solid:bid(2,90),head:bid(3,100),node_type:0,lowest_block_num:0,code_version:b"4.7.4".to_vec(),address:vec![],signature:vec![]}}

#[test]
fn exact_positive_factory_rejects_reserved_and_preserves_java_message_semantics(){
 let accepted=[1,2,3,6,7,8,9,0x14,0x20,0x21,0x34];
 for code in accepted{let m=AppMessage::parse(vec![code,0xaa,0xbb]).unwrap();assert_eq!(m.kind().byte(),code);assert_eq!(m.payload(),[0xaa,0xbb]);assert_eq!(m.send_bytes(),[code,0xaa,0xbb]);}
 for code in [0,4,5,0x10,0x11,0x12,0x13,0x30,0x31,0x32,0x33,0xff]{assert_eq!(AppMessage::parse(vec![code]).unwrap_err(),AppMessageError::Unsupported(code));}
 assert_eq!(AppMessage::from_payload(AppMessageType::Transaction,[1,2,3]).unwrap(),AppMessage::from_payload(AppMessageType::Block,[1,2,3]).unwrap());
 assert_eq!(hex::encode(AppMessage::from_payload(AppMessageType::Transaction,b"abc".to_vec()).unwrap().message_id()),"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
}

#[test]
fn application_keepalive_is_fixed_and_distinct_from_c020_external_control(){
 assert_eq!(AppMessage::ping().send_bytes(),[0x22,0xc0]);assert_eq!(AppMessage::pong().send_bytes(),[0x23,0xc0]);
 assert!(AppMessage::parse(vec![0x22]).is_err());assert!(AppMessage::parse(vec![0x23,0xc0,0]).is_err());
 assert_ne!(AppMessage::ping().send_bytes()[0],tron_network::handshake::Control::KeepAlivePing.byte());
}

#[test]
fn connected_session_events_expose_the_positive_application_layer(){
 let event=tron_network::session::SessionEvent::Message(vec![0x22,0xc0]);
 assert_eq!(event.app_message().unwrap().unwrap().kind(),AppMessageType::Ping);
 let reserved=tron_network::session::SessionEvent::Message(vec![0x10]);
 assert_eq!(reserved.app_message().unwrap_err(),AppMessageError::Unsupported(0x10));
}

#[test]
fn pinned_java_hello_vector_roundtrips_exact_bytes_and_policy_reasons(){
 let encoded=local().build().encode_to_vec();
 // Captured from the pinned Java Protocol.HelloMessage builder for `local()`.
 const JAVA_HEX:&str="0a510a093132372e302e302e3110c893011a400707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070710011880d095ffbc3122220a2001010101010101010101010101010101010101010101010101010101010101012a240a200202020202020202020202020202020202020202020202020202020202020202105a32240a20030303030303030303030303030303030303030303030303030303030303030310645a05342e372e34";
 assert_eq!(hex::encode(&encoded),JAVA_HEX);
 let hello=AppHello::decode(hex::decode(JAVA_HEX).unwrap()).unwrap();assert_eq!(hello.payload(),encoded);assert!(hello.structurally_valid());
 let msg=hello.message();let solid=msg.solid_block_id.clone().unwrap();
 let mut p=HelloPolicy{version:1,genesis_hash:&vec![1;32],local_head_num:100,local_lowest_num:0,local_solid_num:90,duplicate_hello:false,duplicate_peer:false,identity_valid:true,effective_peer:false,solid_in_main_chain:&|id|id==&solid};
 assert_eq!(apply_policy(msg,&p),Ok(()));p.duplicate_hello=true;assert_eq!(apply_policy(msg,&p),Err(ReasonCode::BadProtocol));p.duplicate_hello=false;p.duplicate_peer=true;assert_eq!(apply_policy(msg,&p),Err(ReasonCode::DuplicatePeer));p.duplicate_peer=false;p.version=2;assert_eq!(apply_policy(msg,&p),Err(ReasonCode::IncompatibleVersion));
 let mut malformed=msg.clone();malformed.head_block_id.as_mut().unwrap().hash.pop();assert!(!validate_structure(&malformed));
}

#[test]
fn sixty_slot_java_quirks_have_explicit_bounds(){let mut c=MessageCount::new(100);c.add(3,100);assert_eq!(c.count(1,100),3);assert_eq!(c.count(0,100),0);assert_eq!(c.count(61,100),0);c.reset_total();assert_eq!(c.total(),0);assert_eq!(c.count(1,100),3);c.add(2,161);assert_eq!(c.count(60,161),2);let mut s=ProtocolStats::new(100);s.record_in(&AppMessage::ping(),100);assert_eq!(s.inbound_count(AppMessageType::Ping,1,100),1);assert_eq!(s.byte_totals(),(2,0));}
