use std::collections::HashSet;
use tron_crypto::{derive_address,PublicKey,Secp256k1Key};
use tron_network::relay::{sign_witness_hello,successor_witnesses,verify_witness_hello,RelayHelloError};
use tron_protocol::protocol::HelloMessage;
fn key()->Secp256k1Key{let mut b=[0u8;32];b[31]=9;Secp256k1Key::from_private_bytes(&b).unwrap()}
#[test]fn witness_hello_authenticates_timestamp_and_enforces_java_peer_boundary(){let key=key();let address=derive_address(&PublicKey::Secp256k1(key.public_key())).as_bytes().to_vec();let mut hello=HelloMessage{timestamp:1234,..Default::default()};sign_witness_hello(&mut hello,&address,&key).unwrap();let active=HashSet::from([address.clone()]);assert_eq!(verify_witness_hello(&hello,true,&active,5,None).unwrap(),address);assert!(matches!(verify_witness_hello(&hello,true,&active,6,None),Err(RelayHelloError::TooManyPeers)));hello.timestamp+=1;assert!(matches!(verify_witness_hello(&hello,true,&active,5,None),Err(RelayHelloError::WrongSigner)));}
#[test]fn scheduled_successors_wrap_and_are_distinct_from_ordinary_gossip(){let schedule=vec![vec![1],vec![2],vec![3],vec![4]];assert_eq!(successor_witnesses(&schedule,&[3],2),HashSet::from([vec![4],vec![1]]));assert_eq!(successor_witnesses(&schedule,&[9],2),schedule.into_iter().collect());}
