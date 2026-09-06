use std::collections::HashSet;
use tron_crypto::{derive_address, selected_digest, CryptoEngine, PublicKey, RecoverableSignature, Secp256k1Key};
use tron_protocol::protocol::HelloMessage;
use crate::peer::{InventoryItem, PeerConnection};

pub const MAX_PEERS_PER_WITNESS_ADDRESS: usize = 5;

#[derive(Clone,Debug,Eq,PartialEq)] pub enum RelayHelloError{MissingAddress,InactiveWitness,TooManyPeers,BadSignatureLength,BadSignature,WrongSigner,MissingPermissionAddress}

pub fn sign_witness_hello(hello:&mut HelloMessage,witness:&[u8],key:&Secp256k1Key)->Result<(),tron_crypto::CryptoError>{
    let digest=selected_digest(CryptoEngine::Secp256k1,&hello.timestamp.to_be_bytes());
    hello.address=witness.to_vec(); hello.signature=key.sign_prehash(&digest)?.to_wire().to_vec(); Ok(())
}

pub fn verify_witness_hello(hello:&HelloMessage,fast_forward:bool,active_witnesses:&HashSet<Vec<u8>>,connected_same_address:usize,witness_permission:Option<&[u8]>)->Result<Vec<u8>,RelayHelloError>{
    if !fast_forward{return Ok(hello.address.clone())} if hello.address.is_empty(){return Err(RelayHelloError::MissingAddress)}
    if !active_witnesses.contains(&hello.address){return Err(RelayHelloError::InactiveWitness)} if connected_same_address>MAX_PEERS_PER_WITNESS_ADDRESS{return Err(RelayHelloError::TooManyPeers)}
    if !(65..=68).contains(&hello.signature.len()){return Err(RelayHelloError::BadSignatureLength)}
    let digest=selected_digest(CryptoEngine::Secp256k1,&hello.timestamp.to_be_bytes()); let signature=RecoverableSignature::from_consensus_wire(&hello.signature).map_err(|_|RelayHelloError::BadSignature)?;
    let public=PublicKey::recover_prehash(CryptoEngine::Secp256k1,&digest,&signature).map_err(|_|RelayHelloError::BadSignature)?; let recovered=derive_address(&public).as_bytes().to_vec();
    let expected=witness_permission.unwrap_or(&hello.address); if recovered!=expected{return Err(RelayHelloError::WrongSigner)} Ok(hello.address.clone())
}

pub fn successor_witnesses(schedule:&[Vec<u8>],producer:&[u8],count:usize)->HashSet<Vec<u8>>{
    if schedule.is_empty(){return HashSet::new()} let Some(mut index)=schedule.iter().position(|w|w.as_slice()==producer)else{return schedule.iter().cloned().collect()};
    let mut out=HashSet::with_capacity(count.min(schedule.len())); for _ in 0..count{index=(index+1)%schedule.len();out.insert(schedule[index].clone());} out
}

#[derive(Clone,Debug,Eq,PartialEq)] pub struct FullBlockRelay{pub peer:std::net::SocketAddr,pub block:Vec<u8>}
pub fn fast_forward_block(peers:&mut [PeerConnection],schedule:&[Vec<u8>],producer:&[u8],block_id:[u8;32],encoded_block:&[u8],successor_count:usize,now:i64)->Vec<FullBlockRelay>{
    let witnesses=successor_witnesses(schedule,producer,successor_count); let item=InventoryItem{hash:block_id,kind:1}; let mut relays=Vec::new();
    for peer in peers { let address=peer.hello_received.as_ref().map(|h|h.message().address.as_slice()); if !peer.is_sync_finished()||address.is_none_or(|a|!witnesses.contains(a)){continue} if peer.received_contains(&item,now)||peer.spread_contains(&item,now){continue} peer.remember_spread(item.clone(),now); relays.push(FullBlockRelay{peer:peer.address,block:encoded_block.to_vec()}); }
    relays
}
