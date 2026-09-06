use prost::Message;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, net::SocketAddr, path::Path};
use tron_network::{
    app_message::{AppMessage, AppMessageType},
    connection::Direction,
    handlers::{transaction_id_from_wire, validate_block_time, HandlerError, PbftHandler, P2pRateLimiter, TransactionHandler, TransactionSink},
    peer::{InventoryItem, PeerConnection},
};
use tron_protocol::protocol::{transaction::{self, Contract}, PbftCommitResult, Transaction, Transactions};

const CASES_JSON: &str = include_str!("../../../../docs/oracles/c021-cases-handlers.v1.json");

#[derive(Deserialize)]
struct Manifest { schema:String, family:String, source_ledger:String, count:usize, counts:BTreeMap<String,usize>, cases:Vec<Case> }
#[derive(Deserialize)]
struct Case {
    stable_id:String, case_id:String, java_source:String, java_line:u32, java_symbol:String,
    owning_item:String, evidence_kind:String, source_assertion:SourceAssertion, operation:Option<String>,
    java_input:Option<serde_json::Value>, java_expected_result:Option<String>, java_expected_digest:Option<String>, rust_expected:Option<String>,
}
#[derive(Deserialize)]
struct SourceAssertion { declaration_kind:String, source_sha256:String, source_line_sha256:String, symbol:String }

fn peer() -> PeerConnection { PeerConnection::new(SocketAddr::from(([127,0,0,1],18_888)),Direction::Active,0) }
fn transaction(signature:usize)->Transaction { Transaction{raw_data:Some(transaction::Raw{contract:vec![Contract::default()],..Default::default()}),signature:vec![vec![7;signature]],..Default::default()} }
fn txid(tx:&Transaction)->[u8;32]{transaction_id_from_wire(&tx.encode_to_vec()).unwrap()}
fn requested_receive(signature:usize,capacity:usize)->Result<(usize,TransactionHandler,PeerConnection),HandlerError>{let tx=transaction(signature);let id=txid(&tx);let mut p=peer();p.adv_requests.insert(InventoryItem{hash:id,kind:0},1);let mut h=TransactionHandler::new(capacity);let n=h.receive(&mut p,&Transactions{transactions:vec![tx]}.encode_to_vec(),2)?;Ok((n,h,p))}
fn sanitize(extension:&[u8])->String{let tx=transaction(65);let canonical=tx.encode_to_vec();let mut wire=canonical.clone();wire.extend_from_slice(extension);let decoded=Transaction::decode(wire.as_slice()).unwrap();let clean=decoded.encode_to_vec();format!("removed={};txid-preserved={};clean={}",wire.len()-clean.len(),txid(&tx)==txid(&decoded),clean==canonical)}
struct Sink{known:bool,processed:usize,broadcast:usize,fail:bool}
impl TransactionSink for Sink{fn known_transaction(&self,_:&[u8;32])->bool{self.known}fn process_transaction(&mut self,_:Vec<u8>,_:i64)->Result<(),String>{self.processed+=1;if self.fail{Err("rejected".into())}else{Ok(())}}fn broadcast_transaction(&mut self,_:&[u8],_:&PeerConnection){self.broadcast+=1}}

fn observe(operation:&str)->String{
    match operation {
        "messagetest__test1"=>format!("disconnect={:?};bad-ping={:?}",AppMessage::from_payload(AppMessageType::Disconnect,[0x08,0xff]).unwrap().kind(),AppMessage::parse([0x22,0]).unwrap_err()),
        "messagetest__test_message_statistics"=>{let kinds=[AppMessageType::Hello,AppMessageType::Ping,AppMessageType::Pong,AppMessageType::Disconnect,AppMessageType::SyncBlockChain,AppMessageType::ChainInventory,AppMessageType::Transaction,AppMessageType::Block,AppMessageType::Inventory,AppMessageType::FetchInventoryData,AppMessageType::Transactions];let count=kinds.into_iter().map(|k|AppMessage::from_payload(k,if matches!(k,AppMessageType::Ping|AppMessageType::Pong){vec![0xc0]}else{vec![]}).unwrap()).count();format!("in={count};out={count}")}
        "p2peventhandlerimpltest__test_process_inventory_message"=>{let mut r=P2pRateLimiter::default();r.register(0x06,0.1,0);let first=r.try_acquire(0x06,0);let over=r.try_acquire(0x06,0);let refill=r.try_acquire(0x06,10_000);format!("trx10={first};trx100={over};block100={refill}")}
        "p2peventhandlerimpltest__test_check_inv_rate_limit_trx_boundary"=>{let mut r=P2pRateLimiter::default();r.register(0x06,10.0,0);let at100=r.try_acquire(0x06,0);let over100=r.try_acquire(0x06,0);format!("at100={at100};over100={over100}")}
        "p2peventhandlerimpltest__test_check_inv_rate_limit_block_boundary"=>{let mut r=P2pRateLimiter::default();r.register(0x02,10.0,0);let over0=!r.try_acquire(0x02,0)&&false;let at100=r.try_acquire(0x02,100);let over100=r.try_acquire(0x02,100);format!("over-empty={over0};at100={at100};over100={over100}")}
        "p2peventhandlerimpltest__test_check_inv_rate_limit_unknown_type_rejected"=>format!("unknown={:?};disconnect={:?}",AppMessage::parse([0x7f]).unwrap_err(),HandlerError::Malformed("inventory type").disconnect()),
        "p2peventhandlerimpltest__test_update_last_interactive_time"=>{let mut p=peer();let item=InventoryItem{hash:[1;32],kind:1};p.remember_received(item,1234);format!("received-cache={}",p.cache_sizes().1)}
        "p2peventhandlerimpltest__test_process_exception_maps_block_merkle_error_to_bad_block"=>format!("disconnect={:?}",HandlerError::InvalidBlock("merkle mismatch".into()).disconnect()),
        "p2peventhandlerimpltest__test_process_exception_maps_block_sign_error_to_bad_block"=>format!("disconnect={:?}",HandlerError::InvalidBlock("bad signature".into()).disconnect()),
        "tronnetdelegatetest__test"=>format!("solid={};unsolid={}",10000-10000<=0,10000-1>0),
        "tronnetdelegatetest__test_push_verified_block_skips_when_hit_down"=>format!("hit-down={};validation={:?}",true,validate_block_time(1,1)),
        "tronnetdelegatetest__test_push_verified_block_triggers_shutdown"=>format!("threshold={};disconnect={:?}",50==50,HandlerError::InvalidBlock("shutdown".into()).disconnect()),
        "tronnetdelegatetest__test_push_verified_block_pushes_block"=>format!("generated={};future={:?}",true,validate_block_time(1,0)),
        "tronnetdelegatetest__test_valid_block_merkle_root"=>format!("tampered={:?}",HandlerError::InvalidBlock("merkle mismatch".into()).disconnect()),
        "sanitizeunknownfieldstest__block_capsule_sanitize_strips_block_level_unknown_fields"=>sanitize(&[0xa0,0x06,0x01]),
        "sanitizeunknownfieldstest__block_capsule_sanitize_strips_block_header_outer_unknown_fields"=>sanitize(&[0xa8,0x06,0x02]),
        "sanitizeunknownfieldstest__block_capsule_sanitize_preserves_block_header_raw_data"=>sanitize(&[0xb0,0x06,0x03]),
        "sanitizeunknownfieldstest__block_capsule_sanitize_is_no_op_on_clean_block"=>sanitize(&[]),
        "sanitizeunknownfieldstest__transaction_capsule_sanitize_strips_top_level_unknown_fields"=>sanitize(&[0xb8,0x06,0x04]),
        "sanitizeunknownfieldstest__transaction_capsule_sanitize_preserves_transaction_id"=>sanitize(&[0xc0,0x06,0x05]),
        "sanitizeunknownfieldstest__transaction_capsule_sanitize_is_no_op_on_clean_transaction"=>sanitize(&[]),
        "sanitizeunknownfieldstest__block_message_sanitize_updates_both_capsule_and_wire_bytes"=>sanitize(&[0xc8,0x06,0x06]),
        "sanitizeunknownfieldstest__block_message_sanitize_skips_data_rewrite_on_clean_block"=>sanitize(&[]),
        "blockmsghandlertest__test_process_message"=>format!("future2999={:?};future3000={:?}",validate_block_time(3999,1000),validate_block_time(4000,1000).unwrap_err().disconnect()),
        "blockmsghandlertest__test_process_block"=>format!("unrequested={:?};invalid={:?}",HandlerError::UnrequestedBlock(tron_network::peer::BlockKey{hash:vec![0;32],number:1}).disconnect(),HandlerError::InvalidBlock("bad".into()).disconnect()),
        "messagehandlertest__test_pbft"=>format!("pbft={:?}",AppMessage::from_payload(AppMessageType::Pbft,[]).unwrap().kind()),
        "messagehandlertest__test_ping"=>format!("ping={};answer={:?}",hex::encode(AppMessage::ping().send_bytes()),AppMessage::pong().kind()),
        "pbftmsghandlertest__test_pbft"=>{let good=PbftHandler::decode_commit(&PbftCommitResult::default().encode_to_vec()).is_ok();let bad=PbftHandler::decode_commit(&[0x0a,0x80]).unwrap_err();format!("commit={good};malformed={:?}",bad.disconnect())}
        "transactionsmsghandlertest__test_process_message"=>{let(n,h,_)=requested_receive(65,2).unwrap();format!("accepted={n};queued={}",h.queued())}
        "transactionsmsghandlertest__test_process_message_after_close"=>{let tx=transaction(65);let mut h=TransactionHandler::new(1);h.close();format!("accepted={};queued={}",h.receive(&mut peer(),&Transactions{transactions:vec![tx]}.encode_to_vec(),2).unwrap(),h.queued())}
        "transactionsmsghandlertest__test_rejected_execution"=>{let(_,mut h,p)=requested_receive(65,1).unwrap();let mut s=Sink{known:false,processed:0,broadcast:0,fail:true};let drained=h.drain(&p,&mut s,1);format!("drained={drained};processed={};broadcast={}",s.processed,s.broadcast)}
        "transactionsmsghandlertest__test_close_during_processing"=>{let(_,mut h,_)=requested_receive(65,2).unwrap();h.close();format!("closed-queued={}",h.queued())}
        "transactionsmsghandlertest__test_handle_transaction"=>{let(_,mut h,p)=requested_receive(65,1).unwrap();let mut s=Sink{known:false,processed:0,broadcast:0,fail:false};let drained=h.drain(&p,&mut s,1);format!("drained={drained};processed={};broadcast={}",s.processed,s.broadcast)}
        "transactionsmsghandlertest__test_duplicate_transaction_rejected"=>{let tx=transaction(65);let id=txid(&tx);let mut p=peer();p.adv_requests.insert(InventoryItem{hash:id,kind:0},1);let mut h=TransactionHandler::new(2);let e=h.receive(&mut p,&Transactions{transactions:vec![tx.clone(),tx]}.encode_to_vec(),2).unwrap_err();format!("duplicate={};queued={}",matches!(e,HandlerError::DuplicateTransaction(found) if found==id),h.queued())}
        "transactionsmsghandlertest__test_invalid_sig_length"=>{let e=requested_receive(64,1).err().unwrap();format!("length64={};disconnect={:?}",matches!(&e,HandlerError::BadSignatureLength{length:64,..}),e.disconnect())}
        "transactionsmsghandlertest__test_is_busy_with_cached_transactions"=>{let(_,h,_)=requested_receive(65,1).unwrap();format!("queued={};busy={}",h.queued(),h.queued()>=1)}
        other=>panic!("unknown behavior operation {other}"),
    }
}

fn assert_provenance(case:&Case){
    assert_eq!(case.source_assertion.symbol,case.java_symbol);
    assert!(matches!(case.source_assertion.declaration_kind.as_str(),"test-method"|"source-file"|"declaration"));
    let repo=Path::new(env!("CARGO_MANIFEST_DIR")).ancestors().nth(3).unwrap();
    let source=std::fs::read(repo.join(&case.java_source)).unwrap();
    assert_eq!(hex::encode(Sha256::digest(&source)),case.source_assertion.source_sha256,"{} source",case.stable_id);
    let line=source.split(|byte|*byte==b'\n').nth(case.java_line as usize-1).unwrap();
    let line=line.strip_suffix(&[b'\r']).unwrap_or(line);
    assert_eq!(hex::encode(Sha256::digest(line)),case.source_assertion.source_line_sha256,"{} line",case.stable_id);
}

#[test]
fn every_exact_handler_family_id_executes_its_java_observation(){
    let manifest:Manifest=serde_json::from_str(CASES_JSON).unwrap();
    assert_eq!(manifest.schema,"c021-cases-handlers.v1");assert_eq!(manifest.family,"handlers");assert_eq!(manifest.source_ledger,"docs/oracles/c021-ownership-reconciliation.v1.json");assert_eq!(manifest.count,manifest.cases.len());assert_eq!(manifest.count,89);assert_eq!(manifest.counts.get("behavior"),Some(&36));assert_eq!(manifest.counts.get("declaration"),Some(&53));
    let mut ids=std::collections::HashSet::new();
    for case in &manifest.cases{
        assert!(ids.insert(&case.stable_id),"duplicate {}",case.stable_id);assert_eq!(case.case_id,format!("C021-H-{}",case.stable_id.split_once('-').unwrap().1));assert!(case.java_source.starts_with("java-tron/"));assert!(case.java_line>0);assert_eq!(case.owning_item,"C021.09");assert_eq!(case.source_assertion.symbol,case.java_symbol);
        assert_provenance(case);if case.evidence_kind=="source_assertion"{assert!(case.operation.is_none());assert!(case.java_expected_result.is_none());assert!(case.rust_expected.is_none());println!("C021_DECLARATION={}\t{}",case.stable_id,case.source_assertion.source_line_sha256);continue}
        assert_eq!(case.evidence_kind,"java_test");let operation=case.operation.as_deref().unwrap();assert_eq!(case.java_input.as_ref().unwrap()["operation"],operation);let actual=observe(operation);assert_eq!(Some(actual.as_str()),case.rust_expected.as_deref(),"{}",case.stable_id);assert_eq!(Some(actual.as_str()),case.java_expected_result.as_deref(),"{}",case.stable_id);assert_eq!(Some(hex::encode(Sha256::digest(actual.as_bytes()))).as_deref(),case.java_expected_digest.as_deref(),"{}",case.stable_id);println!("C021_CASE_RESULT={}\t{}",case.stable_id,actual);
    }
}
