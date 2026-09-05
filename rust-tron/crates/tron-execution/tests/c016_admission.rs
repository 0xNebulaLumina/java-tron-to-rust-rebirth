use prost::Message;
use tron_crypto::{derive_address,CryptoEngine,DuplicateSignerPolicy,PrivateKey};
use tron_execution::*;
use tron_protocol::protocol::{Key,Permission,Transaction,permission::PermissionType,transaction::{Contract,Raw}};

fn hex(s:&str)->Vec<u8>{(0..s.len()).step_by(2).map(|i|u8::from_str_radix(&s[i..i+2],16).unwrap()).collect()}
fn hexed(b:&[u8])->String{b.iter().map(|v|format!("{v:02x}")).collect()}
fn cache()->TransactionCache{TransactionCache::new(CacheConfig{maximum_entries:4,ttl_millis:100,bloom_blocks:2,bloom_bits:256}).unwrap()}

#[test]
fn pinned_java_raw_wire_hash_boundaries_and_tapos_slices(){let oracle:serde_json::Value=serde_json::from_str(include_str!("../../../../docs/oracles/c016-admission-vectors.v1.json")).unwrap();let v=&oracle["vectors"][0];let wire=RawWireTransaction::decode(hex(v["transaction_hex"].as_str().unwrap())).unwrap();assert_eq!(hexed(wire.raw_data_bytes()),v["raw_data_hex"]);assert_eq!(hexed(wire.transaction_id(CryptoEngine::Secp256k1).as_bytes()),v["sha256_txid"]);assert_eq!(hexed(wire.full_hash(CryptoEngine::Secp256k1).as_bytes()),v["sha256_full_hash"]);assert_eq!(tapos_ref_block_bytes(0x0102_0304_0506_0708),[7,8]);assert_eq!(tapos_ref_block_hash(&(0u8..32).collect::<Vec<_>>()).unwrap(),[8,9,10,11,12,13,14,15]);}

fn signed_wire(permission_id:i32,expiration:i64,extra_results:usize,unknown:bool)->(RawWireTransaction,Permission){let private=PrivateKey::from_bytes(CryptoEngine::Secp256k1,&[1;32]).unwrap();let address=derive_address(&private.public_key());let contract=Contract{r#type:1,permission_id,..Default::default()};let raw=Raw{ref_block_bytes:vec![0xab,0xcd],ref_block_hash:vec![8,9,10,11,12,13,14,15],expiration,contract:vec![contract],timestamp:100,..Default::default()};let mut tx=Transaction{raw_data:Some(raw),ret:vec![Default::default();extra_results],..Default::default()};let initial=RawWireTransaction::decode(tx.encode_to_vec()).unwrap();tx.signature.push(private.sign_prehash(initial.transaction_id(CryptoEngine::Secp256k1).as_bytes()).unwrap().to_wire().to_vec());let mut bytes=tx.encode_to_vec();if unknown{bytes.extend_from_slice(&[0xa0,0x06,0x01])}let mut ops=vec![0;32];ops[0]|=1<<1;let permission=Permission{r#type:if permission_id==0{PermissionType::Owner as i32}else{PermissionType::Active as i32},id:permission_id,threshold:1,operations:ops,keys:vec![Key{address:address.as_bytes().to_vec(),weight:1}],..Default::default()};(RawWireTransaction::decode(bytes).unwrap(),permission)}
fn signature<'a>(permission:&'a Permission)->SignatureAdmission<'a>{SignatureAdmission{permission:Some(permission),default_owner:None,default_active_operations:None,ownerless_shielded:false}}
fn clock(now:i64)->AdmissionClock{AdmissionClock{head_block_time:500,next_block_slot_time:600,now,block_number:10,head_slot:10}}

#[test]
fn admission_is_structural_and_side_effect_free_until_processor_persists(){let(mut tx,permission)=signed_wire(0,1_000,3,true);let raw=tx.raw_data_bytes().to_vec();let id=tx.transaction_id(CryptoEngine::Secp256k1);let validator=AdmissionValidator{policy:Default::default()};let accepted=validator.validate(&mut tx,AdmissionOrigin::Network,clock(1),signature(&permission),|key|(key==&[0xab,0xcd]).then(||vec![8,9,10,11,12,13,14,15])).unwrap();assert_eq!(accepted,id);assert_eq!(tx.raw_data_bytes(),raw);assert!(!tx.has_top_level_unknown_fields());assert_eq!(tx.message().ret.len(),1);let(mut again,_)=signed_wire(0,1_000,0,false);assert_eq!(validator.validate(&mut again,AdmissionOrigin::Network,clock(2),signature(&permission),|_|Some(vec![8,9,10,11,12,13,14,15])).unwrap(),id);}

#[test]
fn block_result_count_rejection_preserves_wire_bytes_and_network_normalizes(){
    let recent=|_:&[u8;2]|Some(vec![8,9,10,11,12,13,14,15]);
    for optimized in [false,true]{
        let(mut network,permission)=signed_wire(0,1_000,3,true);
        let validator=AdmissionValidator{policy:AdmissionPolicy{consensus_logic_optimization:optimized,..Default::default()}};
        validator.validate(&mut network,AdmissionOrigin::Network,clock(1),signature(&permission),recent).unwrap();
        assert_eq!(network.message().ret.len(),1,"network normalization must not depend on consensus optimization");
        assert!(!network.has_top_level_unknown_fields());

        let(mut block,permission)=signed_wire(0,1_000,3,true);
        let preserved=block.full_bytes().to_vec();
        let transaction_id=block.transaction_id(CryptoEngine::Secp256k1);
        let result=validator.validate(&mut block,AdmissionOrigin::Block,clock(1),signature(&permission),recent);
        if optimized{
            let expected=AdmissionError::BadBlockResultCount{result_count:3,transaction_id,contract_count:1};
            assert_eq!(result,Err(expected.clone()));
            assert_eq!(expected.to_string(),format!("The result count 3 of this transaction {transaction_id} is greater than its contract count 1"));
        }else{
            assert_eq!(result,Ok(transaction_id));
            assert_eq!(block.message().ret.len(),3);
        }
        assert_eq!(block.full_bytes(),preserved,"block admission must preserve the received transaction bytes");
        assert!(block.has_top_level_unknown_fields(),"block admission must preserve unknown top-level fields");
    }
}

#[test]
fn exact_structural_time_and_tapos_errors(){let raw=Raw{contract:vec![],expiration:10,..Default::default()};let mut empty=RawWireTransaction::decode(Transaction{raw_data:Some(raw),..Default::default()}.encode_to_vec()).unwrap();let v=AdmissionValidator{policy:Default::default()};assert_eq!(v.validate(&mut empty,AdmissionOrigin::Network,clock(0),SignatureAdmission{permission:None,default_owner:None,default_active_operations:None,ownerless_shielded:true},|_|None).unwrap_err(),AdmissionError::MissingContract);let(mut expired,p)=signed_wire(0,500,0,false);assert!(matches!(v.validate(&mut expired,AdmissionOrigin::Network,clock(1),signature(&p),|_|Some(vec![8,9,10,11,12,13,14,15])),Err(AdmissionError::Expired{..})));let(mut bad,p)=signed_wire(0,1000,0,false);assert!(matches!(v.validate(&mut bad,AdmissionOrigin::Network,clock(2),signature(&p),|_|Some(vec![0;8])),Err(AdmissionError::TaposHashMismatch{..})));}

#[test]
fn permission_ingress_operations_and_ownerless_rules(){let(tx,permission)=signed_wire(2,1000,0,false);let validator=AdmissionValidator{policy:AdmissionPolicy{duplicate_signer_policy:DuplicateSignerPolicy::CanonicalSignature,..Default::default()}};validator.validate_signatures(&tx,signature(&permission)).unwrap();let mut denied=permission.clone();denied.operations.fill(0);assert_eq!(validator.validate_signatures(&tx,signature(&denied)).unwrap_err(),AdmissionError::PermissionDenied);let mut unsigned=tx.message().clone();unsigned.signature.clear();let unsigned=RawWireTransaction::decode(unsigned.encode_to_vec()).unwrap();validator.validate_signatures(&unsigned,SignatureAdmission{permission:None,default_owner:None,default_active_operations:None,ownerless_shielded:true}).unwrap();assert_eq!(validator.validate_signatures(&tx,SignatureAdmission{permission:None,default_owner:None,default_active_operations:None,ownerless_shielded:true}).unwrap_err(),AdmissionError::UnexpectedTransparentSignature);}

#[test]
fn cache_is_bounded_ttl_checked_and_rotates_two_blooms(){let mut c=cache();let ids=(0..6).map(|n|tron_primitives::Hash32::from([n;32])).collect::<Vec<_>>();for(i,id)in ids.iter().enumerate().take(5){c.insert(*id,i as i64,i as i64).unwrap()}assert_eq!(c.len(),4);assert!(!c.contains_recent(&ids[0],5).unwrap());assert!(c.might_contain(&ids[4],5).unwrap());assert!(!c.contains_recent(&ids[4],105).unwrap());assert!(matches!(c.contains_recent(&ids[4],104),Err(CacheError::TimeReversal{..})));}
