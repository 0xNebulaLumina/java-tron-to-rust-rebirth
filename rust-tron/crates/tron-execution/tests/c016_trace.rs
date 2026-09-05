use tron_execution::*;
use tron_protocol::protocol::transaction::result::ContractResult as ProtoResult;
use tron_state::{global_limit, GlobalResource, ResourceWindow};
use tron_tvm::{ContractResult,ExecutionOutcome,ExitStatus,VmFault};

#[test]
fn bandwidth_frozen_free_fee_and_metadata_order(){
 let policy=BandwidthPolicy{total_net_limit:1000,total_net_weight:1,free_net_limit:100,public_net_limit:100,transaction_fee:2,multi_sign_fee:7,memo_fee:11,..BandwidthPolicy::default()};
 let mut account=BandwidthAccount{address:vec![0x41;21],balance:1000,frozen_bandwidth:1_000_000,..BandwidthAccount::default()};let mut public=PublicBandwidth::default();
 assert_eq!(consume_bandwidth(&mut account,&mut public,40,1,3,false,0,policy).unwrap().source,BandwidthSource::Frozen);
 account.frozen_bandwidth=0;
 assert_eq!(consume_bandwidth(&mut account,&mut public,40,2,4,false,0,policy).unwrap().source,BandwidthSource::Free);
 account.free_net_usage=100;public.usage=100;
 let paid=consume_bandwidth(&mut account,&mut public,40,2,4,false,0,policy).unwrap();assert_eq!((paid.source,paid.net_fee,account.balance),(BandwidthSource::Fee,80,920));
 assert_eq!(charge_metadata_fees(&mut account,2,true,policy).unwrap(),(7,11));assert_eq!(account.balance,902);
}

#[test]
fn energy_origin_caller_split_and_destinations_are_exact(){
 let mut receipt=Receipt::default();receipt.set_bill(100);receipt.resource.result=ProtoResult::Success as i32;receipt.origin_energy_left=100;receipt.caller_energy_left=30;
 let origin_account=EnergyAccount{address:vec![1],frozen_energy_left:100,..EnergyAccount::default()};let mut origin=EnergyOrigin::Distinct(origin_account);let mut caller=EnergyAccount{address:vec![2],balance:1000,frozen_energy_left:30,..EnergyAccount::default()};let mut totals=BillingTotals::default();
 receipt.pay_energy_bill(&mut origin,&mut caller,40,25,EnergyBillingPolicy{energy_price:10,transaction_fee_pool:true,..EnergyBillingPolicy::default()},&mut totals).unwrap();
 let EnergyOrigin::Distinct(origin)=origin else{panic!("distinct origin changed relationship")};assert_eq!((receipt.resource.origin_energy_usage,receipt.resource.energy_usage,receipt.resource.energy_fee),(25,30,450));assert_eq!((origin.frozen_energy_left,caller.frozen_energy_left,caller.balance,totals.transaction_fee_pool),(75,0,550,450));
 receipt.resource.result=ProtoResult::OutOfTime as i32;receipt.resource.energy_usage_total=1;receipt.caller_energy_left=0;caller.frozen_energy_left=0;let mut origin=EnergyOrigin::Absent;
 receipt.pay_energy_bill(&mut origin,&mut caller,0,0,EnergyBillingPolicy{energy_price:10,allow_constantinople:true,transaction_fee_pool:true,blackhole_optimization:true,..EnergyBillingPolicy::default()},&mut totals).unwrap();assert_eq!(totals.burned,10);
}

#[test]
fn same_origin_charges_caller_before_and_after_constantinople() {
 for allow in [false,true] { let mut receipt=Receipt::default();receipt.set_bill(7);receipt.caller_energy_left=7;let mut origin=EnergyOrigin::SameAsCaller;let mut caller=EnergyAccount{address:vec![1],frozen_energy_left:7,..Default::default()};let mut totals=BillingTotals::default();receipt.pay_energy_bill(&mut origin,&mut caller,100,7,EnergyBillingPolicy{allow_constantinople:allow,..Default::default()},&mut totals).unwrap();assert_eq!(receipt.resource.energy_usage,7);assert_eq!(receipt.resource.origin_energy_usage,0);assert_eq!(caller.frozen_energy_left,0);assert_eq!(origin,EnergyOrigin::SameAsCaller); }
}

#[test]
fn absent_origin_is_the_only_constantinople_gated_relationship() {
 let mut receipt=Receipt::default();receipt.set_bill(1);receipt.caller_energy_left=1;let mut caller=EnergyAccount{address:vec![1],frozen_energy_left:1,..Default::default()};let mut totals=BillingTotals::default();let mut absent=EnergyOrigin::Absent;
 assert_eq!(receipt.pay_energy_bill(&mut absent,&mut caller,0,0,EnergyBillingPolicy{allow_constantinople:false,..Default::default()},&mut totals),Err(ReceiptError::MissingOrigin));
 assert_eq!((caller.frozen_energy_left,receipt.resource.energy_usage),(1,0));
}

#[test]
fn energy_recovery_and_global_limit_edges_are_exact() {
 let missed=ResourceWindow{usage:28_800,latest_slot:10,window:0,precise:false,standard_window:28_800};assert_eq!(missed.recover(11).unwrap(),28_798);assert_eq!(missed.recover(28_810).unwrap(),0);
 let consumed=missed.consume(100,11).unwrap();assert_eq!((consumed.usage,consumed.latest_slot,consumed.window,consumed.precise),(28_898,11,28_800,false));
 assert_eq!(global_limit(1_999_999,GlobalResource{limit:10,weight:2},false).unwrap(),5);assert_eq!(global_limit(1_999_999,GlobalResource{limit:10,weight:2},true).unwrap(),9);assert_eq!(global_limit(1_000_000,GlobalResource{limit:10,weight:0},true).unwrap(),0);assert!(global_limit(i64::MAX,GlobalResource{limit:i64::MAX,weight:1},true).is_err());
}

#[test]
fn frozen_energy_recovers_once_before_each_charge() {
 let mut account=EnergyAccount{address:vec![1],frozen_energy_left:10_000,energy_usage:28_800,latest_consume_slot:10,energy_window:0,head_slot:11,..Default::default()};
 let mut receipt=Receipt::default();receipt.set_bill(100);receipt.caller_energy_left=10_000;let mut totals=BillingTotals::default();let mut origin=EnergyOrigin::Absent;
 receipt.pay_energy_bill(&mut origin,&mut account,0,0,EnergyBillingPolicy{allow_constantinople:true,..EnergyBillingPolicy::default()},&mut totals).unwrap();
 assert_eq!((account.energy_usage,account.latest_consume_slot,account.energy_window),(28_898,11,28_800));
 receipt.set_bill(100);receipt.caller_energy_left=account.frozen_energy_left;
 receipt.pay_energy_bill(&mut origin,&mut account,0,0,EnergyBillingPolicy{allow_constantinople:true,..EnergyBillingPolicy::default()},&mut totals).unwrap();
 assert_eq!((account.energy_usage,account.latest_consume_slot,account.energy_window,account.frozen_energy_left,receipt.resource.energy_fee),(28_998,11,28_800,9_800,0));
}

#[test]
fn bandwidth_v1_v2_hardened_and_legacy_formulas_are_distinct() {
 let base=BandwidthPolicy{total_net_limit:10,total_net_weight:2,..Default::default()};
 assert_eq!(global_net_limit(1_999_999,BandwidthPolicy{support_unfreeze_delay:false,harden_calculation:false,..base}).unwrap(),5);
 assert_eq!(global_net_limit(1_999_999,BandwidthPolicy{support_unfreeze_delay:false,harden_calculation:true,..base}).unwrap(),5);
 assert_eq!(global_net_limit(1_999_999,BandwidthPolicy{support_unfreeze_delay:true,harden_calculation:false,..base}).unwrap(),9);
 assert_eq!(global_net_limit(1_999_999,BandwidthPolicy{support_unfreeze_delay:true,harden_calculation:true,..base}).unwrap(),9);
 assert_eq!(unsigned_create_account_size(200,2).unwrap(),70);
}

fn process_context(origin:AdmissionOrigin,expected_result:Option<ContractResult>)->ProcessContext{ProcessContext{origin,clock:AdmissionClock{head_block_time:0,next_block_slot_time:0,now:0,block_number:0,head_slot:0},expected_result,block_timestamp:0}}
fn run_timeout_policy(context:&ProcessContext,second:ContractResult)->(RuntimeResult,bool,usize){let mut calls=0;let(result,retried)=run_with_out_of_time_retry(context.origin,context.expected_result,|retry|{calls+=1;let vm=if retry{if second==ContractResult::Success{ExecutionOutcome::success()}else{ExecutionOutcome::revert(Vec::new())}}else{ExecutionOutcome::fault(VmFault::OutOfTime)};Ok(RuntimeResult::from_vm(vm))}).unwrap();(result,retried,calls)}

#[test]
fn retry_and_witness_policy_match_java(){let context=process_context(AdmissionOrigin::Block,Some(ContractResult::Success));let(result,retried,calls)=run_timeout_policy(&context,ContractResult::Success);assert!(retried);assert_eq!(calls,2);assert_eq!(result.vm.unwrap().contract_result,ContractResult::Success);assert!(check_witness_result(Some(ContractResult::Success),ContractResult::Success,true).is_ok());}

#[test]
fn network_vm_success_without_expected_result_skips_witness_comparison(){let context=process_context(AdmissionOrigin::Network,None);let mut trace=TransactionTrace::new(TraceKind::Trigger);trace.set_runtime(RuntimeResult::from_vm(ExecutionOutcome::success()));assert!(!trace.needs_out_of_time_retry(context.origin,context.expected_result));assert!(trace.check_witness(context.expected_result).is_ok());assert!(check_witness_result(None,ContractResult::Success,true).is_ok());}

#[test]
fn network_out_of_time_executes_once(){let context=process_context(AdmissionOrigin::Network,None);let(result,retried,calls)=run_timeout_policy(&context,ContractResult::Success);assert!(!retried);assert_eq!(calls,1);assert_eq!(result.vm.unwrap().contract_result,ContractResult::OutOfTime);}

#[test]
fn block_without_expected_result_retries_but_skips_witness_comparison(){let context=process_context(AdmissionOrigin::Block,None);let(result,retried,calls)=run_timeout_policy(&context,ContractResult::Success);assert!(retried);assert_eq!(calls,2);let actual=result.vm.unwrap().contract_result;assert_eq!(actual,ContractResult::Success);assert!(check_witness_result(context.expected_result,actual,true).is_ok());}

#[test]
fn signed_block_witness_match_and_mismatch_are_enforced(){let matching=process_context(AdmissionOrigin::Block,Some(ContractResult::Success));assert!(check_witness_result(matching.expected_result,ContractResult::Success,true).is_ok());let mismatch=process_context(AdmissionOrigin::Block,Some(ContractResult::Revert));assert!(check_witness_result(mismatch.expected_result,ContractResult::Success,true).is_err());let(_,retried,calls)=run_timeout_policy(&mismatch,ContractResult::Success);assert!(retried);assert_eq!(calls,2);}

#[test]
fn exact_ret_receipt_and_transaction_info_ordering(){
 let actuator=tron_execution::ActuatorResult{fee:3,code:tron_protocol::protocol::transaction::result::Code::Sucess,asset_issue_id:b"7".to_vec(),withdraw_amount:4,unfreeze_amount:5,exchange_id:6,order_id:vec![9],..Default::default()};
 let mut vm=ExecutionOutcome::success();vm.return_data=vec![1,2];vm.energy_used=8;vm.energy_penalty=2;
 let mut trace=TransactionTrace::new(TraceKind::Trigger);trace.receipt.resource.net_fee=10;trace.receipt.resource.energy_fee=20;trace.receipt.multi_sign_fee=30;trace.receipt.memo_fee=40;trace.set_runtime(RuntimeResult{actuator:actuator.clone(),vm:Some(vm),runtime_error:String::new()});
 let ret=trace.transaction_result().unwrap();assert_eq!((ret.fee,ret.asset_issue_id,ret.contract_ret),(3,"7".into(),ProtoResult::Success as i32));
 let info=trace.transaction_info([3;32],Some((11,12)),true,false,true).unwrap();assert_eq!((info.fee,info.packing_fee,info.block_number,info.block_time_stamp),(103,30,11,12));assert_eq!(info.contract_result,vec![vec![1,2]]);assert_eq!(info.receipt.unwrap().energy_penalty_total,2);
}

#[test]
fn packing_fee_obeys_live_flag_eligibility_and_out_of_time() {
 let mut receipt=Receipt::default();receipt.resource.net_fee=11;receipt.resource.energy_fee=13;receipt.multi_sign_fee=17;receipt.memo_fee=19;receipt.resource.result=ProtoResult::Success as i32;
 assert_eq!(receipt.packing_fee(false,true),0);assert_eq!(receipt.packing_fee(true,true),24);assert_eq!(receipt.packing_fee(true,false),13);
 receipt.resource.result=ProtoResult::OutOfTime as i32;assert_eq!(receipt.packing_fee(true,true),11);assert_eq!(receipt.packing_fee(true,false),0);
}


#[test]
fn ownership_case_table_is_exact_and_row_specific() {
 let document:serde_json::Value=serde_json::from_str(include_str!("../../../../docs/oracles/c016-ownership-reconciliation.v1.json")).unwrap();let rows=document["rows"].as_array().unwrap();let cases=document["case_table"].as_array().unwrap();assert_eq!((rows.len(),cases.len()),(66,66));let mut ids=std::collections::BTreeSet::new();for (row,case) in rows.iter().zip(cases){assert_eq!(case["case_id"],row["case_id"]);assert_eq!(case["behavior_id"],row["behavior_id"]);assert_eq!(case["java_symbol"],row["java_symbol"]);assert_eq!(case["rust_dispatch"],row["rust_dispatch"]);assert!(ids.insert(case["case_id"].as_str().unwrap()));}assert_eq!(ids.len(),66);
}
#[test]
fn negative_bill_and_penalty_clamp_to_zero(){let mut receipt=Receipt::default();receipt.set_bill(-1);receipt.set_penalty(-2);assert_eq!((receipt.resource.energy_usage_total,receipt.resource.energy_penalty_total),(0,0));let fault=RuntimeResult::from_vm(ExecutionOutcome{status:ExitStatus::Faulted(VmFault::InvalidCode),..ExecutionOutcome::success()});assert_eq!(fault.vm.unwrap().status,ExitStatus::Faulted(VmFault::InvalidCode));}
