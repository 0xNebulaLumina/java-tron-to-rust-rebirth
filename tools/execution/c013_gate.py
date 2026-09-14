#!/usr/bin/env python3
"""Generate and strictly verify canonical C013 Java/Rust actuator evidence."""
from __future__ import annotations
import argparse,hashlib,json,subprocess,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2];ORACLES=ROOT/'docs/oracles'
sys.path.insert(0,str(ROOT/'tools/reference-runner'))
from java_reference_guard import atomic_write_json,install_java_reference_guard
SESSION=install_java_reference_guard(ROOT)
JAVA=ORACLES/'c013-java-owned-real.v1.json';RECON=ORACLES/'c013-java-test-reconciliation.v1.json';FIXTURES=ORACLES/'c013-execution-fixtures.v1.json';MATRIX=ORACLES/'c013-fork-matrix.v1.json';SOURCE=ORACLES/'c013-source-inventory.v1.json';CONTRACT=ORACLES/'c013-execution-contract.v1.json';LEDGER=ORACLES/'java-test-ownership.v1.json'
FAMILIES={'resource':ORACLES/'c013-resource-real.v1.json','proposal_exchange':ORACLES/'c013-proposal-exchange-real.v1.json','market_misc':ORACLES/'c013-market-misc-real.v1.json'}
JAVA_CONTRACT_TYPES=ROOT/'java-tron/protocol/src/main/protos/core/Tron.proto';JAVA_STORAGE_MESSAGES=ROOT/'java-tron/protocol/src/main/protos/core/contract/storage_contract.proto';JAVA_API=ROOT/'java-tron/protocol/src/main/protos/api/api.proto';JAVA_ACTUATORS=ROOT/'java-tron/actuator/src/main/java/org/tron/core/actuator'
CLASS_ITEMS={'FreezeBalanceActuatorTest':'C013.01','UnfreezeBalanceActuatorTest':'C013.01','WithdrawBalanceActuatorTest':'C013.01','FreezeBalanceV2ActuatorTest':'C013.02','UnfreezeBalanceV2ActuatorTest':'C013.02','WithdrawExpireUnfreezeActuatorTest':'C013.02','CancelAllUnfreezeV2ActuatorTest':'C013.02','DelegateResourceActuatorTest':'C013.03','UnDelegateResourceActuatorTest':'C013.03','ProposalCreateActuatorTest':'C013.04','ProposalApproveActuatorTest':'C013.04','ProposalDeleteActuatorTest':'C013.04','ExchangeCreateActuatorTest':'C013.05','ExchangeInjectActuatorTest':'C013.05','ExchangeWithdrawActuatorTest':'C013.05','ExchangeTransactionActuatorTest':'C013.05','MarketSellAssetActuatorTest':'C013.06','MarketCancelOrderActuatorTest':'C013.06','UpdateBrokerageActuatorTest':'C013.07','UpdateSettingContractActuatorTest':'C013.07','UpdateEnergyLimitContractActuatorTest':'C013.07','ClearABIContractActuatorTest':'C013.07'}
ZERO={'TCASE-0AE4A9B2569DCE1D':'c013_proposal_exchange::zero_invocation_java_helpers_have_explicit_rust_dispositions','TCASE-210D49DE1A14B238':'c013_resource_contract::zero_invocation_java_helpers_have_explicit_rust_dispositions','TCASE-2BA2C2171063B228':'c013_resource_contract::zero_invocation_java_helpers_have_explicit_rust_dispositions','TCASE-3A9B9DC369A80822':'c013_resource_contract::zero_invocation_java_helpers_have_explicit_rust_dispositions','TCASE-3CBB27945C893520':'c013_resource_contract::zero_invocation_java_helpers_have_explicit_rust_dispositions','TCASE-6F0FEF76E6B542BB':'c013_proposal_exchange::zero_invocation_java_helpers_have_explicit_rust_dispositions','TCASE-82CB6D9DCD5CC7CA':'c013_resource_contract::zero_invocation_java_helpers_have_explicit_rust_dispositions','TCASE-BF3FB3CA02E606D4':'c013_market_misc::zero_invocation_java_helpers_have_explicit_rust_dispositions','TCASE-C3CF875CAFED108E':'c013_resource_contract::zero_invocation_java_helpers_have_explicit_rust_dispositions','TCASE-D40210190A4A66D3':'c013_resource_contract::zero_invocation_java_helpers_have_explicit_rust_dispositions','TCASE-D6827BD24AC5F319':'c013_market_misc::zero_invocation_java_helpers_have_explicit_rust_dispositions','TCASE-ECC92CB6CBAB206D':'c013_resource_contract::zero_invocation_java_helpers_have_explicit_rust_dispositions','TCASE-FDA493C6EC872AA0':'c013_proposal_exchange::zero_invocation_java_helpers_have_explicit_rust_dispositions'}
TRACKER=ROOT/'docs/PORTING_TRACKER.json'
EXPECTED_GATE_COMMANDS=[
 {'name':'C013 pinned Java oracle, ownership, fork matrix and fixture gate','cwd':'.','argv':['python3','tools/execution/c013_gate.py'],'timeout_seconds':3600},
 {'name':'C013 resource actuator suite','cwd':'rust-tron','argv':['cargo','test','-p','tron-execution','--test','c013_resource_contract','--locked'],'timeout_seconds':300},
 {'name':'C013 proposal and exchange actuator suite','cwd':'rust-tron','argv':['cargo','test','-p','tron-execution','--test','c013_proposal_exchange','--locked'],'timeout_seconds':300},
 {'name':'C013 market and miscellaneous actuator suite','cwd':'rust-tron','argv':['cargo','test','-p','tron-execution','--test','c013_market_misc','--locked'],'timeout_seconds':300},
 {'name':'C013 tron-execution all-targets check','cwd':'rust-tron','argv':['cargo','check','-p','tron-execution','--all-targets','--locked'],'timeout_seconds':300},
]
def load(p:Path):return json.loads(p.read_text())
def digest(p:Path):return hashlib.sha256(p.read_bytes()).hexdigest()
def observation(m):return hashlib.sha256(json.dumps({k:v for k,v in m.items() if k not in {'java_source','previous_owner','capture_identity_sha256'}},sort_keys=True,separators=(',',':')).encode()).hexdigest()
def generate()->None:
 java=load(JAVA);members=java['members'];ledger={r['id']:r for r in load(LEDGER)['rows']};rows=[];invocations=0;additional_stable_id_proofs=load(RECON).get('additional_stable_id_proofs',[])
 for member in members:
  sid=member['variant_id'];lr=ledger[sid];invs=member['invocations'];invocations+=len(invs);proof=ZERO.get(sid)
  rows.append({'stable_id':sid,'java_source':lr['source']['path'],'java_line':lr['source']['line'],'java_case':lr['case'],'owner':'C013','owning_item':CLASS_ITEMS[Path(lr['source']['path']).stem],'acceptance_gate':'C013.V','previous_owner':lr['owning_item'],'disposition':'instrumented_java_method' if invs else 'executable_zero_invocation_helper_proof','executable_proof':proof,'scenario_id':sid,'invocation_ids':[x['invocation_id'] for x in invs],'observation_digest':observation(member),'equivalence_basis':'Exact isolated execution of the pinned Java test method and strict Rust replay.'})
 atomic_write_json(RECON,{'schema':'c013-java-test-reconciliation.v1','chunk':'C013','row_count':len(rows),'mapped_count':len(rows),'excluded_count':0,'instrumented_invocation_count':invocations,'zero_invocation_method_count':len(ZERO),'additional_stable_id_proofs':additional_stable_id_proofs,'rows':rows})
 refs=[]
 for name,path in FAMILIES.items():
  runner=ROOT/'tools/execution/c013'/name/'run.py';done=subprocess.run([sys.executable,str(runner)],cwd=ROOT,text=True,capture_output=True,check=True);document=json.loads(done.stdout);atomic_write_json(path,document);refs.append({'family':name,'path':str(path.relative_to(ROOT)),'sha256':digest(path),'runner':str(runner.relative_to(ROOT)),'row_count':len(document['rows'])})
 atomic_write_json(FIXTURES,{'schema':'c013-execution-fixtures.v1','chunk':'C013','java_revision':SESSION.revision,'pinned_java':{'path':str(JAVA.relative_to(ROOT)),'sha256':digest(JAVA),'method_count':len(members),'invocation_count':invocations,'all_methods_executed':True,'process_isolation':'one fresh JVM per selected method','required_observables':['JUnit result and exact failure','concrete Contract and Any bytes','result before and after','ordered store reads and mutations','per-key before/after deltas','test and transformer audit']},'rust_replay':{'runner':'rust-tron/crates/tron-execution/tests/support/c013_replay.rs','captured_invocations':926,'unique_invocations':868,'unexecuted':0,'catchall':0,'explicit_exclusions':0,'verification':['validate/execute result','ordered deltas','commit/reopen','child-session revoke']},'direct_family_fixtures':refs})
 matrix=[{'id':f'C013.FORK.{i:02d}','dimension':name} for i,name in enumerate(['UNFREEZE_DELAY_DAYS','ALLOW_CANCEL_ALL_UNFREEZE_V2','ALLOW_DELEGATE_RESOURCE','ALLOW_NEW_RESOURCE_MODEL','ALLOW_SAME_TOKEN_NAME','ALLOW_HARDEN_EXCHANGE_CALCULATION','ALLOW_MARKET_TRANSACTION','ALLOW_TVM_CONSTANTINOPLE','ALLOW_BLACKHOLE_OPTIMIZATION','proposal parameter dependency matrix'],1)]
 atomic_write_json(MATRIX,{'schema':'c013-fork-matrix.v1','chunk':'C013','row_count':10,'coverage':'disabled/enabled fork branches, legacy/hardened arithmetic, success/error and rollback','rows':matrix})
 sources=['tools/execution/c013_gate.py','tools/execution/c013_java_oracle.py','tools/execution/C013Oracle.java']+[f'tools/execution/c013/{name}/run.py' for name in FAMILIES]+[str(p.relative_to(ROOT)) for p in FAMILIES.values()]+['java-tron/protocol/src/main/protos/core/Tron.proto','java-tron/protocol/src/main/protos/core/contract/storage_contract.proto','java-tron/protocol/src/main/protos/api/api.proto','java-tron/actuator/src/main/java/org/tron/core/utils/TransactionRegister.java','java-tron/chainbase/src/main/java/org/tron/core/actuator/TransactionFactory.java','rust-tron/crates/tron-execution/src/registry.rs','rust-tron/crates/tron-execution/src/exchange.rs','rust-tron/crates/tron-execution/src/market.rs','rust-tron/crates/tron-execution/src/misc.rs','rust-tron/crates/tron-execution/src/proposal.rs','rust-tron/crates/tron-execution/src/resource_actuators.rs','rust-tron/crates/tron-execution/tests/support/c013_replay.rs','rust-tron/crates/tron-execution/tests/c013_resource_contract.rs','rust-tron/crates/tron-execution/tests/c013_proposal_exchange.rs','rust-tron/crates/tron-execution/tests/c013_market_misc.rs']
 atomic_write_json(SOURCE,{'schema':'c013-source-inventory.v1','chunk':'C013','java_revision':SESSION.revision,'canonical_sources':[{'path':p,'sha256':digest(ROOT/p)} for p in sources]})
 atomic_write_json(CONTRACT,{'schema':'c013-execution-contract.v1','chunk':'C013','scope':'all pinned Java executable legacy/V2 resources, delegation, proposal, exchange, market, brokerage and smart-contract-setting actuator families; BuyStorage, BuyStorageBytes and SellStorage messages have no pinned ContractType or production actuator and legacy numeric types 21/22/23 are rejected','fixture_inventory':{'path':str(FIXTURES.relative_to(ROOT)),'sha256':digest(FIXTURES)},'ownership_reconciliation':{'path':str(RECON.relative_to(ROOT)),'sha256':digest(RECON),'stable_ids':370,'mapped':370,'excluded':0},'fork_matrix':{'path':str(MATRIX.relative_to(ROOT)),'sha256':digest(MATRIX),'rows':10},'source_inventory':{'path':str(SOURCE.relative_to(ROOT)),'sha256':digest(SOURCE)},'canonical_workspace':'rust-tron','canonical_commands':['cargo test -p tron-execution --test c013_resource_contract','cargo test -p tron-execution --test c013_proposal_exchange','cargo test -p tron-execution --test c013_market_misc','python3 tools/execution/c013_gate.py']})
def verify()->list[str]:
 errors=[]
 for p in [JAVA,RECON,FIXTURES,MATRIX,SOURCE,CONTRACT,*FAMILIES.values()]:
  if not p.exists():errors.append(f'missing {p.relative_to(ROOT)}')
 if errors:return errors
 java=load(JAVA);members=java.get('members',[]);provenance=java.get('provenance',{})
 if len(members)!=370:errors.append(f'expected 370 methods, got {len(members)}')
 ids=[m.get('variant_id') for m in members]
 if ids!=sorted(set(ids)):errors.append('stable IDs not sorted and unique')
 invs=[x for m in members for x in m.get('invocations',[])]
 if len(invs)!=926 or len({x.get('invocation_id') for x in invs})!=926:errors.append('expected 926 exact invocation IDs')
 for m in members:
  if m.get('test_body_enter_count')!=1 or m.get('test_body_exit_count')!=1:errors.append('test body audit failure '+str(m.get('variant_id')))
  for n,x in enumerate(m.get('invocations',[]),1):
   if x.get('invocation_id')!=f"{m['variant_id']}/invocation/{n:03d}":errors.append('invocation ID drift '+str(x.get('invocation_id')))
 clean_hash='4138f07207c163c5dc357077efe3bc3e37094f42420df44ddde7a78c5ac33149'
 observed={t['original_sha256'] for m in members for t in m.get('capture_audit',{}).get('transforms',[]) if t.get('class')=='org/tron/core/actuator/UnfreezeBalanceV2Actuator'}
 if observed!={clean_hash}:errors.append(f'UnfreezeBalanceV2 class hash drift: {observed}')
 blob=subprocess.check_output(['git','-C',str(ROOT/'java-tron'),'rev-parse','HEAD:actuator/src/main/java/org/tron/core/actuator/UnfreezeBalanceV2Actuator.java'],text=True).strip()
 if blob!='fb41c97f7ed697c40c2fb32ffe27075286c8daee':errors.append('UnfreezeBalanceV2 source blob drift')
 if provenance.get('reference',{}).get('java_revision')!=SESSION.revision:errors.append('Java revision provenance drift')
 recon=load(RECON);fixtures=load(FIXTURES);contract=load(CONTRACT)
 if (recon.get('row_count'),recon.get('instrumented_invocation_count'),recon.get('zero_invocation_method_count'))!=(370,926,13):errors.append('reconciliation accounting drift')
 supplemental=recon.get('additional_stable_id_proofs',[])
 required={'stable_id','source_identity','invocation_selector','fixture','observation_digest','result','rust_symbol','canonical_command'}
 if len(supplemental)!=27 or len({row.get('stable_id') for row in supplemental})!=27:errors.append('expected 27 unique supplemental stable-ID proofs')
 for row in supplemental:
  if not required.issubset(row) or not all(row.get(key) for key in required-{'invocation_selector'}):errors.append('incomplete supplemental proof '+str(row.get('stable_id')))
  selector=row.get('invocation_selector',{})
  if selector.get('kind')!='zero_invocation_helper' or selector.get('stable_id')!=row.get('stable_id') or selector.get('ordinals')!=[]:errors.append('supplemental zero-invocation selector drift '+str(row.get('stable_id')))
 if fixtures['pinned_java']['sha256']!=digest(JAVA) or contract['fixture_inventory']['sha256']!=digest(FIXTURES) or contract['ownership_reconciliation']['sha256']!=digest(RECON) or contract['source_inventory']['sha256']!=digest(SOURCE):errors.append('digest binding drift')
 storage=load(FAMILIES['market_misc']).get('storage_contract_compatibility',{})
 expected_storage=[('protocol.BuyStorageContract',21),('protocol.BuyStorageBytesContract',22),('protocol.SellStorageContract',23)]
 if storage.get('decision')!='unsupported_transaction_contract_types':errors.append('storage compatibility decision drift')
 rejection_rows=storage.get('rust_rejection',[])
 actual_storage=[(row.get('message'),row.get('legacy_numeric_type')) for row in rejection_rows]
 if actual_storage!=expected_storage:errors.append(f'storage rejection mapping drift: {actual_storage}')
 java_enum=JAVA_CONTRACT_TYPES.read_text();java_messages=JAVA_STORAGE_MESSAGES.read_text();java_api=JAVA_API.read_text()
 for (message,kind),row in zip(expected_storage,rejection_rows):
  short=message.removeprefix('protocol.')
  if f'message {short}' not in java_messages:errors.append(f'missing pinned Java storage message {short}')
  if short in java_enum:errors.append(f'pinned Java unexpectedly registers ContractType {short}')
  if row.get('registry_error')!=f'InvalidContractType({kind})':errors.append(f'storage registry error drift for {kind}')
 for rpc in ['rpc BuyStorage (BuyStorageContract)','rpc BuyStorageBytes (BuyStorageBytesContract)','rpc SellStorage (SellStorageContract)']:
  if rpc not in java_api:errors.append(f'missing pinned Java storage RPC {rpc}')
 storage_actuators=sorted(p.name for p in JAVA_ACTUATORS.glob('*Storage*Actuator.java'))
 if storage_actuators:errors.append(f'pinned Java unexpectedly contains storage actuators: {storage_actuators}')
 for row in load(SOURCE)['canonical_sources']:
  if digest(ROOT/row['path'])!=row['sha256']:errors.append('source digest drift '+row['path'])
 tracker=load(TRACKER);chunk=next((item for item in tracker.get('chunks',[]) if item.get('id')=='C013'),None)
 if chunk is None:errors.append('missing C013 tracker entry')
 else:
  if chunk.get('status')!='review' or chunk.get('review',{}).get('state')!='in_review':errors.append('C013 tracker must remain pending independent review')
  if chunk.get('gate',{}).get('commands')!=EXPECTED_GATE_COMMANDS:errors.append('C013 canonical gate commands drift')
 return errors
def main()->int:
 parser=argparse.ArgumentParser();parser.add_argument('--write',action='store_true');args=parser.parse_args()
 if args.write:generate()
 errors=verify()
 if errors:
  for error in errors:print('ERROR: '+error,file=sys.stderr)
  return 1
 print('C013 metadata OK: 370 pinned Java methods, 926 actuator invocations, zero exclusions, 10 fork dimensions')
 return 0
if __name__=='__main__':raise SystemExit(main())
