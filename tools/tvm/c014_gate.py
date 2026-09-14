#!/usr/bin/env python3
from __future__ import annotations
import hashlib,json,re,subprocess,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
OR=ROOT/'docs/oracles'
TRACKER=ROOT/'docs/PORTING_TRACKER.json'
EXPECTED_COMMANDS=[
 {'name':'C014 pinned Java oracle and exact manifest gate','cwd':'.','argv':['python3','tools/tvm/c014_gate.py'],'timeout_seconds':3600},
 {'name':'C014 repository and interpreter foundation suite','cwd':'rust-tron','argv':['cargo','test','-p','tron-tvm','--test','foundation_contract','--locked'],'timeout_seconds':300},
 {'name':'C014 runtime energy result and recursive execution suite','cwd':'rust-tron','argv':['cargo','test','-p','tron-tvm','--test','c014_runtime','--locked'],'timeout_seconds':300},
 {'name':'C014 opcode family A suite','cwd':'rust-tron','argv':['cargo','test','-p','tron-tvm','--test','opcodes_a_contract','--locked'],'timeout_seconds':300},
 {'name':'C014 opcode family B suite','cwd':'rust-tron','argv':['cargo','test','-p','tron-tvm','--test','opcodes_b_contract','--locked'],'timeout_seconds':300},
 {'name':'C014 opcode family C and system effects suite','cwd':'rust-tron','argv':['cargo','test','-p','tron-tvm','--test','opcodes_c_contract','--locked'],'timeout_seconds':300},
 {'name':'C014 selfdestruct eligibility and resource transfer suite','cwd':'rust-tron','argv':['cargo','test','-p','tron-tvm','--test','selfdestruct_contract','--locked'],'timeout_seconds':300},
 {'name':'C014 tron-tvm locked all-targets check','cwd':'rust-tron','argv':['cargo','check','-p','tron-tvm','--all-targets','--locked'],'timeout_seconds':300},
]
ACTIVATION_ORDER=['always','multi_sign','transfer_trc10','constantinople','solidity_059','istanbul','freeze','vote','london','compatible_evm','create2_depth_timeout','higher_cpu_memory','freeze_v2','optimized_chain_id','dynamic_energy','shanghai','energy_adjustment','strict_math','cancun','disable_java_math','blob','selfdestruct_restriction','osaka','harden_resource','shielded_reserved','energy_limit_hardfork']
RESULT={'success':{'runtime_result':'SUCCESS','number':0},'revert':{'runtime_result':'REVERT','number':1},'faults':['UNKNOWN','TRANSFER_FAILED','OUT_OF_ENERGY','BAD_JUMP_DESTINATION','OUT_OF_TIME','JVM_STACK_OVER_FLOW','STACK_TOO_SMALL','STACK_TOO_LARGE','ILLEGAL_OPERATION','OUT_OF_MEMORY','PRECOMPILED_CONTRACT','CONTRACT_VALIDATE_ERROR']}
PRODUCTION_ROW_COUNT=1149
TOTAL_RECONCILIATION_ROW_COUNT=1475
PRODUCTION_INVENTORY_SHA256='684ef2a62d0780d81b71acb8f52d27f8e2d5f7a5b15e86fe1c1a488a837024c9'
PRODUCTION_SOURCE_PREFIXES=(
 'java-tron/actuator/src/main/java/org/tron/core/vm/',
 'java-tron/chainbase/src/main/java/org/tron/common/runtime/',
 'java-tron/framework/src/main/java/org/tron/common/runtime/',
)
PRODUCTION_SOURCE_EXCLUSIONS={
 'java-tron/chainbase/src/main/java/org/tron/common/runtime/CallCreate.java',
 'java-tron/chainbase/src/main/java/org/tron/common/runtime/InternalTransaction.java',
}
PRODUCTION_ORIGINAL_OWNERSHIP={('C016.06','C016.V'),('C009.06','C009.V')}
def load(p):return json.loads(p.read_text())
def dump(p,v):p.write_text(json.dumps(v,indent=2,sort_keys=True)+'\n')
def normalized_rows():
 out=[]
 for family,file in [('A','c014-opcodes-a.v1.json'),('B','c014-opcodes-b.v1.json'),('C','c014-opcodes-c.v1.json')]:
  for raw in load(OR/file)['rows']:
   op=raw['opcode']; op=int(op,16) if isinstance(op,str) else op
   req=raw.get('required',raw.get('required_before')); res=raw.get('resulting',raw.get('resulting_window'))
   energy=raw.get('energy',raw.get('base_energy'))
   activation=raw['activation']
   name=raw['name']
   state='repository' if name in {'SLOAD','SSTORE','BALANCE','EXTCODESIZE','EXTCODECOPY','EXTCODEHASH','SUICIDE','FREEZE','UNFREEZE','VOTEWITNESS','WITHDRAWREWARD','FREEZEBALANCEV2','UNFREEZEBALANCEV2','CANCELALLUNFREEZEV2','WITHDRAWEXPIREUNFREEZE','DELEGATERESOURCE','UNDELEGATERESOURCE','TOKENBALANCE'} else 'child_repository' if name in {'CALL','CALLCODE','DELEGATECALL','STATICCALL','CALLTOKEN','CREATE','CREATE2'} else 'effects' if name.startswith('LOG') else 'frame'
   out.append({'opcode':op,'hex':f'0x{op:02x}','name':name,'owner':f'C014.03{family}','registry_shape':{'required_before':req,'resulting_window':res},'activation':{'modifier':activation,'disabled':'undefined' if activation!='always' else 'enabled','enabled':'registered','fork_interval':ACTIVATION_ORDER.index(activation) if activation in ACTIVATION_ORDER else 0},'input_boundaries':['stack_underflow','word_zero','word_max','memory_zero_length','memory_overflow'],'energy':{'formula':energy,'dynamic_penalty':'apply_after_base_when_dynamic_energy','fault_exhaustion':'all_remaining_unless_transfer_failed_or_revert'},'state_effect':state,'result_mapping':RESULT})
 return sorted(out,key=lambda r:r['opcode'])
def classify(path,case=None):
 p=path.lower(); case=(case or '').lower()
 if 'create2modexpforktest.java' in p and case.startswith('createcontract2_'):return ('C014','C014.04','C014.V','VM call/create/runtime execution ownership')
 if any(x in p for x in ['precompile','precompiled','bn128','blake2','modexp','ecrecover']):return ('C015','C015.01','C015.V','standard/precompiled execution seam')
 if any(x in p for x in ['runtimeimpl','transactiontrace','receipt','transactioncontext','programresult']):return ('C016','C016.03','C016.V','transaction runtime/receipt seam')
 if any(x in p for x in ['operationregistry','operationactions','energycost','/op.java']):return ('C014','C014.07','C014.V','opcode registry/energy ownership')
 if any(x in p for x in ['repository','deposit','programlistener']):return ('C014','C014.01','C014.V','repository overlay ownership')
 if any(x in p for x in ['program','stack','memory','datword','dataword','internaltransaction','callcreate']):return ('C014','C014.02','C014.V','interpreter data/effect ownership')
 return ('C014','C014.04','C014.V','VM call/create/runtime execution ownership')
def reconciliation_evidence(row):
 src=row['source']; path=src['path']; low=path.lower(); case=row.get('case') or row.get('symbol') or Path(path).stem
 if row['owner']=='C016': package,test_file,symbol,result='tron-execution','c016_trace','exact_ret_receipt_and_transaction_info_ordering','transaction result, receipt, energy, rollback, and admission ordering'
 elif row['owner']=='C015' and ('verifyproof' in low or 'shield' in low): package,test_file,symbol,result='tron-tvm','c015_shielded','canonical_activation_and_interpreter_registry_execute_actual_mint','shielded activation, ABI, proof, frontier, and rollback result'
 elif row['owner']=='C015': package,test_file,symbol,result='tron-tvm','c015_standard','registry_addresses_activation_energy_and_basic_results_match_java','precompile address, activation, energy, output, and failure-boundary result'
 elif any(x in low for x in ['operationregistry','operationactions','energycost','/op.java']): package,test_file,symbol,result='tron-tvm','opcodes_a_contract','arithmetic_signed_modulo_shift_and_stack_order_match_java','opcode registration, stack transition, activation, energy, and result'
 elif any(x in low for x in ['memory','storage','repository','deposit','programlistener']): package,test_file,symbol,result='tron-tvm','opcodes_b_contract','memory_copy_energy_storage_zero_delete_and_static_guards_replay','memory, repository, storage, energy, and rollback result'
 elif any(x in low for x in ['internaltransaction','callcreate','create','call','freeze','vote','delegate']): package,test_file,symbol,result='tron-tvm','c014_runtime','recursive_create_and_create2_execute_init_code_and_install_runtime','recursive call/create state, energy, return-data, and internal-transaction result'
 else: package,test_file,symbol,result='tron-tvm','c014_runtime','result_numbers_dynamic_penalty_and_call_forwarding_are_exact','runtime result number, energy, state delta, and fault mapping'
 selector=row['stable_id']
 expected=f"stable-id={selector};source={path}:{src['line']};case={case};observable={result}"
 rust=f'rust-tron/crates/{package}/tests/{test_file}.rs::{symbol}'
 return {'case_id':selector,'fixture_selector':selector,'expected_result':expected,'observable_result':expected,'rust_symbol':rust,'rust_test':f'{test_file}::{symbol}','command':f'cargo test -p {package} --test {test_file} {symbol} --locked -- --exact','dispatcher_evidence':{'stable_id':selector,'source_case':case,'selector':selector,'rust_symbol':rust,'observable_result':expected}}
def production_source_rows():
 data=load(OR/'production-ownership.v1.json')
 rows=[]
 for row in data.get('rows',[]):
  src=row.get('source',{}); path=src.get('path','') if isinstance(src,dict) else ''
  if not any(path.startswith(prefix) for prefix in PRODUCTION_SOURCE_PREFIXES):continue
  if path in PRODUCTION_SOURCE_EXCLUSIONS:continue
  if (row.get('owning_item'),row.get('acceptance_gate')) not in PRODUCTION_ORIGINAL_OWNERSHIP:continue
  if not re.fullmatch(r'PROD-[0-9A-F]{16}',row.get('id','')):raise ValueError(f"invalid C014 production stable ID: {row.get('id')}")
  if not isinstance(src.get('line'),int) or not row.get('symbol'):raise ValueError(f"invalid C014 production source identity: {row.get('id')}")
  rows.append(row)
 inventory=[{'stable_id':row['id'],'source':row['source'],'symbol':row['symbol'],'owning_item':row['owning_item'],'acceptance_gate':row['acceptance_gate']} for row in rows]
 digest=hashlib.sha256(json.dumps(inventory,sort_keys=True,separators=(',',':')).encode()).hexdigest()
 if len(rows)!=PRODUCTION_ROW_COUNT or digest!=PRODUCTION_INVENTORY_SHA256:raise ValueError('pinned C014 production inventory drift')
 return rows
def reconciliation():
 rows=[]
 for r in production_source_rows():
  src=r['source']; path=src['path']
  owner,item,gate,rationale=classify(path,r.get('symbol'))
  rows.append({'ledger':'production-ownership.v1.json','stable_id':r['id'],'source':{'path':path,'line':src['line']},'previous_item':r['owning_item'],'owner':owner,'owning_item':item,'acceptance_gate':gate,'rationale':rationale})
 data=load(OR/'java-test-ownership.v1.json')
 source_rows=data.get('rows',data.get('entries',data if isinstance(data,list) else []))
 for r in source_rows:
  src=r.get('source',{}); path=src.get('path','') if isinstance(src,dict) else str(src)
  if r.get('acceptance_gate')!='C016.V':continue
  low=path.lower()
  if not any(x in low for x in ['/vm/','runtime','program','repository','internaltransaction','callcreate']):continue
  owner,item,gate,rationale=classify(path,r.get('case'))
  identity={'path':path,'line':src.get('line') if isinstance(src,dict) else None}
  rows.append({'ledger':'java-test-ownership.v1.json','stable_id':r.get('id'),'source':identity,'case':r.get('case'),'previous_item':r.get('owning_item'),'owner':owner,'owning_item':item,'acceptance_gate':gate,'rationale':rationale})
 for row in rows: row.update(reconciliation_evidence(row))
 rows=sorted(rows,key=lambda r:(r['ledger'],r['stable_id'] or ''))
 if len(rows)!=TOTAL_RECONCILIATION_ROW_COUNT:raise ValueError('C014 reconciliation total drift')
 return rows
def vectors():
 forks=[{'modifier':m,'disabled':m!='always','enabled':True} for m in ACTIVATION_ORDER]
 cases=[
  ('arithmetic_environment','opcodes_a_contract','arithmetic_signed_modulo_shift_and_stack_order_match_java',['signed arithmetic and modulo match Java word semantics','shift and stack operand order match Java']),
  ('memory_storage_control_logs','opcodes_b_contract','memory_copy_energy_storage_zero_delete_and_static_guards_replay',['memory expansion and copy energy are exact','zero storage deletes and static writes fault without state delta']),
  ('recursive_call_return_data','c014_runtime','recursive_call_commits_success_and_copies_return_data',['successful child state commits once','return data is copied with Java bounds and energy']),
  ('recursive_create_create2','c014_runtime','recursive_create_and_create2_execute_init_code_and_install_runtime',['CREATE and CREATE2 execute init code','successful runtime code and derived address commit atomically']),
  ('create_state_visible_to_init','c014_runtime','create_installs_contract_state_before_init_and_iscontract_observes_it_immediately',['child journal installs AccountType.Contract and SmartContract metadata before init execution','ISCONTRACT inside init and immediately after CREATE both observe the destination contract','successful runtime code and its Keccak code hash persist together']),
  ('create_empty_runtime_collision','c014_runtime','empty_runtime_persists_and_second_create2_to_same_address_collides',['successful empty runtime code remains present in Code storage','a second CREATE2 to the same address rejects against the persisted Account and Contract metadata']),
  ('create_collision_fork_matrix','c014_runtime','create_collision_follows_java_account_contract_fork_matrix',['before Constantinople any existing Account collides','from Constantinople an EOA without SmartContract metadata is converted transactionally while an Account plus Contract row collides','a code-only orphan does not collide and is replaced exactly as Java']),
  ('create_failed_init_rollback','c014_runtime','failed_create_init_rolls_back_account_contract_and_code',['failed init rejects the CREATE result','Account, SmartContract metadata and Code writes all roll back']),
  ('create_endowment_nonce_sender_metadata','c014_runtime','create_prechecks_endowment_and_preserves_nonce_and_absent_sender',['insufficient CREATE endowment emits no internal transaction and does not advance the root create nonce','a following zero-value CREATE uses nonce zero without synthesizing the absent sender Account','the fresh destination is AccountType.Contract with account_name CreatedByContract before execution']),
  ('create2_istanbul_london_forks','c014_runtime','create2_source_and_ef_deployment_follow_istanbul_and_london',['CREATE2 derives from caller before Istanbul and context address from Istanbul','0xEF-prefixed deployed code succeeds before London and rejects atomically from London']),
  ('create_collision_child_allowance','c014_runtime','create_collision_consumes_full_child_allowance',['a colliding CREATE2 emits one rejected internal transaction','collision consumes the full forwarded child allowance without refund while preserving destination state']),
  ('create_depth_fork_matrix','c014_runtime','create_and_create2_depth_64_follow_java_fork_gates',['CREATE at depth 64 always pushes zero without consuming nonce or mutating state','legacy CREATE2 at depth 64 proceeds before VERSION_4_8_1_1, faults OUT_OF_TIME from VERSION_4_8_1_1, and compatible-EVM or Osaka instead pushes zero','successful legacy CREATE2 emits nonce zero and installs empty runtime while every rejected branch emits no internal transaction']),
  ('create_return_data_fork_matrix','opcodes_c_contract','create_return_data_clearing_matches_pre_and_post_osaka_returndata_ops',['CREATE clears stale prior revert data before RETURNDATASIZE and RETURNDATACOPY','CREATE2 preserves bytes aa bb before Osaka and clears them from Osaka','RETURNDATASIZE and RETURNDATACOPY observe the exact fork-selected buffer']),
  ('call_create_memory_bounds','opcodes_c_contract','call_and_create_families_reject_huge_memory_ranges_before_action',['CALL, CALLCODE, DELEGATECALL, STATICCALL, CALLTOKEN, CREATE, and CREATE2 reject maximum-word, over-3MiB, and over-i64 memory destinations before action','checked range and memory-energy arithmetic returns OUT_OF_MEMORY without allocation, panic, or wrap']),
  ('system_resource_vote_delegation','opcodes_c_contract','system_state_adapter_replays_java_freeze_v2_withdraw_cancel_and_rollback_deltas',['freeze-v2, withdraw, cancel, vote and delegation deltas match Java','failed system effects roll back']),
  ('top_level_child_rollback','c014_runtime','top_level_and_child_revert_revoke_sstore_deltas',['child revert revokes child storage','ancestor revert revokes committed descendant storage']),
  ('internal_transactions_logs','opcodes_b_contract','jump_validation_log_limits_and_return_revert_replay',['invalid jumps and oversized logs fault exactly','return and revert preserve their distinct result and data semantics']),
  ('dynamic_penalties_cpu_faults','c014_runtime','result_numbers_dynamic_penalty_and_call_forwarding_are_exact',['dynamic penalty is charged after base energy','call forwarding and CPU exhaustion match Java']),
  ('runtime_result_mapping','c014_runtime','result_numbers_dynamic_penalty_and_call_forwarding_are_exact',['success, revert and every fault map to exact contractResult names and numbers']),
  ('call_energy_internal_transactions','c014_runtime','call_reserve_is_refunded_once_and_emits_java_internal_transaction',['successful empty child CALL consumes exactly 61 energy and refunds its reserve once','exactly one non-rejected Java-hashed call transaction has the root transaction id as parent, root sender context, child receiver, and depth/index/nonce zero']),
  ('selfdestruct_transactional_rollback','c014_runtime','selfdestruct_transfers_deletes_and_parent_fault_rolls_everything_back',['SELFDESTRUCT transfers 77 balance, deletes the executing account, and emits a suicide transaction','an ancestor illegal operation restores both balances and marks every internal transaction rejected']),
  ('legacy_freeze_unfreeze_v1','opcodes_c_contract','pinned_java_legacy_freeze_unfreeze_vectors_preserve_v1_state_and_v2_queues',['self bandwidth freeze of 2000000 at timestamp 1700000000000 and minimum 3 days leaves balance 8000000, expiry 1700259200000, total net weight 2, and empty v2 queues','delegated energy freeze of 3000000 leaves owner balance 5000000, owner delegated and receiver acquired balances 3000000, expiry 1700259200000, and total energy weight 3','unfreeze before expiry is a no-op; at expiry self and delegated balances restore owner to 10000000, clear legacy fields, clear receiver acquired balance, and zero both weights; insufficient 20000000 freeze rolls back']),
  ('legacy_energy_account_resource','opcodes_c_contract','legacy_energy_self_path_uses_account_resource_not_freeze_v2',['legacy self energy freeze and unfreeze use AccountResource.frozen_balance_for_energy','legacy energy operations never populate frozen_v2 or unfrozen_v2 queues']),
  ('call_preexecution_refund_lineage','c014_runtime','call_preexecution_failures_refund_reserve_and_do_not_mutate_lineage',['depth-64 CALL, insufficient TRX CALL, and insufficient TRC10 CALLTOKEN push zero, clear return data, refund the entire reserved child allowance, emit no internal transaction, and preserve balances','a following CREATE derives its address and internal transaction at root nonce zero because failed call prechecks do not advance lineage']),
  ('selfdestruct_eligibility_failures','selfdestruct_contract','eligibility_failure_reverts_without_deltas_or_internal_transaction',['legacy delegated resources, restricted unexpired legacy freeze, delegated v2 resources, and future pending v2 unfreeze each make SELFDESTRUCT revert','every eligibility rejection preserves the owner, emits no delta, and emits no internal transaction']),
  ('selfdestruct_legacy_blackhole_transfer','selfdestruct_contract','legacy_self_beneficiary_moves_trx_tokens_and_frozen_resources_to_configured_blackhole',['legacy self-beneficiary destruction transfers exactly 77 TRX, token 1000001 balance 5, bandwidth freeze 2000000, and energy freeze 3000000 to the configured blackhole','total net and energy weights fall from 2 and 3 to zero, the owner is deleted, and the suicide transaction is accepted']),
  ('canonical_fork_state_loader','c014_runtime','production_rules_load_uses_persisted_version_35_fork_state',['VERSION_NUMBER never short-circuits requested fork evaluation, and version 35 without passing stats is false','VERSION_4_8_1_1 uses timestamp 1596780000000, rate 70, and the raw persisted stats length as the quorum denominator','19 of 27 upgrade bytes pass while 18 of 27 fail, every stats value other than 1 counts false, and malformed active-witness schedule bytes do not affect rule loading']),
  ('selfdestruct_restricted_new_contract_lineage','selfdestruct_contract','restricted_existing_self_is_noop_while_new_contract_deletes_with_expired_v2_lineage',['restricted existing-contract self-beneficiary execution preserves the account, TRX and tokens without deletion while emitting an accepted suicide transaction','the same address marked new transfers TRX, tokens and frozen v2 to the configured blackhole, withdraws expired pending v2, and deletes the account','the suicide transaction value is 86 and its accepted child withdraw transaction has value 9; both parent hashes equal the enclosing frame root transaction hash'])]
 observations=['result','energy','state_delta','return_data','internal_transactions','logs']
 return {'schema':'c014-execution-oracle.v1','java_revision':'4a21592f95e37908b21bc3f611c6e7a1a67f09f3','scope':'executable end-to-end family, fork interval, recursive execution, state/effect rollback, return-data, call-energy refund and precheck failure, internal-transaction lineage, selfdestruct eligibility/resource transfer/fork rollback, legacy freeze and RuntimeImpl result assertions','fork_intervals':forks,'vectors':[{'id':f'C014-E2E-{i+1:03d}','family':a,'rust_target':b,'rust_case':c,'observations':observations,'assertions':d} for i,(a,b,c,d) in enumerate(cases)]}
def generate():
 rows=normalized_rows(); assert len(rows)==165 and len({r['opcode'] for r in rows})==165
 dump(OR/'c014-tvm-conformance.v1.json',{'schema':'c014-tvm-conformance.v1','version':1,'java_revision':'4a21592f95e37908b21bc3f611c6e7a1a67f09f3','row_count':165,'undefined_opcode_count':91,'rows':rows})
 rec=reconciliation();dump(OR/'c014-ownership-reconciliation.v1.json',{'schema':'c014-ownership-reconciliation.v1','source_owner':'C016','row_count':len(rec),'rule':'every VM row is assigned to a concrete C014 item or an explicit C015/C016 seam; generic deferral is forbidden','rows':rec})
 dump(OR/'c014-execution-oracle.v1.json',vectors())
 manifest=load(OR/'manifest.v1.json')
 for key,name in {'c014_tvm_conformance':'c014-tvm-conformance.v1.json','c014_execution_oracle':'c014-execution-oracle.v1.json','c014_ownership_reconciliation':'c014-ownership-reconciliation.v1.json'}.items():
  manifest[key]={'path':name,'sha256':hashlib.sha256((OR/name).read_bytes()).hexdigest()}
 dump(OR/'manifest.v1.json',manifest)
def verify():
 errors=[]
 for oracle in ['c014_a_oracle.py','c014_b_oracle.py','c014_c_oracle.py']:
  completed=subprocess.run([sys.executable,str(ROOT/'tools/tvm'/oracle)],cwd=ROOT,text=True,capture_output=True)
  if completed.returncode:errors.append(f'{oracle} failed: {completed.stderr.strip() or completed.stdout.strip()}')
 rows=normalized_rows(); committed=load(OR/'c014-tvm-conformance.v1.json')
 if committed.get('rows')!=rows or committed.get('row_count')!=165:errors.append('exact 165-opcode conformance manifest drift')
 if len({r['opcode'] for r in rows})!=165:errors.append('duplicate opcode in registry manifest')
 required={'registry_shape','activation','input_boundaries','energy','state_effect','result_mapping','owner'}
 for r in rows:
  missing=required-r.keys()
  if missing:errors.append(f"opcode {r['hex']} missing {sorted(missing)}")
 rec=load(OR/'c014-ownership-reconciliation.v1.json'); actual=reconciliation()
 if rec.get('rows')!=actual or rec.get('row_count')!=TOTAL_RECONCILIATION_ROW_COUNT:errors.append('C016 VM production/test reconciliation exact source drift')
 stable_ids=[r.get('stable_id') for r in actual]
 if any(not stable_id for stable_id in stable_ids):errors.append('null or missing ownership reconciliation stable ID')
 if len(stable_ids)!=len(set(stable_ids)):errors.append('duplicate ownership reconciliation stable ID')
 ledger_rows={}
 for ledger in ['production-ownership.v1.json','java-test-ownership.v1.json']:
  ledger_rows.update({r.get('id'):r for r in load(OR/ledger).get('rows',[])})
 for r in actual:
  source=r.get('source'); ledger_row=ledger_rows.get(r.get('stable_id'))
  if not isinstance(source,dict) or not source.get('path') or not isinstance(source.get('line'),int):errors.append(f"{r.get('stable_id')} missing exact source path/line")
  elif not ledger_row or source!=ledger_row.get('source'):errors.append(f"{r.get('stable_id')} exact source mismatch")
  if r['ledger']=='java-test-ownership.v1.json' and (not r.get('case') or not ledger_row or r.get('case')!=ledger_row.get('case')):errors.append(f"{r.get('stable_id')} missing or mismatched exact Java case")
 if any(r['owner'] not in {'C014','C015','C016'} or not r['rationale'] for r in actual):errors.append('generic ownership reconciliation row')
 for r in actual:
  required={'case_id','fixture_selector','expected_result','observable_result','rust_symbol','rust_test','command','dispatcher_evidence'}
  if required-r.keys() or r['case_id']!=r['stable_id'] or r['fixture_selector']!=r['stable_id']:errors.append(f"{r.get('stable_id')} missing exact dispatcher evidence")
  dispatch=r.get('dispatcher_evidence',{})
  if dispatch.get('stable_id')!=r.get('stable_id') or dispatch.get('selector')!=r.get('stable_id') or dispatch.get('rust_symbol')!=r.get('rust_symbol') or dispatch.get('observable_result')!=r.get('expected_result'):errors.append(f"{r.get('stable_id')} dispatcher evidence drift")
 if load(OR/'c014-execution-oracle.v1.json')!=vectors():errors.append('execution/fork oracle drift')
 manifest=load(OR/'manifest.v1.json')
 for key,name in {'c014_tvm_conformance':'c014-tvm-conformance.v1.json','c014_execution_oracle':'c014-execution-oracle.v1.json','c014_ownership_reconciliation':'c014-ownership-reconciliation.v1.json'}.items():
  entry=manifest.get(key); digest=hashlib.sha256((OR/name).read_bytes()).hexdigest()
  if entry!={'path':name,'sha256':digest}:errors.append(f'{key} manifest entry drift')
 chunk=next(c for c in load(TRACKER)['chunks'] if c['id']=='C014')
 if chunk['gate']['commands']!=EXPECTED_COMMANDS:errors.append('canonical C014 gate command drift')
 tests='\n'.join((ROOT/'rust-tron/crates/tron-tvm/tests'/f'{x}.rs').read_text() for x in ['foundation_contract','c014_runtime','opcodes_a_contract','opcodes_b_contract','opcodes_c_contract','selfdestruct_contract'])
 for v in vectors()['vectors']:
  if v['rust_case'] not in tests:errors.append(f"missing executable vector {v['rust_case']}")
  if not v.get('assertions') or any(not assertion.strip() for assertion in v['assertions']):errors.append(f"metadata-only execution vector {v['id']}")
 if errors:print('\n'.join(errors),file=sys.stderr);return 1
 print(f'C014 oracle gate: 165 exact opcodes, {len(actual)} reconciled C016 VM rows, {len(vectors()["fork_intervals"])} fork intervals, {len(vectors()["vectors"])} asserted end-to-end vector families')
 return 0
if __name__=='__main__':
 if '--write' in sys.argv:generate()
 raise SystemExit(verify())
