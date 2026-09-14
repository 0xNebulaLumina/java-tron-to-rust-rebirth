#!/usr/bin/env python3
import argparse,hashlib,json,os,pathlib,subprocess,sys,tempfile
ROOT=pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'tools/reference-runner'))
from java_reference_guard import install_java_reference_guard
SESSION=install_java_reference_guard(ROOT)
RUST=ROOT/'rust-tron'
ORACLE=ROOT/'docs/oracles/c016-pipeline-pending.v1.json'
ADMISSION=ROOT/'docs/oracles/c016-admission-vectors.v1.json'
RECON=ROOT/'docs/oracles/c016-ownership-reconciliation.v1.json'
TRACKER=ROOT/'docs/PORTING_TRACKER.json'
LEDGER=ROOT/'docs/oracles/production-ownership.v1.json'
JAVA_TEST_LEDGER=ROOT/'docs/oracles/java-test-ownership.v1.json'
C015_RECON=ROOT/'docs/oracles/c015-ownership-reconciliation.v1.json'
def rust_test_symbols():
 import re
 symbols=set()
 for path in (RUST/'crates/tron-execution/tests').glob('c016_*.rs'):
  text=path.read_text()
  names={match.group(1) for match in re.finditer(r'#\[test\]\s*fn\s+([A-Za-z0-9_]+)\s*\(',text)}
  names.update(match.group(1) for match in re.finditer(r'c016_behavior_case!\(\s*([A-Za-z0-9_]+)\s*,',text))
  symbols.update(f'{path.stem}::{name}' for name in names)
 return symbols

def metadata():
 data=json.loads(ORACLE.read_text());pending=data.get('pending',{})
 if pending.get('requeue_order')!=['pending','popped'] or pending.get('pending_timestamp')!='preserved' or pending.get('popped_timestamp')!='refreshed_at_requeue':raise SystemExit('C016 pending oracle contract drift')
 retry=data.get('retry',{})
 expected_retry={'origin':'block_only','trigger':'block actual OUT_OF_TIME and expected is not OUT_OF_TIME','maximum_additional_attempts':1,'network_and_pending_attempts':1}
 if retry!=expected_retry:raise SystemExit('C016 origin-gated retry oracle contract drift')
 java_execution=data.get('java_execution',{})
 expected_origin_gating={'retry':'block_only','witness_comparison':'signed_block_only','local_block_without_expected_result':'skip_witness_comparison'}
 if java_execution.get('capture_schema')!='c016-java-execution-v7' or java_execution.get('origin_gating')!=expected_origin_gating:raise SystemExit('C016 Java origin-gating oracle contract drift')
 admission=json.loads(ADMISSION.read_text());policy=admission.get('result_count_policy',{})
 expected_policy={'network':{'consensus_optimization_false':'strip_redundant_results','consensus_optimization_true':'strip_redundant_results'},'block':{'consensus_optimization_false':'preserve_and_admit','consensus_optimization_true':'reject_bad_block_and_preserve_bytes'},'bad_block_message':'The result count {result_count} of this transaction {transaction_id} is greater than its contract count {contract_count}'}
 if policy!=expected_policy:raise SystemExit('C016 admission block/network result-count policy drift')
 recon=json.loads(RECON.read_text());rows=recon.get('rows',[])
 case_table=recon.get('case_table',[])
 if recon.get('row_count')!=len(rows) or len({row.get('id') for row in rows})!=len(rows):raise SystemExit('C016 ownership reconciliation count/identity drift')
 if len(case_table)!=len(rows) or len({case.get('case_id') for case in case_table})!=len(rows):raise SystemExit('C016 row-specific case table drift')
 expected_cases=[{key:row.get(key) for key in ('case_id','behavior_id','java_symbol','rust_dispatch')} for row in rows]
 if case_table!=expected_cases or any(not row.get('case_id') for row in rows):raise SystemExit('C016 ownership case identity drift')
 evidence_fields={'stable_id','source_identity','fixture_selector','expected_result','rust_symbol','rust_test','command'}
 if any(evidence_fields-row.keys() or row.get('stable_id')!=row.get('id') or row.get('fixture_selector')!=row.get('case_id') or row.get('rust_test')!=row.get('rust_dispatch') for row in rows):raise SystemExit('C016 row-specific observable evidence drift')
 ledger_doc=json.loads(LEDGER.read_text());ledger_rows=ledger_doc.get('rows',[]);ledger={row['id'] for row in ledger_rows}
 if recon.get('source_ledger_sha256')!=hashlib.sha256(LEDGER.read_bytes()).hexdigest():raise SystemExit('C016 ownership source ledger digest drift')
 missing=[row.get('id') for row in rows if row.get('id') not in ledger]
 if missing:raise SystemExit(f'C016 ownership rows absent from production ledger: {missing[:3]}')
 excluded=sorted(ledger-{row['id'] for row in rows});excluded_digest=hashlib.sha256('\n'.join(excluded).encode()).hexdigest()
 if recon.get('excluded_count')!=len(excluded) or recon.get('excluded_ids_sha256')!=excluded_digest:raise SystemExit('C016 exact excluded ownership set drift')
 if any(row.get('acceptance_gate')!='C016.V' or not str(row.get('owning_item','')).startswith('C016.') for row in rows):raise SystemExit('C016 ownership mapping drift')
 behavior_ids=[row.get('behavior_id') for row in rows]
 if len(set(behavior_ids))!=len(rows) or any(value!=f"C016.B{row['id'].removeprefix('PROD-')}" for value,row in zip(behavior_ids,rows)):raise SystemExit('C016 behavior identity drift')
 symbols=rust_test_symbols()
 if any(row.get('case_dispatch')!=row.get('rust_dispatch') or row.get('case_dispatch') not in symbols for row in rows):raise SystemExit('C016 behavior case dispatch missing actual Rust test')
 if any(case['rust_dispatch'] not in symbols for case in case_table):raise SystemExit('C016 case table dispatch missing actual Rust test')
 test_rows=recon.get('java_test_rows',[]);test_ids=recon.get('java_test_ids',[])
 expected_test_ids_sha256='c8f94904f784284efa70b5fe91b37cd5da834979e50703a3561b93d3c203a86d'
 if len(rows)!=66 or recon.get('row_count')!=66:raise SystemExit('C016 production ownership row count drift')
 if len(test_rows)!=45 or recon.get('java_test_row_count')!=45 or recon.get('total_authoritative_row_count')!=111:raise SystemExit('C016 exact production/test authoritative union count drift')
 actual_test_ids=sorted(row.get('stable_id') for row in test_rows)
 if test_ids!=actual_test_ids or len(set(actual_test_ids))!=45 or hashlib.sha256('\n'.join(actual_test_ids).encode()).hexdigest()!=expected_test_ids_sha256 or recon.get('java_test_ids_sha256')!=expected_test_ids_sha256:raise SystemExit('C016 exact 45-row Java test identity union drift')
 if set(actual_test_ids)&{row['id'] for row in rows}:raise SystemExit('C016 production and Java test authoritative rows overlap')
 java_rows={row['id']:row for row in json.loads(JAVA_TEST_LEDGER.read_text()).get('rows',[])}
 test_evidence={'stable_id','source_identity','behavior_claim','fixture_selector','scenario_selector','expected_result','expected_result_sha256','observable_result','rust_symbol','rust_test','target_family','command'}
 for row in test_rows:
  stable_id=row.get('stable_id');source=row.get('source_identity',{});ledger_row=java_rows.get(stable_id);family=row.get('target_family');suffix=stable_id.removeprefix('TCASE-').lower() if isinstance(stable_id,str) else ''
  selector=f'{stable_id}:{source.get("case")}'
  expected_test=f'c016_{family}::c016_tcase_{suffix}';expected_symbol=f'rust-tron/crates/tron-execution/tests/c016_{family}.rs::c016_tcase_{suffix}';expected_command=f'cargo test -p tron-execution --test c016_{family} c016_tcase_{suffix} --locked -- --exact';expected_result=f'{stable_id}|observable:{source.get("case")}'
  if test_evidence-row.keys() or row.get('id')!=stable_id or row.get('case_id')!=stable_id or row.get('fixture_selector')!=selector or row.get('owner')!='C016' or row.get('owning_item')!='C016.06' or row.get('acceptance_gate')!='C016.V':raise SystemExit(f'C016 incomplete authoritative Java test row: {stable_id}')
  expected_scenario={'case':source.get('case'),'line':source.get('line'),'path':source.get('path'),'stable_id':stable_id,'observable':source.get('case')}
  if not ledger_row or ledger_row.get('owning_item')!='C016.06' or source!={'case':ledger_row.get('case'),'line':ledger_row.get('source',{}).get('line'),'path':ledger_row.get('source',{}).get('path')} or row.get('scenario_selector')!=expected_scenario or row.get('behavior_claim')!=f'{source.get("case")} preserves the Java row observable contract through its dedicated Rust case.':raise SystemExit(f'C016 Java source identity mismatch: {stable_id}')
  if family not in COMMANDS or family=='pending' or row.get('rust_test')!=expected_test or row.get('rust_symbol')!=expected_symbol or row.get('command')!=expected_command:raise SystemExit(f'C016 deterministic per-ID Rust linkage drift: {stable_id}')
  digest=hashlib.sha256(expected_result.encode()).hexdigest()
  evidence=row.get('dispatcher_evidence',{})
  if row.get('expected_result')!=expected_result or row.get('observable_result')!=expected_result or row.get('expected_result_sha256')!=digest or evidence.get('observable_result')!=expected_result or evidence.get('expected_result_sha256')!=digest or evidence.get('rust_symbol')!=expected_symbol or evidence.get('selector')!=selector:raise SystemExit(f'C016 per-ID observable result linkage drift: {stable_id}')
  if expected_test not in symbols:raise SystemExit(f'C016 per-ID executable Rust test missing: {expected_test}')
 c015=json.loads(C015_RECON.read_text());seam=c015.get('c016_06_seam_preservation',{});seam_ids=seam.get('stable_ids',[])
 if seam.get('row_count')!=27 or len(seam.get('rows',[]))!=27 or len(seam_ids)!=27 or len(set(seam_ids))!=27 or set(seam_ids)&set(actual_test_ids) or seam.get('stable_ids_sha256')!=hashlib.sha256('\n'.join(seam_ids).encode()).hexdigest():raise SystemExit('C016/C015 exact disjoint seam ownership drift')
 if any(entry.get('stable_id')!=stable_id or entry.get('owner')!='C016' or entry.get('owning_item')!='C016.06' for stable_id,entry in zip(seam_ids,seam.get('rows',[]))):raise SystemExit('C016/C015 retained seam row drift')
 runtime=(RUST/'crates/tron-execution/src/runtime.rs').read_text()
 pipeline=(RUST/'crates/tron-execution/src/pipeline.rs').read_text()
 public=(RUST/'crates/tron-execution/src/lib.rs').read_text()
 forbidden=('pub struct VmInvocation','pub enum VmTimeLimit','vm_invocation','retry_vm_invocation')
 if any(token in runtime or token in pipeline or token in public for token in forbidden):raise SystemExit('C016 caller-controlled VM invocation surface returned')
 if 'pub(crate) fn execute_transaction' not in runtime or 'struct CanonicalVmInvocation' not in runtime:raise SystemExit('C016 canonical VM invocation boundary missing')
 if 'c016_pipeline::transaction_data_cannot_substitute_runtime_code_frame_rules_or_energy' not in symbols:raise SystemExit('C016 adversarial canonical VM proof missing')
 for proof in ('network_vm_success_without_expected_result_skips_witness_comparison','network_out_of_time_executes_once','block_without_expected_result_retries_but_skips_witness_comparison','signed_block_witness_match_and_mismatch_are_enforced'):
  if f'c016_trace::{proof}' not in symbols:raise SystemExit(f'C016 origin-gating proof missing: {proof}')
 vm=data.get('vm_invocation',{})
 if vm.get('caller_executable_inputs')!=[] or vm.get('retry_mutable_fields')!=['deadline'] or not vm.get('transaction_any_decoded') or not vm.get('state_derived'):raise SystemExit('C016 canonical VM oracle contract drift')
 plan=vm.get('energy_plan',{})
 expected_plan={'runtime_scope':'Create/Trigger only; NonVm bypasses fee_limit, energy dynamics, and settlement','snapshot':'single_session_head_slot','caller_frozen_sources':['legacy','delegated_legacy','v2','delegated_v2'],'caller_total_limit':'min(left_frozen + affordable_paid, validated_fee_limit / effective_energy_price)','paid_cap':'caller_total_limit - min(left_frozen, caller_total_limit)','effective_energy_price':'ENERGY_FEE > 0 ? ENERGY_FEE : SUN_PER_ENERGY(100)','fee_limit_zero_total_energy':0,'creator_share':['consume_user_resource_percent','origin_energy_limit','recovered_creator_energy'],'origin_relationship':['Absent','SameAsCaller','Distinct'],'missing_origin_constantinople_policy':'Absent only','same_origin_settlement':'charge caller branch once and persist one live account','execution_equals_settlement':True,'settlement_balances':'refresh caller and distinct origin from live post-VM session'}
 if plan!=expected_plan or 'EnergyExecutionPlan' not in pipeline or 'energy_plan: &EnergyExecutionPlan' not in runtime or 'pub enum EnergyOrigin' not in (RUST/'crates/tron-execution/src/receipt.rs').read_text():raise SystemExit('C016 canonical energy execution plan drift')
 for proof in ('energy_settlement_preserves_vm_value_received_by_distinct_origin','same_origin_preserves_live_value_balance_and_persists_one_energy_account_pre_and_post_constantinople'):
  if f'c016_pipeline::{proof}' not in symbols:raise SystemExit(f'C016 live energy conservation proof missing: {proof}')
 if 'c016_pipeline::non_vm_actuators_ignore_vm_energy_policy_and_preserve_energy_state' not in symbols or 'RuntimeKind::NonVm => None' not in pipeline or 'if let Some(energy_plan) = energy_plan.as_ref()' not in pipeline:raise SystemExit('C016 non-VM energy-policy bypass proof missing')
 if 'c016_trace::absent_origin_is_the_only_constantinople_gated_relationship' not in symbols or 'c016_trace::same_origin_charges_caller_before_and_after_constantinople' not in symbols:raise SystemExit('C016 explicit origin relationship proof missing')
 if 'origin: Option<EnergyAccount>' in (RUST/'crates/tron-execution/src/receipt.rs').read_text():raise SystemExit('C016 origin=None ambiguity returned')
 tracker=json.loads(TRACKER.read_text());chunk=next((row for row in tracker.get('chunks',[]) if row.get('id')=='C016'),None)
 review=chunk.get('review',{}) if chunk else {}
 if not chunk or chunk.get('status')!='done' or chunk.get('owner') is not None or chunk.get('resume') is not None or review.get('state')!='approved' or any(row.get('status')!='closed' for row in review.get('findings',[])):raise SystemExit('C016 tracker closure metadata drift')
 print(json.dumps({'schema':'c016-metadata-v2','ownership_rows':len(rows),'review':'approved','status':'passed'},separators=(',',':')))
COMMANDS={
 'admission':['cargo','test','-p','tron-execution','--test','c016_admission','--locked'],
 'trace':['cargo','test','-p','tron-execution','--test','c016_trace','--locked'],
 'pipeline':['cargo','test','-p','tron-execution','--test','c016_pipeline','--locked'],
 'pending':['cargo','test','-p','tron-execution','--test','c016_pending','--locked'],
 'all-targets':['cargo','check','-p','tron-execution','--all-targets','--locked'],
}
def run(command,cwd):
 print('+',' '.join(command),flush=True);subprocess.run(command,cwd=cwd,check=True)
def oracle():
 data=json.loads(ORACLE.read_text())
 for row in data['java_sources']:
  actual=hashlib.sha256((SESSION.tree/row['path']).read_bytes()).hexdigest()
  if actual!=row['sha256']:raise SystemExit(f"Java source identity mismatch: {row['path']} {actual}")
 with tempfile.TemporaryDirectory(prefix='c016-java-',dir=SESSION.work) as raw:
  out=pathlib.Path(raw);init=out/'classpath.gradle'
  init.write_text("""allprojects { p ->
  if (p.path == ':framework') { p.afterEvaluate {
    p.tasks.register('c016RuntimeClasspath') { doLast { println p.sourceSets.test.runtimeClasspath.asPath } }
  } }
}
""")
  built=SESSION.gradle(['-I',str(init),':framework:testClasses',':actuator:jar',':consensus:jar',':chainbase:jar',':crypto:jar',':common:jar',':protocol:jar',':platform:jar'])
  if built.returncode:raise SystemExit('C016 Java testClasses failed:\n'+built.stderr.decode('utf-8','replace'))
  queried=SESSION.gradle(['-I',str(init),'-q',':framework:c016RuntimeClasspath'])
  if queried.returncode:raise SystemExit('C016 Java classpath query failed:\n'+queried.stderr.decode('utf-8','replace'))
  lines=[line.strip() for line in queried.stdout.decode().splitlines() if os.pathsep in line]
  if not lines:raise SystemExit('C016 Java runtime classpath missing')
  classpath=lines[-1]
  source=ROOT/'tools/execution/C016Oracle.java'
  SESSION.run([str(SESSION.java_home/'bin/javac'),'-cp',classpath,'-d',str(out),str(source)],cwd=SESSION.work,classpath=classpath,check=True)
  oracle_cp=str(out)+os.pathsep+classpath
  observed=SESSION.run([str(SESSION.java_home/'bin/java'),'-cp',oracle_cp,'C016Oracle'],cwd=SESSION.work,classpath=oracle_cp)
  if observed.returncode:raise SystemExit('C016 Java execution probe failed:\n'+observed.stdout.decode('utf-8','replace')+'\n'+observed.stderr.decode('utf-8','replace'))
  output=observed.stdout.decode();sys.stdout.write(output)
  captures=[json.loads(line) for line in output.splitlines() if line.startswith('{')]
  capture=captures[0] if captures else {}
  result_policy=capture.get('result_policy',{})
  origin_gating=capture.get('origin_gating',{})
  fixed_ratio=capture.get('fixed_ratio_vectors',{})
  expected_fixed={'zero_fee_total':0,'frozen_above_cap_total':3,'frozen_below_cap_total':5,'frozen_below_cap_paid':3,'affordable_total':4,'affordable_paid':2,'zero_energy_fee_fallback_total':5,'negative_energy_fee_fallback_total':5}
  expected_origin_gating={'retry':'block_only','witness_comparison':'signed_block_only','local_block_without_expected_result':'skip_witness_comparison'}
  if len(captures)!=1 or capture.get('schema')!='c016-java-execution-v7' or capture.get('pending_requeue')!=['pending','popped'] or not capture.get('pending_timestamp_preserved') or not capture.get('popped_timestamp_refreshed') or capture.get('energy_vectors')!={'legacy':5,'v2':9,'zero_weight':0} or fixed_ratio!=expected_fixed or origin_gating!=expected_origin_gating or result_policy!={'network_redundant_ret_removed':True,'block_excess_ret_detected':True,'block_probe_bytes_preserved':True}:raise SystemExit('C016 Java execution capture mismatch')
  tests=SESSION.gradle([':framework:test','--tests','org.tron.core.db.ManagerTest.transactionTest','--tests','org.tron.core.db.TransactionTraceTest'])
  if tests.returncode:raise SystemExit('C016 pinned Manager/TransactionTrace tests failed:\n'+tests.stderr.decode('utf-8','replace'))
  print(json.dumps({'schema':'c016-java-test-execution-v1','manager':'ManagerTest.transactionTest','transaction_trace':'TransactionTraceTest','status':'passed'},separators=(',',':')))
def main():
 parser=argparse.ArgumentParser();parser.add_argument('targets',nargs='*',choices=[*COMMANDS,'metadata','oracle','all']);args=parser.parse_args();targets=args.targets or ['all']
 if 'all' in targets:targets=['metadata','oracle','admission','trace','pipeline','pending','all-targets']
 for target in targets:
  if target=='metadata':metadata()
  elif target=='oracle':oracle()
  else:run(COMMANDS[target],RUST)
 print(json.dumps({'schema':'c016-gate-v1','status':'passed','targets':targets},separators=(',',':')))
if __name__=='__main__':main()
