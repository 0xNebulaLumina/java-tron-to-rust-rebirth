#!/usr/bin/env python3
import argparse, hashlib, json, os, pathlib, re, subprocess, sys, tempfile
ROOT=pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'tools/reference-runner'))
from java_reference_guard import install_java_reference_guard
RUST=ROOT/'rust-tron'; SCENARIOS=ROOT/'docs/oracles/c017-scenarios.v1.json'; RECON=ROOT/'docs/oracles/c017-ownership-reconciliation.v1.json'; SOURCE=ROOT/'docs/oracles/c017-source-inventory.v1.json'
PROD=ROOT/'docs/oracles/production-ownership.v1.json'; TESTS=ROOT/'docs/oracles/java-test-ownership.v1.json'; TRACKER=ROOT/'docs/PORTING_TRACKER.json'; ORACLE_MANIFEST=ROOT/'docs/oracles/manifest.v1.json'
COMMANDS={
 'schedule':['cargo','test','-p','tron-consensus','--test','c017_cases_schedule','--locked','--','--nocapture'],
 'production':['cargo','test','-p','tron-consensus','--test','c017_cases_production','--locked','--','--nocapture'],
 'maintenance':['cargo','test','-p','tron-consensus','--test','c017_cases_maintenance','--locked','--','--nocapture'],
 'reward':['cargo','test','-p','tron-consensus','--test','c017_cases_rewards','--locked','--','--nocapture'],
 'proposal':['cargo','test','-p','tron-consensus','--test','c017_cases_proposals','--locked','--','--nocapture'],
 'solidity':['cargo','test','-p','tron-consensus','--test','c017_cases_solidity_fork','--locked','--','--nocapture'],
 'lifecycle':['cargo','test','-p','tron-consensus','--test','c017_cases_lifecycle','--locked','--','--nocapture'],
 'scenarios':['cargo','test','-p','tron-consensus','--test','c017_scenarios','--locked'],
 'all-targets':['cargo','check','-p','tron-consensus','--all-targets','--locked'],
}
FAMILY_TARGETS=('schedule','production','maintenance','reward','proposal','solidity','lifecycle')
FAMILY_FILES={
 'schedule':'c017-cases-schedule.v1.json','production':'c017-cases-production.v1.json',
 'maintenance':'c017-cases-maintenance.v1.json','reward':'c017-cases-rewards.v1.json',
 'proposal':'c017-cases-proposals.v1.json','solidity':'c017-cases-solidity-fork.v1.json',
 'lifecycle':'c017-cases-lifecycle.v1.json',
}

JAVA_SOURCES={'java-tron/consensus/src/main/java/org/tron/consensus/dpos/DposSlot.java','java-tron/consensus/src/main/java/org/tron/consensus/dpos/DposTask.java','java-tron/consensus/src/main/java/org/tron/consensus/dpos/StateManager.java','java-tron/consensus/src/main/java/org/tron/consensus/dpos/MaintenanceManager.java','java-tron/chainbase/src/main/java/org/tron/core/store/WitnessStore.java','java-tron/common/src/main/java/org/tron/common/utils/RandomGenerator.java','java-tron/framework/src/test/java/org/tron/core/db/BlockFilledSlotsTest.java','java-tron/chainbase/src/main/java/org/tron/core/service/MortgageService.java','java-tron/chainbase/src/main/java/org/tron/core/service/RewardViCalService.java','java-tron/framework/src/main/java/org/tron/core/consensus/ProposalController.java','java-tron/chainbase/src/main/java/org/tron/core/capsule/ProposalCapsule.java','java-tron/consensus/src/main/java/org/tron/consensus/dpos/DposService.java','java-tron/chainbase/src/main/java/org/tron/common/utils/ForkController.java'}
RUST_PROOFS={'rust-tron/crates/tron-consensus/src/lib.rs','rust-tron/crates/tron-consensus/src/schedule.rs','rust-tron/crates/tron-consensus/src/production.rs','rust-tron/crates/tron-consensus/src/maintenance.rs','rust-tron/crates/tron-consensus/src/rewards.rs','rust-tron/crates/tron-consensus/src/proposal.rs','rust-tron/crates/tron-consensus/src/solidity.rs','rust-tron/crates/tron-consensus/src/state.rs','rust-tron/crates/tron-consensus/tests/c017_schedule.rs','rust-tron/crates/tron-consensus/tests/c017_production.rs','rust-tron/crates/tron-consensus/tests/c017_maintenance.rs','rust-tron/crates/tron-consensus/tests/c017_rewards.rs','rust-tron/crates/tron-consensus/tests/c017_proposals.rs','rust-tron/crates/tron-consensus/tests/c017_solidity.rs','rust-tron/crates/tron-consensus/tests/c017_scenarios.rs'}
MANIFESTS={'docs/oracles/c017-scenarios.v1.json','docs/oracles/c017-schedule-vectors.v1.json','docs/oracles/c017-ownership-reconciliation.v1.json'}
def case_digest(row):
 p=row['parameters']; payload='|'.join([row['case_id'],row['case_kind'],p['java_source'],str(p['java_line']),p['java_symbol'],p['owning_item'],p['acceptance_gate'],row['expected_result']]); return hashlib.sha256(payload.encode()).hexdigest()
def family_rows(name):
 doc=json.loads((ROOT/'docs/oracles'/FAMILY_FILES[name]).read_text()); return doc.get('cases',doc.get('retained_cases',[]))
def family_expected(name):
 rows=family_rows(name); expected={}
 for row in rows:
  case_id=row['case_id']; value=row.get('expected_result',row.get('expected',row.get('scenario')))
  if not isinstance(value,str) or not value: raise SystemExit(f'C017 {name} missing expected result for {case_id}')
  if case_id in expected: raise SystemExit(f'C017 {name} duplicate expected case ID: {case_id}')
  expected[case_id]=value
 return expected
def require_exact_results(name,expected,emitted):
 if emitted==expected: return
 missing=sorted(expected.keys()-emitted.keys()); extra=sorted(emitted.keys()-expected.keys())
 wrong=sorted(case_id for case_id in expected.keys()&emitted.keys() if expected[case_id]!=emitted[case_id])
 raise ValueError(f'C017 {name} result mismatch: expected={len(expected)} actual={len(emitted)} missing={missing} extra={extra} wrong={[(case_id,expected[case_id],emitted[case_id]) for case_id in wrong]}')
def metadata():
 scenario=json.loads(SCENARIOS.read_text()); recon=json.loads(RECON.read_text()); inventory=json.loads(SOURCE.read_text()); oracle_manifest=json.loads(ORACLE_MANIFEST.read_text())
 if scenario.get('schema')!='c017-scenarios.v1' or scenario.get('genesis',{}).get('witnesses')!=27 or scenario.get('clock',{}).get('kind')!='fixed': raise SystemExit('C017 fixed-clock genesis contract drift')
 if scenario.get('final',{}).get('pbft_cursor')!='excluded:C018' or scenario.get('final',{}).get('manager_block_application')!='excluded:C019': raise SystemExit('C017 exclusion seam drift')
 source=(ROOT/'tools/consensus/C017Oracle.java').read_text(); rust=(RUST/'crates/tron-consensus/tests/c017_scenarios.rs').read_text()
 required_java=['DposService','validBlock(','statistic.applyBlock(','maintenance.doMaintenance(','payBlockReward(','queryReward(','withdrawReward(','processProposals(','ForkController.instance().update(','buildSession()','allRows(context)','outer-session-close']
 if any(token not in source for token in required_java) or 'sessions.pop()' not in rust or 'StoreKind::ALL' not in rust or 'full_root(' not in rust: raise SystemExit('C017 full-root integration proof drift')
 if inventory.get('schema')!='c017-source-inventory.v1': raise SystemExit('C017 source inventory schema drift')
 for field in ('java_sources','rust_proofs','manifests'):
  for row in inventory.get(field,[]):
   path=ROOT/row['path']
   if not path.is_file() or row.get('sha256')!=hashlib.sha256(path.read_bytes()).hexdigest(): raise SystemExit(f'C017 {field} digest drift: {row["path"]}')
 manifest_names=['c017-ownership-reconciliation.v1.json','c017-scenarios.v1.json','c017-schedule-vectors.v1.json','c017-source-inventory.v1.json',*FAMILY_FILES.values()]
 for name in manifest_names:
  key=name.removesuffix('.v1.json').replace('-','_'); path=ROOT/'docs/oracles'/name
  if oracle_manifest.get(key)!={'path':name,'sha256':hashlib.sha256(path.read_bytes()).hexdigest()}: raise SystemExit(f'C017 central oracle manifest digest drift: {key}')
 if recon.get('source_ledgers',{}).get('production_sha256')!=hashlib.sha256(PROD.read_bytes()).hexdigest() or recon.get('source_ledgers',{}).get('java_tests_sha256')!=hashlib.sha256(TESTS.read_bytes()).hexdigest(): raise SystemExit('C017 source ledger digest drift')
 prows=recon.get('production_rows',[]); trows=recon.get('java_test_rows',[]); retained=[r for r in prows+trows if r.get('disposition')!='excluded']; excluded=[r for r in prows+trows if r.get('disposition')=='excluded']; cases=recon['case_table']; excluded_rows=recon['excluded_rows']
 if (len(retained),len(excluded),recon.get('retained_case_count'),recon.get('excluded_case_count'))!=(155,81,155,81): raise SystemExit('C017 retained/excluded count drift')
 retained_ids={r['case_id'] for r in retained}; excluded_ids={r['case_id'] for r in excluded}
 family=[r for name in FAMILY_TARGETS for r in family_rows(name)]; family_ids=[r['case_id'] for r in family]
 if len(family_ids)!=155 or len(set(family_ids))!=155 or set(family_ids)!=retained_ids: raise SystemExit('C017 family manifest union is not exact/unique')
 if {r['case_id'] for r in cases}!=retained_ids or {r['case_id'] for r in excluded_rows}!=excluded_ids: raise SystemExit('C017 reconciliation binding drift')
 canonical={case_id:value for name in FAMILY_TARGETS for case_id,value in family_expected(name).items()}
 reconciled={r['case_id']:r.get('expected_result') for r in cases}
 try: require_exact_results('reconciliation',canonical,reconciled)
 except ValueError as error: raise SystemExit(str(error))
 if any(r.get('expected_digest')!=case_digest(r) for r in cases+excluded_rows): raise SystemExit('C017 expected digest drift')
 for r in excluded:
  p=(r['java_source']+' '+r.get('java_symbol',r.get('java_case',''))).lower(); expected=('C018.06','C018.V') if 'pbft' in p else ('C019.01','C019.V')
  if (r['owning_item'],r['acceptance_gate'])!=expected: raise SystemExit(f'C017 explicit exclusion owner drift: {r["case_id"]}')
 tracker=json.loads(TRACKER.read_text()); chunk=next(r for r in tracker['chunks'] if r['id']=='C017')
 if chunk['gate']['status']!='passed': raise SystemExit('C017 tracker gate drift')
 print(json.dumps({'schema':'c017-metadata-v3','source_production_rows':216,'retained_cases':155,'excluded_cases':81,'family_cases':155,'status':'passed'},separators=(',',':')))

def oracle():
 session=install_java_reference_guard(ROOT)
 with tempfile.TemporaryDirectory(prefix='c017-java-',dir=session.work) as raw:
  out=pathlib.Path(raw)
  classes=['org.tron.core.consensus.DposServiceTest','org.tron.core.consensus.DposTaskTest','org.tron.core.services.DelegationServiceTest','org.tron.core.services.ProposalServiceTest','org.tron.core.services.WitnessProductBlockServiceTest','org.tron.core.witness.ProposalControllerTest','org.tron.core.witness.WitnessControllerTest','org.tron.core.db.BlockFilledSlotsTest']
  args=[':framework:test']
  for cls in classes: args+=['--tests',cls]
  tests=session.gradle(args)
  if tests.returncode: raise SystemExit('C017 pinned Java tests failed:\n'+tests.stderr.decode('utf-8','replace'))
  init=out/'classpath.gradle'; init.write_text("allprojects { p -> if (p.path == ':framework') { p.afterEvaluate { p.tasks.register('c017RuntimeClasspath') { doLast { println 'C017_CLASSPATH=' + p.sourceSets.test.runtimeClasspath.asPath } } } } }\n")
  classpath_result=session.gradle(['-I',str(init),':framework:c017RuntimeClasspath'])
  if classpath_result.returncode: raise SystemExit('C017 Java classpath failed:\n'+classpath_result.stderr.decode('utf-8','replace'))
  lines=classpath_result.stdout.decode().splitlines(); matches=[line.split('=',1)[1] for line in lines if line.startswith('C017_CLASSPATH=')]
  if len(matches)!=1: raise SystemExit('C017 Java classpath was not captured exactly once')
  classpath=matches[0]; source=ROOT/'tools/consensus/C017Oracle.java'
  session.run([str(session.java_home/'bin/javac'),'-cp',classpath,'-d',str(out),str(source)],cwd=session.work,classpath=classpath,check=True)
  runtime=str(out)+os.pathsep+classpath
  result=session.run([str(session.java_home/'bin/java'),'-cp',runtime,'C017Oracle'],cwd=session.work,classpath=runtime,check=False)
  captures=[json.loads(line) for line in result.stdout.decode().splitlines() if line.startswith('{')]
  if len(captures)!=1:
   detail=result.stderr.decode('utf-8','replace') if result.returncode else result.stdout.decode('utf-8','replace')
   raise SystemExit('C017 Java oracle emitted no unique capture:\n'+detail)
  got=captures[0]; scenario=json.loads(SCENARIOS.read_text()); capture=scenario.get('java_capture',{})
  if os.environ.get('C017_UPDATE_MANIFEST'):
   scenario['java_capture']=got;SCENARIOS.write_text(json.dumps(scenario,indent=2)+'\n');print(json.dumps({'schema':'c017-capture-update-v1','head_root':got['head_root'],'status':'updated'},separators=(',',':')));return
  if os.environ.get('C017_CAPTURE'):
   print(json.dumps(got,separators=(',',':'))); return
  for key in ['schema','root_schema','rollback_event','future_local_duplicate','initial_rows','initial_root','schedule','produced','missed','reward_query','fork_pass','dynamic_bytes','snapshots','events','head_rows','head_root','rollback_rows','rollback_root']:
   if got.get(key)!=capture.get(key): raise SystemExit(f'C017 Java oracle mismatch at {key}: {got.get(key)!r}')
  print(json.dumps({'schema':'c017-java-tests-v4','owned_cases':17,'block_filled_slots':3,'root_schema':got['root_schema'],'rollback_event':got['rollback_event'],'initial_root':got['initial_root'],'head_root':got['head_root'],'rollback_root':got['rollback_root'],'status':'passed'},separators=(',',':')))
def run(target,cmd):
 print('+',' '.join(cmd),flush=True)
 if target not in FAMILY_TARGETS: subprocess.run(cmd,cwd=RUST,check=True); return
 expected=family_expected(target)
 result=subprocess.run(cmd,cwd=RUST,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
 print(result.stdout,end='')
 if result.returncode: raise subprocess.CalledProcessError(result.returncode,cmd)
 records=[]
 for line in result.stdout.splitlines():
  match=re.search(r'(C017-[PT]-[0-9A-F]+)=(.+)$',line)
  if match: records.append((match.group(1),match.group(2)))
 emitted={case_id:value for case_id,value in records}
 if len(records)!=len(emitted): raise SystemExit(f'C017 {target} emitted duplicate case IDs')
 try: require_exact_results(target,expected,emitted)
 except ValueError as error: raise SystemExit(str(error))
 print(json.dumps({'schema':'c017-family-report-v2','family':target,'asserted':len(emitted),'status':'passed'},separators=(',',':')))
def selftest():
 try: require_exact_results('negative-selftest',{'C017-P-DEADBEEF':'canonical'},{'C017-P-DEADBEEF':'mutated'})
 except ValueError as error:
  if "('C017-P-DEADBEEF', 'canonical', 'mutated')" not in str(error): raise SystemExit('C017 mismatch-negative selftest reported incomplete evidence')
 else: raise SystemExit('C017 mismatch-negative selftest accepted a result mismatch')
 print(json.dumps({'schema':'c017-negative-selftest-v1','mismatch_rejected':True,'status':'passed'},separators=(',',':')))

def main():
 p=argparse.ArgumentParser(); p.add_argument('targets',nargs='*',choices=[*COMMANDS,'metadata','oracle','selftest','all']); a=p.parse_args(); targets=a.targets or ['all']
 if 'all' in targets: targets=['metadata','selftest','oracle','schedule','production','maintenance','reward','proposal','solidity','lifecycle','scenarios','all-targets']
 for target in targets:
  if target=='metadata': metadata()
  elif target=='oracle': oracle()
  elif target=='selftest': selftest()
  else: run(target,COMMANDS[target])
 print(json.dumps({'schema':'c017-gate-v1','targets':targets,'status':'passed'},separators=(',',':')))
if __name__=='__main__': main()
