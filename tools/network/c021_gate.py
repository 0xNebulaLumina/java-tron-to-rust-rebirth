#!/usr/bin/env python3
import argparse,hashlib,importlib.util,json,os,pathlib,subprocess,sys,tempfile
ROOT=pathlib.Path(__file__).resolve().parents[2];RUST=ROOT/'rust-tron';ORACLES=ROOT/'docs/oracles'
sys.path.insert(0,str(ROOT/'tools/reference-runner'))
from java_reference_guard import install_java_reference_guard
OWN=ORACLES/'c021-ownership-reconciliation.v1.json';SCENARIOS=ORACLES/'c021-scenarios.v1.json';MANIFEST=ORACLES/'manifest.v1.json';TRACKER=ROOT/'docs/PORTING_TRACKER.json'
FAMILIES={
 'protocol-peer':('c021_cases_protocol_peer','c021-cases-protocol-peer.v1.json'),
 'sync-gossip':('c021_cases_sync_gossip','c021-cases-sync-gossip.v1.json'),
 'handlers':('c021_cases_handlers','c021-cases-handlers.v1.json'),
 'relay-watchdog':('c021_cases_relay_watchdog','c021-cases-relay-watchdog.v1.json'),
}
COMMANDS={
 'protocol':['cargo','test','-p','tron-network','--test','c021_protocol','--locked'],
 'peer':['cargo','test','-p','tron-network','--test','c021_peer','--locked'],
 'sync':['cargo','test','-p','tron-network','--test','c021_sync','--locked'],
 'gossip':['cargo','test','-p','tron-network','--test','c021_gossip','--locked'],
 'handlers-runtime':['cargo','test','-p','tron-network','--test','c021_handlers','--locked'],
 'relay':['cargo','test','-p','tron-network','--test','c021_relay','--locked'],
 'watchdog':['cargo','test','-p','tron-network','--test','c021_watchdog','--locked'],
 'session':['cargo','test','-p','tron-network','--test','c020_session','--locked'],
 'all-targets':['cargo','check','-p','tron-network','--all-targets','--locked'],
}
def load(path): return json.loads(path.read_text())
def sha(path): return hashlib.sha256(path.read_bytes()).hexdigest()
def ledger(name): return load(ORACLES/name)['rows']
def canonical():
 java=[r for r in ledger('java-test-ownership.v1.json') if r.get('acceptance_gate')=='C021.V']
 prod=[r for r in ledger('production-ownership.v1.json') if r.get('acceptance_gate')=='C021.V']
 if len(java)!=103 or len(prod)!=399: raise SystemExit('C021 canonical ledger count drift')
 return {r['id']:r for r in java+prod}
def metadata():
 own=load(OWN); canon=canonical(); rows=own.get('rows',[]); review=own.get('closure_review',{})
 if own.get('schema')!='c021-ownership-reconciliation.v2' or own.get('canonical_counts')!={'java_tests':103,'production':399,'total':502}: raise SystemExit('C021 reconciliation schema/count drift')
 if own.get('evidence_counts')!={'declaration':250,'behavior':230}: raise SystemExit('C021 declaration/behavior count drift')
 if len(rows)!=502 or len({r['id'] for r in rows})!=502 or {r['id'] for r in rows}!=set(canon): raise SystemExit('C021 reconciliation identity/uniqueness drift')
 executed=[r for r in rows if r.get('disposition')=='executed']; excluded=[r for r in rows if r.get('disposition')=='seam_exclusion']
 if len(executed)!=480 or len(excluded)!=22 or any(r.get('seam_owner')!='C022' or '/org/tron/common/client/' not in r['source']['path'] for r in excluded): raise SystemExit('C021 seam exclusions are not the exact C022 client surface')
 if review!={'state':'approved','round':1,'findings':[],'canonical':502,'executed':480,'declarations':250,'behaviors':230,'c022_seam_exclusions':22,'scenarios':9}: raise SystemExit('C021 closure review metadata drift')
 artifacts={}
 for family,(_,name) in FAMILIES.items():
  cases=load(ORACLES/name)['cases']; artifacts.update({case['stable_id']:(family,name,case) for case in cases})
 if len(artifacts)!=480: raise SystemExit('C021 family artifact union drift')
 for row in rows:
  source=canon[row['id']]; symbol=source.get('symbol',source.get('case'))
  if row['source']!=source['source'] or row['symbol']!=symbol or row['ledger_item']!=source['owning_item']: raise SystemExit('C021 provenance drift: '+row['id'])
  if row['disposition']!='executed': continue
  if row['id'] not in artifacts: raise SystemExit('C021 executable artifact binding missing: '+row['id'])
  family,name,case=artifacts[row['id']]
  if row.get('family')!=family or row.get('artifact')!=name or row.get('case_id')!=case['case_id'] or '::' not in row.get('rust_test',''): raise SystemExit('C021 executable binding drift: '+row['id'])
  if case['java_source']!=row['source']['path'] or case['java_line']!=row['source']['line'] or case['java_symbol']!=row['symbol'] or case['source_assertion']!=row['source_assertion']: raise SystemExit('C021 artifact provenance drift: '+row['id'])
  path=ROOT/case['java_source']; data=path.read_bytes(); lines=data.splitlines()
  line=lines[case['java_line']-1].strip() if family=='sync-gossip' else lines[case['java_line']-1]
  if hashlib.sha256(data).hexdigest()!=case['source_assertion']['source_sha256'] or hashlib.sha256(line).hexdigest()!=case['source_assertion']['source_line_sha256']: raise SystemExit('C021 direct source/file/line hash drift: '+row['id'])
  if case['evidence_kind']=='source_assertion':
   if row.get('evidence_kind')!='source_assertion' or any(k in row for k in ('java_input','expected_result','expected_digest')): raise SystemExit('C021 declaration evidence contaminated by behavior: '+row['id'])
  else:
   result=case.get('rust_expected'); digest=case.get('java_expected_digest')
   if not isinstance(case.get('java_input'),dict) or case.get('java_expected_result')!=result or hashlib.sha256(result.encode()).hexdigest()!=digest: raise SystemExit('C021 behavior input/result/digest drift: '+row['id'])
   if (row.get('java_input'),row.get('expected_result'),row.get('expected_digest'))!=(case['java_input'],result,digest): raise SystemExit('C021 reconciliation behavior map drift: '+row['id'])
 manifest=load(MANIFEST)
 for name in [x[1] for x in FAMILIES.values()]+[OWN.name,SCENARIOS.name]:
  key=name.removesuffix('.v1.json').replace('-','_')
  if manifest.get(key)!={'path':name,'sha256':sha(ORACLES/name)}: raise SystemExit('central manifest drift: '+key)
 chunk=next(c for c in load(TRACKER)['chunks'] if c['id']=='C021')
 if chunk['status']!='done' or chunk.get('owner') is not None or chunk.get('resume') is not None or chunk['gate']['status']!='passed' or any(i['status']!='done' for i in chunk['items']) or chunk['review']!={'state':'approved','round':1,'findings':[]} or chunk.get('blocker') is not None: raise SystemExit('C021 tracker closure drift')
 print(json.dumps({'schema':'c021-metadata-v2','canonical':502,'executed':480,'declarations':250,'behaviors':230,'seam_exclusions':22,'status':'passed'},separators=(',',':')))
def run_family(name):
 target,_=FAMILIES[name];cmd=['cargo','test','-p','tron-network','--test',target,'--locked','--','--nocapture']
 print('+',' '.join(cmd),flush=True); result=subprocess.run(cmd,cwd=RUST,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True);print(result.stdout,end='')
 prefix='C021_CASE_RESULT='; declaration_prefix='C021_DECLARATION='; emitted={}
 for line in result.stdout.splitlines():
  marker=prefix if prefix in line else declaration_prefix if declaration_prefix in line else None
  if marker is None: continue
  payload=line.split(marker,1)[1]; stable,value=payload.split('\t',1)
  if stable in emitted: raise SystemExit('duplicate emitted C021 evidence ID: '+stable)
  emitted[stable]=value
 rows=[r for r in load(OWN)['rows'] if r.get('disposition')=='executed' and r.get('family')==name]
 cases={case['stable_id']:case for case in load(ORACLES/FAMILIES[name][1])['cases']}
 expected={}
 for row in rows:
  if row.get('evidence_kind')!='source_assertion': expected[row['id']]=row['expected_result']
  elif name=='protocol-peer': expected[row['id']]='declaration:'+row['source_assertion']['source_line_sha256']
  elif name=='handlers': expected[row['id']]=row['source_assertion']['source_line_sha256']
  else: expected[row['id']]=cases[row['id']]['rust_expected']
 if emitted!=expected:
  raise SystemExit(f'C021 {name} exact evidence mismatch: missing={sorted(set(expected)-set(emitted))} extra={sorted(set(emitted)-set(expected))} wrong={sorted(k for k in set(expected)&set(emitted) if expected[k]!=emitted[k])}')
 return emitted
def exact_cases():
 metadata(); union={}
 for name in FAMILIES:
  for stable,result in run_family(name).items():
   if stable in union: raise SystemExit('duplicate C021 family ownership: '+stable)
   union[stable]=result
 if len(union)!=480: raise SystemExit('C021 executed union count drift')
 print(json.dumps({'schema':'c021-exact-cases-v1','executed':480,'seam_exclusions':22,'canonical':502,'status':'passed'},separators=(',',':')))
def prepare(session,out):
 init=out/'classpath.gradle';init.write_text("allprojects { p -> if (p.path == ':framework') { p.afterEvaluate { p.tasks.register('c021RuntimeClasspath') { doLast { println 'C021_CLASSPATH=' + p.sourceSets.test.runtimeClasspath.asPath } } } } }\n")
 built=session.gradle(['-I',str(init),':framework:testClasses',':actuator:jar',':consensus:jar',':chainbase:jar',':crypto:jar',':common:jar',':protocol:jar',':platform:jar'])
 if built.returncode: raise SystemExit('C021 Java production classpath build failed:\n'+built.stderr.decode('utf-8','replace'))
 queried=session.gradle(['-I',str(init),':framework:c021RuntimeClasspath']);matches=[x.split('=',1)[1] for x in queried.stdout.decode().splitlines() if x.startswith('C021_CLASSPATH=')]
 if queried.returncode or len(matches)!=1: raise SystemExit('C021 Java production classpath capture failed')
 cp=matches[0];source=ROOT/'tools/network/C021Oracle.java';javac=str(session.java_home/'bin/javac');built=session.run([javac,'-cp',cp,'-d',str(out),str(source)],cwd=session.work,classpath=cp)
 if built.returncode: raise SystemExit('C021 Java oracle compilation failed:\n'+built.stderr.decode('utf-8','replace'))
 return str(out)+os.pathsep+cp
def scenario():
 with install_java_reference_guard(ROOT) as session:
  with tempfile.TemporaryDirectory(prefix='c021-java-',dir=session.work) as raw:
   cp=prepare(session,pathlib.Path(raw));before=session.guard(phase='immediately before C021 application captures',classpath=cp);result=session.run([str(session.java_home/'bin/java'),'-cp',cp,'C021Oracle','evidence'],cwd=session.work,classpath=cp);text=result.stdout.decode('utf-8','replace')
   spec=importlib.util.spec_from_file_location('c021_capture',ROOT/'tools/network/instrumentation/c021_capture.py');module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);captured=module.parse(text);expected={r['id']:{k:r[k] for k in ('hex','size','sha256')} for r in load(SCENARIOS)['captures']}
   if result.returncode or captured!=expected: raise SystemExit('authenticated Java C021 capture mismatch:\n'+text+result.stderr.decode('utf-8','replace'))
   scenario_manifest=load(SCENARIOS); specs=scenario_manifest.get('scenarios',[])
   expected_ids=['java-passive-rust-active','java-active-rust-passive','tx-propagation','block-propagation','pbft-dispatch','ordinary-propagation','reorg-handoff-c019','fast-forward-propagation','timeout-disconnect-terminal']
   expected_cases=['c021_scenarios::java_passive_rust_active_genesis_to_head_and_terminal_state','c021_scenarios::java_active_rust_passive_genesis_to_head_and_terminal_state','c021_scenarios::tx_propagation_correlates_java_signed_transaction_and_clears_request','c021_scenarios::block_propagation_advances_ordered_sync_head','c021_scenarios::pbft_dispatch_decodes_java_commit_at_c018_seam','c021_scenarios::ordinary_propagation_uses_inventory_request_and_full_block_response','c021_scenarios::reorg_handoff_c019_processes_competing_height_once','c021_scenarios::fast_forward_propagation_sends_full_block_without_request_correlation','c021_scenarios::timeout_disconnect_clears_requests_and_payload_cache']
   if [s.get('id') for s in specs]!=expected_ids or [s.get('rust_case_id') for s in specs]!=expected_cases or any(not s.get('java_participation') or not s.get('expected_terminal_state') for s in specs): raise SystemExit('C021 exact nine-scenario manifest drift')
   capture_hex=[r['hex'] for r in scenario_manifest['captures']]; reports=[]
   for spec_row in specs:
    probe=session.run([str(session.java_home/'bin/java'),'-cp',cp,'C021Oracle','scenario',spec_row['id']],cwd=session.work,classpath=cp); probe_text=probe.stdout.decode('utf-8','replace')
    fields=dict(line.split('=',1) for line in probe_text.splitlines() if '=' in line)
    raw_messages=fields.get('RAW_MESSAGES','').split(',')
    if probe.returncode or fields.get('SCENARIO_ID')!=spec_row['id'] or raw_messages!=capture_hex or not fields.get('JAVA_STATE','').endswith(spec_row['expected_terminal_state']) or 'SCENARIO_OK' not in probe_text.splitlines(): raise SystemExit('C021 scenario report drift: '+spec_row['id']+'\n'+probe_text)
    reports.append({'id':spec_row['id'],'rust_case_id':spec_row['rust_case_id'],'java_participation':spec_row['java_participation'],'raw_sha256':[hashlib.sha256(bytes.fromhex(raw)).hexdigest() for raw in raw_messages],'terminal_state':fields['JAVA_STATE']})
   print('C021_SCENARIO_REPORT='+json.dumps(reports,separators=(',',':')))
   env=os.environ.copy();env.update(C021_JAVA=str(session.java_home/'bin/java'),C021_ORACLE_CP=cp);subprocess.run(['cargo','test','-p','tron-network','--test','c021_scenarios','--locked','--','--test-threads=1'],cwd=RUST,env=env,check=True);after=session.guard(phase='immediately after C021 live Java/Rust scenario',classpath=cp)
   if before!=after: raise SystemExit('Java reference identity changed across C021 scenario')
def run(target): print('+',' '.join(COMMANDS[target]),flush=True);subprocess.run(COMMANDS[target],cwd=RUST,check=True)
def main():
 choices=['metadata','cases','scenario',*FAMILIES,*COMMANDS,'handlers','all'];p=argparse.ArgumentParser();p.add_argument('targets',nargs='*',choices=choices);targets=p.parse_args().targets or ['all']
 if 'all' in targets: targets=['cases','protocol','peer','sync','gossip','handlers-runtime','relay','watchdog','session','scenario','all-targets']
 for target in targets:
  if target=='metadata': metadata()
  elif target=='cases': exact_cases()
  elif target=='scenario': scenario()
  elif target in FAMILIES: metadata();run_family(target)
  elif target=='handlers': run('handlers-runtime')
  else: run(target)
 print(json.dumps({'schema':'c021-gate-v2','targets':targets,'status':'passed'},separators=(',',':')))
if __name__=='__main__': main()
