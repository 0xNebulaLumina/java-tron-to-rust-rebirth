#!/usr/bin/env python3
import argparse, hashlib, json, os, pathlib, re, subprocess, sys, tempfile
ROOT=pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'tools/reference-runner'))
from java_reference_guard import install_java_reference_guard
RUST=ROOT/'rust-tron'; ORACLES=ROOT/'docs/oracles'
PBFT=ORACLES/'c018-pbft-vectors.v1.json'; BACKUP=ORACLES/'c018-backup-vectors.v1.json'; SOURCE=ORACLES/'c018-backup-source-inventory.v1.json'
RECON=ORACLES/'c018-ownership-reconciliation.v1.json'; CASES=ORACLES/'c018-cases.v1.json'; PROD=ORACLES/'production-ownership.v1.json'
TESTS=ORACLES/'java-test-ownership.v1.json'; C017=ORACLES/'c017-ownership-reconciliation.v1.json'; MANIFEST=ORACLES/'manifest.v1.json'; TRACKER=ROOT/'docs/PORTING_TRACKER.json'
FAMILIES={
 'c018_cases_pbft':('c018-cases-pbft.v1.json','every_retained_pbft_row_executes_its_exact_rust_behavior','expected_result',51),
 'c018_cases_persistence':('c018-cases-persistence.v1.json','retained_persistence_rows_execute_exact_row_specific_calls','expected_result',15),
 'c018_cases_backup_wire':('c018-cases-backup-wire.v1.json','c018_backup_wire_rows_have_row_specific_executable_evidence','java_expected_result',60),
 'c018_cases_backup_election':('c018-cases-backup-election.v1.json','every_backup_manager_row_has_specific_executable_evidence','canonical_expected_result',10),
}
COMMANDS={'pbft':['cargo','test','-p','tron-consensus','--test','c018_pbft','--locked'],'backup':['cargo','test','-p','tron-consensus','--test','c018_backup','--locked'],'scenario':['cargo','test','-p','tron-consensus','--test','c018_scenarios','--locked'],'all-targets':['cargo','check','-p','tron-consensus','--all-targets','--locked']}
def load(path): return json.loads(path.read_text())
def digest(path): return hashlib.sha256(path.read_bytes()).hexdigest()
def case_digest(row):
 p=row['parameters']; payload='|'.join([row['case_id'],row['case_kind'],p['java_source'],str(p['java_line']),p['java_symbol'],p['owning_item'],p['acceptance_gate'],row['expected_result'],row['assertion_family'],row['seam_owner']]); return hashlib.sha256(payload.encode()).hexdigest()
def json_digest(value): return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':')).encode()).hexdigest()
def contains_forbidden_seed(value):
 if isinstance(value,dict): return any('seed' in str(k).lower() or contains_forbidden_seed(v) for k,v in value.items())
 if isinstance(value,list): return any(contains_forbidden_seed(v) for v in value)
 if isinstance(value,str): return 'seed=' in value.lower() or 'seed-generated' in value.lower()
 return False
def validate_evidence(row,expected):
 cid=row['case_id']; path=ROOT/row['java_source']; actual_hash=digest(path)
 if row['java_source_sha256']!=actual_hash: raise SystemExit('C018 family Java source digest drift: '+cid)
 if row['java_expected_digest']!=hashlib.sha256(expected.encode()).hexdigest(): raise SystemExit('C018 Java expected-result digest drift: '+cid)
 if row.get('executable_id')!=cid: raise SystemExit('C018 executable ID drift: '+cid)
 if contains_forbidden_seed(row): raise SystemExit('C018 generic seed/fanout evidence forbidden: '+cid)
 kind=row.get('evidence_kind')
 if kind=='source_assertion':
  proof=row.get('source_assertion',{}); lines=path.read_text().splitlines(); line=lines[row['java_line']-1].strip()
  if proof.get('source_sha256')!=actual_hash or proof.get('source_line_sha256')!=hashlib.sha256(line.encode()).hexdigest() or proof.get('symbol')!=row['java_symbol'] or not expected.startswith('source:'): raise SystemExit('C018 declaration source proof drift: '+cid)
 elif kind=='method_fixture':
  fixture=row.get('java_fixture',{}); observation=hashlib.sha256((json.dumps(fixture.get('input'),sort_keys=True,separators=(',',':'))+'|'+expected).encode()).hexdigest()
  if fixture.get('id')!='JAVA-'+row['stable_id'] or fixture.get('output_or_error')!=expected or fixture.get('observation_digest')!=observation: raise SystemExit('C018 method fixture drift: '+cid)
 else: raise SystemExit('C018 evidence kind drift: '+cid)
def require_exact(name,expected,actual):
 if expected==actual:return
 missing=sorted(expected.keys()-actual.keys()); extra=sorted(actual.keys()-expected.keys()); wrong=sorted(k for k in expected.keys()&actual.keys() if expected[k]!=actual[k])
 raise SystemExit(f'C018 {name} result mismatch: expected={len(expected)} actual={len(actual)} missing={missing} extra={extra} wrong={[(k,expected[k],actual[k]) for k in wrong]}')
def provenance(row):
 p=row.get('parameters',row); return {'java_source':p['java_source'],'java_line':p['java_line'],'java_symbol':p['java_symbol'],'owning_item':p['owning_item'],'acceptance_gate':p['acceptance_gate']}
def source_rows():
 prod={r['id']:{'origin':'c018-production-ledger','java_source':r['source']['path'],'java_line':r['source']['line'],'java_symbol':r['symbol'],'owning_item':r['owning_item'],'acceptance_gate':r['acceptance_gate']} for r in load(PROD)['rows'] if r.get('acceptance_gate')=='C018.V'}
 tests={r['id']:{'origin':'c018-java-test-ledger','java_source':r['source']['path'],'java_line':r['source']['line'],'java_symbol':r['case'],'owning_item':r['owning_item'],'acceptance_gate':r['acceptance_gate']} for r in load(TESTS)['rows'] if r.get('acceptance_gate')=='C018.V'}
 inherited={(r.get('stable_id') or 'PROD-'+r['case_id'].split('-')[-1]):{'origin':'c017-explicit-pbft-exclusion',**provenance(r)} for r in load(C017)['excluded_rows'] if r.get('owning_item')=='C018.06'}
 expected={**inherited,**prod,**tests}; assert len(inherited)==64 and len(prod)==59 and len(tests)==13 and len(expected)==136
 return expected

def family_maps():
 maps={}; owners={}; declared=[]; fixtures={}
 source=source_rows()
 for target,(name,test,field,count) in FAMILIES.items():
  artifact=load(ORACLES/name); rows=artifact['cases']
  if len(rows)!=count: raise SystemExit(f'C018 {name} count drift')
  current={}
  for row in rows:
   cid=row['case_id']; expected=row[field]; stable=row['stable_id']
   if cid in current: raise SystemExit(f'C018 duplicate ID within {name}: {cid}')
   current[cid]=expected; declared.append(cid)
   if cid in owners: raise SystemExit(f'C018 cross-family duplicate ID: {cid} in {owners[cid]} and {name}')
   owners[cid]=(target,test,name); maps[cid]=expected
   if stable not in source: raise SystemExit('C018 family stable ID absent from authenticated source ledgers: '+stable)
   want=source[stable]
   for key in ('java_source','java_line','java_symbol','owning_item','acceptance_gate'):
    if row.get(key)!=want[key]: raise SystemExit(f'C018 family provenance drift: {cid}.{key}')
   if row.get('seam_owner')!='C018' or row.get('case_kind') not in ('java-symbol','java-test') or not row.get('assertion_family'): raise SystemExit('C018 family ownership/type drift: '+cid)
   validate_evidence(row,expected)
   if row['evidence_kind']=='method_fixture':
    fixture=row['java_fixture']; prior=fixtures.setdefault(fixture['id'],fixture['observation_digest'])
    if prior!=fixture['observation_digest']: raise SystemExit('C018 non-identical shared Java fixture: '+fixture['id'])
 return maps,owners,declared

def metadata():
 pbft=load(PBFT); backup=load(BACKUP); source=load(SOURCE); recon=load(RECON); cases=load(CASES); manifest=load(MANIFEST); tracker=load(TRACKER)
 if (pbft.get('schema'),backup.get('schema'),source.get('schema'),recon.get('schema'),cases.get('schema'))!=('c018-pbft-vectors.v1','c018-backup-vectors.v1','c018-backup-source-inventory.v1','c018-ownership-reconciliation.v1','c018-cases.v1'): raise SystemExit('C018 oracle schema drift')
 for row in pbft['java_sources']:
  path=ROOT/row['path']
  if not path.is_file() or digest(path)!=row['sha256']: raise SystemExit('C018 PBFT source drift: '+row['path'])
 for row in source['sources']:
  path=ROOT/'java-tron'/row['path']
  if not path.is_file() or digest(path)!=row['sha256']: raise SystemExit('C018 backup source drift: '+row['path'])
 expected_source=source_rows(); rows=recon['rows']; by_stable={r['stable_id']:r for r in rows}
 if set(by_stable)!=set(expected_source) or len(by_stable)!=len(rows): raise SystemExit('C018 ownership reconciliation set/identity drift')
 for stable,want in expected_source.items():
  got=by_stable[stable]
  for key,value in want.items():
   if got.get(key)!=value: raise SystemExit(f'C018 originating ledger field drift: {stable}.{key}: {got.get(key)!r} != {value!r}')
  if got.get('parameters')!=provenance(got): raise SystemExit('C018 duplicated provenance drift: '+stable)
 expected,owners,declared=family_maps(); canonical={r['case_id']:r for r in cases['cases']}; reconciled={r['case_id']:r for r in rows}
 family_rows={r['case_id']:r for _,(name,_,_,_) in FAMILIES.items() for r in load(ORACLES/name)['cases']}
 if len(declared)!=136 or len(set(declared))!=136 or set(canonical)!=set(expected) or set(reconciled)!=set(expected): raise SystemExit('C018 exact family union drift')
 if recon['counts']!={'c017_pbft_exclusions':64,'c018_production_rows':59,'c018_java_test_rows':13,'retained':136,'excluded':0,'total':136}: raise SystemExit('C018 retained/excluded count drift')
 for cid,value in expected.items():
  target,test,name=owners[cid]; family=family_rows[cid]
  for row in (canonical[cid],reconciled[cid]):
   if row['stable_id'] not in expected_source or row['expected_result']!=value or row['rust_target']!=target or row['rust_test']!=test or row['family_manifest']!=name or row['seam_owner']!='C018' or row['expected_digest']!=case_digest(row): raise SystemExit('C018 canonical assignment drift: '+cid)
   if row['parameters']!=provenance(reconciled[cid]): raise SystemExit('C018 canonical provenance drift: '+cid)
   for key in ('case_kind','assertion_family','evidence_kind','executable_id','java_source_sha256','java_expected_digest'):
    if row.get(key)!=family.get(key): raise SystemExit(f'C018 canonical exact field drift: {cid}.{key}')
   detail='source_assertion' if row['evidence_kind']=='source_assertion' else 'java_fixture'
   if row.get(detail)!=family.get(detail): raise SystemExit(f'C018 canonical evidence detail drift: {cid}.{detail}')
 names=['c018-pbft-vectors.v1.json','c018-backup-vectors.v1.json','c018-backup-source-inventory.v1.json','c018-ownership-reconciliation.v1.json','c018-cases.v1.json',*(v[0] for v in FAMILIES.values())]
 for name in names:
  key=name.removesuffix('.v1.json').replace('-','_')
  if manifest.get(key)!={'path':name,'sha256':digest(ORACLES/name)}: raise SystemExit('C018 central manifest drift: '+key)
 if recon['source_ledgers']!={'production_sha256':digest(PROD),'java_tests_sha256':digest(TESTS),'c017_reconciliation_sha256':digest(C017)}: raise SystemExit('C018 source-ledger digest drift')
 chunk=next((row for row in tracker['chunks'] if row.get('id')=='C018'),None); c019=next((row for row in tracker['chunks'] if row.get('id')=='C019'),None)
 review=chunk.get('review',{}) if chunk else {}
 if not chunk or chunk.get('status')!='done' or chunk.get('owner') is not None or chunk.get('resume') is not None or [row.get('id') for row in chunk.get('items',[])]!=[f'C018.{index:02d}' for index in range(1,7)] or any(row.get('status')!='done' for row in chunk.get('items',[])) or chunk.get('gate',{}).get('status')!='passed' or review.get('state')!='approved' or any(row.get('status')!='closed' for row in review.get('findings',[])): raise SystemExit('C018 tracker closure metadata drift')
 if not c019 or c019.get('status')!='todo' or c019.get('items',[{}])[0].get('id')!='C019.01' or c019.get('items',[{}])[0].get('status')!='todo': raise SystemExit('C018 next tracker item drift')
 print(json.dumps({'schema':'c018-metadata-v3','c017_pbft_exclusions':64,'production_rows':59,'java_tests':13,'retained':136,'excluded':0,'family_suites':4,'review':'approved','next':'C019.01','status':'passed'},separators=(',',':')))
def oracle():
 session=install_java_reference_guard(ROOT)
 with tempfile.TemporaryDirectory(prefix='c018-java-',dir=session.work) as raw:
  out=pathlib.Path(raw); init=out/'classpath.gradle'; init.write_text("allprojects { p -> if (p.path == ':framework') { p.afterEvaluate { p.tasks.register('c018RuntimeClasspath') { doLast { println 'C018_CLASSPATH=' + p.sourceSets.test.runtimeClasspath.asPath } } } } }\n")
  classes=['org.tron.common.backup.BackupManagerTest','org.tron.common.backup.BackupServerTest','org.tron.common.backup.KeepAliveMessageTest','org.tron.common.backup.UdpMessageTypeEnumTest']; args=[':framework:test']
  for cls in classes: args+=['--tests',cls]
  result=session.gradle(args)
  if result.returncode: raise SystemExit('C018 pinned Java backup tests failed:\n'+result.stderr.decode('utf-8','replace'))
  cp_result=session.gradle(['-I',str(init),':framework:c018RuntimeClasspath'])
  if cp_result.returncode: raise SystemExit('C018 Java classpath failed:\n'+cp_result.stderr.decode('utf-8','replace'))
  matches=[line.split('=',1)[1] for line in cp_result.stdout.decode().splitlines() if line.startswith('C018_CLASSPATH=')]
  if len(matches)!=1: raise SystemExit('C018 Java classpath was not captured exactly once')
  classpath=matches[0]; source=ROOT/'tools/consensus/C018Oracle.java'; session.run([str(session.java_home/'bin/javac'),'-cp',classpath,'-d',str(out),str(source)],cwd=session.work,classpath=classpath,check=True)
  runtime=str(out)+os.pathsep+classpath; capture=session.run([str(session.java_home/'bin/java'),'-cp',runtime,'C018Oracle'],cwd=session.work,classpath=runtime,check=True)
  records=[json.loads(line) for line in capture.stdout.decode().splitlines() if line.startswith('{')]
  if len(records)!=1: raise SystemExit('C018 Java oracle emitted no unique capture')
  got=records[0]; vectors={r['id']:r for r in load(PBFT)['vectors']}; backup=load(BACKUP)
  expected={'schema':'c018-java-capture.v3','capture_contract':'pinned-input-output-error','block_raw_hex':vectors['C018.PBFT.BLOCK.UNSIGNED']['raw_hex'],'block_unsigned_hex':vectors['C018.PBFT.BLOCK.UNSIGNED']['message_hex'],'block_signed_hex':vectors['C018.PBFT.BLOCK.SIGNED']['message_hex'],'block_view':7,'block_epoch':42,'block_no':'7_0','block_data_type':'BLOCK','srl_raw_hex':vectors['C018.PBFT.SRL.UNSIGNED']['raw_hex'],'srl_no':'99_1','srl_members':2,'backup_false_hex':backup['wire']['vectors'][0]['hex'],'backup_false_flag':False,'backup_false_priority':6,'backup_true_hex':backup['wire']['vectors'][1]['hex'],'backup_true_flag':True,'backup_true_priority':10,'backup_type':5}
  for key,value in expected.items():
   if got.get(key)!=value: raise SystemExit(f'C018 Java capture mismatch at {key}: {got.get(key)!r} != {value!r}')
  if len(got['block_signature_hex'])!=130: raise SystemExit('C018 Java recoverable signature length drift')
  print(json.dumps({'schema':'c018-java-oracle-v3','backup_tests':13,'direct_capture_fields':len(expected)+1,'method_contract':'pinned-input-output-error','status':'passed'},separators=(',',':')))
def run_cases():
 expected,owners,_=family_maps(); all_emitted={}
 for target,(name,test,field,count) in FAMILIES.items():
  wanted={cid:value for cid,value in expected.items() if owners[cid][0]==target}
  cmd=['cargo','test','-p','tron-consensus','--test',target,'--locked',test,'--','--exact','--nocapture']; print('+',' '.join(cmd),flush=True)
  result=subprocess.run(cmd,cwd=RUST,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT); print(result.stdout,end='')
  if result.returncode: raise subprocess.CalledProcessError(result.returncode,cmd)
  records=[]
  for line in result.stdout.splitlines():
   match=re.search(r'(C018-[PT]-[0-9A-F]{16})=(.+)$',line)
   if match: records.append((match.group(1),match.group(2)))
  emitted=dict(records)
  if len(records)!=len(emitted): raise SystemExit('C018 emitted duplicate case IDs in '+target)
  require_exact(target,wanted,emitted)
  if all_emitted.keys()&emitted.keys(): raise SystemExit('C018 cross-suite emitted duplicate IDs')
  all_emitted.update(emitted)
 require_exact('all family suites',expected,all_emitted)
 print(json.dumps({'schema':'c018-case-report-v2','family_suites':4,'asserted':len(all_emitted),'duplicates':0,'excluded':0,'status':'passed'},separators=(',',':')))
def run(target):
 cmd=COMMANDS[target]; print('+',' '.join(cmd),flush=True); subprocess.run(cmd,cwd=RUST,check=True)
def main():
 choices=['metadata','oracle','cases',*COMMANDS,'all']; parser=argparse.ArgumentParser(); parser.add_argument('targets',nargs='*',choices=choices); args=parser.parse_args(); targets=args.targets or ['all']
 if 'all' in targets: targets=['metadata','oracle','cases','pbft','backup','scenario','all-targets']
 for target in targets:
  if target=='metadata': metadata()
  elif target=='oracle': oracle()
  elif target=='cases': run_cases()
  else: run(target)
 print(json.dumps({'schema':'c018-gate-v3','targets':targets,'status':'passed'},separators=(',',':')))
if __name__=='__main__': main()
