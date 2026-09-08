#!/usr/bin/env python3
"""Exact guarded Java, ownership, production and Rust-dispatch gate for C027."""
from __future__ import annotations
import argparse,copy,hashlib,json,re,subprocess,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2];ORACLES=ROOT/'docs/oracles'
sys.path.insert(0,str(ROOT/'tools/reference-runner'))
from java_reference_guard import install_java_reference_guard
SESSION=install_java_reference_guard(ROOT)
SOURCE=ORACLES/'c027-java-source-inventory.v1.json';FIXTURES=ORACLES/'c027-fixtures.v1.json';RECON=ORACLES/'c027-ownership-reconciliation.v1.json';COMMANDS=ORACLES/'c027-command-manifest.v1.json';RESULTS=ORACLES/'c027-java-reference-results.v1.json';TEST_LEDGER=ORACLES/'java-test-ownership.v1.json';PROD_LEDGER=ORACLES/'production-ownership.v1.json';MANIFEST=ORACLES/'manifest.v1.json';ORACLE=Path(__file__).with_name('c027_oracle.py')
DIRECT_LITE_IDS={'TCASE-07830A292D3A80E9','TCASE-CA377A3F0CCDED17','TCASE-73568EC3033FC84A','TCASE-1FDB8C6B77896021','TCASE-3B94179296286BCD'}
FAMILIES={'db':{'C027.03','C027.04'},'lite':{'C027.05'},'keystore':{'C027.06'},'resources':{'C027.03'}}
def load(p):return json.loads(p.read_text())
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def test_key(r):return (r['id'],r['source']['path'],r['source']['line'],r['case'])
def prod_key(r):return (r['id'],r['source']['path'],r['source']['line'],r['kind'],r['symbol'])
def canonical(v):return json.dumps(v,sort_keys=True,separators=(',',':')).encode()
def value_sha(v):return hashlib.sha256(canonical(v)).hexdigest()
C027_MANIFEST={
 'c027_java_source_inventory':SOURCE,'c027_fixtures':FIXTURES,
 'c027_ownership_reconciliation':RECON,'c027_command_manifest':COMMANDS,
 'c027_java_reference_results':RESULTS,
 'c027_gate_source':Path(__file__),'c027_oracle_source':ORACLE,
 'c027_junit_runner_source':Path(__file__).with_name('C027Oracle.java'),
 'c027_command_agent_source':Path(__file__).with_name('C027CommandAgent.java'),
 'c027_direct_oracle_source':Path(__file__).with_name('C027DirectOracle.java')}
def normalize_string(text):
 text=re.sub(r'/tmp/c027-java-oracle-[^/]+/runs/\d+-[^/]+','${SANDBOX}',text)
 text=re.sub(r'/tmp/java-reference-[^/]+/java-tron/','${JAVA_REFERENCE}/',text)
 text=re.sub(r'(?:tmp/)?junit\d+(?:/junit\d+)*','${JUNIT_ROOT}',text)
 text=re.sub(r'\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}\b','${DYNAMIC_UUID}',text)
 text=re.sub(r'(?<=/)\d{10,17}(?=/|$)','${DYNAMIC_CHECKPOINT}',text)
 text=re.sub(r'UTC--\d{4}-\d\d-\d\dT[^/\\\s]+','${UTC_FILENAME}',text)
 text=re.sub(r'\bT[1-9A-HJ-NP-Za-km-z]{33}\b','${DYNAMIC_ADDRESS}',text)
 return re.sub(r'(?i)(take|use) \d+ (ms|s|seconds)',r'\1 ${ELAPSED_SECONDS} \2',text)
def command_observation(actual):
 physical=re.compile(r'(?:^|/)(?:CURRENT|LOCK|LOG(?:\.old)?|MANIFEST-[^/]+|OPTIONS-[^/]+|\d+\.(?:log|sst|ldb))$');grouped={}
 for mutation in actual.get('mutation_set',[]):
  path=mutation.get('path','')
  if re.match(r'^tmp/(?:libjansi|librocksdbjni|libleveldbjni)-',path) or re.search(r'/(?:CURRENT|LOG|LOCK|LOG\.old(?:\.\d+)?)$',path) or re.search(r'/(?:engine\.properties|IDENTITY)$',path) or physical.search(path):continue
  path=normalize_string(path);parent,name=path.rsplit('/',1) if '/' in path else ('',path)
  if re.fullmatch(r'MANIFEST-.+',name):name='${MANIFEST}'
  elif re.fullmatch(r'OPTIONS-.+',name):name='${OPTIONS}'
  elif re.fullmatch(r'\d+\.log',name):name='${DB_LOG}'
  elif name.endswith('.sst'):name='${SST}'
  elif name.endswith('.ldb'):name='${LDB}'
  item={'path':parent+'/'+name if parent else name,'operation':mutation.get('operation'),'before_mode':mutation.get('before_mode'),'after_mode':mutation.get('after_mode')};key=canonical(item);grouped[key]=(item,grouped.get(key,(None,0))[1]+1)
 stable=[]
 for key in sorted(grouped):item,count=grouped[key];item['count']=count;stable.append(item)
 return {'argv':[normalize_string(x) for x in actual.get('argv',[])],'logical_exit':actual.get('logical_exit'),'process_exit':actual.get('process_exit'),'stdout_normalized_utf8':actual.get('stdout',{}).get('normalized_utf8'),'stderr_normalized_utf8':actual.get('stderr',{}).get('normalized_utf8'),'mutation_set':stable,'capture_scope':actual.get('capture_scope')}
def row_observation(row):
 p=row.get('junit_provenance',{})
 return {'stable_id':row.get('stable_id'),'run_count':p.get('run_count'),'failure_count':p.get('failure_count'),'ignore_count':p.get('ignore_count'),'status':p.get('status'),'command_result_ids':row.get('command_result_ids',[]),'direct_result_ids':row.get('direct_result_ids',[]),'retained_reason':row.get('retained_reason')}
def manifest_errors(manifest=None):
 manifest=load(MANIFEST) if manifest is None else manifest;errors=[]
 for key,path in C027_MANIFEST.items():
  want={'path':str(path.relative_to(ORACLES) if path.parent==ORACLES else path.relative_to(ROOT)),'sha256':sha(path)}
  if manifest.get(key)!=want:errors.append('central manifest drift: '+key)
 return errors
def rust_dispatch_errors(row):
 spec=row.get('rust_test','');parts=spec.split('::',1)
 if len(parts)!=2:return ['invalid rust_test '+spec]
 module,symbol=parts;matches=list((ROOT/'rust-tron').glob(f'crates/*/tests/{module}.rs'))
 if len(matches)!=1:return [f'{row["stable_id"]}: expected one Rust test module {module}, got {len(matches)}']
 text=matches[0].read_text();pos=text.find(row['stable_id'])
 if pos<0:return [f'{row["stable_id"]}: stable ID absent from {matches[0].relative_to(ROOT)}']
 sym=re.search(r'\bfn\s+'+re.escape(symbol)+r'\b',text)
 if not sym:return [f'{row["stable_id"]}: Rust test symbol {symbol} absent']
 next_test=text.find('\n#[test]',sym.end());body=text[sym.start():next_test if next_test>=0 else len(text)]
 if re.search(re.escape(row['stable_id'])+r'\s*=>\s*\{?\s*\}?\s*,',text):return [f'{row["stable_id"]}: empty dispatch arm']
 if not re.search(r'assert(?:_eq|_ne|!|_matches)|panic!|expect\(|unwrap_err\(|run_[a-zA-Z0-9_]+\(|dispatch_row\(|assert_row_behavior\(',body):return [f'{row["stable_id"]}: no behavioral assertion/terminal scenario call']
 return []
def rust_name(java_case):return 'scenario_'+re.sub(r'(?<!^)(?=[A-Z])','_',java_case).lower()
def keystore_dispatch_errors(rows):
 path=ROOT/'rust-tron/crates/tron-toolkit/tests/c027_keystore.rs';text=path.read_text();errors=[]
 results={r['stable_id']:r for r in load(RESULTS)['rows'] if r.get('implementation_item')=='C027.06'}
 seen={}
 for row in rows:
  sid=row['stable_id'];result=results.get(sid);expected_fn=rust_name(row['java_case'])
  if result is None:errors.append(f'{sid}: missing final Java observation');continue
  observation=result.get('observation_sha256','')
  arm=re.search(r'"'+re.escape(sid)+r'"\s*=>\s*assert_oracle_bound\(id,\s*"([0-9a-f]{64})",\s*([a-zA-Z0-9_]+)\)',text)
  if not arm:errors.append(f'{sid}: missing exact ID -> observation -> scenario dispatch');continue
  actual_hash,actual_fn=arm.groups()
  if actual_hash!=observation:errors.append(f'{sid}: dispatch observation signature mismatch')
  if actual_fn!=expected_fn:errors.append(f'{sid}: misrouted scenario {actual_fn}, expected {expected_fn}')
  prior=seen.get(actual_fn)
  if prior and prior[0]!=observation:errors.append(f'{sid}: scenario {actual_fn} shared across distinct observations ({prior[1]})')
  seen[actual_fn]=(observation,sid)
  fn=re.search(r'\bfn\s+'+re.escape(actual_fn)+r'\s*\(\)\s*\{',text)
  if not fn:errors.append(f'{sid}: concrete scenario {actual_fn} absent');continue
  next_fn=re.search(r'\nfn\s+',text[fn.end():]);end=fn.end()+(next_fn.start() if next_fn else len(text)-fn.end());body=text[fn.start():end]
  if sid not in body or observation not in body:errors.append(f'{sid}: scenario lacks exact ID/signature assertion')
  if not re.search(r'assert(?:_eq|_ne|!|_matches)|unwrap_err\(|dispatch\(',body):errors.append(f'{sid}: scenario lacks behavioral assertion')
  if re.search(r'\b(?:assert_(?:cli_utils_behavior|import_dispatch|list_dispatch|new_dispatch|update_tty_dispatch)|dispatch_row|assert_row_behavior|run_[a-zA-Z0-9_]+)\s*\(',body):errors.append(f'{sid}: generic family/catchall scenario helper is forbidden')
 if len(seen)!=len(rows):errors.append(f'keystore scenarios are not one-to-one with {len(rows)} unique observation signatures')
 return errors
def metadata_errors(check_rust=True,documents=None):
 errors=[];documents=documents or {}
 for p in (*C027_MANIFEST.values(),TEST_LEDGER,PROD_LEDGER,MANIFEST):
  if not p.is_file():errors.append('missing '+str(p.relative_to(ROOT)))
 if errors:return errors
 errors.extend(manifest_errors(documents.get('manifest')))
 source=documents.get('source') or load(SOURCE);recon=documents.get('recon') or load(RECON);commands=documents.get('commands') or load(COMMANDS)
 ledger=[r for r in load(TEST_LEDGER)['rows'] if r.get('acceptance_gate')=='C027.V'];actual=[(r['stable_id'],r['source']['path'],r['source']['line'],r['java_case']) for r in recon['rows']]
 if actual!=[test_key(r) for r in ledger]:errors.append('reconciliation differs from exact ordered C027.V test ledger')
 prod=[r for r in load(PROD_LEDGER)['rows'] if r.get('acceptance_gate')=='C027.V'];captured=source.get('production_accounting',{}).get('rows',[])
 if [(r['id'],r['path'],r['line'],r['kind'],r['symbol']) for r in captured]!=[prod_key(r) for r in prod]:errors.append('production inventory differs from exact ordered 204-row C027.V ledger')
 if len(source.get('sources',[]))!=57 or len(captured)!=204:errors.append('57/204 source accounting drift')
 dispositions={d:sum(r['disposition']==d for r in recon['rows']) for d in ('rust_equivalent','retained_reference_only','reviewed_non_applicable')}
 if dispositions!={'rust_equivalent':126,'retained_reference_only':11,'reviewed_non_applicable':3}:errors.append('126/11/3 disposition drift')
 if recon.get('unmapped_count')!=0 or recon.get('generic_count')!=0:errors.append('unmapped/generic rows are forbidden')
 result_ids=commands.get('result_ids',[])
 if result_ids!=[r['id'] for r in ledger]:errors.append('command manifest does not reference every exact result ID')
 if check_rust:
  for row in recon['rows']:errors.extend(rust_dispatch_errors(row))
  errors.extend(keystore_dispatch_errors([r for r in recon['rows'] if r['implementation_item']=='C027.06']))
 return errors
def fixture_errors():
 done=subprocess.run(['cargo','test','-p','tron-storage','--test','c027_toolkit_transactions','emit_c027_six_row_fixture_json','--','--ignored','--exact','--nocapture'],cwd=ROOT/'rust-tron',text=True,capture_output=True)
 if done.returncode:return ['canonical rustlog fixture emitter failed: '+done.stderr.strip()]
 line=next((line for line in done.stdout.splitlines() if line.startswith('{"entry_count":6,')),None)
 if line is None:return ['canonical rustlog fixture emitter omitted JSON']
 actual=json.loads(line);expected=load(FIXTURES)['storage_fixture']
 checks={'entry_count':expected['entry_count'],'physical_size':expected['physical_size'],'state_sha256':expected['state_sha256'],'tree_sha256':expected['tree_sha256'],'manifest_sha256':expected['manifest_sha256'],'manifest':expected['manifest_layout'],'wal':expected['wal_layout']}
 return [] if actual==checks else [f'canonical rustlog fixture drift: {actual} != {checks}']
def result_errors(doc=None):
 if doc is None and not RESULTS.is_file():return ['missing guarded Java results artifact']
 doc=load(RESULTS) if doc is None else doc;ledger=[r for r in load(TEST_LEDGER)['rows'] if r.get('acceptance_gate')=='C027.V'];rows=doc.get('rows',[])
 errors=[]
 if [r.get('stable_id') for r in rows]!=[r['id'] for r in ledger] or len(rows)!=140:errors.append('results differ from exact ordered 140-row ledger')
 for r in rows:
  provenance=r.get('junit_provenance',{});is_resource=not r.get('source',{}).get('path','').endswith('.java');is_direct_lite=r.get('stable_id') in DIRECT_LITE_IDS
  if r.get('observation_sha256')!=value_sha(row_observation(r)) or not provenance:errors.append('invalid guarded observation hash '+str(r.get('stable_id')))
  if is_direct_lite:
   if provenance.get('status')!='replaced_by_deterministic_direct' or not r.get('direct_result_ids'):errors.append('invalid direct-lite replacement '+str(r.get('stable_id')))
  elif not is_resource and (provenance.get('run_count')!=1 or provenance.get('failure_count')!=0 or provenance.get('ignore_count')!=0 or provenance.get('timed_out')):errors.append('failed/skipped/timed-out Java row '+str(r.get('stable_id')))
  if r.get('invocation_kind')=='toolkit' and not r.get('command_result_ids') and not r.get('direct_result_ids'):errors.append('missing command/direct Java evidence '+str(r.get('stable_id')))
  if r.get('invocation_kind') in {'direct_api','archive_manifest'} and not r.get('direct_result_ids'):errors.append('missing direct Java evidence '+str(r.get('stable_id')))
  if not r.get('command_result_ids') and not r.get('direct_result_ids') and not r.get('retained_reason'):errors.append('unmapped Java result '+str(r.get('stable_id')))
 commands=doc.get('command_results',[]);known={c.get('id') for c in commands};direct=doc.get('direct_results',[]);direct_known={c.get('id') for c in direct}
 for r in rows:
  if any(cid not in known for cid in r.get('command_result_ids',[])):errors.append('dangling command result link '+str(r.get('stable_id')))
  if any(cid not in direct_known for cid in r.get('direct_result_ids',[])):errors.append('dangling direct result link '+str(r.get('stable_id')))
 for command in commands:
  actual=command.get('actual',{});expected=command.get('expected',{});observed=command_observation(actual)
  if actual.get('logical_exit') is None or not actual.get('argv') or expected!=observed or command.get('observation_projection')!=observed or command.get('observation_sha256')!=value_sha(observed) or not command.get('matches'):errors.append('incomplete/mismatched command result '+str(command.get('id')))
  if actual.get('capture_scope')!='picocli_execute_advice':errors.append('non-immediate command capture '+str(command.get('id')))
  if not actual.get('filesystem_before',{}).get('tree_sha256') or not actual.get('filesystem_after',{}).get('tree_sha256'):errors.append('missing immediate command tree '+str(command.get('id')))
 for result in direct:
  actual=result.get('actual');expected=result.get('expected')
  if not result.get('matches') or not isinstance(actual,dict) or expected!=actual or result.get('observation_sha256')!=value_sha(actual):errors.append('invalid direct Java result '+str(result.get('id')))
 if any(c.get('actual',{}).get('process_exit_verification')=='junit_success' for c in commands):errors.append('JUnit-derived command process exits are forbidden')
 return errors
def mutation_errors():
 errors=[];base_results=load(RESULTS);base_source=load(SOURCE);base_recon=load(RECON);base_commands=load(COMMANDS);base_manifest=load(MANIFEST)
 def rejected(label,fn):
  try:found=fn()
  except Exception:found=['exception']
  if not found:errors.append('bypass mutation accepted: '+label)
 paired=copy.deepcopy(base_results);cmd=paired['command_results'][0];cmd['actual']['logical_exit']+=1;cmd['expected']['logical_exit']+=1
 rejected('paired expected+actual edit',lambda:result_errors(paired))
 retained=copy.deepcopy(base_results);retained['rows'][0]['retained_reason']='mutated while retaining observation hash'
 rejected('observation hash retention',lambda:result_errors(retained))
 drift_source=copy.deepcopy(base_source);drift_recon=copy.deepcopy(base_recon);drift_commands=copy.deepcopy(base_commands)
 drift_source['production_accounting']['rows'][0]['symbol']='coordinated-drift';drift_recon['rows'][0]['java_case']='coordinatedDrift';drift_commands['result_ids'][0]='TCASE-COORDINATEDDRIFT'
 rejected('coordinated row/source/reconciliation drift',lambda:metadata_errors(False,{'source':drift_source,'recon':drift_recon,'commands':drift_commands}))
 central=copy.deepcopy(base_manifest);central['c027_java_reference_results']['sha256']='0'*64
 rejected('central digest edit',lambda:manifest_errors(central))
 return errors
def run_oracle(write=False):
 argv=[sys.executable,str(ORACLE)]+(['--write'] if write else []);done=subprocess.run(argv,cwd=ROOT,text=True,capture_output=True)
 if done.stdout.strip():print(done.stdout.strip())
 return [] if done.returncode==0 else [done.stderr.strip() or 'guarded Java oracle failed']
def main():
 ap=argparse.ArgumentParser();ap.add_argument('target',nargs='?',default='all',choices=['metadata','oracle','db','lite','keystore','resources','reconciliation','mutations','all']);ap.add_argument('--write',action='store_true');a=ap.parse_args()
 errors=metadata_errors(check_rust=a.target not in {'oracle','mutations'})
 if not errors and a.target in {'oracle','all'}:errors+=run_oracle(a.write)
 if not errors and a.target in {'oracle','all'}:errors+=result_errors()
 if not errors and a.target in {'mutations','all'}:errors+=mutation_errors()
 if not errors:errors+=fixture_errors()
 if not errors and a.target in FAMILIES:
  rows=[r for r in load(RECON)['rows'] if r['implementation_item'] in FAMILIES[a.target]]
  if not rows:errors.append('empty '+a.target+' family')
 if errors:
  for e in errors:print('ERROR: '+e,file=sys.stderr)
  return 1
 print(f'C027 {a.target} OK: source={sha(SOURCE)} fixtures={sha(FIXTURES)} reconciliation={sha(RECON)} commands={sha(COMMANDS)}'+(f' results={sha(RESULTS)}' if RESULTS.exists() else ''))
 return 0
if __name__=='__main__':raise SystemExit(main())
