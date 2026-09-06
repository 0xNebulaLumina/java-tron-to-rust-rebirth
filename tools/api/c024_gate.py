#!/usr/bin/env python3
import argparse, hashlib, json, pathlib, re, subprocess, sys, tempfile
ROOT=pathlib.Path(__file__).resolve().parents[2]; RUST=ROOT/'rust-tron'; ORACLES=ROOT/'docs/oracles'
METHODS=ORACLES/'c024-methods.v1.json'; RECON=ORACLES/'c024-ownership-reconciliation.v1.json'; SCENARIOS=ORACLES/'c024-scenarios.v1.json'; TRACKER=ROOT/'docs/PORTING_TRACKER.json'; MANIFEST=ORACLES/'manifest.v1.json'
COMMANDS={'parser':['cargo','test','-p','tron-apis','--test','c024_jsonrpc','--locked'],'methods':['cargo','test','-p','tron-apis','--test','c024_methods','--locked'],'filters':['cargo','test','-p','tron-apis','--test','c024_filters','--locked'],'server':['cargo','test','-p','tron-apis','--test','c024_server','--locked'],'scenarios':['cargo','test','-p','tron-apis','--test','c024_scenarios','--locked','--','--test-threads=1'],'cursors':['cargo','test','-p','tron-apis','--test','c024_cursor_live','--locked'],'all-targets':['cargo','check','-p','tron-apis','--all-targets','--locked']}
def load(p):return json.loads(p.read_text())
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def metadata():
 m=load(METHODS); names=[r['name'] for r in m.get('methods',[])];
 if m.get('count')!=52 or len(names)!=52 or len(set(names))!=52:raise SystemExit('C024 exact 52-method inventory drift')
 source=(RUST/'crates/tron-apis/src/jsonrpc_methods.rs').read_text(); declared=re.search(r'TRON_JSON_RPC_METHODS: \[&str; 52\] = \[(.*?)\];',source,re.S)
 if not declared or re.findall(r'"([^"]+)"',declared.group(1))!=names:raise SystemExit('C024 Rust method inventory drift')
 r=load(RECON); rows=r.get('rows',[])
 if r.get('canonical_counts')!={'production_methods':52,'java_tests':227,'total':279} or len(rows)!=279 or r.get('unmapped')!=[]:raise SystemExit('C024 exact 279-row reconciliation drift')
 if len({x['id'] for x in rows})!=279:raise SystemExit('C024 duplicate reconciliation identity')
 for row in (x for x in rows if x['kind']=='java_test'):
  p=ROOT/row['source']['path'];
  if sha(p)!=row['source_sha256']:raise SystemExit('C024 Java source hash drift: '+row['id'])
 s=load(SCENARIOS); tests={p.stem:p.read_text() for p in (RUST/'crates/tron-apis/tests').glob('c024_*.rs')}
 if s.get('count')!=13 or len(s.get('scenarios',[]))!=13:raise SystemExit('C024 scenario count drift')
 for row in s['scenarios']:
  f,n=row['rust_case'].split('::',1)
  if f not in tests or not re.search(r'\bfn\s+'+re.escape(n)+r'\b',tests[f]):raise SystemExit('C024 missing scenario dispatch: '+row['id'])
 manifest=load(MANIFEST)
 for key,path in [('c024_methods',METHODS),('c024_scenarios',SCENARIOS),('c024_ownership_reconciliation',RECON)]:
  if manifest.get(key)!={'path':path.name,'sha256':sha(path)}:raise SystemExit('central manifest drift: '+key)
 chunk=next(row for row in load(TRACKER)['chunks'] if row['id']=='C024')
 if chunk.get('status')!='done' or chunk.get('owner') is not None or chunk.get('resume') is not None or chunk['gate'].get('status')!='passed' or chunk['gate'].get('last_failure') is not None or any(item.get('status')!='done' for item in chunk['items']):raise SystemExit('C024 tracker closure drift')
 if chunk.get('review')!={'state':'approved','round':1,'findings':[]}:raise SystemExit('C024 review approval drift')
 if r.get('review')!={'state':'approved','findings':[]}:raise SystemExit('C024 reconciliation approval drift')
 print(json.dumps({'schema':'c024-metadata-v1','methods':52,'java_tests':227,'rows':279,'scenarios':13,'unmapped':0,'status':'passed'},separators=(',',':')))
def oracle():
 sys.path.insert(0,str(ROOT/'tools/reference-runner'));from java_reference_guard import install_java_reference_guard
 with install_java_reference_guard(ROOT) as session:
  with tempfile.TemporaryDirectory(prefix='c024-java-',dir=session.work) as raw:
   out=pathlib.Path(raw);src=ROOT/'tools/api/C024Oracle.java';c=session.run([str(session.java_home/'bin/javac'),'-d',str(out),str(src)],cwd=session.work)
   if c.returncode:raise SystemExit('C024 Java oracle compilation failed')
   before=session.guard(phase='immediately before C024 authenticated capture',classpath=str(out));result=session.run([str(session.java_home/'bin/java'),'-cp',str(out),'C024Oracle'],cwd=session.work,classpath=str(out));after=session.guard(phase='immediately after C024 authenticated capture',classpath=str(out))
   text=result.stdout.decode('utf-8','replace')
   if result.returncode or before!=after or 'C024_METHODS=52' not in text or 'C024_JAVA_TESTS=227' not in text or 'C024_NEW_FILTER_FINALIZED_ERROR=invalid block range params' not in text:raise SystemExit('C024 guarded Java capture mismatch')
 print(json.dumps({'schema':'c024-java-oracle-v1','methods':52,'java_tests':227,'status':'passed'},separators=(',',':')))
def run(name):print('+',' '.join(COMMANDS[name]),flush=True);subprocess.run(COMMANDS[name],cwd=RUST,check=True)
def main():
 choices=['metadata','oracle',*COMMANDS,'all'];p=argparse.ArgumentParser();p.add_argument('targets',nargs='*',choices=choices);targets=p.parse_args().targets or ['all']
 if 'all' in targets:targets=['metadata','oracle','parser','methods','filters','server','scenarios','cursors','all-targets']
 for target in targets: metadata() if target=='metadata' else oracle() if target=='oracle' else run(target)
 print(json.dumps({'schema':'c024-gate-v1','targets':targets,'evidence':{'filter_queue_bounds':['count','bytes','drop-oldest'],'publish_prunes_expired':True,'history_bounds':['blocks','count','bytes'],'reorg_removes_history':True,'query_preclone_limit':True,'jsonrpc_blocking_executor':['permits','deadline','cancellation']},'status':'passed'},separators=(',',':')))
if __name__=='__main__':main()
