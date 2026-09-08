#!/usr/bin/env python3
"""Build and execute the pinned Java plugin test surface under the reference guard."""
import argparse,base64,copy,hashlib,json,os,re,subprocess,sys,tempfile,zipfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'tools/reference-runner'))
from java_reference_guard import atomic_write_json,install_java_reference_guard
SESSION=install_java_reference_guard(ROOT)
ORACLES=ROOT/'docs/oracles'; RECON=ORACLES/'c027-ownership-reconciliation.v1.json'; LEDGER=ORACLES/'java-test-ownership.v1.json'
OUTPUT=ORACLES/'c027-java-reference-results.v1.json'; PROBE=Path(__file__).with_name('C027Oracle.java')

def load(p:Path): return json.loads(p.read_text())
def canonical(v): return json.dumps(v,sort_keys=True,separators=(',',':')).encode()
def sha(b:bytes): return hashlib.sha256(b).hexdigest()
def file_sha(p:Path): return sha(p.read_bytes())
def c027_ledger(): return [r for r in load(LEDGER)['rows'] if r.get('acceptance_gate')=='C027.V']
def tree(root:Path):
 rows=[]
 if root.exists():
  for p in sorted(root.rglob('*')):
   relative=p.relative_to(root)
   if relative.name=='command-capture.txt': continue
   rel=relative.as_posix();st=p.lstat()
   if p.is_symlink(): rows.append({'path':rel,'type':'symlink','mode':oct(st.st_mode&0o7777),'uid':st.st_uid,'gid':st.st_gid,'size':st.st_size,'mtime_ns':st.st_mtime_ns,'link_target':os.readlink(p)})
   elif p.is_dir(): rows.append({'path':rel,'type':'directory','mode':oct(st.st_mode&0o7777),'uid':st.st_uid,'gid':st.st_gid,'size':st.st_size,'mtime_ns':st.st_mtime_ns})
   elif p.is_file(): rows.append({'path':rel,'type':'file','mode':oct(st.st_mode&0o7777),'uid':st.st_uid,'gid':st.st_gid,'size':st.st_size,'mtime_ns':st.st_mtime_ns,'content_sha256':file_sha(p)})
 stable=[{k:v for k,v in row.items() if k not in {'uid','gid','mtime_ns'}} for row in rows]
 return {'rows':rows,'tree_sha256':sha(b'C027TREE1\0'+canonical(stable))}
def mutations(a,b):
 left={r['path']:r for r in a['rows']};right={r['path']:r for r in b['rows']};out=[]
 for path in sorted(set(left)|set(right)):
  x=left.get(path);y=right.get(path)
  if x==y: continue
  out.append({'path':path,'operation':'create' if x is None else ('delete' if y is None else ('symlink' if (x or y).get('type')=='symlink' else 'modify')),'before_mode':x.get('mode') if x else None,'after_mode':y.get('mode') if y else None,'before_sha256':x.get('content_sha256') if x else None,'after_sha256':y.get('content_sha256') if y else None})
 return out
def canonicalize_string(text:str,sandbox:Path|None=None)->str:
 if sandbox is not None:text=text.replace(str(sandbox),'${SANDBOX}')
 text=re.sub(r'/tmp/c027-java-oracle-[^/]+/runs/\d+-[^/]+','${SANDBOX}',text)
 text=re.sub(r'/tmp/java-reference-[^/]+/java-tron/','${JAVA_REFERENCE}/',text)
 text=re.sub(r'(?:tmp/)?junit\d+(?:/junit\d+)*','${JUNIT_ROOT}',text)
 text=re.sub(r'\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}\b','${DYNAMIC_UUID}',text)
 text=re.sub(r'(?<=/)\d{10,17}(?=/|$)','${DYNAMIC_CHECKPOINT}',text)
 text=re.sub(r'UTC--\d{4}-\d\d-\d\dT[^/\\\s]+','${UTC_FILENAME}',text)
 text=re.sub(r'\bT[1-9A-HJ-NP-Za-km-z]{33}\b','${DYNAMIC_ADDRESS}',text)
 text=re.sub(r'(?i)(take|use) \d+ (ms|s|seconds)',r'\1 ${ELAPSED_SECONDS} \2',text)
 return text
def normalize_text(text:str,sandbox:Path)->str:return canonicalize_string(text,sandbox)
def stream(raw:bytes,sandbox:Path):
 text=raw.decode('utf-8','replace');norm=normalize_text(text,sandbox)
 return {'raw_base64':base64.b64encode(raw).decode(),'sha256':sha(raw),'normalized_utf8':norm}
def captured_tree(encoded:bytes):
 rows=[]
 for line in encoded.decode('utf-8','replace').splitlines():
  parts=line.split('\t',4)
  if len(parts)!=5:continue
  path=base64.b64decode(parts[0]).decode('utf-8','replace');kind={'D':'directory','F':'file','L':'symlink'}[parts[1]];row={'path':path,'type':kind,'mode':'0o'+parts[2],'uid':0,'gid':0,'size':int(parts[3]),'mtime_ns':0}
  if kind=='file':row['content_sha256']=parts[4]
  elif kind=='symlink':row['link_target']=base64.b64decode(parts[4]).decode('utf-8','replace')
  rows.append(row)
 stable=[{k:v for k,v in row.items() if k not in {'uid','gid','mtime_ns'}} for row in rows]
 return {'rows':rows,'tree_sha256':sha(b'C027TREE1\0'+canonical(stable))}
def build(work:Path):
 init=work/'classpath.gradle';init.write_text("""allprojects { p ->
 if (p.path == ':plugins') { p.afterEvaluate {
  p.tasks.register('c027RuntimeClasspath') { doLast { println p.sourceSets.test.runtimeClasspath.asPath } }
 } }
}
""")
 args=['-I',str(init),':plugins:testClasses',':framework:jar',':actuator:jar',':consensus:jar',':chainbase:jar',':crypto:jar',':common:jar',':protocol:jar',':platform:jar']
 done=SESSION.gradle(args)
 if done.returncode: raise RuntimeError(done.stderr.decode('utf-8','replace'))
 query=SESSION.gradle(['-I',str(init),'-q',':plugins:c027RuntimeClasspath'])
 lines=[x.strip() for x in query.stdout.decode().splitlines() if os.pathsep in x]
 if not lines: raise RuntimeError('Gradle omitted plugin runtime classpath')
 cp=lines[-1];classes=work/'classes';classes.mkdir()
 done=SESSION.run([str(SESSION.java_home/'bin/javac'),'-encoding','UTF-8','-source','8','-target','8','-cp',cp,'-d',str(classes),str(PROBE),str(Path(__file__).with_name('C027CommandAgent.java')),str(Path(__file__).with_name('C027DirectOracle.java'))],cwd=ROOT,classpath=cp)
 if done.returncode: raise RuntimeError(done.stderr.decode('utf-8','replace'))
 agent=work/'c027-command-agent.jar'
 with zipfile.ZipFile(agent,'w',zipfile.ZIP_DEFLATED) as archive:
  archive.writestr('META-INF/MANIFEST.MF','Manifest-Version: 1.0\nPremain-Class: C027CommandAgent\nCan-Redefine-Classes: false\n\n')
  for compiled in classes.glob('C027CommandAgent*.class'): archive.write(compiled,compiled.name)
 full=str(classes)+os.pathsep+cp;identity=SESSION.guard(phase='C027 plugin oracle classpath',classpath=full)
 byte_buddy=[Path(x) for x in cp.split(os.pathsep) if Path(x).name.startswith('byte-buddy-') and 'agent' not in Path(x).name]
 if len(byte_buddy)!=1: raise RuntimeError(f'expected one ByteBuddy runtime JAR, got {byte_buddy}')
 identity.update({'command_agent_jar':str(agent),'command_agent_jar_sha256':file_sha(agent),'command_agent_source_sha256':file_sha(Path(__file__).with_name('C027CommandAgent.java')),'byte_buddy_jar':byte_buddy[0].name,'byte_buddy_sha256':file_sha(byte_buddy[0])})
 return full,identity,agent
def parse_marker(raw:bytes):
 line=next((x for x in raw.decode('utf-8','replace').splitlines() if x.startswith('C027_RESULT|')),None)
 if line is None: raise RuntimeError('C027_RESULT marker missing')
 p=line.split('|',7)
 return {'successful':p[1]=='true','run_count':int(p[2]),'failure_count':int(p[3]),'ignore_count':int(p[4]),'captured_stdout':base64.b64decode(p[5]),'captured_stderr':base64.b64decode(p[6]),'failures':base64.b64decode(p[7])}
def architecture(identity):
 rows=[
  {'id':'C027.JAVA.X64','platform':'linux/x86_64','jdk':'8','source_set':'common+x86','backends':['LEVELDB','ROCKSDB'],'evidence_mode':'guarded_execution','java_identity':identity},
  {'id':'C027.JAVA.ARM.CONVERT','platform':'linux/aarch64','jdk':'17','source_set':'common+arm','backend':'ROCKSDB','evidence_mode':'source_bound_future_native','expected_logical_exit':0,'stream':'stderr','expected_text':'This command is not supported on {os.arch} architecture.','source':'java-tron/plugins/src/main/java/common/org/tron/plugins/DbConvert.java'},
  {'id':'C027.JAVA.ARM.ARCHIVE','platform':'linux/aarch64','jdk':'17','source_set':'common+arm','backend':'ROCKSDB','evidence_mode':'source_bound_future_native','expected_logical_exit':0,'stream':'stderr','expected_text':'{os.arch} architecture only supports RocksDB, which does not require manifest rebuilding (manifest rebuilding is a LevelDB-only feature).','source':'java-tron/plugins/src/main/java/arm/org/tron/plugins/DbArchive.java'},
  {'id':'C027.JAVA.ARM.ARCHIVE_STANDALONE','platform':'linux/aarch64','jdk':'17','source_set':'common+arm','backend':'ROCKSDB','evidence_mode':'source_bound_future_native','expected_logical_exit':0,'stream':'stdout','expected_text':'{os.arch} architecture only supports RocksDB, which does not require manifest rebuilding (manifest rebuilding is a LevelDB-only feature).','source':'java-tron/plugins/src/main/java/arm/org/tron/plugins/ArchiveManifest.java'}]
 for row in rows[1:]:row['source_sha256']=file_sha(SESSION.tree/row['source'].removeprefix('java-tron/'))
 return rows
def compact_document(document):
 identity=document.pop('java_identity')
 canonical_identity={k:v for k,v in identity.items() if k not in {'classpath','command_agent_jar','command_agent_jar_sha256'}}
 canonical_identity['classpath']=[{'role':Path(entry['path']).name,'kind':entry['kind'],'sha256':entry['sha256'],'files':entry.get('files')} for entry in identity.get('classpath',[])]
 identity_id=sha(canonical(canonical_identity))
 document['identities']={identity_id:identity}
 for collection in ('rows','command_results','direct_results'):
  for row in document.get(collection,[]):row.pop('java_identity',None);row['java_identity_id']=identity_id
 for row in document.get('architecture_results',[]):
  if row.pop('java_identity',None) is not None:row['java_identity_id']=identity_id
 for command in document.get('command_results',[]):
  actual=command['actual'];norm_arg=lambda value:canonicalize_string(value)
  physical=re.compile(r'(?:^|/)(?:CURRENT|LOCK|LOG(?:\.old)?|MANIFEST-[^/]+|OPTIONS-[^/]+|\d+\.(?:log|sst|ldb))$')
  def mutation_path(value):
   value=norm_arg(value);parent,name=value.rsplit('/',1) if '/' in value else ('',value)
   if re.fullmatch(r'MANIFEST-.+',name):name='${MANIFEST}'
   elif re.fullmatch(r'OPTIONS-.+',name):name='${OPTIONS}'
   elif re.fullmatch(r'\d+\.log',name):name='${DB_LOG}'
   elif name.endswith('.sst'):name='${SST}'
   elif name.endswith('.ldb'):name='${LDB}'
   return parent+'/'+name if parent else name
  grouped={}
  for m in actual['mutation_set']:
   if re.match(r'^tmp/(?:libjansi|librocksdbjni|libleveldbjni)-',m['path']):continue
   if re.search(r'/(?:CURRENT|LOG|LOCK|LOG\.old(?:\.\d+)?)$',m['path']):continue
   if re.search(r'/(?:engine\.properties|IDENTITY)$',m['path']) or physical.search(m['path']):continue
   item={'path':mutation_path(m['path']),'operation':m['operation'],'before_mode':m.get('before_mode'),'after_mode':m.get('after_mode')};key=canonical(item);grouped[key]=(item,grouped.get(key,(None,0))[1]+1)
  stable_mutations=[]
  for key in sorted(grouped):
   item,count=grouped[key];item['count']=count;stable_mutations.append(item)
  command['expected']={'argv':[norm_arg(x) for x in actual['argv']],'logical_exit':actual['logical_exit'],'process_exit':actual['process_exit'],'stdout_normalized_utf8':actual['stdout']['normalized_utf8'],'stderr_normalized_utf8':actual['stderr']['normalized_utf8'],'mutation_set':stable_mutations,'capture_scope':actual.get('capture_scope')}
  command['matches']=True;command['observation_sha256']=sha(canonical(command['expected']));command['observation_projection']=command['expected']
 for row in document.get('rows',[]):
  p=row.get('junit_provenance',{});row['observation_sha256']=sha(canonical({'stable_id':row['stable_id'],'run_count':p.get('run_count'),'failure_count':p.get('failure_count'),'ignore_count':p.get('ignore_count'),'status':p.get('status'),'command_result_ids':row.get('command_result_ids',[]),'direct_result_ids':row.get('direct_result_ids',[]),'retained_reason':row.get('retained_reason')}))
 document.pop('junit_provenance',None)
 return document
def guarded_direct_results(work,cp,identity):
 canonical_identity={k:v for k,v in identity.items() if k not in {'classpath','command_agent_jar','command_agent_jar_sha256'}}
 canonical_identity['classpath']=[{'role':Path(e['path']).name,'kind':e['kind'],'sha256':e['sha256'],'files':e.get('files')} for e in identity.get('classpath',[])]
 identity_id=sha(canonical(canonical_identity));captured=[]
 for stable_id in DIRECT_IDS:
  observations=[]
  for repeat in range(2):
   sandbox=work/'direct'/f'{stable_id}-{repeat}';sandbox.mkdir(parents=True)
   done=SESSION.run([str(SESSION.java_home/'bin/java'),'-Dfile.encoding=UTF-8','-Duser.timezone=UTC','-Dc027.java.identity.id='+identity_id,'-cp',cp,'C027DirectOracle',stable_id,str(sandbox)],cwd=work,classpath=cp,timeout=600)
   marker=next((x for x in done.stdout.decode('utf-8','replace').splitlines() if x.startswith('C027_DIRECT=')),None)
   if done.returncode or marker is None:raise RuntimeError(f'direct {stable_id} failed rc={done.returncode}: {done.stderr.decode("utf-8","replace")}')
   observations.append(json.loads(base64.b64decode(marker.split('=',1)[1])))
  if canonical(observations[0])!=canonical(observations[1]):raise RuntimeError('direct result drift '+stable_id)
  value=observations[0];result_id=stable_id+('/direct-lite/01' if value['family']=='lite' else '/direct-archive/01')
  captured.append({'id':result_id,'stable_id':stable_id,'kind':'direct_lite' if value['family']=='lite' else 'archive_manifest','scenario':value['scenario'],'actual':value,'expected':copy.deepcopy(value),'matches':True,'java_identity_id':identity_id,'observation_sha256':sha(canonical(value))})
 return captured
def capture():
 recon=load(RECON);ledger=c027_ledger();expected=[(r['id'],r['source']['path'],r['source']['line'],r['case']) for r in ledger];actual=[(r['stable_id'],r['source']['path'],r['source']['line'],r['java_case']) for r in recon['rows']]
 if actual!=expected: raise RuntimeError('reconciliation is not the exact ordered C027.V ledger')
 with tempfile.TemporaryDirectory(prefix='c027-java-oracle-') as td:
  work=Path(td);cp,identity,agent=build(work);direct_results=guarded_direct_results(work,cp,identity);rows=[];command_results=[]
  for index,row in enumerate(recon['rows']):
   print(f'C027 capture {index+1}/140 {row["stable_id"]}',file=sys.stderr,flush=True)
   sandbox=work/'runs'/f'{index:03d}-{row["stable_id"]}';sandbox.mkdir(parents=True);tmp=sandbox/'tmp';tmp.mkdir();before=tree(sandbox)
   if row['kind']=='test_resource':
    data=(SESSION.tree/row['source']['path'].removeprefix('java-tron/')).read_bytes();out={'stdout':stream(data,sandbox),'stderr':stream(b'',sandbox)};inv={'junit':{'successful':True,'run_count':0,'failure_count':0,'ignore_count':0},'timed_out':False};links=[]
   else:
    cls='org.tron.plugins.'+Path(row['source']['path']).stem
    if '/leveldb/' in row['source']['path']:cls='org.tron.plugins.leveldb.'+Path(row['source']['path']).stem
    elif '/rocksdb/' in row['source']['path']:cls='org.tron.plugins.rocksdb.'+Path(row['source']['path']).stem
    elif '/utils/' in row['source']['path']:cls='org.tron.plugins.utils.'+Path(row['source']['path']).stem
    control=work/'control';control.mkdir(exist_ok=True);capture_file=control/f'{index:03d}-{row["stable_id"]}.txt';is_direct_lite=row['stable_id'] in set(DIRECT_IDS[:5])
    prefix=[str(SESSION.java_home/'bin/java'),'-Dfile.encoding=UTF-8','-Duser.timezone=UTC','-Djava.io.tmpdir='+str(tmp)]
    if not is_direct_lite:prefix+=['-Dc027.fixture.root='+str(sandbox),'-Dc027.command.capture='+str(capture_file),'-javaagent:'+str(agent)]
    argv=prefix+['-cp',cp,'C027Oracle',cls,row['java_case']]
    if is_direct_lite:
     out={'stdout':stream(b'',sandbox),'stderr':stream(b'',sandbox)};inv={'junit':{'successful':False,'run_count':0,'failure_count':0,'ignore_count':0},'timed_out':False,'status':'replaced_by_deterministic_direct'};links=[]
    else:
     done=SESSION.run(argv,cwd=sandbox,classpath=cp,timeout=300);mark=parse_marker(done.stdout);out={'stdout':stream(mark['captured_stdout'],sandbox),'stderr':stream(mark['captured_stderr']+mark['failures'],sandbox)};inv={'junit':{k:mark[k] for k in ('successful','run_count','failure_count','ignore_count')},'timed_out':False};links=[]
     if capture_file.exists():
      capture_lines=capture_file.read_text().splitlines()
      for number,line in enumerate(capture_lines,1):
       parts=line.split('|',7)
       if len(parts)!=8 or parts[0]!='C027_COMMAND':continue
       command_argv=[base64.b64decode(x).decode('utf-8','replace') for x in parts[1].split(',') if x];logical_exit=int(parts[2]);command_stdout=base64.b64decode(parts[4]);command_stderr=base64.b64decode(parts[5]);command_before=captured_tree(base64.b64decode(parts[6]));command_after=captured_tree(base64.b64decode(parts[7]))
       if len(capture_lines)==1 and not command_stdout:command_stdout=mark['captured_stdout']
       actual_command={'argv':command_argv,'logical_exit':logical_exit,'process_exit':logical_exit&255,'process_exit_verification':'logical_code_mod_256_contract','capture_scope':'picocli_execute_advice','stdout':stream(command_stdout,sandbox),'stderr':stream(command_stderr,sandbox),'filesystem_before':command_before,'filesystem_after':command_after,'mutation_set':mutations(command_before,command_after),'logical_state_before_sha256':None,'logical_state_after_sha256':None,'manifest_before_sha256':None,'manifest_after_sha256':None}
       command={'id':row['stable_id']+f'/command/{number:02d}','stable_id':row['stable_id'],'expected':copy.deepcopy(actual_command),'actual':actual_command,'matches':True,'java_identity':identity};command['observation_sha256']=sha(canonical(actual_command));command_results.append(command);links.append(command['id'])
   provenance={'class':None if row['kind']=='test_resource' else cls,'method':row['java_case'],'run_count':inv.get('junit',{}).get('run_count',0),'failure_count':inv.get('junit',{}).get('failure_count',0),'ignore_count':inv.get('junit',{}).get('ignore_count',0),'timed_out':inv.get('timed_out',False),'status':inv.get('status','executed'),'stdout':out['stdout'],'stderr':out['stderr']}
   direct_ids=[result['id'] for result in direct_results if result.get('stable_id')==row['stable_id']]
   if not links and not direct_ids and row['invocation_kind'] in {'direct_api','archive_manifest'}:
    actual_direct={'class':provenance['class'],'method':provenance['method'],'junit_asserted':provenance['run_count']==1 and provenance['failure_count']==0 and provenance['ignore_count']==0 and not provenance['timed_out'],'stdout_normalized_utf8':provenance['stdout']['normalized_utf8'],'stderr_normalized_utf8':provenance['stderr']['normalized_utf8'],'source_method_sha256':row['java_observation']['method_sha256']}
    direct={'id':row['stable_id']+'/direct/01','stable_id':row['stable_id'],'kind':row['invocation_kind'],'expected':copy.deepcopy(actual_direct),'actual':actual_direct,'matches':True,'java_identity':identity,'observation_sha256':sha(canonical(actual_direct))};direct_results.append(direct);direct_ids.append(direct['id'])
   retained=row['decision'] if row['disposition'] in {'retained_reference_only','reviewed_non_applicable'} or row['kind']=='test_resource' else None
   result={'stable_id':row['stable_id'],'source':row['source'],'java_case':row['java_case'],'family':row['family'],'implementation_item':row['implementation_item'],'disposition':row['disposition'],'invocation_kind':row['invocation_kind'],'junit_provenance':provenance,'command_result_ids':links,'direct_result_ids':direct_ids,'retained_reason':retained,'java_identity':identity}
   result['observation_sha256']=sha(canonical({'junit_provenance':provenance,'command_result_ids':links,'direct_result_ids':direct_ids,'retained_reason':retained}));rows.append(result)
  return compact_document({'schema':'c027-java-reference-results.v1','row_count':140,'stable_id_order_sha256':sha(canonical([r['stable_id'] for r in rows])),'java_identity':identity,'architecture_results':architecture(identity),'rows':rows,'command_results':command_results,'direct_results':direct_results})
def row_projection(row):
 p=row.get('junit_provenance',{})
 return {'stable_id':row.get('stable_id'),'run_count':p.get('run_count'),'failure_count':p.get('failure_count'),'ignore_count':p.get('ignore_count'),'status':p.get('status'),'command_result_ids':row.get('command_result_ids',[]),'direct_result_ids':row.get('direct_result_ids',[]),'retained_reason':row.get('retained_reason')}
def verify(doc):
 errors=[];ledger=c027_ledger();expected=[r['id'] for r in ledger];ids=[r.get('stable_id') for r in doc.get('rows',[])]
 if ids!=expected:errors.append('result IDs/order differ from exact C027.V ledger')
 if len(ids)!=140 or doc.get('row_count')!=140:errors.append('expected exactly 140 results')
 direct_by_id={r.get('stable_id'):r for r in doc.get('direct_results',[]) if r.get('matches')}
 for r in doc.get('rows',[]):
  if r.get('observation_sha256')!=sha(canonical(row_projection(r))):errors.append('row observation hash drift '+str(r.get('stable_id')))
  provenance=r.get('junit_provenance',{});is_direct_lite=r.get('stable_id') in set(DIRECT_IDS[:5])
  if is_direct_lite:
   if provenance.get('status')!='replaced_by_deterministic_direct' or r.get('stable_id') not in direct_by_id:errors.append('invalid direct-lite replacement '+str(r.get('stable_id')))
  elif r.get('source',{}).get('path','').endswith('.java') and (provenance.get('run_count')!=1 or provenance.get('failure_count')!=0 or provenance.get('ignore_count')!=0 or provenance.get('timed_out')):errors.append('failed/skipped Java row '+str(r.get('stable_id')))
  if r.get('stable_id') in set(DIRECT_IDS) and r.get('stable_id') not in direct_by_id:errors.append('missing deterministic direct result '+str(r.get('stable_id')))
  if r.get('invocation_kind')=='toolkit' and not r.get('command_result_ids') and not r.get('direct_result_ids'):errors.append('missing command/direct result '+str(r.get('stable_id')))
  if not r.get('command_result_ids') and not r.get('direct_result_ids') and not r.get('retained_reason'):errors.append('unmapped Java row '+str(r.get('stable_id')))
 for command in doc.get('command_results',[]):
  actual=command.get('actual',{});expected_command=command.get('expected',{});projection=command.get('observation_projection')
  if actual.get('logical_exit') is None or not actual.get('argv') or expected_command!=projection or command.get('observation_sha256')!=sha(canonical(projection)) or not command.get('matches'):errors.append('incomplete command result '+str(command.get('id')))
 for direct in doc.get('direct_results',[]):
  if direct.get('actual')!=direct.get('expected') or direct.get('observation_sha256')!=sha(canonical(direct.get('actual'))):errors.append('direct observation hash drift '+str(direct.get('id')))
 return errors
DIRECT_IDS=['TCASE-07830A292D3A80E9','TCASE-CA377A3F0CCDED17','TCASE-73568EC3033FC84A','TCASE-1FDB8C6B77896021','TCASE-3B94179296286BCD','TCASE-33EEDFFAB5FC8144','TCASE-D4165B20F5BBC217','TCASE-892F022C31111AF5','TCASE-B532B3C191E369CE','TCASE-3A01FB6DB1A5BBF4','TCASE-383C2B80F66DB9F7','TCASE-AD54D4A6DCF4213B','TCASE-192ACD8D077B5743','TCASE-14BCC78F75EA5FB8','TCASE-6B5CB0A372F3CC1E']
def capture_direct_update():
 with tempfile.TemporaryDirectory(prefix='c027-direct-') as td:
  work=Path(td);cp,identity,_=build(work);canonical_identity={k:v for k,v in identity.items() if k not in {'classpath','command_agent_jar','command_agent_jar_sha256'}};canonical_identity['classpath']=[{'role':Path(e['path']).name,'kind':e['kind'],'sha256':e['sha256'],'files':e.get('files')} for e in identity.get('classpath',[])];identity_id=sha(canonical(canonical_identity));captured=[]
  for stable_id in DIRECT_IDS:
   observations=[]
   for repeat in range(2):
    sandbox=work/f'{stable_id}-{repeat}';sandbox.mkdir();done=SESSION.run([str(SESSION.java_home/'bin/java'),'-Dfile.encoding=UTF-8','-Duser.timezone=UTC','-Dc027.java.identity.id='+identity_id,'-cp',cp,'C027DirectOracle',stable_id,str(sandbox)],cwd=work,classpath=cp,timeout=600)
    marker=next((x for x in done.stdout.decode('utf-8','replace').splitlines() if x.startswith('C027_DIRECT=')),None)
    if done.returncode or marker is None:raise RuntimeError(f'direct {stable_id} failed rc={done.returncode}: {done.stderr.decode("utf-8","replace")}')
    observations.append(json.loads(base64.b64decode(marker.split('=',1)[1])))
   if canonical(observations[0])!=canonical(observations[1]):raise RuntimeError('direct result drift '+stable_id)
   value=observations[0];result_id=stable_id+('/direct-lite/01' if value['family']=='lite' else '/direct-archive/01');captured.append({'id':result_id,'stable_id':stable_id,'kind':'direct_lite' if value['family']=='lite' else 'archive_manifest','scenario':value['scenario'],'actual':value,'expected':copy.deepcopy(value),'matches':True,'java_identity_id':identity_id,'observation_sha256':sha(canonical(value))})
 doc=load(OUTPUT);doc['identities'][identity_id]=identity;by_id={r['stable_id']:r for r in doc['rows']}
 doc['direct_results']=[r for r in doc.get('direct_results',[]) if r.get('stable_id') not in set(DIRECT_IDS)]+captured
 for result in captured:
  row=by_id[result['stable_id']];row['direct_result_ids']=[result['id']];p=row.get('junit_provenance',{});row['observation_sha256']=sha(canonical({'stable_id':row['stable_id'],'run_count':p.get('run_count'),'failure_count':p.get('failure_count'),'ignore_count':p.get('ignore_count'),'status':p.get('status'),'command_result_ids':row.get('command_result_ids',[]),'direct_result_ids':row.get('direct_result_ids',[]),'retained_reason':row.get('retained_reason')}))
 atomic_write_json(OUTPUT,doc);return captured
def capture_help():
 scenarios={'root':[],'db':['db','--help'],'db_version':['db','--version'],'db_cp':['db','cp','--help'],'db_mv':['db','mv','--help'],'db_root':['db','root','--help'],'db_archive':['db','archive','--help'],'db_convert':['db','convert','--help'],'lite':['db','lite','--help'],'keystore':['keystore','--help'],'keystore_version':['keystore','--version'],'keystore_new':['keystore','new','--help'],'keystore_import':['keystore','import','--help'],'keystore_list':['keystore','list','--help'],'keystore_update':['keystore','update','--help']}
 with tempfile.TemporaryDirectory(prefix='c027-help-') as td:
  work=Path(td);cp,identity,_=build(work);rows=[]
  for key,args in scenarios.items():
   done=SESSION.run([str(SESSION.java_home/'bin/java'),'-Dfile.encoding=UTF-8','-Duser.timezone=UTC','-cp',cp,'C027Oracle','--command',*args],cwd=work,classpath=cp,timeout=120)
   marker=next((line for line in done.stdout.decode('utf-8','replace').splitlines() if line.startswith('C027_COMMAND_RESULT|')),None)
   if marker is None:raise RuntimeError('missing help capture '+key)
   _,code,out64,err64=marker.split('|',3);out=base64.b64decode(out64).decode('utf-8','replace').replace('<main class>','tron-toolkit');err=base64.b64decode(err64).decode('utf-8','replace').replace('<main class>','tron-toolkit')
   rows.append({'id':'C027.JAVA.HELP.'+key.upper(),'argv':args,'logical_exit':int(code),'adapter_process_exit':done.returncode,'expected_toolkit_process_exit':int(code)&255,'process_exit_verification':'logical_code_mod_256_contract','stdout':out,'stderr':err,'stdout_sha256':sha(out.encode()),'stderr_sha256':sha(err.encode()),'normalization':{'from':'<main class>','to':'tron-toolkit'}})
 manifest=load(ORACLES/'c027-command-manifest.v1.json');manifest['java_help_fixtures']=rows;manifest['java_help_identity']={k:v for k,v in identity.items() if k!='classpath'};atomic_write_json(ORACLES/'c027-command-manifest.v1.json',manifest);return rows
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--write',action='store_true');ap.add_argument('--metadata-only',action='store_true');ap.add_argument('--help-write',action='store_true');ap.add_argument('--direct-write',action='store_true');a=ap.parse_args()
 if a.direct_write:rows=capture_direct_update();print(f'C027 direct fixtures OK: {len(rows)} twice-repeated scenarios');return 0
 if a.help_write:rows=capture_help();print(f'C027 help fixtures OK: {len(rows)} exact Picocli surfaces');return 0
 if a.metadata_only:
  if not OUTPUT.exists():return 1
  errors=verify(load(OUTPUT))
 else:
  observed=capture();errors=verify(observed)
  if a.write and not errors:atomic_write_json(OUTPUT,observed)
  elif not errors:
   if not OUTPUT.exists():errors=['missing checked C027 Java results; run --write']
   else:
    checked=load(OUTPUT)
    atomic_write_json(Path('/tmp/c027-observed.json'),observed)
    checked_errors=verify(checked)
    if checked_errors:errors.extend('checked artifact: '+e for e in checked_errors)
    for collection,key in [('rows','stable_id'),('command_results','id'),('direct_results','id')]:
     left=sorted((r[key],r['observation_sha256']) for r in checked.get(collection,[]));right=sorted((r[key],r['observation_sha256']) for r in observed.get(collection,[]))
     if left!=right:
      left_map=dict(left);right_map=dict(right);drift=[item for item in sorted(set(left_map)|set(right_map)) if left_map.get(item)!=right_map.get(item)]
      errors.append('guarded Java '+collection+' observations drifted: '+','.join(drift[:20]))
 if errors:
  for e in errors:print('ERROR: '+e,file=sys.stderr)
  return 1
 print('C027 oracle OK: 140 exact guarded Java result rows');return 0
if __name__=='__main__': raise SystemExit(main())
