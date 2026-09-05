#!/usr/bin/env python3
"""Execute every pinned C013 actuator test in an isolated authenticated Java JVM."""
from __future__ import annotations
import argparse,hashlib,json,os,shutil,tempfile,zipfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
__import__('sys').path.insert(0,str(ROOT/'tools/reference-runner'))
from java_reference_guard import atomic_write_json,install_java_reference_guard
SESSION=install_java_reference_guard(ROOT); JAVA_TRON=SESSION.tree; JAVA_HOME=SESSION.java_home
ORACLE=Path(__file__).with_name('C013Oracle.java'); INSTR=Path(__file__).with_name('instrumentation')/'org/tron/tools/c012'
LEDGER=ROOT/'docs/oracles/java-test-ownership.v1.json'; OUTPUT=ROOT/'docs/oracles/c013-java-owned-real.v1.json'
CLASSES={'CancelAllUnfreezeV2ActuatorTest.java','ClearABIContractActuatorTest.java','DelegateResourceActuatorTest.java','ExchangeCreateActuatorTest.java','ExchangeInjectActuatorTest.java','ExchangeTransactionActuatorTest.java','ExchangeWithdrawActuatorTest.java','FreezeBalanceActuatorTest.java','FreezeBalanceV2ActuatorTest.java','MarketCancelOrderActuatorTest.java','MarketSellAssetActuatorTest.java','ProposalApproveActuatorTest.java','ProposalCreateActuatorTest.java','ProposalDeleteActuatorTest.java','UnDelegateResourceActuatorTest.java','UnfreezeBalanceActuatorTest.java','UnfreezeBalanceV2ActuatorTest.java','UpdateBrokerageActuatorTest.java','UpdateEnergyLimitContractActuatorTest.java','UpdateSettingContractActuatorTest.java','WithdrawBalanceActuatorTest.java','WithdrawExpireUnfreezeActuatorTest.java'}
def digest(p:Path)->str:return hashlib.sha256(p.read_bytes()).hexdigest()
def canonical(value:object)->bytes:return json.dumps(value,sort_keys=True,separators=(',',':')).encode()
def selected()->list[dict[str,object]]:
 out=[]
 for row in json.loads(LEDGER.read_text())['rows']:
  source=row['source']; path=Path(source['path'])
  if path.name in CLASSES:out.append({'variant_id':row['id'],'java_test_class':'org.tron.core.actuator.'+path.stem,'java_test_method':row['case'],'java_source':source,'previous_owner':row['owning_item']})
 return sorted(out,key=lambda value:value['variant_id'])
def runtime_classpath(work:Path)->str:
 init=work/'classpath.gradle';init.write_text("""allprojects { p ->
  if (p.path == ':framework') { p.afterEvaluate {
    p.tasks.register('c013RuntimeClasspath') { doLast { println p.sourceSets.test.runtimeClasspath.asPath } }
  } }
}
""")
 built=SESSION.gradle(['-I',str(init),':framework:testClasses',':actuator:jar',':consensus:jar',':chainbase:jar',':crypto:jar',':common:jar',':protocol:jar',':platform:jar'])
 if built.returncode:raise SystemExit('C013 Gradle build failed:\n'+built.stderr.decode('utf-8','replace'))
 queried=SESSION.gradle(['-I',str(init),'-q',':framework:c013RuntimeClasspath'])
 if queried.returncode:raise SystemExit('C013 classpath query failed:\n'+queried.stderr.decode('utf-8','replace'))
 lines=[x.strip() for x in queried.stdout.decode().splitlines() if os.pathsep in x]
 if not lines:raise SystemExit('Gradle omitted runtime classpath')
 cp=lines[-1]; SESSION.guard(phase='after C013 classpath build',classpath=cp); return cp
def main()->int:
 parser=argparse.ArgumentParser();parser.add_argument('--fresh',action='store_true');options=parser.parse_args();requests=selected()
 if len(requests)!=370:raise SystemExit(f'expected 370 pinned C013 cases, got {len(requests)}')
 with tempfile.TemporaryDirectory(prefix='c013-java-capture-') as td:
  work=Path(td);cp=runtime_classpath(work);bb=[Path(x) for x in cp.split(os.pathsep) if 'byte-buddy-1.12.19.jar' in x and 'agent' not in Path(x).name]
  if len(bb)!=1:raise SystemExit(f'expected ByteBuddy 1.12.19 runtime jar, found {bb}')
  classes=work/'classes';classes.mkdir();sources=[str(x) for x in sorted(INSTR.glob('*.java'))]+[str(ORACLE)]
  compiled=SESSION.run([str(JAVA_HOME/'bin/javac'),'-encoding','UTF-8','-source','8','-target','8','-cp',cp,'-d',str(classes)]+sources,cwd=ROOT,classpath=cp)
  if compiled.returncode:raise SystemExit(compiled.stderr.decode('utf-8','replace'))
  agent=work/'c013-agent.jar';manifest='Manifest-Version: 1.0\nPremain-Class: org.tron.tools.c012.C012Agent\nCan-Redefine-Classes: false\n\n'
  with zipfile.ZipFile(agent,'w',zipfile.ZIP_DEFLATED) as archive:
   archive.writestr('META-INF/MANIFEST.MF',manifest)
   for f in classes.rglob('*.class'):
    if 'org/tron/tools/c012' in f.as_posix():archive.write(f,f.relative_to(classes).as_posix())
  full_cp=str(classes)+os.pathsep+cp;identity=SESSION.guard(phase='C013 capture provenance',classpath=full_cp)
  expected={'reference':identity,'request_count':len(requests),'request_sha256':hashlib.sha256(canonical(requests)).hexdigest(),'process_isolation':'one fresh JVM per selected method','agent_sources':{x.name:digest(x) for x in sorted(INSTR.glob('*.java'))},'oracle_sha256':digest(ORACLE),'tool_sha256':digest(Path(__file__)),'byte_buddy_jar':bb[0].name,'byte_buddy_sha256':digest(bb[0])}
  identity_sha=hashlib.sha256(canonical(expected)).hexdigest();prior=json.loads(OUTPUT.read_text()) if OUTPUT.exists() and not options.fresh else {};members=prior.get('members',[]) if prior.get('provenance')==expected else []
  if any(m.get('capture_identity_sha256')!=identity_sha for m in members):members=[]
  completed={m['variant_id'] for m in members}
  for index,value in enumerate(requests,1):
   if value['variant_id'] in completed:continue
   before=set(Path('/tmp').glob('junit*'));request=work/'request.json';request.write_text(json.dumps(value,sort_keys=True)+'\n')
   cmd=[str(JAVA_HOME/'bin/java'),'-Duser.timezone=UTC','-Dfile.encoding=UTF-8',f"-Dc012.stable.id={value['variant_id']}",f"-Dc012.test.class={value['java_test_class']}",f"-Dc012.test.method={value['java_test_method']}",'-Dc012.mode=baseline',f'-javaagent:{agent}','-cp',full_cp,'org.tron.core.actuator.C013Oracle',str(request)]
   done=SESSION.run(cmd,cwd=ROOT,classpath=full_cp);out=done.stdout.decode('utf-8','replace');marker=out.rfind('C013_CAPTURE=')
   for path in set(Path('/tmp').glob('junit*'))-before:shutil.rmtree(path,ignore_errors=True)
   for pattern in ('sapling-*.params.*','libzksnarkjni-*','libleveldbjni-*','librocksdbjni*'):
    for path in Path('/tmp').glob(pattern):
     try:path.unlink()
     except FileNotFoundError:pass
   if done.returncode or marker<0:raise SystemExit(f"C013 request {index}/{len(requests)} {value['variant_id']} failed rc={done.returncode}:\n{done.stderr.decode('utf-8','replace')}\n{out[-4000:]}")
   member=json.loads(out[marker+len('C013_CAPTURE='):].strip());member.update(java_source=value['java_source'],previous_owner=value['previous_owner'],capture_identity_sha256=identity_sha);members.append(member)
   atomic_write_json(OUTPUT,{'schema':'c013-java-invocation-batch-v1','members':members,'provenance':expected})
  if len(members)!=len(requests):raise SystemExit(f'incomplete C013 corpus: {len(members)}/{len(requests)}')
 return 0
if __name__=='__main__':raise SystemExit(main())
