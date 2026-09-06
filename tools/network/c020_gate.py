#!/usr/bin/env python3
import argparse,hashlib,json,os,pathlib,subprocess,sys,tempfile,zipfile
ROOT=pathlib.Path(__file__).resolve().parents[2]; RUST=ROOT/'rust-tron'; ORACLES=ROOT/'docs/oracles'
sys.path.insert(0,str(ROOT/'tools/reference-runner'))
from java_reference_guard import install_java_reference_guard
INVENTORY=ORACLES/'c020-binary-inventory.v1.json'; HARNESS=ORACLES/'c020-harness-manifest.v1.json'; DISCOVERY=ORACLES/'c020-discovery.v1.json'; OWNERSHIP=ORACLES/'c020-ownership-reconciliation.v1.json'; CAPTURES=ORACLES/'c020-captures.v1.json'; MANIFEST=ORACLES/'manifest.v1.json'; TRACKER=ROOT/'docs/PORTING_TRACKER.json'
COMMANDS={'tcp':['cargo','test','-p','tron-network','--test','c020_tcp','--test','c020_session','--locked'],'discovery':['cargo','test','-p','tron-network','--test','c020_discovery','--locked'],'all-targets':['cargo','check','-p','tron-network','--all-targets','--locked']}
def load(path):return json.loads(path.read_text())
def digest(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def metadata():
 inv,harness,discovery,ownership,captures=map(load,(INVENTORY,HARNESS,DISCOVERY,OWNERSHIP,CAPTURES))
 if inv.get('schema')!='c020-binary-inventory.v1' or harness.get('schema')!='c020-harness-manifest.v1' or discovery.get('schema')!='c020-discovery.v1' or ownership.get('schema')!='c020-ownership-reconciliation.v1':raise SystemExit('C020 oracle schema drift')
 if ownership.get('production_ledger_rows')!=0 or ownership.get('java_test_ledger_rows')!=0 or not ownership.get('binary_only'):raise SystemExit('C020 binary ownership overclaim')
 if harness.get('udp_envelope_resolution',{}).get('result')!='raw [one-byte message type][protobuf body]':raise SystemExit('UDP ambiguity is unresolved')
 seam=harness.get('secure_datagram_attestation_seam',{})
 if seam.get('consumer')!='C018 BackupService' or seam.get('payload_policy')!='preserve exact enclosed bytes; reject absent/duplicate/stale attestation; no plaintext fallback' or seam.get('production_policy')!='SecureDatagramSocket always invokes seal before UDP send; a missing or rejected seal fails closed' or seam.get('outbound_fields')!=['configured destination identity','destination address and port','local identity and source port','active session','strictly increasing per-peer sequence']:raise SystemExit('C018 secure datagram seam drift')
 if discovery.get('wire',{}).get('envelope')!='type-byte || protobuf' or discovery.get('wire',{}).get('maximum_bytes')!=2047:raise SystemExit('discovery wire drift')
 if discovery['wire'].get('endpoint_address_encoding')!='UTF-8 textual IP literals; address is IPv4, addressIpv6 is IPv6, address takes precedence when both are present; no binary encoding observed':raise SystemExit('endpoint encoding drift')
 if discovery['wire'].get('captured_ip_policy')!='UDP source IP must match the declared preferred endpoint IP; source never overrides declared address or port':raise SystemExit('captured source policy drift')
 if captures.get('schema')!='c020-captures.v1' or len(captures.get('captures',[]))!=5:raise SystemExit('C020 capture set drift')
 for capture in captures['captures']:
  body=bytes.fromhex(capture['hex'])
  if len(body)!=capture['size'] or hashlib.sha256(body).hexdigest()!=capture['sha256']:raise SystemExit('C020 packet capture hash drift: '+capture['id'])
 manifest=load(MANIFEST)
 for name in ('c020-binary-inventory.v1.json','c020-harness-manifest.v1.json','c020-discovery.v1.json','c020-ownership-reconciliation.v1.json','c020-captures.v1.json'):
  key=name.removesuffix('.v1.json').replace('-','_')
  if manifest.get(key)!={'path':name,'sha256':digest(ORACLES/name)}:raise SystemExit('central manifest drift: '+key)
 chunk=next(c for c in load(TRACKER)['chunks'] if c['id']=='C020')
 review=harness.get('closure_review',{}); jar_capture=review.get('actual_jar_capture',{})
 if review.get('state')!='approved' or review.get('round')!=1 or review.get('findings')!=[] or review.get('suite_counts')!={'session':3,'tcp':12,'discovery':13,'live':4}:raise SystemExit('C020 closure review metadata drift')
 if jar_capture.get('artifact_sha256')!=inv['artifact']['sha256'] or jar_capture.get('artifact_size')!=inv['artifact']['size'] or jar_capture.get('authenticated_members')!=len(inv['members']) or jar_capture.get('packet_captures')!=len(captures['captures']):raise SystemExit('C020 actual JAR capture metadata drift')
 if chunk['status']!='done' or chunk.get('resume') is not None or any(i['status']!='done' for i in chunk['items']) or chunk['gate']['status']!='passed' or chunk['review']['state']!='approved' or chunk['review']['findings'] or chunk.get('blocker') is not None:raise SystemExit('C020 tracker closure drift')
 print(json.dumps({'schema':'c020-metadata-v1','binary_source_rows':0,'udp_envelope':'raw-type-byte-protobuf','suite_counts':review['suite_counts'],'actual_jar_capture':jar_capture,'status':'passed'},separators=(',',':')))
def prepare_oracle(session,out):
 init=out/'classpath.gradle';init.write_text("allprojects { p -> if (p.path == ':framework') { p.afterEvaluate { p.tasks.register('c020RuntimeClasspath') { doLast { println 'C020_CLASSPATH=' + p.sourceSets.test.runtimeClasspath.asPath } } } } }\n")
 built=session.gradle(['-I',str(init),':framework:testClasses',':actuator:jar',':consensus:jar',':chainbase:jar',':crypto:jar',':common:jar',':protocol:jar',':platform:jar'])
 if built.returncode:raise SystemExit('C020 Java classpath build failed:\n'+built.stderr.decode('utf-8','replace'))
 queried=session.gradle(['-I',str(init),':framework:c020RuntimeClasspath'])
 matches=[x.split('=',1)[1] for x in queried.stdout.decode().splitlines() if x.startswith('C020_CLASSPATH=')]
 if queried.returncode or len(matches)!=1:raise SystemExit('C020 classpath capture failed')
 cp=matches[0]; jars=[pathlib.Path(p) for p in cp.split(os.pathsep) if pathlib.Path(p).name=='libp2p-2.2.9.jar']
 if len(jars)!=1:raise SystemExit('expected exactly one libp2p 2.2.9 jar')
 jar=jars[0];inv=load(INVENTORY)
 if jar.stat().st_size!=inv['artifact']['size'] or digest(jar)!=inv['artifact']['sha256']:raise SystemExit('libp2p artifact authentication failed')
 with zipfile.ZipFile(jar) as archive:
  for row in inv['members']:
   body=archive.read(row['path'])
   if len(body)!=row['size'] or hashlib.sha256(body).hexdigest()!=row['sha256']:raise SystemExit('libp2p member authentication failed: '+row['path'])
 compiled=session.run([str(session.java_home/'bin/javac'),'-cp',cp,'-d',str(out),str(ROOT/'tools/network/C020Oracle.java')],cwd=session.work,classpath=cp)
 if compiled.returncode:raise SystemExit('C020 Java oracle compilation failed:\n'+compiled.stderr.decode('utf-8','replace'))
 return str(out)+os.pathsep+cp

def scenario():
 with install_java_reference_guard(ROOT) as session:
  with tempfile.TemporaryDirectory(prefix='c020-java-',dir=session.work) as raw:
   cp=prepare_oracle(session,pathlib.Path(raw));before=session.guard(phase='immediately before C020 live Java/Rust scenario',classpath=cp)
   evidence=session.run([str(session.java_home/'bin/java'),'-cp',cp,'C020Oracle','evidence'],cwd=session.work,classpath=cp)
   text=evidence.stdout.decode('utf-8','replace')
   evidence_rows={line.split('=',1)[0]:line.split('=',1)[1] for line in text.splitlines() if '_HEX=' in line}
   vectors=[evidence_rows.get('TCP_MESSAGE_HEX')]
   disabled_upgrade=evidence_rows.get('UPGRADE_DISABLED_HEX');enabled_upgrade=evidence_rows.get('UPGRADE_ENABLED_HEX')
   if evidence.returncode or None in vectors or disabled_upgrade!=vectors[0] or not enabled_upgrade or enabled_upgrade==vectors[0] or 'JAR_CODEC_EVIDENCE_OK' not in text:raise SystemExit('C020 authenticated JAR codec/UpgradeController evidence failed:\n'+evidence.stderr.decode('utf-8','replace'))
   expected={'tcp-java-to-rust':evidence_rows.get('TCP_WIRE_HEX'),'tcp-rust-to-java':evidence_rows.get('TCP_WIRE_HEX'),'udp-java-to-rust-ping':evidence_rows.get('UDP_PING_HEX'),'udp-rust-to-java-pong':evidence_rows.get('UDP_PONG_HEX'),'udp-java-neighbours':evidence_rows.get('UDP_NEIGHBOURS_HEX')}
   drift=next((row['id'] for row in load(CAPTURES)['captures'] if expected.get(row['id'])!=row['hex']),None)
   if drift:raise SystemExit('live JAR capture regeneration drift: '+drift+' expected '+str(expected[drift]))
   subprocess.run([sys.executable,str(ROOT/'tools/network/capture_tcp.py'),'--verify-catalog',str(CAPTURES)],check=True)
   subprocess.run([sys.executable,str(ROOT/'tools/network/c020_discovery/capture_udp.py'),'--verify-catalog',str(CAPTURES),'--artifact-sha256',load(INVENTORY)['artifact']['sha256']],check=True)
   env=os.environ.copy();env['C020_JAVA']=str(session.java_home/'bin/java');env['C020_ORACLE_CP']=cp;env['C020_TCP_MESSAGE_HEX']=vectors[0]
   subprocess.run(['cargo','test','-p','tron-network','--test','c020_scenarios','--locked','--','--test-threads=1'],cwd=RUST,env=env,check=True)
   after=session.guard(phase='immediately after C020 live Java/Rust scenario',classpath=cp)
   if before!=after:raise SystemExit('Java reference identity changed across C020 scenario')

def run(target):print('+',' '.join(COMMANDS[target]),flush=True);subprocess.run(COMMANDS[target],cwd=RUST,check=True)
def main():
 choices=['metadata','scenario',*COMMANDS,'all'];p=argparse.ArgumentParser();p.add_argument('targets',nargs='*',choices=choices);a=p.parse_args();targets=a.targets or ['all']
 if 'all' in targets:targets=['metadata','tcp','discovery','scenario','all-targets']
 for target in targets:
  if target=='metadata':metadata()
  elif target=='scenario':scenario()
  else:run(target)
 print(json.dumps({'schema':'c020-gate-v1','targets':targets,'status':'passed'},separators=(',',':')))
if __name__=='__main__':main()
