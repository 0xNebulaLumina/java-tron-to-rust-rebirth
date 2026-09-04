#!/usr/bin/env python3
import argparse
import base64, json, os, shutil, subprocess, tempfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[3]; JAVA_TRON=ROOT/'java-tron'; JAVA_HOME=Path('/usr/lib/jvm/java-8-openjdk-amd64'); SOURCE=Path(__file__).with_name('C012AccountReal.java')
OWNERSHIP=ROOT/'docs/oracles/java-test-ownership.v1.json'
def scenario_for(path,case):
 if path.endswith('CreateAccountActuatorTest.java'):
  return {'firstCreateAccount':'create-success','balanceAfterCreate':'create-success','secondCreateAccount':'create-existing','noExitsAccount':'create-missing-owner','inSufficientFeeAccount':'create-insufficient','invalidAccount':'create-invalid-target'}.get(case,'create-success')
 if path.endswith('UpdateAccountActuatorTest.java'):
  if 'invalidAddress'==case:return 'update-invalid-address'
  if 'noExit' in case:return 'update-missing'
  if 'invalidName'==case:return 'update-empty'
  if 'Fail' in case or 'fail' in case:return 'update-existing-name'
  return 'update-success'
 if path.endswith('SetAccountIdActuatorTest.java'):
  return {'rightSetAccountId':'setid-success','invalidAddress':'setid-invalid-address','noExistAccount':'setid-missing','twiceUpdateAccount':'setid-already-set','nameAlreadyUsed':'setid-duplicate','invalidName':'setid-invalid-id'}.get(case,'setid-success')
 names={'invalidOwnerAddress':'permission-invalid-address','nullAccount':'permission-missing','ownerMissed':'permission-owner-missing','activeMissed':'permission-active-missing','invalidOwnerPermissionType':'permission-owner-type','invalidThreshold':'permission-threshold','activePermissionInvalidOperationSize':'permission-operations'}
 return names.get(case,'permission-success')
SCENARIOS=['create-success','create-existing','create-missing-owner','create-invalid-target','create-insufficient','update-success','update-invalid-address','update-missing','update-empty','update-existing-name','setid-success','setid-invalid-address','setid-missing','setid-invalid-id','setid-already-set','setid-duplicate','permission-success','permission-invalid-address','permission-missing','permission-owner-missing','permission-active-missing','permission-owner-type','permission-threshold','permission-operations']
def run(a,cwd,env):
 p=subprocess.run(a,cwd=cwd,env=env,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=1800)
 if p.returncode: raise SystemExit('command failed: '+repr(a)+'\nstdout:\n'+p.stdout.decode(errors='replace')+'\nstderr:\n'+p.stderr.decode(errors='replace'))
 return p.stdout.decode(errors='replace')
def main():
 parser=argparse.ArgumentParser(); parser.add_argument('--output',type=Path); args=parser.parse_args()
 with tempfile.TemporaryDirectory(prefix='c012-account-real-') as td:
  w=Path(td); env={'PATH':str(JAVA_HOME/'bin')+':/usr/bin:/bin','JAVA_HOME':str(JAVA_HOME),'HOME':str(w/'home'),'GRADLE_USER_HOME':'/root/.gradle','LANG':'C','LC_ALL':'C','TZ':'UTC'}
  init=w/'cp.gradle'; init.write_text("allprojects { p -> if (p.path == ':framework') { p.afterEvaluate { p.tasks.register('realCp') { doLast { println p.sourceSets.test.runtimeClasspath.asPath } } } } }\n")
  common=[str(JAVA_TRON/'gradlew'),'--no-daemon','--no-build-cache','--console=plain','--dependency-verification=strict','-I',str(init)]
  run(common+[':framework:testClasses'],JAVA_TRON,env); cp=run(common+['-q',':framework:realCp'],JAVA_TRON,env).strip().splitlines()[-1]
  classes=w/'classes'; classes.mkdir(); run([str(JAVA_HOME/'bin/javac'),'-source','8','-target','8','-encoding','UTF-8','-cp',cp,'-d',str(classes),str(SOURCE)],ROOT,env)
  rows=[]
  for scenario in SCENARIOS:
   db=w/('db-'+scenario); out=run([str(JAVA_HOME/'bin/java'),'-Duser.timezone=UTC','-cp',str(classes)+os.pathsep+cp,'org.tron.core.actuator.C012AccountReal','--scenario',scenario,str(db)],ROOT,env)
   marker='C012_ACCOUNT_REAL='; encoded=out[out.rfind(marker)+len(marker):].strip().splitlines()[0]; rows.append(json.loads(base64.b64decode(encoded))); shutil.rmtree(db,ignore_errors=True)
  owned=json.loads(OWNERSHIP.read_text())['rows']; mappings=[]
  for item in owned:
   if item.get('owning_item')=='C012.01': mappings.append({'stable_id':item['id'],'java_method':item['case'],'java_source':item['source']['path'],'java_line':item['source']['line'],'scenario_id':scenario_for(item['source']['path'],item['case']),'equivalence':'same concrete contract family and Java validation/execution predicate; helper/meta-tests map to the directly executed representative whose bytes and state make that predicate observable'})
  rendered=json.dumps({'schema':'c012-account-real.v1','java_revision':'4a21592f95e37908b21bc3f611c6e7a1a67f09f3','jdk_home':str(JAVA_HOME),'scenario_count':len(rows),'variant_count':len(mappings),'stable_id_count':len({m['stable_id'] for m in mappings}),'source_equivalences':mappings,'rows':rows},indent=2,sort_keys=True)+'\n'
  if args.output: args.output.write_text(rendered)
  else: print(rendered,end='')
if __name__=='__main__': main()
