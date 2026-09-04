#!/usr/bin/env python3
import base64,json,os,shutil,subprocess,tempfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[3];JAVA_TRON=ROOT/'java-tron';JAVA_HOME=Path('/usr/lib/jvm/java-8-openjdk-amd64');SOURCE=Path(__file__).with_name('C012TransferReal.java')
SCENARIOS=['right','perfect','more','invalid-owner','invalid-to','self','missing-owner','new-account','zero','negative','recipient-overflow','insufficient-fee','no-contract','wrong-type','null-result','null-manager','contract-allowed','contract-forbid','contract-compatible-missing','contract-compatible-v1']
METHODS=['rightTransfer','perfectTransfer','moreTransfer','iniviateOwnerAddress','iniviateToAddress','iniviateTrx','noExitOwnerAccount','noExitToAccount','zeroAmountTest','negativeAmountTest','addOverflowTest','insufficientFee','commonErrorCheck','commonErrorCheck','commonErrorCheck','commonErrorCheck','transferToSmartContractAddress','transferToSmartContractAddress','transferToSmartContractAddress','transferToSmartContractAddress']
IDS=['TCASE-8C05165ED3D073B6','TCASE-4998ACC99FFAA609','TCASE-2A839836777D192B','TCASE-5ECE89EE9480F885','TCASE-BE03DA635235DC86','TCASE-60950B6D506E1515','TCASE-C38005B9B836BD07','TCASE-7C9C7C2430F5BD58','TCASE-653E96055E9037D5','TCASE-E562ACC4B3F38800','TCASE-C1899BAE3C160FEC','TCASE-57A0E49CA779D734','TCASE-B16B2F51FEC6F809','TCASE-B16B2F51FEC6F809','TCASE-B16B2F51FEC6F809','TCASE-B16B2F51FEC6F809','TCASE-7B9012BA2E5C522D','TCASE-7B9012BA2E5C522D','TCASE-7B9012BA2E5C522D','TCASE-7B9012BA2E5C522D']
def run(a,cwd,env):
 p=subprocess.run(a,cwd=cwd,env=env,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=1800)
 if p.returncode:raise SystemExit(p.stderr.decode(errors='replace'))
 return p.stdout.decode(errors='replace')
def main():
 with tempfile.TemporaryDirectory(prefix='c012-transfer-real-') as td:
  w=Path(td);env={'PATH':str(JAVA_HOME/'bin')+':/usr/bin:/bin','JAVA_HOME':str(JAVA_HOME),'HOME':str(w/'home'),'GRADLE_USER_HOME':str(Path.home()/'.gradle'),'LANG':'C','LC_ALL':'C','TZ':'UTC'}
  init=w/'cp.gradle';init.write_text("allprojects { p -> if (p.path == ':framework') { p.afterEvaluate { p.tasks.register('realCp') { doLast { println p.sourceSets.test.runtimeClasspath.asPath } } } } }\n")
  common=[str(JAVA_TRON/'gradlew'),'--no-daemon','--no-build-cache','--console=plain','--dependency-verification=strict','-I',str(init)];run(common+[':framework:testClasses'],JAVA_TRON,env);cp=run(common+['-q',':framework:realCp'],JAVA_TRON,env).strip().splitlines()[-1]
  classes=w/'classes';classes.mkdir();run([str(JAVA_HOME/'bin/javac'),'-source','8','-target','8','-encoding','UTF-8','-cp',cp,'-d',str(classes),str(SOURCE)],ROOT,env);rows=[]
  for scenario,method,stable in zip(SCENARIOS,METHODS,IDS):
   db=w/('db-'+scenario);out=run([str(JAVA_HOME/'bin/java'),'-Duser.timezone=UTC','-cp',str(classes)+os.pathsep+cp,'org.tron.core.actuator.C012TransferReal','--scenario',scenario,str(db)],ROOT,env);marker='C012_TRANSFER_REAL=';row=json.loads(base64.b64decode(out[out.rfind(marker)+len(marker):].strip().splitlines()[0]));shutil.rmtree(db,ignore_errors=True);row.update(java_test_method=method,stable_id=stable,equivalence='direct reconstruction of the assigned method state and one production TransferActuator validation/execution; branch variants isolate flag behavior');rows.append(row)
  print(json.dumps({'schema':'c012-transfer-real.v1','java_revision':'4a21592f95e37908b21bc3f611c6e7a1a67f09f3','jdk_home':str(JAVA_HOME),'scenario_count':len(rows),'variant_count':len(rows),'stable_id_count':len(set(IDS)),'rows':rows},indent=2,sort_keys=True))
if __name__=='__main__':main()
