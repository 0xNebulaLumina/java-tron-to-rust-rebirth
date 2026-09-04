#!/usr/bin/env python3
import os, subprocess, tempfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[3]
JAVA=ROOT/'java-tron'
JDK=Path('/usr/lib/jvm/java-8-openjdk-amd64')
SOURCE=Path(__file__).with_name('C012AssetReal.java')
OUT=ROOT/'docs/oracles/c012-asset-real.v1.json'
if not (JDK/'bin/java').exists(): raise SystemExit('pinned JDK8 missing')
env=dict(os.environ, JAVA_HOME=str(JDK)); env['PATH']=str(JDK/'bin')+os.pathsep+env.get('PATH','')
init='''allprojects { project -> if (project.path == ':framework') { project.afterEvaluate { project.tasks.register('c012AssetClasspath') { doLast { println project.sourceSets.test.runtimeClasspath.asPath } } } } }'''
with tempfile.TemporaryDirectory(prefix='c012-asset-real-') as td:
 p=Path(td); (p/'init.gradle').write_text(init)
 common=[str(JAVA/'gradlew'),'--no-daemon','--console=plain','-I',str(p/'init.gradle')]
 subprocess.run(common+[':framework:testClasses'],cwd=JAVA,env=env,check=True)
 q=subprocess.run(common+['-q',':framework:c012AssetClasspath'],cwd=JAVA,env=env,check=True,stdout=subprocess.PIPE,text=True)
 cp=[x for x in q.stdout.splitlines() if os.pathsep in x][-1]
 classes=p/'classes'; classes.mkdir()
 subprocess.run([str(JDK/'bin/javac'),'-source','8','-target','8','-cp',cp,'-d',str(classes),str(SOURCE)],cwd=ROOT,env=env,check=True)
 r=subprocess.run([str(JDK/'bin/java'),'-cp',str(classes)+os.pathsep+cp,'org.tron.core.actuator.C012AssetReal'],cwd=ROOT,env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
 marker=r.stdout.rfind('{\"schema\":\"c012-asset-real.v1\"')
 if marker<0: raise SystemExit((r.stdout + '\n' + r.stderr)[-12000:])
 artifact=r.stdout[marker:].splitlines()[0]
 OUT.write_text(artifact+'\n')
 print(OUT)
