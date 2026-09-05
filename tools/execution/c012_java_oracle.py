#!/usr/bin/env python3
"""Build the C012 Java-8 capture agent and run each closed request in a fresh JVM."""
from __future__ import annotations
import argparse, hashlib, json, os, shutil, subprocess, tempfile, zipfile
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]; JAVA_TRON=ROOT/"java-tron"; JAVA_HOME=Path("/usr/lib/jvm/java-8-openjdk-amd64")
ORACLE=Path(__file__).with_name("C012Oracle.java"); INSTR=Path(__file__).with_name("instrumentation")/"org/tron/tools/c012"; REOPEN=Path(__file__).with_name("C012ReopenProbe.java")
REVISION="4a21592f95e37908b21bc3f611c6e7a1a67f09f3"
def digest(p:Path)->str:return hashlib.sha256(p.read_bytes()).hexdigest()
def run(argv:list[str],*,cwd:Path,env:dict[str,str],timeout:int=1800)->subprocess.CompletedProcess[bytes]:return subprocess.run(argv,cwd=cwd,env=env,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=timeout,check=False)
def runtime_classpath(work:Path,env:dict[str,str])->str:
 init=work/"classpath.gradle";init.write_text("""allprojects { p ->
  if (p.path == ':framework') { p.afterEvaluate {
    p.tasks.register('c012RuntimeClasspath') { doLast { println p.sourceSets.test.runtimeClasspath.asPath } }
  } }
}
""")
 common=[str(JAVA_TRON/"gradlew"),"--no-daemon","--no-build-cache","--console=plain","--dependency-verification=strict","-I",str(init)]
 built=run(common+[":framework:testClasses"],cwd=JAVA_TRON,env=env)
 if built.returncode:raise SystemExit("C012 Gradle testClasses failed:\n"+built.stderr.decode("utf-8","replace"))
 queried=run(common+["-q",":framework:c012RuntimeClasspath"],cwd=JAVA_TRON,env=env)
 if queried.returncode:raise SystemExit("C012 classpath query failed:\n"+queried.stderr.decode("utf-8","replace"))
 lines=[x.strip() for x in queried.stdout.decode().splitlines() if os.pathsep in x]
 if not lines:raise SystemExit("Gradle omitted runtime classpath")
 return lines[-1]
def fixture_requests(path:Path,root:Path)->list[Path]:
 doc=json.loads(path.read_text());rows=doc.get("rows") or doc["fixture_namespaces"]["built_in_java_differential"]["rows"]
 for i,row in enumerate(rows):
  e=row["java_execution"]["selected_test_run"]
  (root/f"{i:03d}.json").write_text(json.dumps({"schema":"c012-java-capture-request-v1","variant_id":row["variant_id"],"java_test_class":e["java_test_class"],"java_test_method":e["java_test_method"]},sort_keys=True)+"\n")
 return sorted(root.glob("*.json"))
def main()->int:
 p=argparse.ArgumentParser();g=p.add_mutually_exclusive_group(required=True);g.add_argument("--requests",type=Path);g.add_argument("--fixtures",type=Path);p.add_argument("--output",type=Path,required=True);p.add_argument("--update-fixtures",action="store_true");a=p.parse_args()
 with tempfile.TemporaryDirectory(prefix="c012-java-capture-") as td:
  work=Path(td);env={"PATH":f"{JAVA_HOME/'bin'}:/usr/bin:/bin","JAVA_HOME":str(JAVA_HOME),"HOME":str(work/"home"),"GRADLE_USER_HOME":str(work/"gradle-home"),"LANG":"C","LC_ALL":"C","TZ":"UTC"};cp=runtime_classpath(work,env)
  reqroot=work/"requests";reqroot.mkdir();requests=fixture_requests(a.fixtures,reqroot) if a.fixtures else sorted(a.requests.glob("*.json"))
  if not requests:raise SystemExit("closed C012 manifest contains no requests")
  values=[json.loads(x.read_text()) for x in requests];ids=[x["variant_id"] for x in values]
  if ids!=sorted(set(ids)):raise SystemExit("variant IDs must be sorted and unique")
  bb=[Path(x) for x in cp.split(os.pathsep) if "byte-buddy-1.12.19.jar" in x and "agent" not in Path(x).name]
  if len(bb)!=1:raise SystemExit(f"expected ByteBuddy 1.12.19 runtime jar, found {bb}")
  classes=work/"classes";classes.mkdir();sources=[str(x) for x in sorted(INSTR.glob("*.java"))]+[str(ORACLE),str(REOPEN)]
  compiled=run([str(JAVA_HOME/"bin/javac"),"-encoding","UTF-8","-source","8","-target","8","-cp",cp,"-d",str(classes)]+sources,cwd=ROOT,env=env)
  if compiled.returncode:raise SystemExit(compiled.stderr.decode("utf-8","replace"))
  agent=work/"c012-agent.jar";manifest="Manifest-Version: 1.0\nPremain-Class: org.tron.tools.c012.C012Agent\nCan-Redefine-Classes: false\n\n"
  with zipfile.ZipFile(agent,"w",zipfile.ZIP_DEFLATED) as z:
   z.writestr("META-INF/MANIFEST.MF",manifest)
   for f in classes.rglob("*.class"):
    if "org/tron/tools/c012" in f.as_posix():z.write(f,f.relative_to(classes).as_posix())
  members=[]
  for path,value in zip(requests,values):
   cmd=[str(JAVA_HOME/"bin/java"),"-Duser.timezone=UTC","-Dfile.encoding=UTF-8",f"-Dc012.stable.id={value['variant_id']}",f"-Dc012.test.class={value['java_test_class']}",f"-Dc012.test.method={value['java_test_method']}","-Dc012.mode=baseline",f"-javaagent:{agent}","-cp",str(classes)+os.pathsep+cp,"org.tron.core.actuator.C012Oracle",str(path)]
   done=run(cmd,cwd=ROOT,env=env)
   out=done.stdout.decode("utf-8","replace");marker=out.rfind("C012_CAPTURE=")
   if done.returncode or marker<0:raise SystemExit(f"C012 request {value['variant_id']} failed rc={done.returncode}:\n{done.stderr.decode('utf-8','replace')}\n{out[-4000:]}")
   members.append(json.loads(out[marker+len("C012_CAPTURE="):].strip()))
  batch={"schema":"c012-java-invocation-batch-v1","members":members,"provenance":{"java_revision":REVISION,"request_count":len(requests),"process_isolation":"one fresh JVM per selected method","jdk_home":str(JAVA_HOME),"agent_sources":{x.name:digest(x) for x in sorted(INSTR.glob('*.java'))},"oracle_sha256":digest(ORACLE),"byte_buddy_jar":bb[0].name,"byte_buddy_sha256":digest(bb[0]),"asm":"net.bytebuddy.jar.asm (shaded)"}}
  a.output.write_text(json.dumps(batch,indent=2,sort_keys=True)+"\n")
  if a.update_fixtures:raise SystemExit("fixture mutation was removed; invocation observations are authoritative")
 return 0
if __name__=="__main__":raise SystemExit(main())
