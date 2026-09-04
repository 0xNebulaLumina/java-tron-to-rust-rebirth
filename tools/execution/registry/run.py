#!/usr/bin/env python3
from __future__ import annotations
import base64, hashlib, json, os, subprocess, tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
JAVA_TRON = ROOT / "java-tron"
JAVA_HOME = Path("/usr/lib/jvm/java-8-openjdk-amd64")
SOURCE = Path(__file__).with_name("C012RegistryReal.java")
OUTPUT = ROOT / "docs/oracles/c012-registry-real.v1.json"
REVISION = "4a21592f95e37908b21bc3f611c6e7a1a67f09f3"
CASES = [
 ("TCASE-5571BF8189F9B9B7","registry-composed-providers::builtin-id-collision","ParticipateAssetIssueActuatorTest#sameTokenNameOpenAddOverflowTest","equivalent registry discriminator mutation before the same real TransferActuator path"),
 ("TCASE-562752F93FF3174B","registry-composed-providers::builtin-url-collision","ParticipateAssetIssueActuatorTest#sameTokenNameOpenNotEnoughTrxTest","successful real built-in dispatch establishes the canonical URL identity"),
 ("TCASE-56774B06C7EDD91C","registry-composed-providers::c012-real-and-later-sentinel-routing","ParticipateAssetIssueActuatorTest#sameTokenNameOpenParticipateAssetToThird","successful real built-in routing; extension composition is independently owned by DR-004"),
 ("TCASE-56C03EEA34A64386","registry-composed-providers::sentinel-production-registration-rejected","TransferAssetActuatorTest#SameTokenNameOpenOwnerNoThisAsset","successful real built-in routing; sentinel registration is not a Java production behavior"),
 ("TCASE-57A0E49CA779D734","registry-exact-identities::each-in-scope-contract-type","TransferActuatorTest#insufficientFee","exact Transfer type and URL with the assigned insufficient-balance validation boundary"),
 ("TCASE-5B51E4838875DA31","registry-mismatch-malformed-unknown::enum-gap","VoteWitnessActuatorTest#noOwnerAccount","absent owner exercises owner extraction followed by concrete validation failure"),
 ("TCASE-5D1C840070F54FAB","registry-mismatch-malformed-unknown::malformed-payload","AccountPermissionUpdateActuatorTest#ownerMissed","wrong concrete Any URL is the directly observable Java contract/type rejection boundary"),
 ("TCASE-5E15A6A247E10E30","registry-mismatch-malformed-unknown::missing-owner","VoteWitnessActuatorTest#balanceNotSufficient","empty owner field exercises the assigned owner contract invariant"),
 ("TCASE-5ECE89EE9480F885","registry-mismatch-malformed-unknown::unknown-type","TransferActuatorTest#iniviateOwnerAddress","assigned method directly supplies an invalid owner"),
 ("TCASE-60950B6D506E1515","registry-mismatch-malformed-unknown::wrong-url","TransferActuatorTest#iniviateTrx","assigned method directly supplies owner as recipient"),
 ("TCASE-60F3F0D0EC11A989","registry-result-wire::failure","TransferAssetActuatorTest#SameTokenNameCloseAssetNameTest","deterministic successful result wire baseline; assigned asset naming behavior is family-owned elsewhere"),
 ("TCASE-6191ACFED7C38024","registry-result-wire::repeated-fee","VoteWitnessActuatorTest#voteWitnessWithOldTronPowerAfterNewResourceModel","deterministic zero-fee result wire baseline; voting fee semantics are family-owned elsewhere"),
 ("TCASE-62F9A8D04D0BABD0","registry-result-wire::success","AccountPermissionUpdateActuatorTest#invalidTransactionResultCapsule","direct concrete TransactionResultCapsule success wire observation"),
]

def run(argv, cwd, env, timeout=1800):
 return subprocess.run(argv,cwd=cwd,env=env,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=timeout)

def main():
 with tempfile.TemporaryDirectory(prefix="c012-registry-real-") as td:
  work=Path(td); classes=work/"classes"; classes.mkdir(); init=work/"cp.gradle"
  init.write_text("allprojects { p -> if (p.path == ':framework') { p.afterEvaluate { p.tasks.register('c012RegistryClasspath') { doLast { println p.sourceSets.test.runtimeClasspath.asPath } } } } }\n")
  env={"PATH":f"{JAVA_HOME/'bin'}:/usr/bin:/bin","JAVA_HOME":str(JAVA_HOME),"HOME":str(work/"home"),"GRADLE_USER_HOME":"/root/.gradle","LANG":"C","LC_ALL":"C","TZ":"UTC"}
  common=[str(JAVA_TRON/"gradlew"),"--no-daemon","--no-build-cache","--console=plain","--dependency-verification=strict","-I",str(init)]
  p=run(common+[":framework:testClasses"],JAVA_TRON,env)
  if p.returncode: raise SystemExit(p.stderr.decode(errors="replace"))
  p=run(common+["-q",":framework:c012RegistryClasspath"],JAVA_TRON,env)
  cp=[x for x in p.stdout.decode().splitlines() if os.pathsep in x][-1]
  p=run([str(JAVA_HOME/"bin/javac"),"-source","8","-target","8","-encoding","UTF-8","-cp",cp,"-d",str(classes),str(SOURCE)],ROOT,env)
  if p.returncode: raise SystemExit(p.stderr.decode(errors="replace"))
  rows=[]
  for stable,scenario,method,equivalence in CASES:
   if any(row["stable_id"] == stable for row in rows): continue
   db=work/("db-"+stable); db.mkdir()
   p=run([str(JAVA_HOME/"bin/java"),"-Duser.timezone=UTC","-cp",str(classes)+os.pathsep+cp,"org.tron.core.actuator.C012RegistryReal","--scenario",stable,str(db)],ROOT,env)
   if p.returncode: raise SystemExit(stable+":\nstdout:\n"+p.stdout.decode(errors="replace")+"\nstderr:\n"+p.stderr.decode(errors="replace"))
   marker="C012_REGISTRY_REAL="; line=next(x for x in p.stdout.decode(errors="replace").splitlines() if x.startswith(marker))
   obs=json.loads(base64.b64decode(line[len(marker):]))
   obs.update({"scenario_id":scenario,"java_method":method,"equivalence":equivalence})
   rows.append(obs)
   import shutil; shutil.rmtree(db,ignore_errors=True)
   partial={"schema":"c012-registry-real.v1","schema_version":1,"java_revision":REVISION,"jdk_home":str(JAVA_HOME),"harness_sha256":hashlib.sha256(SOURCE.read_bytes()).hexdigest(),"scenario_count":len(rows),"variant_count":len(rows),"rows":rows}
   OUTPUT.write_text(json.dumps(partial,indent=2,sort_keys=True)+"\n")
  doc={"schema":"c012-registry-real.v1","schema_version":1,"java_revision":REVISION,"jdk_home":str(JAVA_HOME),"harness_sha256":hashlib.sha256(SOURCE.read_bytes()).hexdigest(),"scenario_count":len(rows),"variant_count":len(rows),"rows":rows}
  OUTPUT.write_text(json.dumps(doc,indent=2,sort_keys=True)+"\n")
  print(f"C012 registry real: {len(rows)} scenarios, {len(rows)} variants, {len({r['stable_id'] for r in rows})} stable IDs")
if __name__ == "__main__": main()
