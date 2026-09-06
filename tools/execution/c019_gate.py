#!/usr/bin/env python3
import argparse, hashlib, json, os, pathlib, subprocess, sys, tempfile
ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'tools/reference-runner'))
from java_reference_guard import install_java_reference_guard
RUST = ROOT / 'rust-tron'
ORACLES = ROOT / 'docs/oracles'
SCENARIOS = ORACLES / 'c019-scenarios.v1.json'
RECON = ORACLES / 'c019-ownership-reconciliation.v1.json'
BLOCK = ORACLES / 'c019-block-apply.v1.json'
PROD = ORACLES / 'production-ownership.v1.json'
TESTS = ORACLES / 'java-test-ownership.v1.json'
C017 = ORACLES / 'c017-ownership-reconciliation.v1.json'
C011 = ORACLES / 'c011-java-test-reconciliation.v1.json'
MANIFEST = ORACLES / 'manifest.v1.json'
TRACKER = ROOT / 'docs/PORTING_TRACKER.json'
COMMANDS = {
    'block': ['cargo','test','-p','tron-execution','--test','c019_block_apply','--locked'],
    'fork': ['cargo','test','-p','tron-execution','--test','c019_fork_switch','--locked'],
    'scenario': ['cargo','test','-p','tron-execution','--test','c019_scenarios','--locked'],
    'all-targets': ['cargo','check','-p','tron-execution','--all-targets','--locked'],
}
def load(path): return json.loads(path.read_text())
def digest(path): return hashlib.sha256(path.read_bytes()).hexdigest()
def source_rows():
    prod = [r for r in load(PROD)['rows'] if r.get('acceptance_gate') == 'C019.V']
    tests = [r for r in load(TESTS)['rows'] if r.get('acceptance_gate') == 'C019.V']
    excluded = [r for r in load(C017).get('excluded_rows',[]) if r.get('acceptance_gate') == 'C019.V']
    return prod, tests, excluded
def metadata():
    scenarios, recon, block = load(SCENARIOS), load(RECON), load(BLOCK)
    if scenarios.get('schema') != 'c019-scenarios.v1' or recon.get('schema') != 'c019-ownership-reconciliation.v1' or block.get('schema') != 'java-tron-c019-block-apply-v1': raise SystemExit('C019 schema drift')
    graph = scenarios.get('branch_graph',{})
    if scenarios.get('minimum_reorg_depth') != 2 or graph.get('removed') != ['A2','A1'] or graph.get('replayed') != ['B1','B2','B3']: raise SystemExit('C019 explicit branch graph drift')
    required = {'valid-apply','side-fork','successful-switch','invalid-witness-signature','mid-replay-apply-failure','pending-requeue','event-order','views-and-roots'}
    if {r.get('id') for r in scenarios.get('scenarios',[])} != required: raise SystemExit('C019 scenario set drift')
    prod, tests, excluded = source_rows()
    c11 = [r for r in load(C011)['rows'] if r.get('previous_gate') == 'C019.V']
    counts = {'production':len(prod),'java_tests':len(tests),'c017_exact_exclusions':len(excluded),'c011_exact_exclusions':len(c11),'covered':len(prod)+len(tests)+len(excluded)}
    if recon.get('counts') != counts: raise SystemExit('C019 ownership counts drift')
    expected = {r['id'] for r in prod} | {r['id'] for r in tests} | {(r.get('stable_id') or 'PROD-'+r['case_id'].split('-')[-1]) for r in excluded}
    rows = recon.get('rows',[])
    if len(rows) != len(expected) or {r.get('stable_id') for r in rows} != expected: raise SystemExit('C019 exact ownership union drift')
    if len(recon.get('c011_excluded_rows',[])) != len(c11) or any(r.get('owner') != 'C011' or r.get('acceptance_gate') != 'C011.V' for r in recon['c011_excluded_rows']): raise SystemExit('C019/C011 row exclusion drift')
    ledger_hashes = recon.get('source_ledgers',{})
    expected_hashes = {'production_sha256':digest(PROD),'java_tests_sha256':digest(TESTS),'c017_reconciliation_sha256':digest(C017),'c011_reconciliation_sha256':digest(C011)}
    if ledger_hashes != expected_hashes: raise SystemExit('C019 source ledger digest drift')
    manifest = load(MANIFEST)
    for name in ('c019-block-apply.v1.json','c019-scenarios.v1.json','c019-ownership-reconciliation.v1.json'):
        key = name.removesuffix('.v1.json').replace('-','_')
        if manifest.get(key) != {'path':name,'sha256':digest(ORACLES/name)}: raise SystemExit('C019 central manifest drift: '+key)
    chunk = next((r for r in load(TRACKER)['chunks'] if r.get('id') == 'C019'),None)
    if not chunk or chunk.get('status') != 'done' or chunk.get('owner') is not None or chunk.get('resume') is not None or any(r.get('status') != 'done' for r in chunk.get('items',[])) or chunk.get('gate',{}).get('status') != 'passed' or chunk.get('review',{}).get('state') != 'approved': raise SystemExit('C019 tracker metadata drift')
    print(json.dumps({'schema':'c019-metadata-v1','production':len(prod),'java_tests':len(tests),'c017_exclusions':len(excluded),'c011_exclusions':len(c11),'status':'passed'},separators=(',',':')))
def oracle():
    session = install_java_reference_guard(ROOT)
    with tempfile.TemporaryDirectory(prefix='c019-java-', dir=session.work) as raw:
        out = pathlib.Path(raw); init = out/'classpath.gradle'
        init.write_text("allprojects { p -> if (p.path == ':framework') { p.afterEvaluate { p.tasks.register('c019RuntimeClasspath') { doLast { println 'C019_CLASSPATH=' + p.sourceSets.test.runtimeClasspath.asPath } } } } }\n")
        built = session.gradle(['-I',str(init),':framework:testClasses',':actuator:jar',':consensus:jar',':chainbase:jar',':crypto:jar',':common:jar',':protocol:jar',':platform:jar'])
        queried = session.gradle(['-I',str(init),':framework:c019RuntimeClasspath'])
        if queried.returncode: raise SystemExit('C019 Java classpath failed')
        matches = [x.split('=',1)[1] for x in queried.stdout.decode().splitlines() if x.startswith('C019_CLASSPATH=')]
        if len(matches) != 1: raise SystemExit('C019 classpath capture drift')
        cp = matches[0]; javac = str(session.java_home/'bin/javac')
        oracle_source = ROOT/'tools/execution/C019Oracle.java'
        agent_source = ROOT/'tools/execution/instrumentation/org/tron/tools/c019/C019Agent.java'
        session.run([javac,'-cp',cp,'-d',str(out),str(oracle_source),str(agent_source)],cwd=session.work,classpath=cp,check=True)
        manifest = out/'MANIFEST.MF'; manifest.write_text('Manifest-Version: 1.0\nPremain-Class: org.tron.tools.c019.C019Agent\n\n')
        agent_jar = out/'c019-agent.jar'
        session.run([str(session.java_home/'bin/jar'),'cfm',str(agent_jar),str(manifest),'-C',str(out),'org/tron/tools/c019'],cwd=session.work,check=True)
        runtime = str(out)+os.pathsep+cp
        observed = session.run([str(session.java_home/'bin/java'),'-javaagent:'+str(agent_jar),'-cp',runtime,'C019Oracle'],cwd=session.work,classpath=runtime,check=True)
        captures = [json.loads(line) for line in observed.stdout.decode().splitlines() if line.startswith('{')]
        if len(captures) != 1 or captures[0].get('schema') != 'c019-java-manager-v1' or 'C019_INSTRUMENTATION_MANAGER_LOADED=true' not in observed.stdout.decode(): raise SystemExit('C019 instrumented Java oracle mismatch')
        tests = session.gradle([':framework:test','--tests','org.tron.core.db.ManagerTest.pushSwitchFork','--tests','org.tron.core.db.ManagerMockTest.testSwitchForkRejectsBlockWithInvalidSignature','--tests','org.tron.core.db.ManagerMockTest.testSwitchForkPassesValidSignatureBlockToApply'])
        if tests.returncode: raise SystemExit('C019 pinned Manager scenarios failed:\n'+tests.stderr.decode('utf-8','replace'))
        print(json.dumps({'schema':'c019-java-oracle-v1','manager_scenarios':3,'instrumented':True,'status':'passed'},separators=(',',':')))
def run(target):
    cmd=COMMANDS[target]; print('+',' '.join(cmd),flush=True); subprocess.run(cmd,cwd=RUST,check=True)
def main():
    choices=['metadata','oracle',*COMMANDS,'all']; parser=argparse.ArgumentParser(); parser.add_argument('targets',nargs='*',choices=choices); args=parser.parse_args(); targets=args.targets or ['all']
    if 'all' in targets: targets=['metadata','oracle','block','fork','scenario','all-targets']
    for target in targets:
        if target=='metadata': metadata()
        elif target=='oracle': oracle()
        else: run(target)
    print(json.dumps({'schema':'c019-gate-v1','targets':targets,'status':'passed'},separators=(',',':')))
if __name__=='__main__': main()
