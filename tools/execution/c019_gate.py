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
ROW_EXECUTION = {
    'valid-apply': ('c019_block_apply', 'pinned_java_full_wire_merkle_vectors', 'cargo test -p tron-execution --test c019_block_apply --locked'),
    'side-fork': ('c019_fork_switch', 'multi_branch_switch_rewinds_head_first_and_replays_oldest_first', 'cargo test -p tron-execution --test c019_fork_switch --locked'),
    'successful-switch': ('c019_fork_switch', 'multi_branch_switch_rewinds_head_first_and_replays_oldest_first', 'cargo test -p tron-execution --test c019_fork_switch --locked'),
    'invalid-witness-signature': ('c019_fork_switch', 'invalid_new_witness_signature_removes_branch_and_restores_old_head', 'cargo test -p tron-execution --test c019_fork_switch --locked'),
    'mid-replay-apply-failure': ('c019_fork_switch', 'apply_failure_retracts_partial_new_branch_and_atomically_restores_old_branch', 'cargo test -p tron-execution --test c019_fork_switch --locked'),
    'views-and-roots': ('c019_fork_switch', 'apply_failure_retracts_partial_new_branch_and_atomically_restores_old_branch', 'cargo test -p tron-execution --test c019_fork_switch --locked'),
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
    exact_rows = [r for r in rows if r.get('origin') != 'c017-exact-exclusion' and not r.get('java_source','').endswith('/ConditionallyStopTest.java')]
    if len(exact_rows) != 133: raise SystemExit('C019 exact executable row count drift')
    scenario_by_id = {r['id']:r for r in scenarios['scenarios']}
    evidence = scenarios.get('row_evidence',[])
    if len(evidence) != 133 or {r.get('stable_id') for r in evidence} != {r['stable_id'] for r in exact_rows}: raise SystemExit('C019 exact row evidence union drift')
    evidence_by_id = {r['stable_id']:r for r in evidence}
    for row in exact_rows:
        stable_id = row['stable_id']; case = row['java_symbol']; scenario_id = row.get('scenario_id')
        source_identity = {'stable_id':stable_id,'path':row['java_source'],'line':row['java_line'],'case':case}
        fixture_selector = {'stable_id':stable_id,'scenario_id':scenario_id,'java_case':case}
        execution = ROW_EXECUTION.get(scenario_id)
        if not execution: raise SystemExit('C019 row has no block/fork scenario: '+stable_id)
        rust_target, rust_test_symbol, canonical_command = execution
        observation = scenario_by_id[scenario_id].get('result','observed='+scenario_id)
        result = f'{stable_id}:{case}:{observation}'
        case_id = 'C019-'+stable_id.split('-',1)[1]
        required = {'java_case':case,'source_identity':source_identity,'scenario_observation':observation,'fixture_selector':fixture_selector,'rust_target':rust_target,'rust_test_symbol':rust_test_symbol,'canonical_command':canonical_command,'row_result':result,'case_id':case_id,'expected_result':result,'rust_test':rust_test_symbol,'fixture':fixture_selector}
        if any(row.get(key) != value for key,value in required.items()): raise SystemExit('C019 row-specific executable evidence drift: '+stable_id)
        if evidence_by_id[stable_id] != {'stable_id':stable_id,'source_identity':source_identity,'scenario_id':scenario_id,'scenario_observation':observation,'fixture_selector':fixture_selector,'rust_target':rust_target,'rust_test_symbol':rust_test_symbol,'canonical_command':canonical_command,'row_result':result,'case_id':case_id,'expected_result':result,'rust_test':rust_test_symbol,'fixture':fixture_selector}: raise SystemExit('C019 scenario evidence join drift: '+stable_id)
        if rust_target == 'c019_fork_switch' and (not fixture_selector or not result): raise SystemExit('generic c019_fork_switch credit is forbidden: '+stable_id)
    constrained = [r for r in rows if r.get('java_source','').endswith('/ConditionallyStopTest.java')]
    constrained_ids = {'TCASE-47655B65C468B3B6','TCASE-71021F9EA6E5F635','TCASE-BC4A0B0FC0854DAA','TCASE-D09E3EA1E5C24521'}
    if len(constrained) != 4 or {r.get('stable_id') for r in constrained} != constrained_ids: raise SystemExit('C019 exact constrained exclusion identity drift')
    for row in constrained:
        source_identity = {'stable_id':row['stable_id'],'path':row['java_source'],'line':row['java_line'],'case':row['java_symbol']}
        result = row.get('observable_result',{})
        if row.get('disposition') != 'non_applicable' or row.get('evidence_kind') != 'exact_constrained_exclusion' or row.get('executable_credit') is not False or row.get('rust_target') is not None: raise SystemExit('C019 constrained exclusion executable-credit drift: '+row['stable_id'])
        if row.get('case') != row.get('java_symbol') or row.get('source_identity') != source_identity or result.get('status') != 'non_applicable' or result.get('selector') != row['stable_id'] or not row.get('reason') or not result.get('reason'): raise SystemExit('C019 constrained exclusion evidence drift: '+row['stable_id'])
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
