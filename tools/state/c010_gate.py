#!/usr/bin/env python3
"""Generate and verify pinned C010 state, trie, and logical-migration evidence."""
import argparse, hashlib, json, re, subprocess, sys, tempfile
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]
ORACLES=ROOT/'docs/oracles'; TRACKER=ROOT/'docs/PORTING_TRACKER.json'
TEST=ROOT/'rust-tron/crates/tron-state/tests/c010_contract.rs'
INVENTORY=ORACLES/'c010-source-inventory.v1.json'
FIXTURES=ORACLES/'c010-state-fixtures.v1.json'
RECONCILIATION=ORACLES/'c010-ownership-reconciliation.v1.json'
OWNERSHIP=ORACLES/'java-test-ownership.v1.json'
C008_COVERAGE=ORACLES/'c008-state-coverage.v1.json'
EXPECTED_COMMANDS=[
 {"name":"C010 pinned Java inventory, generated fixtures, ownership and dispatch gate","cwd":".","argv":["python3","tools/state/c010_gate.py"],"timeout_seconds":300},
 {"name":"C010 genesis, defaults, forks, resources, assets, trie and schema migrations","cwd":"rust-tron","argv":["cargo","test","-p","tron-state","--test","c010_contract","--locked"],"timeout_seconds":300},
 {"name":"C010 tron-state module contracts","cwd":"rust-tron","argv":["cargo","test","-p","tron-state","--lib","--locked"],"timeout_seconds":300},
 {"name":"C010 exact workspace target check","cwd":"rust-tron","argv":["cargo","check","-p","tron-state","--all-targets","--locked"],"timeout_seconds":300},
]
SOURCES=[
 'java-tron/chainbase/src/main/java/org/tron/core/ChainBaseManager.java',
 'java-tron/chainbase/src/main/java/org/tron/core/store/DynamicPropertiesStore.java',
 'java-tron/chainbase/src/main/java/org/tron/core/db/ResourceProcessor.java',
 'java-tron/chainbase/src/main/java/org/tron/core/db/BandwidthProcessor.java',
 'java-tron/chainbase/src/main/java/org/tron/core/db/EnergyProcessor.java',
 'java-tron/chainbase/src/main/java/org/tron/core/capsule/AccountCapsule.java',
 'java-tron/chainbase/src/main/java/org/tron/core/capsule/BlockCapsule.java',
 'java-tron/chainbase/src/main/java/org/tron/common/utils/Commons.java',
 'java-tron/chainbase/src/main/java/org/tron/core/db/accountstate/AccountStateEntity.java',
 'java-tron/framework/src/main/java/org/tron/core/trie/TrieKey.java',
 'java-tron/framework/src/main/java/org/tron/core/trie/TrieImpl.java',
]
CASE_TABLE_RE=re.compile(r'^\s*\("([a-z0-9-]+:[a-z0-9-]+)",\s*([a-zA-Z0-9_]+)\),\s*$',re.MULTILINE)

def dispatcher_cases():
    text=TEST.read_text()
    marker='const C010_CASE_TABLE: &[(&str, fn())] = &['
    if marker not in text: raise ValueError('missing C010_CASE_TABLE executable dispatcher')
    table=text.split(marker,1)[1].split('];',1)[0]
    rows=CASE_TABLE_RE.findall(table)
    if not rows: raise ValueError('empty or unparsable C010_CASE_TABLE')
    return dict(rows),rows
CASES={
 'genesis':['accounts-witnesses-assets-block','persisted-store-rows','network-genesis-mismatch','transaction-id-raw-data','advanced-state-restart','substituted-genesis-rejected','substituted-marker-rejected'],
 'dynamic-defaults':['fresh-chain-defaults','missing-only-migration','leading-space-property'],
 'dynamic-slots':['atomic-precommit-retry','filled-percentage'],
 'fork-boundaries':['before-at-after','version-number-int-encoding'], 'fork-quorum':['current-membership'], 'resources':['legacy-window','precision-window','precision-window-midpoint','precision-window-stored-1','precision-window-stored-999','precision-window-stored-1000','adaptive-energy','adaptive-energy-base-floor','fee-sinks','weight-max-overflow','weight-min-overflow','weight-clamp-interaction','adaptive-ratio-zero','adaptive-ratio-negative','adaptive-no-partial-write'],
 'asset-transitions':['legacy-dual-write','v2-only','externalized-balances'],
 'trie-rlp':['empty-root','inline-child','hashed-child','insertion-order','shared-prefix','single-tron-account-root','single-tron-account-node','shared-prefix-root','shared-prefix-node'],
 'trie-limits':['address-exact-max','address-over-limit','value-exact-max','value-over-limit','leaf-exact-max','leaf-over-limit','total-bytes-exact-max','total-bytes-over-limit','node-bytes-exact-max','node-bytes-over-limit','depth-exact-max','depth-over-limit'],
 'forced-root':['report-vs-validation'], 'duplicate-leaf':['last-value-replaces','bounded-replacement'],
 'schema-migrations':['manifest-version','recomputed-root','pre-switch-rollback','post-switch-resume','restart-idempotence','preflight-crash','staging-created-crash','data-written-crash','data-synced-crash','journal-synced-crash','backup-synced-crash','generation-published-crash','manifest-switched-crash','directory-synced-crash'],
}

def sha(path:Path)->str: return hashlib.sha256(path.read_bytes()).hexdigest()
def dump(value)->bytes: return (json.dumps(value,indent=2,sort_keys=True)+'\n').encode()
def gitlink()->str:
    return subprocess.check_output(['git','-C',str(ROOT/'java-tron'),'rev-parse','HEAD'],text=True).strip()
def source_inventory():
    return {'schema_version':1,'chunk':'C010','java_revision':gitlink(),'oracle':{'path':'tools/state/C010Oracle.java','sha256':sha(ROOT/'tools/state/C010Oracle.java')},'sources':[{'path':p,'sha256':sha(ROOT/p)} for p in SOURCES]}
def oracle_rows():
    source=ROOT/'tools/state/C010Oracle.java'
    with tempfile.TemporaryDirectory(prefix='c010-oracle-') as output:
        subprocess.run(['javac','-d',output,str(source)],check=True,cwd=ROOT)
        raw=subprocess.check_output(['java','-cp',output,'C010Oracle'],text=True,cwd=ROOT)
    handlers,table_rows=dispatcher_cases()
    rows=[]
    for line in raw.splitlines():
        fixture_id,input_value,expected=line.split('\t')
        group,case=fixture_id.split(':',1)
        handler=handlers.get(fixture_id)
        if not handler: raise ValueError(f'C010 dispatcher omits {fixture_id}')
        rows.append({'id':fixture_id,'group':group,'case':case,'input':input_value,'expected':expected,'rust_symbol':f'rust-tron/crates/tron-state/tests/c010_contract.rs::{handler}','command_index':1})
    expected_ids=[f'{group}:{case}' for group,cases in CASES.items() for case in cases]
    actual_ids=[row['id'] for row in rows]
    table_ids=[row[0] for row in table_rows]
    if actual_ids!=expected_ids: raise ValueError(f'C010Oracle row order/content mismatch: {actual_ids}')
    if table_ids!=expected_ids: raise ValueError(f'C010_CASE_TABLE row order/content mismatch: {table_ids}')
    if len(handlers)!=len(table_rows): raise ValueError('duplicate C010_CASE_TABLE IDs')
    return rows
def fixtures():
    return {'schema_version':1,'chunk':'C010','generator':'tools/state/C010Oracle.java via tools/state/c010_gate.py --write','rows':oracle_rows()}
ACTIVE_STABLE_ID_CONTRACT={
 'TCASE-8876A645E99563B2':('BandwidthPriceHistoryLoaderTest','testLoaderWork','dynamic-defaults:missing-only-migration'),
 'TCASE-E94DC10F3E417461':('BandwidthPriceHistoryLoaderTest','testProposalEmpty','dynamic-defaults:missing-only-migration'),
 'TCASE-D10BEE6756A0DD6F':('BandwidthPriceHistoryLoaderTest','testLoaderWithProposals','dynamic-defaults:missing-only-migration'),
 'TCASE-C80BD4CC9652C1C9':('CalculateGlobalLimitHardenTest','testGlobalEnergyLimitParity','resources:legacy-window'),
 'TCASE-C787C21CD664C340':('CalculateGlobalLimitHardenTest','testGlobalEnergyLimitOverflowDetectedWithHardening','resources:weight-max-overflow'),
 'TCASE-BE726B61D208DA8A':('CalculateGlobalLimitHardenTest','testGlobalEnergyLimitV2Parity','resources:precision-window'),
 'TCASE-437E11C0CAB96E32':('CalculateGlobalLimitHardenTest','testGlobalEnergyLimitV2CorrectVsDoublePrecisionLoss','resources:precision-window-midpoint'),
 'TCASE-0A84D665D2342ED5':('CalculateGlobalLimitHardenTest','testGlobalNetLimitParity','resources:legacy-window'),
 'TCASE-8ACFD53B6DF955B4':('CalculateGlobalLimitHardenTest','testGlobalNetLimitOverflowDetectedWithHardening','resources:weight-max-overflow'),
 'TCASE-51520052A51273CF':('CalculateGlobalLimitHardenTest','testGlobalNetLimitV2Parity','resources:precision-window'),
 'TCASE-6C164F4FDCDD4C21':('CalculateGlobalLimitHardenTest','testGlobalNetLimitV2ExactPrecision','resources:precision-window-midpoint'),
 'TCASE-066CD56A8A45B08F':('CalculateGlobalLimitHardenTest','testGlobalEnergyLimitV2BelowTrxPrecisionMatchesDouble','resources:precision-window'),
 'TCASE-2DD58B2209AE3A0D':('CalculateGlobalLimitHardenTest','testGlobalNetLimitV2BelowTrxPrecisionMatchesDouble','resources:precision-window'),
 'TCASE-8073EABC7F201406':('CalculateGlobalLimitHardenTest','testGlobalEnergyLimitV1NonIntegerRatioParity','resources:legacy-window'),
 'TCASE-5DB31E5DC2991B45':('CalculateGlobalLimitHardenTest','testV1FlooredWeightVsV2FractionalWeight','resources:precision-window-midpoint'),
 'TCASE-F93C97C9B9151A23':('CalculateGlobalLimitHardenTest','testGlobalNetLimitV1UsesTotalNetWeightNotLimit','resources:legacy-window'),
 'TCASE-35D9FD414586112C':('CalculateGlobalLimitHardenTest','testGlobalNetLimitV2UsesTotalNetWeightNotLimit','resources:precision-window'),
 'TCASE-C0D2D5B8D3C5C3F8':('CalculateGlobalLimitHardenTest','testUpdateAdaptiveTotalEnergyLimitParity','resources:adaptive-energy'),
 'TCASE-530DEE1A85A408E8':('CalculateGlobalLimitHardenTest','testUpdateAdaptiveTotalEnergyLimitOverflowDetected','resources:weight-max-overflow'),
 'TCASE-A666F5D0E114FDFD':('CalculateGlobalLimitHardenTest','testUpdateAdaptiveLimitMultiplierOverflowDetected','resources:weight-max-overflow'),
 'TCASE-EDA1F82ECF12C794':('EnergyPriceHistoryLoaderTest','testLoader','dynamic-defaults:missing-only-migration'),
 'TCASE-97AD7954124B31A7':('EnergyPriceHistoryLoaderTest','testProposalEmpty','dynamic-defaults:missing-only-migration'),
 'TCASE-D098F8F93FBC9F4B':('ResourceProcessorHardenTest','testIncreaseNormalValuesConsistent','resources:legacy-window'),
 'TCASE-9DE39B10C371D14B':('ResourceProcessorHardenTest','testIncreaseV2NormalValuesConsistent','resources:precision-window'),
 'TCASE-DCC7F38CC75B5ADD':('ResourceProcessorHardenTest','testIncreaseOverflowDetectedWithHardening','resources:weight-max-overflow'),
 'TCASE-B26F07D43119483D':('ResourceProcessorHardenTest','testIncreaseOverflowSilentWithoutHardening','resources:weight-max-overflow'),
 'TCASE-DC94F586E38E7BC7':('ResourceProcessorHardenTest','testIncreaseAcceptsIntermediateOverflowWhenResultFits','resources:weight-clamp-interaction'),
 'TCASE-6AD62838496E055C':('ResourceProcessorHardenTest','testIncreaseWithAccountCapsuleConsistent','resources:legacy-window'),
 'TCASE-281BFD9833A6CE00':('ResourceProcessorHardenTest','testUnDelegateIncreaseV2NormalValuesConsistent','resources:precision-window'),
 'TCASE-E16473CD5FAFE69B':('ResourceProcessorHardenTest','testUnDelegateIncreaseV2ConsistentWithHardening','resources:precision-window'),
 'TCASE-6EA68D768E69188B':('ResourceProcessorHardenTest','testIncreaseV2OverflowDetected','resources:weight-max-overflow'),
 'TCASE-D20B8D50572DDFD9':('ResourceProcessorHardenTest','testLargeButSafeValuesWithHardening','resources:weight-clamp-interaction'),
 'TCASE-FCD5AC362C13C85E':('TransactionExpireTest','testExpireTransaction','fork-boundaries:before-at-after'),
 'TCASE-6644C7AE3F480A54':('TransactionExpireTest','testExpireTransactionNew','fork-boundaries:before-at-after'),
 'TCASE-6ACF14B37B4C9DAD':('TransactionExpireTest','testTransactionApprovedList','fork-boundaries:before-at-after'),
 'TCASE-DF57A97352F0A4E5':('TransactionTraceTest','testUseFee','resources:fee-sinks'),
 'TCASE-009BA020A9959F6F':('TransactionTraceTest','testUseUsage','resources:legacy-window'),
 'TCASE-0F5171A8A06E4116':('TransactionTraceTest','testTriggerUseFee','resources:fee-sinks'),
 'TCASE-546C812EF5102A39':('TransactionTraceTest','testTriggerUseUsage','resources:legacy-window'),
 'TCASE-18B091B3E031147F':('TransactionTraceTest','testPay','resources:fee-sinks'),
 'TCASE-0994700D5A2A5223':('TransactionTraceTest','testTriggerUseUsageInWindowSizeV2','resources:precision-window'),
}

def active_rust_case(row):
    contract=ACTIVE_STABLE_ID_CONTRACT.get(row['id'])
    if contract is None: raise ValueError(f'unmapped active C010 stable ID {row["id"]}')
    stem=Path(row['source']['path']).stem
    case=row.get('case'); case_name=case.get('name') if isinstance(case,dict) else case
    if (stem,case_name)!=contract[:2]:
        raise ValueError(f'C010 stable-ID contract metadata drift for {row["id"]}: {stem}::{case_name}')
    return contract[2]
ACTIVE_SEMANTIC_FAMILY={
 'BandwidthPriceHistoryLoaderTest':'dynamic-defaults', 'EnergyPriceHistoryLoaderTest':'dynamic-defaults',
 'CalculateGlobalLimitHardenTest':'resources', 'ResourceProcessorHardenTest':'resources',
 'TransactionExpireTest':'fork-boundaries', 'TransactionTraceTest':'resources',
}
CROSS_C010_CASES={
 'TCASE-639DB1C17027D1E9':'asset-transitions:externalized-balances',
 'TCASE-A0C4B3496675851F':'asset-transitions:legacy-dual-write',
 'TCASE-D20B003F55345095':'asset-transitions:v2-only',
 'TCASE-878087AC456D2528':'asset-transitions:externalized-balances',
 'TCASE-B5C1D55152ACD76F':'asset-transitions:externalized-balances',
}
CROSS_LATER_OWNER={
 'TCASE-ADA6C17DC10097D3':('C012','C012.04'), 'TCASE-8B6650B8003FD547':('C012','C012.04'),
 'TCASE-4EC1950277F501A8':('C014','C014.01'),
 'TCASE-2FB877DFE05E1444':('C013','C013.05'), 'TCASE-52CDFF9183D77269':('C013','C013.05'),
 'TCASE-E6F1B8CAC044DEB5':('C013','C013.05'), 'TCASE-83D945CEA2C1FD5A':('C013','C013.05'),
 'TCASE-FE1CCF836BACF74D':('C013','C013.05'), 'TCASE-F498FED4A9A535CC':('C013','C013.05'),
 'TCASE-1BA32451CD493A9C':('C013','C013.05'), 'TCASE-C94CE146E28DC6EC':('C013','C013.05'),
 'TCASE-0AFA90E251A68CF2':('C013','C013.05'), 'TCASE-AEC64CCCE8BE13EB':('C013','C013.05'),
 'TCASE-0B3F63572FB8AF58':('C013','C013.05'), 'TCASE-6FB8D581BC3E13D3':('C013','C013.05'),
 'TCASE-B53A567613555F77':('C013','C013.05'), 'TCASE-D207EDE1A82F434C':('C013','C013.05'),
 'TCASE-D82D0E898F86514A':('C013','C013.05'), 'TCASE-7BD916901FB7BA89':('C013','C013.05'),
 'TCASE-3069F8B28838449E':('C013','C013.05'), 'TCASE-8EA5EFA10EACB495':('C013','C013.05'),
 'TCASE-91F77838FAA75597':('C013','C013.05'),
 'TCASE-CF3AC78FCFFF0F9C':('C019','C019.04'), 'TCASE-41808BB2E3EDA28E':('C019','C019.04'),
 'TCASE-763E886DBBBC860E':('C019','C019.04'), 'TCASE-999A2BE0789A7EFF':('C019','C019.04'),
 'TCASE-C256E6912892ED7A':('C019','C019.04'), 'TCASE-DCD5386A230BFBD1':('C019','C019.04'),
 'TCASE-1324D9D70B7BAD28':('C019','C019.04'), 'TCASE-88FE24D92ACB6E1B':('C019','C019.04'),
 'TCASE-636D9B19B29B16F3':('C017','C017.02'), 'TCASE-3253F9F9CB619429':('C017','C017.02'),
 'TCASE-B1613DCB8BD8293D':('C017','C017.02'),
 'TCASE-C17A4736D1172F79':('C013','C013.03'), 'TCASE-C964CE27D1CCA51D':('C013','C013.03'),
 'TCASE-39418FB8A0C4B2E5':('C013','C013.03'), 'TCASE-0CC151C0D4E6B56C':('C013','C013.03'),
 'TCASE-C84E15673ADFD602':('C013','C013.03'), 'TCASE-C76DB1243A08C275':('C013','C013.03'),
 'TCASE-34BE7E0660FD5E24':('C013','C013.03'), 'TCASE-DD9482ACE7A84DFC':('C013','C013.03'),
}

def reconciliation():
    handlers,_=dispatcher_cases()
    ledger=json.loads(OWNERSHIP.read_text())
    active=[r for r in ledger['rows'] if r.get('acceptance_gate')=='C010.V']
    prior=json.loads(C008_COVERAGE.read_text())['java_test_reconciliation']
    cross=[r for r in prior if r.get('owner')=='C010']
    fixture_ids={row['id'] for row in fixtures()['rows']}
    rows=[]
    active_ids={row['id'] for row in active}
    if len(ACTIVE_STABLE_ID_CONTRACT)!=41 or active_ids!=set(ACTIVE_STABLE_ID_CONTRACT):
        raise ValueError(f'C010 active stable-ID contract drift: expected=41, active={len(active_ids)}, mapped={len(ACTIVE_STABLE_ID_CONTRACT)}')
    for row in active:
        case=row.get('case'); case_name=case.get('name') if isinstance(case,dict) else case
        rust_case_id=active_rust_case(row)
        expected_family=ACTIVE_SEMANTIC_FAMILY[Path(row['source']['path']).stem]
        if rust_case_id.split(':',1)[0]!=expected_family:
            raise ValueError(f'active C010 stable ID {row["id"]} crosses semantic family: expected {expected_family}, got {rust_case_id}')
        if rust_case_id not in fixture_ids: raise ValueError(f'active C010 stable ID {row["id"]} maps to missing fixture {rust_case_id}')
        handler=handlers.get(rust_case_id)
        if not handler: raise ValueError(f'active C010 stable ID {row["id"]} maps to undispatched fixture {rust_case_id}')
        rows.append({'stable_id':row['id'],'java_source':row['source']['path'],'java_case':case_name,'previous_owner':row.get('reconciled_from'),'owner':'C010','disposition':'rust','rust_case_id':rust_case_id,'rust_symbol':f'rust-tron/crates/tron-state/tests/c010_contract.rs::{handler}'})
    cross_ids={row['stable_id'] for row in cross}
    mapped_cross_ids=set(CROSS_C010_CASES)|set(CROSS_LATER_OWNER)
    if cross_ids!=mapped_cross_ids:
        raise ValueError(f'C010 cross-domain stable-ID contract drift: missing={sorted(cross_ids-mapped_cross_ids)}, stale={sorted(mapped_cross_ids-cross_ids)}')
    for row in cross:
        stable_id=row['stable_id']; rust_case_id=CROSS_C010_CASES.get(stable_id)
        if rust_case_id:
            if rust_case_id not in fixture_ids or rust_case_id not in handlers: raise ValueError(f'cross-domain stable ID {stable_id} maps to unavailable fixture {rust_case_id}')
            out={'stable_id':stable_id,'java_source':row['java_source'],'java_case':row['java_case'],'previous_owner':'C008.V-cross-domain','owner':'C010','disposition':'rust','rust_case_id':rust_case_id,'rust_symbol':f'rust-tron/crates/tron-state/tests/c010_contract.rs::{handlers[rust_case_id]}'}
        else:
            owner,owning_item=CROSS_LATER_OWNER[stable_id]
            out={'stable_id':stable_id,'java_source':row['java_source'],'java_case':row['java_case'],'previous_owner':'C008.V-cross-domain','owner':owner,'disposition':'reassigned','owning_item':owning_item,'acceptance_gate':f'{owner}.V','rationale':f'{owning_item} owns this exact cross-domain behavior; C010 does not claim it.'}
        rows.append(out)
    return {'schema_version':1,'chunk':'C010','active_c010_rows':len(active),'covered_active_c010_rows':sum(r['owner']=='C010' and r['previous_owner']!='C008.V-cross-domain' for r in rows),'c008_cross_domain_rows':len(cross),'rows':rows}
def documents(): return {INVENTORY:source_inventory(),FIXTURES:fixtures(),RECONCILIATION:reconciliation()}
def verify_docs(errors):
    for path,value in documents().items():
        if not path.is_file() or path.read_bytes()!=dump(value): errors.append(f'generated oracle drift: {path.relative_to(ROOT)}; run with --write')
    text=TEST.read_text()
    fixture=fixtures()
    ids=[r['id'] for r in fixture['rows']]
    if len(ids)!=len(set(ids)): errors.append('duplicate C010 fixture IDs')
    handlers,_=dispatcher_cases()
    if 'for &(id, execute) in C010_CASE_TABLE' not in text or 'execute();' not in text:
        errors.append('C010_CASE_TABLE is not executed by the parameterized dispatcher')
    for row in fixture['rows']:
        symbol=row['rust_symbol'].rsplit('::',1)[-1]
        if handlers.get(row['id'])!=symbol: errors.append('fixture/dispatcher handler mismatch: '+row['id'])
        if not re.search(rf'fn\s+{re.escape(symbol)}\s*\(',text): errors.append('missing executable Rust handler: '+row['id'])
        body_match=re.search(rf'fn\s+{re.escape(symbol)}\s*\([^)]*\)\s*\{{(.+?)\n\}}',text,re.DOTALL)
        if body_match and not re.search(r'assert|unwrap|migrate_generation|resume_migration|put_|save_|initialize_',body_match.group(1)):
            errors.append('literal-only C010 handler: '+row['id'])
    rec=reconciliation(); stable=[r['stable_id'] for r in rec['rows']]
    if len(stable)!=len(set(stable)): errors.append('duplicate C010 ownership reconciliation IDs')
    if any(r.get('previous_owner')=='C008.V-provisional' and r.get('owner')!='C010' for r in rec['rows']): errors.append('C008 provisional C010 rows were not accepted')
    active_ids={r['id'] for r in json.loads(OWNERSHIP.read_text())['rows'] if r.get('acceptance_gate')=='C010.V'}
    cross_ids={r['stable_id'] for r in json.loads(C008_COVERAGE.read_text())['java_test_reconciliation'] if r.get('owner')=='C010'}
    if set(stable)!=active_ids|cross_ids: errors.append('C010 reconciliation must explicitly dispose every stable ID exactly once')
    for row in rec['rows']:
        if row.get('owner')=='C010' and (row.get('disposition')!='rust' or row.get('rust_case_id') not in handlers):
            errors.append('incomplete executable C010 stable-ID disposition: '+row['stable_id'])
        if row.get('owner')!='C010' and (row.get('disposition')!='reassigned' or not row.get('owning_item') or not row.get('acceptance_gate')):
            errors.append('incomplete later-owner stable-ID disposition: '+row['stable_id'])
def main()->int:
    parser=argparse.ArgumentParser(); parser.add_argument('--write',action='store_true'); args=parser.parse_args()
    try: expected=documents()
    except (OSError,subprocess.SubprocessError,KeyError) as error: print(f'C010 oracle generation failed: {error}',file=sys.stderr); return 1
    if args.write:
        for path,value in expected.items(): path.write_bytes(dump(value))
        return 0
    errors=[]; verify_docs(errors)
    tracker=json.loads(TRACKER.read_text()); chunk=next((c for c in tracker['chunks'] if c['id']=='C010'),None)
    if not chunk or chunk.get('gate',{}).get('commands')!=EXPECTED_COMMANDS: errors.append('C010 tracker commands must match canonical exact gate')
    if not chunk or chunk.get('status')!='active': errors.append('C010 chunk must remain active until gate execution')
    statuses={r['id']:r['status'] for r in chunk.get('items',[])} if chunk else {}
    expected_statuses={'C010.01':'doing',**{f'C010.{i:02}':'todo' for i in range(2,7)}}
    if statuses!=expected_statuses: errors.append('C010 items must be C010.01 doing and C010.02-C010.06 todo before gate execution')
    if not chunk or chunk.get('gate',{}).get('status')!='not_run': errors.append('C010.V must remain not_run until executed')
    if not chunk or chunk.get('review',{}).get('state')!='not_started': errors.append('C010 review must remain not_started until gate execution')
    if errors:
        print('\n'.join(errors),file=sys.stderr); return 1
    print(f'C010 gate metadata verified: {len(fixtures()["rows"])} fixtures, {len(reconciliation()["rows"])} ownership rows')
    return 0
if __name__=='__main__': raise SystemExit(main())
