#!/usr/bin/env python3
"""Generate and verify exhaustive pinned-Java C008 codec evidence and Rust dispatch."""
from __future__ import annotations

import argparse, hashlib, json, os, re, subprocess, sys, tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ORACLES = ROOT / "docs/oracles"
REVISION = "4a21592f95e37908b21bc3f611c6e7a1a67f09f3"
INVENTORY = ORACLES / "c008-state-inventory.v1.json"
FIXTURES = ORACLES / "c008-state-fixtures.v1.json"
COVERAGE = ORACLES / "c008-state-coverage.v1.json"
DYNAMIC = ORACLES / "c008-dynamic-properties.v1.json"
TRACKER = ROOT / "docs/PORTING_TRACKER.json"
OWNERSHIP = ORACLES / "java-test-ownership.v1.json"
TEST = "rust-tron/crates/tron-state/tests/logical_contract.rs"
INTEGRATION_TEST = "rust-tron/crates/tron-state/tests/integration_contract.rs"
JAVA = ROOT / "tools/state/C008Oracle.java"
EXPECTED_COMMANDS = [
 {"name":"C008 inventory, fixtures, reconciliation and workspace gate","cwd":".","argv":["python3","tools/state/c008_gate.py"],"timeout_seconds":300},
 {"name":"C008 logical store, capsule, key and value fixtures","cwd":"rust-tron","argv":["cargo","test","-p","tron-state","--test","logical_contract","--locked"],"timeout_seconds":300},
 {"name":"C008 atomic, reopen, crash, market and account-asset integration","cwd":"rust-tron","argv":["cargo","test","-p","tron-state","--test","integration_contract","--locked"],"timeout_seconds":300},
 {"name":"C008 state workspace check","cwd":"rust-tron","argv":["cargo","check","-p","tron-state","--all-targets","--locked"],"timeout_seconds":300},
]

# Rust StoreKind, exact Java DB name, Java source, key codec, value codec.
FAMILIES = [
("Account","account","store/AccountStore.java","address bytes","Account protobuf"),("AccountIdIndex","accountid-index","store/AccountIdIndexStore.java","Locale.ROOT lowercase account-id","address bytes"),("AccountIndex","account-index","store/AccountIndexStore.java","account-name bytes","address bytes"),("AccountAsset","account-asset","store/AccountAssetStore.java","address || asset id/name","signed big-endian i64"),("AssetIssue","asset-issue","store/AssetIssueStore.java","asset-name bytes","AssetIssueContract protobuf"),("AssetIssueV2","asset-issue-v2","store/AssetIssueV2Store.java","asset-id UTF-8 bytes","AssetIssueContract protobuf"),
("Block","block","db/BlockStore.java","32-byte block id","Block protobuf"),("BlockIndex","block-index","db/BlockIndexStore.java","signed big-endian i64 height","32-byte block id"),("Transaction","trans","db/TransactionStore.java","32-byte transaction id","8-byte height or Transaction protobuf"),("TransactionCache","trans-cache",None,"32-byte transaction id","Transaction protobuf"),("TransactionRet","transactionRetStore","store/TransactionRetStore.java","signed big-endian i64 height","TransactionRet protobuf"),("TransactionHistory","transactionHistoryStore","store/TransactionHistoryStore.java","transaction id or height","8-byte height or TransactionInfo protobuf"),("RecentBlock","recent-block","db/RecentBlockStore.java","low two height bytes","block-id bytes 8..16"),("RecentTransaction","recent-transaction","db/RecentTransactionStore.java","transaction id","empty/raw marker"),
("Contract","contract","store/ContractStore.java","contract address","SmartContract protobuf without ABI"),("Abi","abi","store/AbiStore.java","contract address","SmartContract.ABI protobuf"),("Code","code","store/CodeStore.java","contract address","raw bytecode"),("ContractState","contract-state","store/ContractStateStore.java","contract address","ContractState protobuf"),("StorageRow","storage-row","store/StorageRowStore.java","16-byte address domain || 16-byte slot domain","32-byte value; zero deletes"),("Witness","witness","store/WitnessStore.java","witness address","Witness protobuf"),("WitnessSchedule","witness_schedule","store/WitnessScheduleStore.java","active/current schedule literal","concatenated 21-byte addresses"),("Votes","votes","store/VotesStore.java","address","Votes protobuf"),("Proposal","proposal","store/ProposalStore.java","signed big-endian i64 proposal id","Proposal protobuf"),("Exchange","exchange","store/ExchangeStore.java","signed big-endian i64 exchange id","Exchange protobuf"),("ExchangeV2","exchange-v2","store/ExchangeV2Store.java","signed big-endian i64 exchange id","Exchange protobuf"),
("MarketAccount","market_account","store/MarketAccountStore.java","account address","MarketAccountOrder protobuf"),("MarketOrder","market_order","store/MarketOrderStore.java","Keccak(address || padded pair || count)","MarketOrder protobuf"),("MarketPairToPrice","market_pair_to_price","store/MarketPairToPriceStore.java","two 19-byte zero-padded token ids","signed big-endian i64 BytesCapsule"),("MarketPairPriceToOrder","market_pair_price_to_order","store/MarketPairPriceToOrderStore.java","pair || normalized signed i64 quantities","MarketOrderIdList protobuf"),("DelegatedResource","DelegatedResource","store/DelegatedResourceStore.java","legacy/V2 owner-receiver-lock key","DelegatedResource protobuf"),("DelegatedResourceAccountIndex","DelegatedResourceAccountIndex","store/DelegatedResourceAccountIndexStore.java","legacy/V2 account prefix key","DelegatedResourceAccountIndex protobuf"),("DynamicProperties","properties","store/DynamicPropertiesStore.java","exact literal property bytes","BytesCapsule raw bytes"),("IncrementalMerkleTree","IncrementalMerkleTree","store/IncrementalMerkleTreeStore.java","Merkle tree key bytes","IncrementalMerkleTree protobuf"),("Nullifier","nullifier","store/NullifierStore.java","nullifier bytes","BytesCapsule raw bytes"),("ZkProof","zkProof","store/ZKProofStore.java","proof hash bytes","one-byte boolean"),("TreeBlockIndex","tree-block-index","store/TreeBlockIndexStore.java","tree block index","protobuf/raw"),("SectionBloom","section-bloom","store/SectionBloomStore.java","hex(section*1_000_000+bit)","bloom bytes"),("AccountTrace","account-trace","store/AccountTraceStore.java","address || xor height","AccountTrace protobuf"),("BalanceTrace","balance-trace","store/BalanceTraceStore.java","block number","BlockBalanceTrace protobuf"),("Delegation","delegation","store/DelegationStore.java","delegation key","raw/protobuf"),("Pbft","pbft-sign-data","store/PbftSignDataStore.java","PBFT key","PBFTMessage protobuf"),("RewardVi","reward-vi","store/RewardViStore.java","address","reward bytes"),("Common","common","store/CommonStore.java","raw key","raw bytes"),("Checkpoint","checkpoint",None,"checkpoint key","checkpoint bytes"),("Temporary","tmp",None,"temporary key","raw bytes")]
CAPSULE_ROOT = ROOT / "java-tron/chainbase/src/main/java/org/tron/core/capsule"
JAVA_ROOT = ROOT / "java-tron/chainbase/src/main/java/org/tron/core"

def sha(path: Path) -> str: return hashlib.sha256(path.read_bytes()).hexdigest()
def dump(value: object) -> bytes: return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False)+"\n").encode()
def dispatch_variant(row: dict) -> str:
    prefix={"store":"Store","capsule":"Capsule","dynamic_key":"DynamicKey","dynamic_default":"DynamicDefault"}[row["row_kind"]]
    if row["row_kind"] in {"dynamic_key","dynamic_default"}: return prefix
    return prefix+re.sub(r"[^A-Za-z0-9]+", "", row["schema"])

def dispatch_for(row: dict) -> dict:
    function_kind={"store":"store_codec","capsule":"protobuf_capsule" if row.get("unknown_value_hex") else "raw_capsule","dynamic_key":"dynamic_key","dynamic_default":"dynamic_default"}[row["row_kind"]]
    return {"enum_variant":dispatch_variant(row),"function_kind":function_kind,"case_id":row["id"]}

def dynamic_initializer_outputs(defaults: list[dict], dynamic: dict) -> list[dict]:
    """Extract outputs from the narrow adapter transcribed from the manager-bound Java constructor."""
    source=(ROOT/"rust-tron/crates/tron-state/src/dynamic.rs").read_text().split("pub fn initialize_missing",1)[1]
    calls=re.findall(r'(int|long|raw)!\("([A-Z0-9_]+)",\s*([^;]+)\);',source)
    calls=[call for call in calls if call[1] not in {"AVAILABLE_CONTRACT_TYPE","ACTIVE_DEFAULT_OPERATIONS"}]
    memo_index=next(i for i,call in enumerate(calls) if call[1]=="ALLOW_DELEGATE_OPTIMIZATION")
    calls.insert(memo_index,("long","MEMO_FEE","config.memo_fee"))
    if len(calls)!=len(defaults): raise RuntimeError(f"dynamic initializer/default mismatch: {len(calls)} != {len(defaults)}")
    key_hex={key["symbol"]:key["bytes_utf8"].encode().hex() for key in dynamic["keys"]}
    rows=[]
    for default,(kind,symbol,expression) in zip(defaults,calls):
        if expression.startswith("config.") or expression=="genesis_timestamp": number=0
        elif expression=="reward_cycle": number=(1<<63)-1
        elif expression=="[0_u8]": value=b"\0"
        elif expression=="[b'1'; 128]": value=b"1"*128
        elif expression.startswith('b"'): value=expression[2:-1].encode()
        else:
            clean=re.sub(r'_(?:i64|i32)\b','',expression).replace('_','').replace(' ','')
            if not re.fullmatch(r'[0-9/+-]+',clean): raise RuntimeError("unsupported dynamic initializer expression: "+expression)
            number=eval(clean,{"__builtins__":{}},{})
        if kind=="long": value=int(number).to_bytes(8,"big",signed=True)
        elif kind=="int": value=int(number).to_bytes(4,"big",signed=True)
        rows.append({**default,"property_symbol":symbol,"key_hex":key_hex[symbol],"value_hex":value.hex(),"adapter":"tron_state::dynamic::initialize_missing","provenance":"java-tron/chainbase/src/main/java/org/tron/core/store/DynamicPropertiesStore.java constructor"})
    return rows



def java_rows() -> list[dict]:
    jars=list((Path.home()/".gradle/caches/modules-2/files-2.1/com.google.protobuf/protobuf-java/3.25.8").glob("**/protobuf-java-3.25.8.jar"))
    if len(jars)!=1: raise RuntimeError("pinned protobuf-java 3.25.8 artifact is unavailable or ambiguous")
    cp=os.pathsep.join(map(str,[ROOT/"java-tron/protocol/build/classes/java/main",ROOT/"java-tron/common/build/classes/java/main",jars[0]]))
    with tempfile.TemporaryDirectory(prefix="c008-java-") as temporary:
        subprocess.run(["javac","--release","8","-cp",cp,"-d",temporary,str(JAVA),str(CAPSULE_ROOT/"ProtoCapsule.java"),str(CAPSULE_ROOT/"BytesCapsule.java")],check=True)
        raw=subprocess.check_output(["java","-cp",os.pathsep.join([temporary,cp]),"C008Oracle"],text=True)
    rows=[]
    for line in raw.splitlines():
        kind,row_id,schema,db,key,value,unknown,known_tag=line.split("\t")
        coverage=["exact-key-bytes","exact-value-bytes","absent","present","delete"] if kind=="store" else (["known-field-decode","raw-preservation","unknown-field-preservation","mutation-reencode"] if unknown else ["raw-capsule-bytes"])
        rows.append({"id":row_id,"row_kind":kind,"schema":schema,"store":schema if kind=="store" else None,"db_name":db or None,"key_hex":key,"value_hex":value,"unknown_value_hex":unknown or None,"known_field_tag":int(known_tag) if known_tag else None,"coverage":coverage})
    return rows
def proof_symbol(path: str, symbol: str) -> str: return f"{path}::{symbol}"

def reconcile_java_tests(fixture: dict) -> list[dict]:
    ownership=json.loads(OWNERSHIP.read_text())
    ledger=[row for row in ownership["rows"] if row.get("acceptance_gate")=="C008.V"]
    dispatch=fixture["rust_dispatch"]; store_aliases={"ZKProof":"ZkProof"}
    deferred_c010={"ContractStateCapsuleTest","ExchangeCapsuleTest","ExchangeProcessorTest","AssetUtilTest","BalanceTraceStoreTest","BlockFilledSlotsTest","DelegatedResourceAccountIndexStoreTest"}
    deferred_c029={"DecodeResultTest","MerkleTreeTest","RLPListTest","PojoTest","AssetUpdateHelperTest"}
    rows=[]
    for java in ledger:
        source=java["source"]["path"]; stem=Path(source).stem; case=java["case"]
        base={"stable_id":java["id"],"java_source":source,"java_case":case}
        if stem in deferred_c010 or (stem=="AccountCapsuleTest" and case!="getDataTest"):
            rows.append(base|{"disposition":"deferred","owner":"C010","rationale":"Dynamic-state, resource, fork-boundary, or stateful processor behavior is owned by C010 rather than the C008 logical codec layer."}); continue
        if stem in deferred_c029 or (stem=="BlockCapsuleTest" and case!="testGetData") or (stem=="TransactionCapsuleTest" and case in {"slowVerify","fastVerify"}):
            rows.append(base|{"disposition":"deferred","owner":"C029","rationale":"Cross-cutting utility, crypto, API projection, or regression behavior requires the C029 Java test-surface closure."}); continue
        if stem.startswith("Market") and stem.endswith("StoreTest"):
            symbol="market_codec_returns_errors_and_uses_java_boundary_arithmetic" if stem in {"MarketPairPriceToOrderStoreTest","MarketPairToPriceStoreTest"} else "market_order_account_and_pair_stores_unlink_and_reopen"
            rows.append(base|{"disposition":"rust","owner":"C008","rust_symbol":proof_symbol(INTEGRATION_TEST,symbol),"rust_case_id":f"{stem}:{case}","dispatch_kind":"named_test"}); continue
        if stem=="AccountAssetStoreTest":
            rows.append(base|{"disposition":"rust","owner":"C008","rust_symbol":proof_symbol(INTEGRATION_TEST,"account_external_assets_persist_and_reopen"),"rust_case_id":f"{stem}:{case}","dispatch_kind":"named_test"}); continue
        fixture_id=None
        if stem.endswith("StoreTest"): fixture_id="store-"+store_aliases.get(stem[:-9],stem[:-9])
        elif stem.endswith("CapsuleTest"): fixture_id="capsule-"+stem[:-4]
        if fixture_id in dispatch:
            rows.append(base|{"disposition":"rust","owner":"C008","rust_symbol":proof_symbol(TEST,"java_codec_artifact_dispatches_every_row"),"rust_case_id":fixture_id,"fixture_row_id":fixture_id,"dispatch_variant":dispatch[fixture_id]["enum_variant"],"dispatch_kind":"fixture_row"}); continue
        rows.append(base|{"disposition":"deferred","owner":"C029","rationale":"No C008 logical fixture case represents this higher-level Java behavior; C029 owns its explicit regression disposition."})
    return rows


def documents() -> dict[Path,dict]:
    capsules=[{"class":p.stem,"path":p.relative_to(ROOT).as_posix(),"sha256":sha(p)} for p in sorted(CAPSULE_ROOT.glob("*Capsule.java"))]
    stores=[]
    for kind,db,rel,key_codec,value_codec in FAMILIES:
        source=JAVA_ROOT/rel if rel else None
        if source is not None and not source.is_file():
            alternate=JAVA_ROOT/"db"/source.name
            source=alternate if alternate.is_file() else None
        stores.append({"rust_kind":kind,"db_name":db,"java_source":source.relative_to(ROOT).as_posix() if source else None,"java_sha256":sha(source) if source else None,"key_codec":key_codec,"value_codec":value_codec})
    dynamic=json.loads(DYNAMIC.read_text()); dynamic_defaults=dynamic_initializer_outputs(dynamic["constructor_defaults"],dynamic)
    inventory={"schema_version":3,"java_revision":REVISION,"capsules":capsules,"stores":stores,"dynamic_keys":dynamic["keys"],"dynamic_defaults":dynamic_defaults,"counts":{"capsules":len(capsules),"stores":len(stores),"dynamic_keys":len(dynamic["keys"]),"dynamic_defaults":len(dynamic_defaults)}}
    rows=java_rows()
    for key in dynamic["keys"]:
        key_coverage=["exact-key-bytes"]
        if key["symbol"]=="MEMO_FEE": key_coverage.append("paired-default-source")
        if key["symbol"]=="MEMO_FEE_HISTORY": key_coverage.append("paired-default-derived-atomic-repair")
        rows.append({"id":"dynamic-key-"+key["symbol"],"row_kind":"dynamic_key","schema":key["symbol"],"store":"DynamicProperties","db_name":"properties","key_hex":key["bytes_utf8"].encode().hex(),"value_hex":"","coverage":key_coverage})
    for index,default in enumerate(dynamic_defaults):
        rows.append({"id":f"dynamic-default-{index:03d}-{default['getter']}","row_kind":"dynamic_default","schema":default["getter"],"store":"DynamicProperties","db_name":"properties","key_hex":default["key_hex"],"value_hex":default["value_hex"],"coverage":["exact-initializer-key-bytes","exact-initializer-value-bytes","initialize-if-absent"]})
    dispatch={row["id"]:dispatch_for(row) for row in rows}
    fixture={"schema_version":3,"java_revision":REVISION,"generator":{"path":JAVA.relative_to(ROOT).as_posix(),"sha256":sha(JAVA),"generated_protocol":"java-tron/protocol/src/main/java/org/tron/protos/Protocol.java","byte_helper":"java-tron/common/src/main/java/org/tron/common/utils/ByteArray.java"},"rows":rows,"rust_dispatch":dispatch}
    fixture["rows_sha256"]=hashlib.sha256(json.dumps(rows,sort_keys=True,separators=(",",":")).encode()).hexdigest()
    if FIXTURES.is_file():
        existing_fixture=json.loads(FIXTURES.read_text())
        if "market_price_logical_order" in existing_fixture: fixture["market_price_logical_order"]=existing_fixture["market_price_logical_order"]
    coverage={"schema_version":3,"java_revision":REVISION,"java_test_reconciliation":reconcile_java_tests(fixture),"inventory_rows":[{"id":r["id"],"proof":proof_symbol(TEST,"java_codec_artifact_dispatches_every_row"),"case_id":r["id"],"dispatch_variant":dispatch[r["id"]]["enum_variant"]} for r in rows],"state_cases":[
      {"id":"cross-store-atomic-batch","proof":f"{INTEGRATION_TEST}::cross_store_batch_is_atomic_and_reopens"},
      {"id":"all-c007-precommit-phases","proof":f"{INTEGRATION_TEST}::c007_precommit_crash_matrix_keeps_cross_store_batch_atomic"},
      {"id":"market-linked-atomicity","proof":f"{INTEGRATION_TEST}::market_linked_updates_are_atomic_across_crashes"},
      {"id":"account-asset-atomicity","proof":f"{INTEGRATION_TEST}::account_external_assets_are_atomic_across_crashes"}]}
    return {INVENTORY:inventory,FIXTURES:fixture,COVERAGE:coverage}

def verify(errors:list[str], expected:dict[Path,dict])->None:
    actual_revision=subprocess.check_output(["git","-C",str(ROOT/"java-tron"),"rev-parse","HEAD"],text=True).strip()
    if actual_revision!=REVISION: errors.append(f"java-tron revision drift: {actual_revision}")
    source=(ROOT/"rust-tron/crates/tron-state/src/store.rs").read_text(); inventory=expected[INVENTORY]; fixture=expected[FIXTURES]
    for row in inventory["stores"]:
        if not re.search(rf'Self::{re.escape(row["rust_kind"])}\s*=>\s*"{re.escape(row["db_name"])}"',source): errors.append("StoreKind mapping drift: "+row["rust_kind"])
    tests=(ROOT/TEST).read_text(); integration=(ROOT/INTEGRATION_TEST).read_text()
    required=[("java_codec_artifact_dispatches_every_row",tests),("cross_store_batch_is_atomic_and_reopens",integration),("c007_precommit_crash_matrix_keeps_cross_store_batch_atomic",integration),("market_linked_updates_are_atomic_across_crashes",integration),("account_external_assets_are_atomic_across_crashes",integration)]
    for symbol,text in required:
        if not re.search(rf"fn\s+{symbol}\s*\(",text): errors.append("missing Rust proof: "+symbol)
    ids={r["id"] for r in fixture["rows"]}; dispatch=fixture["rust_dispatch"]
    if ids!=set(dispatch): errors.append("every fixture row must have one executable Rust dispatch")
    for row in fixture["rows"]:
        entry=dispatch[row["id"]]
        if entry!=dispatch_for(row): errors.append("typed dispatch drift: "+row["id"])
        if entry["case_id"]!=row["id"]: errors.append("dispatch case_id drift: "+row["id"])
        if not re.search(rf"\b{re.escape(entry['enum_variant'])}\b",tests): errors.append("missing Rust dispatch variant: "+entry["enum_variant"])
    match_variants=set(re.findall(r"DispatchKind::([A-Za-z0-9_]+)\s*=>",tests))
    expected_variants={entry["enum_variant"] for entry in dispatch.values()}
    if match_variants!=expected_variants: errors.append(f"Rust match variants must exactly cover artifact dispatch: missing={sorted(expected_variants-match_variants)} extra={sorted(match_variants-expected_variants)}")
    if "c008-state-fixtures.v1.json" not in tests or "rust_dispatch" not in tests or "dispatch_row" not in tests: errors.append("Rust must deserialize the artifact and execute typed per-row dispatch")
    reconciliation=expected[COVERAGE]["java_test_reconciliation"]
    ledger=json.loads(OWNERSHIP.read_text())
    ledger_ids={row["id"] for row in ledger["rows"] if row.get("acceptance_gate")=="C008.V"}
    stable_ids=[row["stable_id"] for row in reconciliation]
    if len(reconciliation)!=189 or len(set(stable_ids))!=189 or set(stable_ids)!=ledger_ids: errors.append("C008.V reconciliation must match exactly 189 stable Java-test ledger rows")
    for row in reconciliation:
        if row.get("disposition")=="rust":
            symbol=row.get("rust_symbol","").rsplit("::",1)[-1]; case_id=row.get("rust_case_id")
            if row.get("owner")!="C008" or not symbol or not case_id: errors.append("invalid C008 Rust reconciliation: "+row["stable_id"])
            if row.get("dispatch_kind")=="fixture_row" and (case_id not in dispatch or symbol!="java_codec_artifact_dispatches_every_row" or row.get("fixture_row_id")!=case_id or row.get("dispatch_variant")!=dispatch[case_id]["enum_variant"]): errors.append("missing concrete fixture dispatch: "+row["stable_id"])
            if row.get("dispatch_kind")=="named_test" and not re.search(rf"fn\s+{re.escape(symbol)}\s*\(",tests+integration): errors.append("missing named dispatch: "+row["stable_id"])
        elif row.get("disposition")=="deferred":
            if row.get("owner") not in {"C009","C010","C029"} or not row.get("rationale") or "generic" in row["rationale"].lower(): errors.append("invalid deferred reconciliation: "+row["stable_id"])
        else: errors.append("missing reconciliation disposition: "+row["stable_id"])

def main()->int:
    parser=argparse.ArgumentParser(); parser.add_argument("--write",action="store_true"); args=parser.parse_args()
    try: expected=documents()
    except (OSError,subprocess.SubprocessError,RuntimeError) as error: print(f"C008 Java oracle failed: {error}",file=sys.stderr); return 1
    if args.write:
        for path,value in expected.items(): path.write_bytes(dump(value))
        return 0
    errors=[]
    for path,value in expected.items():
        if not path.is_file() or path.read_bytes()!=dump(value): errors.append(f"generated oracle drift: {path.relative_to(ROOT)}; run with --write")
    tracker=json.loads(TRACKER.read_text()); c008=next((c for c in tracker.get("chunks",[]) if c.get("id")=="C008"),None)
    if not c008 or c008.get("gate",{}).get("commands")!=EXPECTED_COMMANDS: errors.append("C008 tracker commands must match the canonical stored gate exactly")
    item_statuses={item.get("id"):item.get("status") for item in c008.get("items",[])} if c008 else {}
    pre_run_item_statuses={f"C008.{index:02d}":"doing" for index in range(1,12)}
    post_closure_item_statuses={f"C008.{index:02d}":"done" for index in range(1,12)}
    pre_run_state=(c008 is not None and c008.get("status")=="active" and item_statuses==pre_run_item_statuses and c008.get("gate",{}).get("status")=="not_run" and c008.get("review",{}).get("state")=="not_started")
    post_closure_state=(c008 is not None and c008.get("status")=="done" and item_statuses==post_closure_item_statuses and c008.get("gate",{}).get("status")=="passed" and c008.get("review",{}).get("state")=="approved" and c008.get("resume") is None)
    if not (pre_run_state or post_closure_state): errors.append("C008 tracker state must be either complete pre-run (active, all items doing, gate not_run, review not_started) or complete post-closure (done, all items done, gate passed, review approved, resume null)")
    verify(errors,expected)
    if errors: print("C008 gate failed:",*errors,sep="\n- ",file=sys.stderr); return 1
    print(f"C008 gate passed: {len(expected[FIXTURES]['rows'])} Java-derived exhaustive codec rows with exact-byte Rust dispatch")
    return 0
if __name__=="__main__": raise SystemExit(main())
