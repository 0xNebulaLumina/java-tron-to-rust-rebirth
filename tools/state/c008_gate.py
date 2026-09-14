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
C008_TEST_IDENTITY_SHA256 = "0db78910ec46d6d66e718c915b3188833e8942d097d6de7a3478f0ea5cfe580b"
C008_OWNERSHIP_TRANSITIONS_SHA256 = "f62bfce68df6ba34b83f0014d8896b040dd9be2bd7fa08baae08e8091d69cf7a"

TEST = "rust-tron/crates/tron-state/tests/logical_contract.rs"
INTEGRATION_TEST = "rust-tron/crates/tron-state/tests/integration_contract.rs"
JAVA = ROOT / "tools/state/C008Oracle.java"
EXPECTED_COMMANDS = [
 {"name":"C008 inventory, fixtures, reconciliation and workspace gate","cwd":".","argv":["python3","tools/state/c008_gate.py"],"timeout_seconds":300},
 {"name":"C008 logical store, capsule, key and value fixtures","cwd":"rust-tron","argv":["cargo","test","-p","tron-state","--test","logical_contract","--locked"],"timeout_seconds":300},
 {"name":"C008 atomic, reopen, crash, market and account-asset integration","cwd":"rust-tron","argv":["cargo","test","-p","tron-state","--test","integration_contract","--locked"],"timeout_seconds":300},
 {"name":"C008 state workspace check","cwd":"rust-tron","argv":["cargo","check","-p","tron-state","--all-targets","--locked"],"timeout_seconds":300},
]
C008_TEST_SOURCES = {
    "java-tron/framework/src/test/java/org/tron/core/capsule/AccountCapsuleTest.java",
    "java-tron/framework/src/test/java/org/tron/core/capsule/BlockCapsuleTest.java",
    "java-tron/framework/src/test/java/org/tron/core/capsule/ContractStateCapsuleTest.java",
    "java-tron/framework/src/test/java/org/tron/core/capsule/ExchangeCapsuleTest.java",
    "java-tron/framework/src/test/java/org/tron/core/capsule/TransactionCapsuleTest.java",
    "java-tron/framework/src/test/java/org/tron/core/capsule/VotesCapsuleTest.java",
    "java-tron/framework/src/test/java/org/tron/core/capsule/utils/AssetUtilTest.java",
    "java-tron/framework/src/test/java/org/tron/core/capsule/utils/DecodeResultTest.java",
    "java-tron/framework/src/test/java/org/tron/core/capsule/utils/ExchangeProcessorTest.java",
    "java-tron/framework/src/test/java/org/tron/core/capsule/utils/MerkleTreeTest.java",
    "java-tron/framework/src/test/java/org/tron/core/capsule/utils/RLPListTest.java",
    "java-tron/framework/src/test/java/org/tron/core/db/AbiStoreTest.java",
    "java-tron/framework/src/test/java/org/tron/core/db/AccountAssetStoreTest.java",
    "java-tron/framework/src/test/java/org/tron/core/db/AccountIdIndexStoreTest.java",
    "java-tron/framework/src/test/java/org/tron/core/db/AccountIndexStoreTest.java",
    "java-tron/framework/src/test/java/org/tron/core/db/AccountStoreTest.java",
    "java-tron/framework/src/test/java/org/tron/core/db/AccountTraceStoreTest.java",
    "java-tron/framework/src/test/java/org/tron/core/db/AssetIssueStoreTest.java",
    "java-tron/framework/src/test/java/org/tron/core/db/AssetIssueV2StoreTest.java",
    "java-tron/framework/src/test/java/org/tron/core/db/BalanceTraceStoreTest.java",
    "java-tron/framework/src/test/java/org/tron/core/db/BlockFilledSlotsTest.java",
    "java-tron/framework/src/test/java/org/tron/core/db/BlockIndexStoreTest.java",
    "java-tron/framework/src/test/java/org/tron/core/db/BlockStoreTest.java",
    "java-tron/framework/src/test/java/org/tron/core/db/CodeStoreTest.java",
    "java-tron/framework/src/test/java/org/tron/core/db/ContractStoreTest.java",
    "java-tron/framework/src/test/java/org/tron/core/db/DelegatedResourceAccountIndexStoreTest.java",
    "java-tron/framework/src/test/java/org/tron/core/db/DelegatedResourceStoreTest.java",
    "java-tron/framework/src/test/java/org/tron/core/db/DelegationStoreTest.java",
    "java-tron/framework/src/test/java/org/tron/core/db/ExchangeStoreTest.java",
    "java-tron/framework/src/test/java/org/tron/core/db/ExchangeV2StoreTest.java",
    "java-tron/framework/src/test/java/org/tron/core/db/IncrementalMerkleTreeStoreTest.java",
    "java-tron/framework/src/test/java/org/tron/core/db/MarketAccountStoreTest.java",
    "java-tron/framework/src/test/java/org/tron/core/db/MarketOrderStoreTest.java",
    "java-tron/framework/src/test/java/org/tron/core/db/MarketPairPriceToOrderStoreTest.java",
    "java-tron/framework/src/test/java/org/tron/core/db/MarketPairToPriceStoreTest.java",
    "java-tron/framework/src/test/java/org/tron/core/db/NullifierStoreTest.java",
    "java-tron/framework/src/test/java/org/tron/core/db/ProposalStoreTest.java",
    "java-tron/framework/src/test/java/org/tron/core/db/RecentBlockStoreTest.java",
    "java-tron/framework/src/test/java/org/tron/core/db/RecentTransactionStoreTest.java",
    "java-tron/framework/src/test/java/org/tron/core/db/TransactionHistoryTest.java",
    "java-tron/framework/src/test/java/org/tron/core/db/TransactionRetStoreTest.java",
    "java-tron/framework/src/test/java/org/tron/core/db/TransactionStoreTest.java",
    "java-tron/framework/src/test/java/org/tron/core/db/TreeBlockIndexStoreTest.java",
    "java-tron/framework/src/test/java/org/tron/core/db/VotesStoreTest.java",
    "java-tron/framework/src/test/java/org/tron/core/db/WitnessScheduleStoreTest.java",
    "java-tron/framework/src/test/java/org/tron/core/db/WitnessStoreTest.java",
    "java-tron/framework/src/test/java/org/tron/core/db/ZKProofStoreTest.java",
    "java-tron/framework/src/test/java/org/tron/core/db/api/AssetUpdateHelperTest.java",
    "java-tron/framework/src/test/java/org/tron/core/db/api/pojo/PojoTest.java",
}

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
def canonical_sha256(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()

def test_identity_rows(rows: list[dict]) -> list[list[object]]:
    return [[row["id"], row["source"]["path"], row["source"]["line"], row["case"]] for row in rows]

def ownership_transition_rows(rows: list[dict]) -> list[list[object]]:
    return [[row["stable_id"], row["disposition"], row["owner"], row.get("final_owner"), row.get("destination_artifact"), row.get("destination_selector")] for row in rows]

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

def c008_ledger_rows() -> list[dict]:
    ownership=json.loads(OWNERSHIP.read_text())
    identity=ownership.get("java_reference_identity",{})
    if ownership.get("java_source_revision")!=REVISION or identity.get("java_revision")!=REVISION:
        raise RuntimeError("C008 Java-test ownership ledger revision drift")
    rows=[row for row in ownership["rows"] if row.get("acceptance_gate")=="C008.V" and row["source"]["path"] in C008_TEST_SOURCES]
    paths={row["source"]["path"] for row in rows}
    if len(rows)!=189 or len({row["id"] for row in rows})!=189 or paths!=C008_TEST_SOURCES:
        raise RuntimeError(f"C008 immutable Java-test inventory drift: rows={len(rows)} missing_sources={sorted(C008_TEST_SOURCES-paths)} extra_sources={sorted(paths-C008_TEST_SOURCES)}")
    if canonical_sha256(test_identity_rows(rows)) != C008_TEST_IDENTITY_SHA256:
        raise RuntimeError("C008 pinned ordered stable-ID/source identity digest drift")
    return rows

def c008_source_inventory(rows: list[dict]) -> dict:
    return {"row_count":len(rows),"sources":[{"path":path,"sha256":sha(ROOT/path),"case_count":sum(row["source"]["path"]==path for row in rows)} for path in sorted(C008_TEST_SOURCES)]}

def reconcile_java_tests(fixture: dict, ledger: list[dict]) -> list[dict]:
    dispatch=fixture["rust_dispatch"]; fixture_rows={row["id"]:row for row in fixture["rows"]}; store_aliases={"ZKProof":"ZkProof"}
    deferred_c010={"ContractStateCapsuleTest","ExchangeCapsuleTest","ExchangeProcessorTest","AssetUtilTest","BalanceTraceStoreTest","BlockFilledSlotsTest","DelegatedResourceAccountIndexStoreTest"}
    deferred_c029={"DecodeResultTest","MerkleTreeTest","RLPListTest","PojoTest","AssetUpdateHelperTest"}
    c010_rows={row["stable_id"]:row for row in json.loads((ORACLES/"c010-ownership-reconciliation.v1.json").read_text())["rows"]}
    rows=[]
    for java in ledger:
        source=java["source"]["path"]; line=java["source"]["line"]; stem=Path(source).stem; case=java["case"]; stable_id=java["id"]
        base={"stable_id":stable_id,"case_id":stable_id,"fixture_selector":stable_id,"source_identity":{"id":stable_id,"path":source,"line":line,"case":case,"kind":java["kind"]},"java_source":source,"java_line":line,"java_case":case}
        if stem in deferred_c010 or (stem=="AccountCapsuleTest" and case!="getDataTest"):
            destination=c010_rows.get(stable_id)
            if destination is None:
                rows.append(base|{"disposition":"non_applicable","owner":"C010","final_owner":"C010","expected_result":f"stable-id={stable_id}; source={source}:{line}::{case}; result=outside C008 logical codec boundary","non_applicable_constraint":{"boundary":"C008 logical key/value codec fixtures only","excluded_behavior":f"{stem}.{case}","reason":"stateful resource, fork, processor, or capsule behavior has no standalone logical-codec invocation"}}); continue
            rust=destination["rust_symbol"]; symbol=rust.rsplit("::",1)[-1]; selector=destination["rust_case_id"]
            rows.append(base|{"disposition":"reassigned","owner":"C010","final_owner":"C010","destination_artifact":"docs/oracles/c010-ownership-reconciliation.v1.json","destination_selector":stable_id,"rust_case_selector":selector,"expected_result":f"stable-id={stable_id}; destination=C010; case={selector}; result=destination Rust contract passes","rust_test":rust,"rust_symbol":rust,"proof_command":f"cargo test -p tron-state --test c010_contract --locked {symbol} -- --exact","canonical_command":f"cargo test -p tron-state --test c010_contract --locked {symbol} -- --exact"}); continue
        if stem in deferred_c029 or (stem=="BlockCapsuleTest" and case!="testGetData") or (stem=="TransactionCapsuleTest" and case in {"slowVerify","fastVerify"}):
            rows.append(base|{"disposition":"non_applicable","owner":"C029","final_owner":"C029","expected_result":f"stable-id={stable_id}; source={source}:{line}::{case}; result=outside C008 logical codec boundary","non_applicable_constraint":{"boundary":"C008 logical key/value codec fixtures only","excluded_behavior":f"{stem}.{case}","reason":"cross-cutting utility, cryptographic, API projection, or regression behavior has no standalone logical-codec invocation"}}); continue
        if stem.startswith("Market") and stem.endswith("StoreTest"):
            symbol="market_codec_returns_errors_and_uses_java_boundary_arithmetic" if stem in {"MarketPairPriceToOrderStoreTest","MarketPairToPriceStoreTest"} else "market_order_account_and_pair_stores_unlink_and_reopen"
            selector=f"{stem}:{case}"; rust=proof_symbol(INTEGRATION_TEST,symbol); command="cargo test -p tron-state --test integration_contract --locked "+symbol+" -- --exact"
            rows.append(base|{"disposition":"rust","owner":"C008","final_owner":"C008","rust_case_selector":selector,"expected_result":f"stable-id={stable_id};case={selector};result=named store contract passes","rust_test":rust,"rust_symbol":rust,"rust_case_id":selector,"proof_command":command,"canonical_command":command,"dispatch_kind":"named_test"}); continue
        if stem=="AccountAssetStoreTest":
            symbol="account_external_assets_persist_and_reopen"; selector=f"{stem}:{case}"; rust=proof_symbol(INTEGRATION_TEST,symbol); command="cargo test -p tron-state --test integration_contract --locked "+symbol+" -- --exact"
            rows.append(base|{"disposition":"rust","owner":"C008","final_owner":"C008","rust_case_selector":selector,"expected_result":f"stable-id={stable_id};case={selector};result=named store contract passes","rust_test":rust,"rust_symbol":rust,"rust_case_id":selector,"proof_command":command,"canonical_command":command,"dispatch_kind":"named_test"}); continue
        fixture_id="store-"+store_aliases.get(stem[:-9],stem[:-9]) if stem.endswith("StoreTest") else ("capsule-"+stem[:-4] if stem.endswith("CapsuleTest") else None)
        if fixture_id in dispatch:
            fixture_row=fixture_rows[fixture_id]; variant=dispatch[fixture_id]["enum_variant"]; rust=proof_symbol(TEST,"java_codec_artifact_dispatches_every_row"); command="cargo test -p tron-state --test logical_contract --locked java_codec_artifact_dispatches_every_row -- --exact"
            result=f"stable-id={stable_id};fixture={fixture_id};dispatch={variant};key={fixture_row.get('key_hex','')};value={fixture_row.get('value_hex',fixture_row.get('unknown_value_hex',''))}"
            rows.append(base|{"disposition":"rust","owner":"C008","final_owner":"C008","rust_case_selector":fixture_id,"expected_result":result,"rust_test":rust,"rust_symbol":rust,"rust_case_id":fixture_id,"proof_command":command,"canonical_command":command,"fixture_row_id":fixture_id,"dispatch_variant":variant,"dispatch_kind":"fixture_row"}); continue
        rows.append(base|{"disposition":"non_applicable","owner":"C029","final_owner":"C029","expected_result":f"stable-id={stable_id}; source={source}:{line}::{case}; result=outside C008 logical codec boundary","non_applicable_constraint":{"boundary":"C008 logical key/value codec fixtures only","excluded_behavior":f"{stem}.{case}","reason":"the Java case has no logical codec fixture row or named C008 store contract"}})
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
    java_test_rows=c008_ledger_rows()
    reconciliation=reconcile_java_tests(fixture,java_test_rows)
    if canonical_sha256(ownership_transition_rows(reconciliation)) != C008_OWNERSHIP_TRANSITIONS_SHA256:
        raise RuntimeError("C008 pinned reviewed ownership-transition digest drift")
    coverage={"schema_version":3,"java_revision":REVISION,"pinned_test_inventory":{"row_count":189,"ordered_identity_sha256":C008_TEST_IDENTITY_SHA256,"ordered_ownership_transitions_sha256":C008_OWNERSHIP_TRANSITIONS_SHA256},"source_inventory":c008_source_inventory(java_test_rows),"java_test_reconciliation":reconciliation,"inventory_rows":[{"id":r["id"],"proof":proof_symbol(TEST,"java_codec_artifact_dispatches_every_row"),"case_id":r["id"],"dispatch_variant":dispatch[r["id"]]["enum_variant"]} for r in rows],"state_cases":[
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
    ledger_rows=c008_ledger_rows()
    ledger_by_id={row["id"]:row for row in ledger_rows}
    stable_ids=[row["stable_id"] for row in reconciliation]
    if len(reconciliation)!=189 or len(set(stable_ids))!=189 or set(stable_ids)!=set(ledger_by_id): errors.append("C008.V reconciliation must preserve exactly the immutable 189-row Java-test inventory")
    if expected[COVERAGE].get("source_inventory")!=c008_source_inventory(ledger_rows): errors.append("C008 Java-test source identity inventory drift")
    pinned=expected[COVERAGE].get("pinned_test_inventory",{})
    if pinned != {"row_count":189,"ordered_identity_sha256":C008_TEST_IDENTITY_SHA256,"ordered_ownership_transitions_sha256":C008_OWNERSHIP_TRANSITIONS_SHA256}: errors.append("C008 pinned Java-test inventory metadata drift")
    if canonical_sha256(test_identity_rows(ledger_rows)) != C008_TEST_IDENTITY_SHA256: errors.append("C008 ordered stable-ID/source identity digest drift")
    if canonical_sha256(ownership_transition_rows(reconciliation)) != C008_OWNERSHIP_TRANSITIONS_SHA256: errors.append("C008 ordered ownership-transition digest drift")
    for row in reconciliation:
        source=ledger_by_id.get(row["stable_id"],{}).get("source",{})
        common_valid=(row.get("case_id")==row["stable_id"] and row.get("fixture_selector")==row["stable_id"] and row.get("final_owner")==row.get("owner") and bool(row.get("expected_result")) and row.get("java_source")==source.get("path") and row.get("java_line")==source.get("line") and row.get("java_case")==ledger_by_id.get(row["stable_id"],{}).get("case") and row.get("source_identity")=={"id":row["stable_id"],"path":source.get("path"),"line":source.get("line"),"case":ledger_by_id.get(row["stable_id"],{}).get("case"),"kind":ledger_by_id.get(row["stable_id"],{}).get("kind")})
        if not common_valid: errors.append("invalid exact C008 reconciliation identity: "+row["stable_id"])
        if row.get("disposition")=="rust":
            symbol=row.get("rust_symbol","").rsplit("::",1)[-1]; case_id=row.get("rust_case_id")
            if row.get("owner")!="C008" or not symbol or not case_id or not row.get("rust_case_selector") or not row.get("rust_test") or not row.get("proof_command") or not row.get("canonical_command"): errors.append("invalid row-specific C008 Rust reconciliation: "+row["stable_id"])
            if row.get("dispatch_kind")=="fixture_row" and (case_id not in dispatch or symbol!="java_codec_artifact_dispatches_every_row" or row.get("fixture_row_id")!=case_id or row.get("rust_case_selector")!=case_id or row.get("dispatch_variant")!=dispatch[case_id]["enum_variant"]): errors.append("missing concrete fixture dispatch: "+row["stable_id"])
            if row.get("dispatch_kind")=="named_test" and (row.get("rust_case_selector")!=case_id or not re.search(rf"fn\s+{re.escape(symbol)}\s*\(",tests+integration)): errors.append("missing named dispatch: "+row["stable_id"])
        elif row.get("disposition")=="reassigned":
            if row.get("owner")!="C010" or row.get("destination_artifact")!="docs/oracles/c010-ownership-reconciliation.v1.json" or row.get("destination_selector")!=row["stable_id"] or not row.get("rust_case_selector") or not row.get("rust_symbol") or not row.get("proof_command"): errors.append("invalid exact C008 reassignment: "+row["stable_id"])
        elif row.get("disposition")=="non_applicable":
            constraint=row.get("non_applicable_constraint",{})
            if row.get("owner") not in {"C010","C029"} or constraint.get("boundary")!="C008 logical key/value codec fixtures only" or not constraint.get("excluded_behavior") or not constraint.get("reason"): errors.append("invalid constrained C008 non-applicable disposition: "+row["stable_id"])
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
