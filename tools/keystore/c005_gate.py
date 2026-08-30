#!/usr/bin/env python3
"""C005 provenance, deterministic Java oracle, fixture, seam and Rust-dispatch gate."""
from __future__ import annotations
import hashlib, json, re, subprocess, sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
SOURCE=ROOT/"docs/oracles/c005-keystore-source-manifest.v1.json"
FIXTURE=ROOT/"docs/oracles/c005-keystore-fixture-manifest.v1.json"
FILESYSTEM=ROOT/"docs/oracles/c005-keystore-filesystem-fixtures.v1.json"
RUST_TEST=ROOT/"rust-tron/crates/tron-crypto/tests/c005_vectors.rs"
KEYSTORE=ROOT/"rust-tron/crates/tron-crypto/src/keystore.rs"
STORE=ROOT/"rust-tron/crates/tron-crypto/src/keystore_store.rs"
ORACLE=ROOT/"tools/keystore/c005_oracle.py"
TRACKER=ROOT/"docs/PORTING_TRACKER.json"
EXPECTED_COMMANDS=[
    {"name":"C005 Java oracle","cwd":".","argv":["python3","tools/keystore/c005_oracle.py"],"timeout_seconds":300},
    {"name":"C005 provenance and vector gate","cwd":".","argv":["python3","tools/keystore/c005_gate.py"],"timeout_seconds":300},
    {"name":"C005 exhaustive keystore dispatch tests","cwd":"rust-tron","argv":["cargo","test","-p","tron-crypto","--test","c005_vectors","--locked"],"timeout_seconds":300},
    {"name":"Rust workspace all-targets check","cwd":"rust-tron","argv":["cargo","check","--workspace","--all-targets","--locked"],"timeout_seconds":300},
]
REVISION="4a21592f95e37908b21bc3f611c6e7a1a67f09f3"
SEAMS={("C027","toolkit/CLI rendering and command inventory"),("C003","node lifecycle and KeystoreFactory composition"),("C025","operational logging, metrics and failure propagation")}
PREFIXES={"C005.CROSS.SCRYPT.","C005.CROSS.PBKDF2.","C005.ERROR.","C005.PASSWORD.","C005.NEW.","C005.IMPORT.","C005.LIST.","C005.DIRECT.","C005.UPDATE.","C005.WRITE.","C005.WINDOWS."}
FILESYSTEM_DISPATCH={
    "C005.NEW.INJECTED":"fs_new_injected()",
    "C005.IMPORT.DUPLICATE":"fs_import_duplicate()",
    "C005.IMPORT.OVERWRITE":"fs_import_overwrite()",
    "C005.LIST.CORRUPT":'fs_list_invalid(b"{")',
    "C005.LIST.BOM":'fs_list_invalid(format!("\\u{feff}{}", sample_wallet().to_json().unwrap()).as_bytes())',
    "C005.LIST.MULTILINE":"fs_list_multiline()",
    "C005.LIST.SYMLINK":"fs_list_symlink()",
    "C005.LIST.PERMISSIONS":"fs_list_permissions()",
    "C005.LIST.OWNERSHIP":"fs_list_ownership()",
    "C005.DIRECT.SYMLINK":"fs_direct_symlink()",
    "C005.DIRECT.UNQUOTED":"fs_direct_unquoted()",
    "C005.DIRECT.CORRUPT":"fs_direct_corrupt()",
    "C005.UPDATE.PASSWORD":"fs_update_password()",
    "C005.UPDATE.WRONG_PASSWORD":"fs_update_wrong_password()",
    "C005.UPDATE.DUPLICATE":"fs_update_duplicate()",
    "C005.UPDATE.SYMLINK_SWAP":"fs_update_inode_swap()",
    "C005.WRITE.CLEANUP":"fs_write_cleanup()",
    "C005.WRITE.MODE":"fs_write_mode()",
    "C005.WINDOWS.LIMIT":"fs_windows_decision()",
}
CROSS_OPEN_IDS={
    "C005.CROSS.SCRYPT.EC",
    "C005.CROSS.SCRYPT.SM2",
    "C005.CROSS.PBKDF2.EC",
    "C005.CROSS.PBKDF2.SM2",
    "C005.CROSS.PBKDF2.MISSING_DKLEN.EC",
}
SCHEMA_ERROR_IDS={
    "C005.ERROR.WRONG_PASSWORD",
    "C005.ERROR.VERSION",
    "C005.ERROR.VERSION_INT_OVERFLOW",
    "C005.ERROR.MISSING_CRYPTO",
    "C005.ERROR.CIPHER",
    "C005.ERROR.KDF",
    "C005.ERROR.PRF",
}
BEHAVIOR_MARKERS={
    "C005.IMPORT.OVERWRITE":("StoreError::TargetExists", "StoreError::DuplicateAddress", "false, true", "true, false"),
    "C005.LIST.MULTILINE":("serde_json::to_string_pretty", "report.keystores.len()", "report.warnings.is_empty()"),
    "C005.DIRECT.UNQUOTED":("load_keystore_direct", "list_keystores", "StoreWarning::SkippedInvalidJson"),
}
def digest(path:Path)->str:return hashlib.sha256(path.read_bytes()).hexdigest()
def load(path:Path,errors:list[str])->dict:
    try:value=json.loads(path.read_text())
    except Exception as error:errors.append(f"{path.relative_to(ROOT)}: {error}");return {}
    if not isinstance(value,dict) or value.get("schema_version")!=1:errors.append(f"{path.relative_to(ROOT)} must be schema_version 1")
    return value
def main()->int:
    errors=[];source=load(SOURCE,errors);fixture=load(FIXTURE,errors);filesystem=load(FILESYSTEM,errors)
    expected_failure_stages={"serialization","write","file_fsync","rename","directory_fsync"}
    expected_failure_semantics={"pre_publication":["serialization","write","file_fsync","rename"],"post_publication":["directory_fsync"],"rollback":"any post-publication failure restores the original destination from the retained-directory backup before releasing the lock"}
    if filesystem.get("status")!="passed":errors.append("filesystem policy artifact status must be passed")
    if set(filesystem.get("atomic_write_failure_stages",[]))!=expected_failure_stages:errors.append("filesystem policy artifact must cover every atomic-write failure stage")
    if filesystem.get("atomic_write_failure_semantics")!=expected_failure_semantics:errors.append("filesystem policy artifact must classify pre-publication stages separately from post-publication directory_fsync")
    try:tracker=json.loads(TRACKER.read_text())
    except Exception as error:errors.append(f"{TRACKER.relative_to(ROOT)}: {error}");tracker={}
    chunks=tracker.get("chunks",[]) if isinstance(tracker,dict) and tracker.get("schema_version")==2 else []
    c005=next((chunk for chunk in chunks if isinstance(chunk,dict) and chunk.get("id")=="C005"),None)
    if c005 is None:errors.append("tracker must contain schema-version-2 C005")
    elif c005.get("gate",{}).get("commands")!=EXPECTED_COMMANDS:errors.append("C005 tracker gate commands must match the canonical command objects exactly")
    if source.get("java_revision")!=REVISION:errors.append("source manifest revision drift")
    try:
        actual=subprocess.check_output(["git","-C",str(ROOT/"java-tron"),"rev-parse","HEAD"],text=True).strip()
        if actual!=REVISION:errors.append(f"java-tron gitlink drift: {actual}")
    except Exception as error:errors.append(f"cannot authenticate java-tron revision: {error}")
    paths=set()
    for row in source.get("whitelist",[]):
        if not isinstance(row,dict) or set(row)!={"path","sha256","covers"} or not row.get("covers"):errors.append(f"invalid whitelist row: {row!r}");continue
        path_text=row["path"]
        if path_text in paths:errors.append(f"duplicate whitelist path: {path_text}")
        paths.add(path_text);path=ROOT/path_text
        if not path.is_file() or digest(path)!=row["sha256"]:errors.append(f"pinned Java source missing or drifted: {path_text}")
    seams={(r.get("owner"),r.get("domain")) for r in source.get("scope_seams",[]) if isinstance(r,dict) and r.get("status")=="excluded" and r.get("reason")}
    if seams!=SEAMS:errors.append(f"scope seams must be exactly {sorted(SEAMS)}")
    oracle=subprocess.run([sys.executable,str(ORACLE)],cwd=ROOT,text=True,capture_output=True)
    if oracle.returncode:errors.append((oracle.stderr or oracle.stdout).strip() or "C005 Java oracle failed")
    vectors=fixture.get("vectors",[]);dispatch=fixture.get("rust_dispatch",{});ids=[v.get("id") for v in vectors if isinstance(v,dict)]
    if len(ids)!=37 or len(ids)!=len(vectors) or len(ids)!=len(set(ids)) or set(ids)!=set(dispatch):errors.append("exactly 37 unique Java vectors must each have one Rust dispatch")
    for prefix in PREFIXES:
        if not any(isinstance(i,str) and i.startswith(prefix) for i in ids):errors.append(f"missing vector family {prefix}")
    payload=json.dumps(vectors,sort_keys=True,separators=(",",":")).encode()
    if fixture.get("vectors_sha256")!=hashlib.sha256(payload).hexdigest():errors.append("vector payload digest drift")
    fixture_text=json.dumps(fixture,sort_keys=True).lower()
    if any(marker in fixture_text for marker in ("placeholder","see_c005","not_run","todo")):errors.append("C005 fixture must not contain placeholder results")
    for row in vectors:
        if not isinstance(row,dict):continue
        if row.get("kind")=="cross_open" and (row.get("direction") not in {"rust_deterministic_create_to_java_open","pbkdf2_missing_dklen_java_and_rust_open"} or not row.get("java_api")):errors.append(f"{row.get('id')} must record actual Java open execution")
        if row.get("id")=="C005.CROSS.PBKDF2.MISSING_DKLEN.EC" and (row.get("java_default_dklen")!=0 or '"dklen"' in row.get("wallet_json","")):errors.append("missing-dklen PBKDF2 vector must authenticate Java's zero default without serializing dklen")
        if row.get("kind")=="filesystem" and row.get("oracle_basis") not in {"java_execution","rust_security_strengthening"}:errors.append(f"{row.get('id')} must label Java execution or Rust security strengthening")
    policy_ids={row.get("id") for row in filesystem.get("fixtures",[]) if isinstance(row,dict)}
    dispatched_filesystem_ids={i for i in ids if isinstance(i,str) and dispatch.get(i)=="filesystem_and_atomic_vectors"}
    security_regression_ids={"C005.PASSWORD.FIFO","C005.UPDATE.PASSWORD_FIFO","C005.WRITE.SYMLINKED_PARENT","C005.WRITE.FIFO_PARENT","C005.WRITE.PARENT_SWAP","C005.DIRECT.PARENT_SYMLINK","C005.DIRECT.INSECURE_DIRECTORY"}
    if policy_ids!=dispatched_filesystem_ids|security_regression_ids:errors.append("filesystem policy artifact must contain dispatched cases plus directory-boundary regressions")
    text=RUST_TEST.read_text() if RUST_TEST.is_file() else "";functions=set(re.findall(r"(?m)^fn ([a-z0-9_]+)\([^\n]*\)\s*\{",text))
    for vector_id,target in dispatch.items():
        if target not in functions:errors.append(f"{vector_id} dispatches to missing Rust test {target!r}")
    if "c005-keystore-fixture-manifest.v1.json" not in text or "rust_dispatch" not in text:errors.append("Rust C005 test must consume fixture and dispatch every vector")
    dispatch_body=re.search(r"fn filesystem_and_atomic_vectors\(\)\s*\{(?P<body>.*?)\n\}",text,re.S)
    actual_dispatch={key:value.strip() for key,value in re.findall(r'"(C005\.[A-Z0-9_.]+)"\s*=>\s*(.*?),\s*$',dispatch_body.group("body") if dispatch_body else "",re.M)}
    if actual_dispatch!=FILESYSTEM_DISPATCH:errors.append("filesystem Rust dispatch arms must match every C005 ID's specific assertion call exactly")
    cross_body=re.search(r"fn java_rust_cross_open_vectors\(\)\s*\{(?P<body>.*?)\n\}",text,re.S)
    cross_dispatch=set(re.findall(r'"(C005\.CROSS\.[A-Z0-9_.]+)"\s*=>',cross_body.group("body") if cross_body else ""))
    if cross_dispatch!=CROSS_OPEN_IDS:errors.append("cross-open Rust dispatch arms must exhaust every C005 cross vector exactly")
    schema_body=re.search(r"fn schema_and_decrypt_error_vectors\(\)\s*\{(?P<body>.*?)\n\}",text,re.S)
    schema_dispatch=set(re.findall(r'"(C005\.ERROR\.[A-Z0-9_]+)"\s*=>',schema_body.group("body") if schema_body else ""))
    if schema_dispatch!=SCHEMA_ERROR_IDS:errors.append("schema/decrypt Rust dispatch arms must exhaust every C005 error vector exactly")
    overflow_helper=re.search(r"fn version_integer_overflow\([^\n]*\)[^\n]*\{(?P<body>.*?)(?=\n#\[test\])",text,re.S)
    overflow_text=overflow_helper.group("body") if overflow_helper else ""
    for marker in ("WalletFile::parse_strict", "WalletFile::parse(json)", "KeystoreError::Json", "4294967299"):
        if marker not in overflow_text:errors.append(f"C005.ERROR.VERSION_INT_OVERFLOW lacks Rust assertion marker {marker!r}")
    keystore_text=KEYSTORE.read_text() if KEYSTORE.is_file() else ""
    pbkdf2_params=re.search(r"pub struct Pbkdf2KdfParams\s*\{(?P<body>.*?)\n\}",keystore_text,re.S)
    if not pbkdf2_params or "#[serde(default)]\n    pub dklen: i64" not in pbkdf2_params.group("body"):errors.append("PBKDF2 dklen must deserialize to zero when absent")
    derive_pbkdf2_body=re.search(r"fn derive_pbkdf2\([^\n]*\)\s*->[^\{]*\{(?P<body>.*?)\n\}",keystore_text,re.S)
    derived_text=derive_pbkdf2_body.group("body") if derive_pbkdf2_body else ""
    if "params.dklen" in derived_text or "vec![0u8; 32]" not in derived_text:errors.append("PBKDF2 derivation must ignore dklen and always derive 32 bytes")
    password_reader=re.search(r"fn read_bounded_nofollow\([^\n]*\)[^\{]*\{(?P<body>.*?)(?=\n\})",keystore_text,re.S)
    password_reader_text=password_reader.group("body") if password_reader else ""
    for marker in ("libc::O_NOFOLLOW | libc::O_NONBLOCK", "file.metadata()", "PasswordFileError::NotRegularFile", "file.take((MAX_PASSWORD_FILE_BYTES + 1) as u64)"):
        if marker not in password_reader_text:errors.append(f"password-file reader lacks FIFO-safe marker {marker!r}")
    metadata_index=password_reader_text.find("file.metadata()")
    read_index=password_reader_text.find("file.take((MAX_PASSWORD_FILE_BYTES + 1) as u64)")
    if metadata_index < 0 or read_index < 0 or metadata_index > read_index:errors.append("password-file reader must fstat and reject non-regular descriptors before bounded reading")
    password_fifo=re.search(r"fn password_file_fifo_regressions\(\)\s*\{(?P<body>.*?)\n\}",text,re.S)
    password_fifo_text=password_fifo.group("body") if password_fifo else ""
    for marker in ("Command::new(\"mkfifo\")", "read_password_file", "read_update_password_file", "recv_timeout(Duration::from_secs(1))", "PasswordFileError::NotRegularFile"):
        if marker not in password_fifo_text:errors.append(f"password FIFO regression lacks assertion marker {marker!r}")
    cleanup_body=re.search(r"fn fs_write_cleanup\(\)\s*\{(?P<body>.*?)\n\}",text,re.S)
    cleanup_text=cleanup_body.group("body") if cleanup_body else ""
    for stage in ("Serialization","Write","FileFsync","Rename","DirectoryFsync"):
        if f"AtomicWriteStage::{stage}" not in cleanup_text:errors.append(f"C005.WRITE.CLEANUP must dispatch {stage} failure coverage")
    for marker in ("pre_publication_stages", "fs::read(&destination).unwrap(), original", "StoreError::AtomicWriteFailure(AtomicWriteStage::DirectoryFsync)", ".keystore-0000000000000000.tmp", ".keystore-0000000000000000.backup", "fs_insecure_directory()", "fs_direct_parent_symlink()"):
        if marker not in cleanup_text:errors.append(f"C005.WRITE.CLEANUP lacks lifecycle assertion marker {marker!r}")
    store_text=STORE.read_text() if STORE.is_file() else ""
    forbidden_path_publication=("fs::rename(&temp, destination)", "publish_no_replace(&temp, destination)", "sync_directory(parent)")
    if any(marker in store_text for marker in forbidden_path_publication):errors.append("sensitive publication must not use pathname rename or pathname directory fsync")
    for marker in ("rustix::fs::flock", "FlockOperation::LockExclusive", "check_directory_security", "InsecureDirectory", "rustix::fs::Dir::read_from", "readlinkat(&parent.file", "AnchoredDirectory::open(parent_path, true)", "let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC", "openat(&parent.file, &temp_name", "pre_publish_hook();", "renameat(&parent.file", "renameat_with(&parent.file", "linkat(&parent.file", "backup_name", "parent.file.sync_all()", "ParentSymlink", "ParentNotDirectory", "ParentChanged", "UnsupportedPlatform"):
        if marker not in store_text:errors.append(f"descriptor-locked keystore store lacks {marker!r}")
    for helper,markers in {
        "fs_write_symlinked_parent":("StoreError::ParentSymlink", "wallet.json", ".keystore-0000000000000000.tmp"),
        "fs_write_fifo_parent":("Command::new(\"mkfifo\")", "recv_timeout(Duration::from_secs(1))", "StoreError::ParentNotDirectory", "wallet.json", ".keystore-0000000000000000.tmp"),
        "fs_write_parent_swap":("atomic_write_wallet_with_hook", "StoreError::ParentChanged", "fs::read(displaced.join(\"wallet.json\"))", ".keystore-0000000000000000.backup"),
        "fs_insecure_directory":("StoreError::InsecureDirectory", "0o770"),
        "fs_direct_parent_symlink":("load_keystore_direct", "StoreError::ParentSymlink"),
    }.items():
        body=re.search(rf"fn {helper}\(\)\s*\{{(?P<body>.*?)\n\}}",text,re.S)
        if not body:errors.append(f"missing directory-boundary regression {helper}");continue
        for marker in markers:
            if marker not in body.group("body"):errors.append(f"{helper} lacks assertion marker {marker!r}")
    for vector_id,call in FILESYSTEM_DISPATCH.items():
        helper=call.split("(",1)[0]
        start=re.search(rf"(?m)^(?:#\[cfg\([^\n]+\)\]\s*)?fn {re.escape(helper)}\([^\n]*\)\s*\{{",text)
        if not start:errors.append(f"{vector_id} assertion helper {helper!r} is missing");continue
        end=re.search(r"(?m)^(?:#\[cfg\([^\n]+\)\]\s*)?fn [a-z0-9_]+\(|^struct [A-Za-z0-9_]+",text[start.end():])
        body=text[start.end():start.end()+(end.start() if end else len(text))]
        if "assert" not in body:errors.append(f"{vector_id} helper {helper!r} has no behavioral assertion")
        for marker in BEHAVIOR_MARKERS.get(vector_id,()):
            if marker not in body:errors.append(f"{vector_id} helper {helper!r} lacks required behavior marker {marker!r}")
    adapter=(ROOT/"tools/keystore/C005Oracle.java").read_text()
    runner=ORACLE.read_text()
    for api in ("Wallet.createLight", "WalletUtils.writeWalletFile", "WalletUtils.loadCredentials", "Credentials.create", "Wallet.decrypt", "WalletUtils.stripPasswordLine", "WalletUtils.passwordValid"):
        if api not in adapter:errors.append(f"Java adapter must call actual {api} API")
    for marker in ("versionIntegerOverflow()", "4294967299", "out of range of int", "WalletFile.setVersion(int)"):
        if marker not in adapter:errors.append(f"Java adapter must authenticate overflow binding marker {marker!r}")
    if ":crypto:classes" not in runner or "c005RuntimeClasspath" not in runner or "GRADLE_VERSION" not in runner or "JAVA_HOME" not in runner:errors.append("Java oracle must build pinned :crypto classes and runtime classpath")
    if errors:
        for error in errors:print(f"C005 gate: {error}",file=sys.stderr)
        return 1
    print(f"C005 gate passed: {len(paths)} pinned Java sources, {len(vectors)} vectors, {len(set(dispatch.values()))} Rust dispatches, exact C003/C025/C027 seams")
    return 0
if __name__=="__main__":raise SystemExit(main())
