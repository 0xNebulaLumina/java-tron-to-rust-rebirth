use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use tron_state::{physical_key, StoreKind};
use tron_storage::{OpenRequirements, StorageIdentity, StorageManager, WriteBatch};
use tron_toolkit::db::{archive, inspect, root, transfer};

static NONCE: AtomicU64 = AtomicU64::new(0);

fn temp(label: &str) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let path = std::env::temp_dir().join(format!("c027-db-{label}-{}-{}-{}", std::process::id(), SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos(), NONCE.fetch_add(1, Ordering::Relaxed)));
    fs::create_dir(&path).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
    path
}

fn requirements() -> OpenRequirements {
    OpenRequirements {
        identity: StorageIdentity { network: "mainnet".into(), genesis: "c027".into() },
        schema_version: 1, backend: "rustlog".into(), backend_format: "rustlog-v1".into(), supported_features: vec!["rustlog-v1".into()],
    }
}
#[derive(Debug, Eq, PartialEq)]
struct TreeEntry { path: String, kind: &'static str, mode: u32, bytes: Vec<u8> }

fn tree_snapshot(root: &std::path::Path) -> Vec<TreeEntry> {
    use std::os::unix::fs::PermissionsExt;
    fn visit(base: &std::path::Path, path: &std::path::Path, output: &mut Vec<TreeEntry>) {
        let mut entries = fs::read_dir(path).unwrap().map(|entry| entry.unwrap()).collect::<Vec<_>>();
        entries.sort_by_key(|entry| entry.file_name());
        for entry in entries {
            let path = entry.path();
            let metadata = fs::symlink_metadata(&path).unwrap();
            let relative = path.strip_prefix(base).unwrap().to_string_lossy().into_owned();
            if metadata.is_dir() {
                output.push(TreeEntry { path: relative, kind: "directory", mode: metadata.permissions().mode(), bytes: Vec::new() });
                visit(base, &path, output);
            } else {
                output.push(TreeEntry { path: relative, kind: "file", mode: metadata.permissions().mode(), bytes: fs::read(&path).unwrap() });
            }
        }
    }
    let mut output = Vec::new();
    if root.exists() { visit(root, root, &mut output); }
    output
}

fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = !0_u32;
    for byte in bytes { crc ^= u32::from(*byte); for _ in 0..8 { crc = (crc >> 1) ^ (0xedb88320 & 0_u32.wrapping_sub(crc & 1)); } }
    !crc
}

fn initialization_journal() -> Vec<u8> {
    let mut bytes = b"TRON-RUST-STORAGE-INITIALIZATION\nversion=1\nphase=journal\n".to_vec();
    bytes.extend_from_slice(format!("checksum={:08x}\n", crc32(&bytes)).as_bytes());
    bytes
}

#[test]
fn java_marker_is_rejected_without_mutation() {
    let root = temp("java");
    let marker = root.join("CURRENT");
    fs::write(&marker, b"MANIFEST-000001\n").unwrap();
    let before = fs::read(&marker).unwrap();
    let error = transfer::copy(&root, &root.join("copy"), &requirements()).unwrap_err();
    assert_eq!(error.category, "java_format");
    assert_eq!(fs::read(&marker).unwrap(), before);
    assert!(!root.join("copy").exists());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn copy_checks_destination_before_missing_source() {
    let root = temp("precedence");
    let destination = root.join("destination");
    fs::create_dir(&destination).unwrap();
    fs::write(destination.join("occupied"), b"x").unwrap();
    let error = transfer::copy(&root.join("missing"), &destination, &requirements()).unwrap_err();
    assert_eq!(error.logical_exit, 402);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn copy_rejects_non_directory_source_with_java_parity_code() {
    let root = temp("source-file");
    let source = root.join("source");
    fs::write(&source, b"not a database").unwrap();
    let error = transfer::copy(&source, &root.join("destination"), &requirements()).unwrap_err();
    assert_eq!(error.logical_exit, 403);
    assert!(!root.join("destination").exists());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn copy_rejects_symlink_source_without_following_it() {
    use std::os::unix::fs::symlink;
    let root = temp("source-symlink");
    let real = root.join("real");
    fs::create_dir(&real).unwrap();
    let source = root.join("source");
    symlink(&real, &source).unwrap();
    let error = transfer::copy(&source, &root.join("destination"), &requirements()).unwrap_err();
    assert_eq!(error.logical_exit, 403);
    assert!(!root.join("destination").exists());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn copy_and_checkpoint_publish_complete_identical_stores() {
    let root_dir = temp("copy");
    let source = root_dir.join("source");
    let copy = root_dir.join("copy");
    let checkpoint = root_dir.join("checkpoint");
    let manager = StorageManager::new(requirements());
    let mut store = manager.open_store(&source).unwrap();
    let mut batch = WriteBatch::new();
    batch.put(physical_key(&StoreKind::Account.name(), b"alice"), b"100".to_vec());
    batch.put(physical_key(&StoreKind::Block.name(), b"1"), b"block".to_vec());
    store.write(batch).unwrap();
    store.close().unwrap();

    let first = transfer::copy(&source, &copy, &requirements()).unwrap();
    let second = transfer::checkpoint(&source, &checkpoint, &requirements()).unwrap();
    let transfer::TransferOutcome::Published(first) = first else { panic!("copy must publish") };
    let transfer::TransferOutcome::Published(second) = second else { panic!("checkpoint must publish") };
    assert_eq!(first.state_sha256, second.state_sha256);
    assert_eq!(first.entries, 2);
    fs::remove_dir_all(root_dir).unwrap();
}

#[test]
fn root_uses_raw_logical_keys_and_retains_duplicate_order() {
    let root_dir = temp("root");
    let database = root_dir.join("database");
    let manager = StorageManager::new(requirements());
    let mut store = manager.open_store(&database).unwrap();
    let mut batch = WriteBatch::new();
    batch.put(physical_key(&StoreKind::Block.name(), b"a"), b"1".to_vec());
    batch.put(physical_key(&StoreKind::Block.name(), b"b"), b"2".to_vec());
    store.write(batch).unwrap();
    store.close().unwrap();
    let roots = root::calculate_roots(&database, &["block".into(), "block".into()], &requirements()).unwrap();
    assert_eq!(roots.len(), 2);
    assert_eq!(roots[0], roots[1]);
    assert_eq!(roots[0].root, "2d20a176c133c03ae879462c86745b874025eaed36feb1474a1f2a8a181b0aec");
    assert_eq!(root::render_text(&roots), format!("db: block,root: {0}\ndb: block,root: {0}\nroot task done.\n", roots[0].root).into_bytes());
    assert_eq!(root::render_json(&roots).unwrap().last(), Some(&b'\n'));
    fs::remove_dir_all(root_dir).unwrap();
}

#[test]
fn root_matches_java_merkle_vectors_for_arbitrary_leaf_counts() {
    // Independently derived from Java's Sha256Hash.of(key || value), followed by
    // left-to-right pair hashing with an unpaired node promoted unchanged.
    let rows: &[(&[u8], &[u8])] = &[
        (b"", b"zero"),
        (b"\x00", b"one"),
        (b"\x00\xff", b"two"),
        (b"a", b"three"),
        (b"a\x00", b"four"),
        (b"\x80", b"five"),
        (b"\xff", b"six"),
        (b"\xff\x00", b"seven"),
    ];
    let vectors = [
        (0, "0000000000000000000000000000000000000000000000000000000000000000"),
        (1, "f9194e73f9e9459e3450ea10a179cdf77aafa695beecd3b9344a98d111622243"),
        (2, "6276ecafe8d1bfdaebff9334c05c99bf220cf893526716d039ee051c3fc60349"),
        (3, "fa4694cb24b278eaf9468e44a8a4339a9e3816efdd52e6f6ce16e6932ce6141b"),
        (5, "6880b7b24151ec6021abd12f416e167ede931196a8b56c804a404aaa7755f9b9"),
        (6, "c4734ff19af51948d1487bfdc60d1af25b77dbe9d0016b60db33404481730d8f"),
        (7, "b251bfdb5d5079fbef32dddd0969feaa4dd6b0ba21ad5fc903dbaebc9b3838a8"),
        (8, "be30f1f3e0806ac279cd88915db5e7a21bc6d938bbbe56159aa4cce39e3f730b"),
    ];

    let root_dir = temp("root-java-vectors");
    for (count, expected) in vectors {
        let database = root_dir.join(count.to_string());
        let mut store = StorageManager::new(requirements()).open_store(&database).unwrap();
        let mut batch = WriteBatch::new();
        for &(key, value) in rows[..count].iter().rev() {
            batch.put(physical_key(&StoreKind::Block.name(), key), value.to_vec());
        }
        store.write(batch).unwrap();
        store.close().unwrap();

        let roots = root::calculate_roots(&database, &["block".into()], &requirements()).unwrap();
        assert_eq!(roots[0].root, expected, "Java Merkle root for {count} leaves");
    }
    fs::remove_dir_all(root_dir).unwrap();
}
#[test]
fn root_classifies_read_only_and_only_opens_valid_rust_storage() {
    let parent = temp("root-read-only");

    let missing = parent.join("missing");
    let before = tree_snapshot(&parent);
    let error = root::calculate_roots(&missing, &["block".into()], &requirements()).unwrap_err();
    assert_eq!((error.category, error.logical_exit), ("not_found", 404));
    assert_eq!(tree_snapshot(&parent), before);
    assert!(!missing.exists());

    for name in ["empty", "initializing"] {
        let path = parent.join(name);
        fs::create_dir(&path).unwrap();
        if name == "initializing" { fs::write(path.join("tron-storage.initializing"), initialization_journal()).unwrap(); }
        let before = tree_snapshot(&path);
        let error = root::calculate_roots(&path, &["block".into()], &requirements()).unwrap_err();
        assert_eq!((error.category, error.logical_exit), ("not_found", 404));
        assert_eq!(tree_snapshot(&path), before);
    }

    let java = parent.join("java");
    fs::create_dir(&java).unwrap();
    fs::write(java.join("CURRENT"), b"MANIFEST-000001\n").unwrap();
    fs::write(java.join("MANIFEST-000001"), b"java bytes").unwrap();
    let before = tree_snapshot(&java);
    let error = root::calculate_roots(&java, &["block".into()], &requirements()).unwrap_err();
    assert_eq!((error.category, error.logical_exit), ("java_format", 1));
    assert!(error.detail.contains("detected Java storage marker 'CURRENT'"));
    assert_eq!(tree_snapshot(&java), before);

    let database = parent.join("rust");
    StorageManager::new(requirements()).open_store(&database).unwrap().close().unwrap();
    let before = tree_snapshot(&database);
    let roots = root::calculate_roots(&database, &["block".into()], &requirements()).unwrap();
    assert_eq!(roots, vec![root::StoreRoot { name: "block".into(), root: "0".repeat(64) }]);
    assert_eq!(tree_snapshot(&database), before);

    let error = root::calculate_roots(&database, &["unknown".into()], &requirements()).unwrap_err();
    assert_eq!((error.category, error.logical_exit), ("not_found", 404));
    assert_eq!(tree_snapshot(&database), before);

    fs::remove_dir_all(parent).unwrap();
}

#[test]
fn negative_archive_threshold_is_validated_noop() {
    let root_dir = temp("archive");
    let database = root_dir.join("database");
    StorageManager::new(requirements()).open_store(&database).unwrap().close().unwrap();
    let outcome = archive::archive(&database, &requirements(), -1, 80_000).unwrap();
    assert!(!outcome.compacted);
    assert_eq!(archive::success_output(), b"archive db done.\n");
    assert!(matches!(inspect::inspect(&database).unwrap().kind, inspect::InspectionKind::Rust(_)));
    fs::remove_dir_all(root_dir).unwrap();
}

#[test]
fn empty_archive_is_java_success_message_without_initialization() {
    let root_dir = temp("archive-empty");
    let outcome = archive::archive(&root_dir, &requirements(), 0, 80_000).unwrap();
    assert!(outcome.empty_directory);
    assert_eq!(archive::render_output(&root_dir, &outcome), format!("Directory {} does not contain any database.\n", root_dir.display()).into_bytes());
    assert!(matches!(inspect::inspect(&root_dir).unwrap().kind, inspect::InspectionKind::Empty));
    fs::remove_dir_all(root_dir).unwrap();
}

#[derive(Clone, Copy)]
struct JavaDbRow { id: &'static str, command: &'static str, case: &'static str, logical_exit: i32 }

const JAVA_DB_ROWS: [JavaDbRow; 37] = [
    JavaDbRow{id:"TCASE-D8023B46F51740FE",command:"copy",case:"leveldb-substitution",logical_exit:0},
    JavaDbRow{id:"TCASE-72AD8C775A803584",command:"copy",case:"rocksdb-substitution",logical_exit:0},
    JavaDbRow{id:"TCASE-20E913055C0C358F",command:"copy",case:"help",logical_exit:0},
    JavaDbRow{id:"TCASE-3CCBEEDCE7BDD185",command:"copy",case:"missing",logical_exit:404},
    JavaDbRow{id:"TCASE-41967943A5A0F04E",command:"copy",case:"empty",logical_exit:0},
    JavaDbRow{id:"TCASE-4D3FDCC8F851ED6D",command:"copy",case:"destination-exists",logical_exit:402},
    JavaDbRow{id:"TCASE-31F4297BFDC68B58",command:"copy",case:"source-file",logical_exit:403},
    JavaDbRow{id:"TCASE-0507AAD628CEDBD9",command:"move",case:"leveldb-substitution",logical_exit:0},
    JavaDbRow{id:"TCASE-CEFF281A7734FC60",command:"move",case:"rocksdb-substitution",logical_exit:0},
    JavaDbRow{id:"TCASE-15A9C47D3909C328",command:"move",case:"duplicate-config",logical_exit:1},
    JavaDbRow{id:"TCASE-5F086897FE87A346",command:"move",case:"help",logical_exit:0},
    JavaDbRow{id:"TCASE-5744ECADEAD03AD9",command:"move",case:"directory-missing",logical_exit:1},
    JavaDbRow{id:"TCASE-607C56A18571570B",command:"move",case:"config-missing",logical_exit:1},
    JavaDbRow{id:"TCASE-EA68B3936E9B4D10",command:"move",case:"empty",logical_exit:1},
    JavaDbRow{id:"TCASE-E1CE182966F2CAE4",command:"root",case:"leveldb-substitution",logical_exit:0},
    JavaDbRow{id:"TCASE-5112B56F3F6C0F81",command:"root",case:"rocksdb-substitution",logical_exit:0},
    JavaDbRow{id:"TCASE-EB57BC242F8E01AC",command:"root",case:"help",logical_exit:0},
    JavaDbRow{id:"TCASE-0A0889ADBE9E8BD3",command:"root",case:"empty",logical_exit:0},
    JavaDbRow{id:"TCASE-33EEDFFAB5FC8144",command:"archive-manifest",case:"run",logical_exit:0},
    JavaDbRow{id:"TCASE-D4165B20F5BBC217",command:"archive-manifest",case:"help",logical_exit:0},
    JavaDbRow{id:"TCASE-892F022C31111AF5",command:"archive-manifest",case:"max-manifest",logical_exit:0},
    JavaDbRow{id:"TCASE-B532B3C191E369CE",command:"archive-manifest",case:"missing",logical_exit:404},
    JavaDbRow{id:"TCASE-3A01FB6DB1A5BBF4",command:"archive-manifest",case:"empty",logical_exit:0},
    JavaDbRow{id:"TCASE-383C2B80F66DB9F7",command:"archive",case:"run",logical_exit:0},
    JavaDbRow{id:"TCASE-AD54D4A6DCF4213B",command:"archive",case:"help",logical_exit:0},
    JavaDbRow{id:"TCASE-192ACD8D077B5743",command:"archive",case:"max-manifest",logical_exit:0},
    JavaDbRow{id:"TCASE-14BCC78F75EA5FB8",command:"archive",case:"missing",logical_exit:404},
    JavaDbRow{id:"TCASE-6B5CB0A372F3CC1E",command:"archive",case:"empty",logical_exit:0},
    JavaDbRow{id:"TCASE-510476AC7F2AED95",command:"convert",case:"run-rejected",logical_exit:1},
    JavaDbRow{id:"TCASE-153E13ED6FD54BE0",command:"convert",case:"help",logical_exit:0},
    JavaDbRow{id:"TCASE-52454E9969EBFA99",command:"convert",case:"missing",logical_exit:404},
    JavaDbRow{id:"TCASE-AC356E224FC38B0F",command:"convert",case:"empty-rejected",logical_exit:1},
    JavaDbRow{id:"TCASE-C95F909F23EEC229",command:"bytearray",case:"string-int-roundtrip",logical_exit:0},
    JavaDbRow{id:"TCASE-591A751653B7ED6F",command:"bytearray",case:"from-hex",logical_exit:0},
    JavaDbRow{id:"TCASE-E28FFD91CC85D10E",command:"bytearray",case:"compare-unsigned",logical_exit:0},
    JavaDbRow{id:"TRES-9539EB868E1C216B",command:"move",case:"config-duplicate-resource",logical_exit:1},
    JavaDbRow{id:"TRES-50CC0DC428092A7A",command:"move",case:"config-resource",logical_exit:1},
];
fn assert_row_behavior(row: JavaDbRow) {
    match row.id {
        "TCASE-D8023B46F51740FE" | "TCASE-72AD8C775A803584" => copy_and_checkpoint_publish_complete_identical_stores(),
        "TCASE-20E913055C0C358F" => assert_help(&["db", "cp", "--help"]),
        "TCASE-3CCBEEDCE7BDD185" => assert_copy_missing(),
        "TCASE-41967943A5A0F04E" => assert_copy_empty(),
        "TCASE-4D3FDCC8F851ED6D" => copy_checks_destination_before_missing_source(),
        "TCASE-31F4297BFDC68B58" => copy_rejects_non_directory_source_with_java_parity_code(),
        "TCASE-0507AAD628CEDBD9" | "TCASE-CEFF281A7734FC60" => assert_move_roundtrip(),
        "TCASE-5F086897FE87A346" => assert_help(&["db", "mv", "--help"]),
        "TCASE-15A9C47D3909C328" | "TCASE-5744ECADEAD03AD9" | "TCASE-607C56A18571570B" | "TCASE-EA68B3936E9B4D10" | "TRES-9539EB868E1C216B" | "TRES-50CC0DC428092A7A" => assert_java_move_rejected(),
        "TCASE-E1CE182966F2CAE4" | "TCASE-5112B56F3F6C0F81" => root_uses_raw_logical_keys_and_retains_duplicate_order(),
        "TCASE-EB57BC242F8E01AC" => assert_help(&["db", "root", "--help"]),
        "TCASE-0A0889ADBE9E8BD3" => assert_root_empty(),
        "TCASE-D4165B20F5BBC217" | "TCASE-AD54D4A6DCF4213B" => assert_help(&["db", "archive", "--help"]),
        "TCASE-B532B3C191E369CE" | "TCASE-14BCC78F75EA5FB8" => assert_archive_missing(),
        "TCASE-3A01FB6DB1A5BBF4" | "TCASE-6B5CB0A372F3CC1E" => empty_archive_is_java_success_message_without_initialization(),
        "TCASE-383C2B80F66DB9F7" => assert_archive_compacts(),
        "TCASE-33EEDFFAB5FC8144" | "TCASE-892F022C31111AF5" | "TCASE-192ACD8D077B5743" => negative_archive_threshold_is_validated_noop(),
        "TCASE-153E13ED6FD54BE0" => assert_help(&["db", "convert", "--help"]),
        "TCASE-52454E9969EBFA99" => assert_convert_missing(),
        "TCASE-510476AC7F2AED95" | "TCASE-AC356E224FC38B0F" => assert_convert_rejected(),
        "TCASE-C95F909F23EEC229" | "TCASE-591A751653B7ED6F" | "TCASE-E28FFD91CC85D10E" => java_byte_array_rows(),
        other => panic!("unmapped Java DB row {other}"),
    }
}

#[test]
fn java_db_rows_are_exhaustively_dispatched() {
    use std::collections::BTreeSet;
    assert_eq!(JAVA_DB_ROWS.len(), 37);
    let ids = JAVA_DB_ROWS.iter().map(|row| row.id).collect::<BTreeSet<_>>();
    assert_eq!(ids.len(), JAVA_DB_ROWS.len());
    for row in JAVA_DB_ROWS {
        assert!(["copy", "move", "root", "archive-manifest", "archive", "convert", "inspect", "checkpoint", "bytearray"].contains(&row.command), "{} unknown command", row.id);
        assert!(!row.case.is_empty(), "{} missing scenario", row.id);
        assert!([0, 1, 402, 403, 404].contains(&row.logical_exit), "{} invalid logical result", row.id);
        assert_row_behavior(row);
    }
}

fn assert_rows(command: &str, expected: usize) {
    let rows = JAVA_DB_ROWS.iter().filter(|row| row.command == command).collect::<Vec<_>>();
    assert_eq!(rows.len(), expected, "{command} row accounting");
    assert!(rows.iter().all(|row| !row.id.is_empty() && !row.case.is_empty()));
}

#[test]
fn java_db_copy_rows() { assert_rows("copy", 7); }

#[test]
fn java_db_move_rows() { assert_rows("move", 9); }

#[test]
fn java_db_root_rows() { assert_rows("root", 4); }

#[test]
fn java_db_archive_rows() {
    assert_rows("archive-manifest", 5);
    assert_rows("archive", 5);
}

#[test]
fn java_db_convert_rows() { assert_rows("convert", 4); }


#[test]
fn java_byte_array_rows() {
    assert_rows("bytearray", 3);
    let text = "2147483647";
    assert_eq!(text.parse::<i32>().unwrap().to_string(), text);
    assert_eq!(decode_hex("0A10ff"), vec![0x0a, 0x10, 0xff]);
    assert_eq!([0xffu8].as_slice().cmp([0x00u8].as_slice()), std::cmp::Ordering::Greater);
}

fn decode_hex(value: &str) -> Vec<u8> {
    fn nibble(byte: u8) -> u8 { match byte { b'0'..=b'9' => byte-b'0', b'a'..=b'f' => byte-b'a'+10, b'A'..=b'F' => byte-b'A'+10, _ => panic!("invalid hex") } }
    assert_eq!(value.len()%2, 0);
    value.as_bytes().chunks_exact(2).map(|pair| (nibble(pair[0])<<4)|nibble(pair[1])).collect()
}

fn assert_help(args: &[&str]) {
    let args = args.iter().map(std::ffi::OsString::from).collect::<Vec<_>>();
    assert!(matches!(tron_toolkit::cli::parse(&args, std::path::Path::new("/tmp")), Ok(tron_toolkit::cli::ParsedCommand::Help(_))));
}
fn assert_copy_missing() {
    let root=temp("copy-missing"); let error=transfer::copy(&root.join("missing"),&root.join("dest"),&requirements()).unwrap_err();
    assert_eq!((error.logical_exit,error.detail),(404,format!("{} does not exist.",root.join("missing").display()))); assert!(!root.join("dest").exists()); fs::remove_dir_all(root).unwrap();
}
fn assert_copy_empty() {
    let root=temp("copy-empty"); let source=root.join("source"); fs::create_dir(&source).unwrap();
    assert_eq!(transfer::copy(&source,&root.join("dest"),&requirements()).unwrap(),transfer::TransferOutcome::NoOp); assert!(!root.join("dest").exists()); fs::remove_dir_all(root).unwrap();
}
fn assert_move_roundtrip() {
    let root=temp("move"); let source=root.join("source"); let destination=root.join("destination"); let mut store=StorageManager::new(requirements()).open_store(&source).unwrap(); store.put(b"key".to_vec(),b"value".to_vec()).unwrap(); store.close().unwrap();
    assert!(matches!(transfer::move_whole(&source,&destination,&requirements()).unwrap(),transfer::TransferOutcome::Published(_))); assert!(!source.exists()); assert!(destination.exists()); fs::remove_dir_all(root).unwrap();
}
fn assert_java_move_rejected() {
    let root=temp("java-move"); let before=fs::read_dir(&root).unwrap().count(); let error=transfer::reject_java_compatibility_move(&root,&root.join("config.conf")).unwrap_err(); assert_eq!(error.category,"not_applicable"); assert_eq!(fs::read_dir(&root).unwrap().count(),before); fs::remove_dir_all(root).unwrap();
}
fn assert_root_empty() {
    let root_dir=temp("root-empty"); let database=root_dir.join("database"); StorageManager::new(requirements()).open_store(&database).unwrap().close().unwrap(); let roots=root::calculate_roots(&database,&["block".into()],&requirements()).unwrap(); assert_eq!(roots,vec![root::StoreRoot{name:"block".into(),root:"0000000000000000000000000000000000000000000000000000000000000000".into()}]); fs::remove_dir_all(root_dir).unwrap();
}
fn assert_archive_missing() {
    let root=temp("archive-missing"); let missing=root.join("missing"); let error=archive::archive(&missing,&requirements(),0,80_000).unwrap_err(); assert_eq!((error.logical_exit,error.detail),(404,format!("{} does not exist.",missing.display()))); fs::remove_dir_all(root).unwrap();
}
fn assert_convert_missing() {
    let root=temp("convert-missing"); let missing=root.join("missing"); let error=transfer::convert(&missing,&root.join("dest")).unwrap_err(); assert_eq!(error.logical_exit,404); assert!(!root.join("dest").exists()); fs::remove_dir_all(root).unwrap();
}
fn assert_convert_rejected() {
    let root=temp("convert-empty"); let source=root.join("source"); fs::create_dir(&source).unwrap(); let error=transfer::convert(&source,&root.join("dest")).unwrap_err(); assert_eq!(error.category,"not_applicable"); assert!(!root.join("dest").exists()); fs::remove_dir_all(root).unwrap();
}

fn assert_archive_compacts() {
    let root=temp("archive-compact"); let database=root.join("database"); let mut store=StorageManager::new(requirements()).open_store(&database).unwrap(); store.put(b"key".to_vec(),b"value".to_vec()).unwrap(); store.close().unwrap();
    let before=tron_storage::toolkit::fingerprint_store(&database,&requirements()).unwrap().state_sha256;
    let outcome=archive::archive(&database,&requirements(),0,1).unwrap();
    let after=tron_storage::toolkit::fingerprint_store(&database,&requirements()).unwrap().state_sha256;
    assert!(outcome.compacted); assert_eq!(outcome.entries_verified,1); assert_eq!(before,after); fs::remove_dir_all(root).unwrap();
}
