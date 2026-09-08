//! Generated from docs/oracles/c027-command-manifest.v1.json java_help_fixtures.
//! Only the authenticated `<main class>` to `tron-toolkit` normalization is applied.

pub const ROOT_STDOUT: &[u8] = "Usage: tron-toolkit [COMMAND]\nCommands:\n  help      Displays help information about the specified command\n  db        An rich command set that provides high-level operations  for dbs.\n  keystore  Manage keystore files for account keys.\n".as_bytes();
pub const ROOT_STDERR: &[u8] = "".as_bytes();
pub const ROOT_LOGICAL_EXIT: i32 = 0;

pub const DB_STDOUT: &[u8] = "".as_bytes();
pub const DB_STDERR: &[u8] = "".as_bytes();
pub const DB_LOGICAL_EXIT: i32 = 0;

pub const DB_VERSION_STDOUT: &[u8] = "".as_bytes();
pub const DB_VERSION_STDERR: &[u8] = "".as_bytes();
pub const DB_VERSION_LOGICAL_EXIT: i32 = 0;

pub const DB_COPY_STDOUT: &[u8] = "Usage: tron-toolkit db cp [-h] <src> <dest>\nQuick copy leveldb or rocksdb data.\n      <src>    Input path. Default: output-directory/database\n      <dest>   Output path. Default: output-directory-cp/database\n  -h, --help\nExit Codes:\n  0   Successful\n  n   Internal error: exception occurred,please check toolkit.log\n".as_bytes();
pub const DB_COPY_STDERR: &[u8] = "".as_bytes();
pub const DB_COPY_LOGICAL_EXIT: i32 = 0;

pub const DB_MOVE_STDOUT: &[u8] = "Usage: tron-toolkit db mv [-h] [-c=<config>] [-d=<database>]\nMove db to pre-set new path . For example HDD,reduce storage expenses.\n  -c, --config=<config>    config file. Default: config.conf\n  -d, --database-directory=<database>\n                          database directory path. Default: output-directory\n  -h, --help\n".as_bytes();
pub const DB_MOVE_STDERR: &[u8] = "".as_bytes();
pub const DB_MOVE_LOGICAL_EXIT: i32 = 0;

pub const DB_ROOT_STDOUT: &[u8] = "Usage: tron-toolkit db root [-h] [--db=<dbs>]... <db>\ncompute merkle root for tiny db. NOTE: large db may GC overhead limit exceeded.\n      <db>         Input path. Default: output-directory/database\n      --db=<dbs>   db name for show root\n  -h, --help       display a help message\nExit Codes:\n  0   Successful\n  n   query failed,please check toolkit.log\n".as_bytes();
pub const DB_ROOT_STDERR: &[u8] = "".as_bytes();
pub const DB_ROOT_LOGICAL_EXIT: i32 = 0;

pub const DB_ARCHIVE_STDOUT: &[u8] = "Usage: tron-toolkit db archive [-h] [-b=<maxBatchSize>]\n                               [-d=<databaseDirectory>] [-m=<maxManifestSize>]\nA helper to rewrite leveldb manifest.\n  -b, --batch-size=<maxBatchSize>\n               deal manifest batch size. Default: 80000\n  -d, --database-directory=<databaseDirectory>\n               java-tron database directory. Default: output-directory/database\n  -h, --help\n  -m, --manifest-size=<maxManifestSize>\n               manifest min size(M) to archive. Default: 0\n".as_bytes();
pub const DB_ARCHIVE_STDERR: &[u8] = "".as_bytes();
pub const DB_ARCHIVE_LOGICAL_EXIT: i32 = 0;

pub const DB_CONVERT_STDOUT: &[u8] = "Usage: tron-toolkit db convert [-h] <src> <dest>\nCovert leveldb to rocksdb.\n      <src>     Input path for leveldb. Default: output-directory/database\n      <dest>   Output path for rocksdb. Default: output-directory-dst/database\n  -h, --help\nExit Codes:\n  0   Successful\n  n   Internal error: exception occurred,please check toolkit.log\n".as_bytes();
pub const DB_CONVERT_STDERR: &[u8] = "".as_bytes();
pub const DB_CONVERT_LOGICAL_EXIT: i32 = 0;

pub const LITE_STDOUT: &[u8] = "".as_bytes();
pub const LITE_STDERR: &[u8] = "Missing required options: '--fn-data-path=<fnDataPath>', '--dataset-path=<datasetPath>'\nUsage: tron-toolkit db lite [-h] [--exclude-historical-balance]\n                            -ds=<datasetPath> -fn=<fnDataPath> [-o=<operate>]\n                            [-t=<type>]\nSplit lite data for java-tron.\n      -ds, --dataset-path=<datasetPath>\n                            when operation is `split`,`dataset-path` is the\n                              path that store the `snapshot` or `history`,when\n                              operation is `split`,`dataset-path` is the\n                              `history` data path.\n      --exclude-historical-balance\n                            only used with `operate=split -t snapshot`: when\n                              true, balance-trace and account-trace are\n                              excluded from the lite snapshot. Default: false\n                              (legacy behavior; trace stores stay in the\n                              snapshot). This flag only has a functional impact\n                              when the source full node ran with\n                              `historyBalanceLookup=true` (off by default; most\n                              operators are unaffected). WARNING: when\n                              historyBalanceLookup was enabled, this loss is\n                              permanent: a lite node booted from such a\n                              snapshot cannot safely serve historical balance\n                              lookups (getBlockBalance may fail, and\n                              getAccountBalance may return balance=0 when\n                              account-trace data is missing). Running merge\n                              afterwards will NOT restore the feature. If you\n                              need to keep historyBalanceLookup working on the\n                              resulting lite node, do NOT enable this flag.\n                              `split -t history` and `merge` ignore this flag.\n      -fn, --fn-data-path=<fnDataPath>\n                            the database path to be split or merged.\n  -h, --help\n  -o, --operate=<operate>   operate: [ split, merge ]. Default: split\n  -t, --type=<type>         only used with operate=split: [ snapshot, history\n                              ]. Default: snapshot\nExit Codes:\n  0   Successful\n  1   Internal error: exception occurred,please check toolkit.log\n".as_bytes();
pub const LITE_LOGICAL_EXIT: i32 = 2;

pub const KEYSTORE_STDOUT: &[u8] = "".as_bytes();
pub const KEYSTORE_STDERR: &[u8] = "".as_bytes();
pub const KEYSTORE_LOGICAL_EXIT: i32 = 0;

pub const KEYSTORE_VERSION_STDOUT: &[u8] = "".as_bytes();
pub const KEYSTORE_VERSION_STDERR: &[u8] = "".as_bytes();
pub const KEYSTORE_VERSION_LOGICAL_EXIT: i32 = 0;

pub const KEYSTORE_NEW_STDOUT: &[u8] = "".as_bytes();
pub const KEYSTORE_NEW_STDERR: &[u8] = "".as_bytes();
pub const KEYSTORE_NEW_LOGICAL_EXIT: i32 = 0;

pub const KEYSTORE_IMPORT_STDOUT: &[u8] = "".as_bytes();
pub const KEYSTORE_IMPORT_STDERR: &[u8] = "".as_bytes();
pub const KEYSTORE_IMPORT_LOGICAL_EXIT: i32 = 0;

pub const KEYSTORE_LIST_STDOUT: &[u8] = "".as_bytes();
pub const KEYSTORE_LIST_STDERR: &[u8] = "".as_bytes();
pub const KEYSTORE_LIST_LOGICAL_EXIT: i32 = 0;

pub const KEYSTORE_UPDATE_STDOUT: &[u8] = "".as_bytes();
pub const KEYSTORE_UPDATE_STDERR: &[u8] = "".as_bytes();
pub const KEYSTORE_UPDATE_LOGICAL_EXIT: i32 = 0;
