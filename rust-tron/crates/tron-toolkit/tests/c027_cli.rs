use std::ffi::OsString;
use std::path::Path;
use tron_toolkit::cli::*;

fn parse(words:&[&str])->ParsedCommand{let args=words.iter().map(OsString::from).collect::<Vec<_>>();tron_toolkit::cli::parse(&args,Path::new("/fixed")).unwrap()}
#[test] fn root_and_group_help(){assert_eq!(parse(&[]),ParsedCommand::Help(HelpTarget::Root));assert_eq!(parse(&["help"]),ParsedCommand::Help(HelpTarget::Root));assert_eq!(parse(&["db","--help"]),ParsedCommand::Help(HelpTarget::Db));assert_eq!(parse(&["keystore","-V"]),ParsedCommand::Version(VersionTarget::Keystore));}
#[test] fn copy_alias_defaults_and_features(){match parse(&["db","cp","--network","n","--genesis","g"]){ParsedCommand::Db(DbCommand::Copy(v))=>{assert_eq!(v.source,Path::new("/fixed/output-directory/database"));assert_eq!(v.destination,Path::new("/fixed/output-directory-cp/database"));},v=>panic!("{v:?}")}match parse(&["db","copy","a","b","--network=n","--genesis=g","--feature","x","--feature","y"]){ParsedCommand::Db(DbCommand::Copy(v))=>assert_eq!(v.selector.features,vec!["rustlog-v1","x","y"]),v=>panic!("{v:?}")}}
#[test] fn lite_aliases(){match parse(&["db","lite","-o","split","-t","history","-fn","a","-ds","b","--exclude-historical-balance","--network","n","--genesis","g"]){ParsedCommand::Db(DbCommand::Lite(v))=>{assert_eq!(v.kind,LiteKind::History);assert!(v.exclude_historical_balance)},v=>panic!("{v:?}")}}
#[test] fn move_modes_are_exclusive(){assert!(tron_toolkit::cli::parse(&["db","mv","a","b","-c","x"].map(OsString::from),Path::new("/fixed")).is_err());assert!(matches!(parse(&["db","move","-d","a","-c","x"]),ParsedCommand::Db(DbCommand::Move(MoveArgs::JavaCompatibility{..}))));}
#[test] fn keystore_defaults_and_update_required(){match parse(&["keystore","new"]){ParsedCommand::Keystore(KeystoreCommand::New(v))=>assert_eq!(v.keystore_dir,Path::new("/fixed/Wallet")),v=>panic!("{v:?}")}assert!(tron_toolkit::cli::parse(&[OsString::from("keystore"),OsString::from("update")],Path::new("/fixed")).is_err());}
#[test] fn usage_failures_do_not_parse(){for words in [&["wat"][..],&["db","cp"],&["db","backup","a","b","--name","../x","--network","n","--genesis","g"]]{let args=words.iter().map(OsString::from).collect::<Vec<_>>();assert!(tron_toolkit::cli::parse(&args,Path::new("/fixed")).is_err())}}

#[test] fn command_specific_options_and_paths(){for words in [&["keystore","list","--force"][..],&["keystore","new","--key-file","x"],&["keystore","list","--password-file","x"],&["db","lite","-fn=x","-ds","y","--network","n","--genesis","g"]]{let args=words.iter().map(OsString::from).collect::<Vec<_>>();assert!(tron_toolkit::cli::parse(&args,Path::new("/fixed")).is_err())}match parse(&["db","inspect","relative"]){ParsedCommand::Db(DbCommand::Inspect(v))=>assert_eq!(v.path,Path::new("/fixed/relative")),v=>panic!("{v:?}")}}
#[test]
fn authenticated_java_help_and_versions_are_byte_exact() {
    let manifest: serde_json::Value = serde_json::from_str(include_str!("../../../../docs/oracles/c027-command-manifest.v1.json")).unwrap();
    let fixtures = manifest["java_help_fixtures"].as_array().unwrap();
    let cases = [
        ("C027.JAVA.HELP.ROOT", ParsedCommand::Help(HelpTarget::Root)),
        ("C027.JAVA.HELP.DB", ParsedCommand::Help(HelpTarget::Db)),
        ("C027.JAVA.HELP.DB_VERSION", ParsedCommand::Version(VersionTarget::Db)),
        ("C027.JAVA.HELP.DB_CP", ParsedCommand::Help(HelpTarget::DbCommand(DbCommandName::Copy))),
        ("C027.JAVA.HELP.DB_MV", ParsedCommand::Help(HelpTarget::DbCommand(DbCommandName::Move))),
        ("C027.JAVA.HELP.DB_ROOT", ParsedCommand::Help(HelpTarget::DbCommand(DbCommandName::Root))),
        ("C027.JAVA.HELP.DB_ARCHIVE", ParsedCommand::Help(HelpTarget::DbCommand(DbCommandName::Archive))),
        ("C027.JAVA.HELP.DB_CONVERT", ParsedCommand::Help(HelpTarget::DbCommand(DbCommandName::Convert))),
        ("C027.JAVA.HELP.LITE", ParsedCommand::Help(HelpTarget::DbCommand(DbCommandName::Lite))),
        ("C027.JAVA.HELP.KEYSTORE", ParsedCommand::Help(HelpTarget::Keystore)),
        ("C027.JAVA.HELP.KEYSTORE_VERSION", ParsedCommand::Version(VersionTarget::Keystore)),
        ("C027.JAVA.HELP.KEYSTORE_NEW", ParsedCommand::Help(HelpTarget::KeystoreCommand(KeystoreCommandName::New))),
        ("C027.JAVA.HELP.KEYSTORE_IMPORT", ParsedCommand::Help(HelpTarget::KeystoreCommand(KeystoreCommandName::Import))),
        ("C027.JAVA.HELP.KEYSTORE_LIST", ParsedCommand::Help(HelpTarget::KeystoreCommand(KeystoreCommandName::List))),
        ("C027.JAVA.HELP.KEYSTORE_UPDATE", ParsedCommand::Help(HelpTarget::KeystoreCommand(KeystoreCommandName::Update))),
    ];
    for (id, command) in cases {
        let fixture = fixtures.iter().find(|row| row["id"] == id).unwrap();
        let output = match command { ParsedCommand::Help(target) => tron_toolkit::cli::help_output(target), ParsedCommand::Version(target) => tron_toolkit::cli::version_output(target), _ => unreachable!() };
        assert_eq!(output.logical_exit, fixture["logical_exit"].as_i64().unwrap() as i32, "{id}");
        assert_eq!(output.stdout, fixture["stdout"].as_str().unwrap().as_bytes(), "{id}");
        assert_eq!(output.stderr, fixture["stderr"].as_str().unwrap().as_bytes(), "{id}");
    }
}