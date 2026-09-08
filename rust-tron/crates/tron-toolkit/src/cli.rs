pub const ROOT_USAGE: &str = "Usage: tron-toolkit [help [COMMAND...]] <db|keystore> ...\n";
pub const DB_USAGE: &str = "Usage: tron-toolkit db <convert|archive|cp|checkpoint|lite|mv|root|inspect|backup|migrate|resume|rollback|capabilities>\n";
pub const KEYSTORE_USAGE: &str = "Usage: tron-toolkit keystore <new|import|list|update>\n";

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use tron_config::toolkit::ToolkitBackend;

use crate::error::{CommandOutput, ParseFailure};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ParsedCommand { Help(HelpTarget), Version(VersionTarget), Db(DbCommand), Keystore(KeystoreCommand) }
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HelpTarget { Root, Db, Keystore, DbCommand(DbCommandName), KeystoreCommand(KeystoreCommandName) }
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VersionTarget { Db, Keystore }
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DbCommandName { Convert, Archive, Copy, Checkpoint, Lite, Move, Root, Inspect, Backup, Migrate, Resume, Rollback, Capabilities }
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeystoreCommandName { New, Import, List, Update }

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StorageSelector { pub backend: ToolkitBackend, pub schema_version: u32, pub network: String, pub genesis: String, pub features: Vec<String> }
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DbCommand { Convert(ConvertArgs), Archive(ArchiveArgs), Copy(CopyArgs), Checkpoint(CheckpointArgs), Lite(LiteArgs), Move(MoveArgs), Root(RootArgs), Inspect(InspectArgs), Backup(BackupArgs), Migrate(MigrateArgs), Resume(ResumeArgs), Rollback(RollbackArgs), Capabilities(CapabilitiesArgs) }
#[derive(Clone, Debug, Eq, PartialEq)] pub struct ConvertArgs { pub source: PathBuf, pub destination: PathBuf }
#[derive(Clone, Debug, Eq, PartialEq)] pub struct ArchiveArgs { pub database_directory: PathBuf, pub batch_size: u64, pub manifest_size_mib: i64, pub selector: StorageSelector }
#[derive(Clone, Debug, Eq, PartialEq)] pub struct CopyArgs { pub source: PathBuf, pub destination: PathBuf, pub selector: StorageSelector }
#[derive(Clone, Debug, Eq, PartialEq)] pub struct CheckpointArgs { pub source: PathBuf, pub destination: PathBuf, pub selector: StorageSelector }
#[derive(Clone, Copy, Debug, Eq, PartialEq)] pub enum LiteOperation { Split, Merge }
#[derive(Clone, Copy, Debug, Eq, PartialEq)] pub enum LiteKind { Snapshot, History }
#[derive(Clone, Debug, Eq, PartialEq)] pub struct LiteArgs { pub operation: LiteOperation, pub kind: LiteKind, pub fullnode_data_path: PathBuf, pub dataset_path: PathBuf, pub exclude_historical_balance: bool, pub selector: StorageSelector }
#[derive(Clone, Debug, Eq, PartialEq)] pub enum MoveArgs { Rust { source: PathBuf, destination: PathBuf, selector: StorageSelector }, JavaCompatibility { database_directory: PathBuf, config: PathBuf } }
#[derive(Clone, Debug, Eq, PartialEq)] pub struct RootArgs { pub path: PathBuf, pub stores: Vec<String>, pub json: bool, pub selector: StorageSelector }
#[derive(Clone, Debug, Eq, PartialEq)] pub struct InspectArgs { pub path: PathBuf, pub json: bool }
#[derive(Clone, Debug, Eq, PartialEq)] pub struct BackupArgs { pub source: PathBuf, pub backup_directory: PathBuf, pub name: String, pub selector: StorageSelector }
#[derive(Clone, Debug, Eq, PartialEq)] pub struct MigrateArgs { pub path: PathBuf, pub target_schema: u32, pub selector: StorageSelector }
#[derive(Clone, Debug, Eq, PartialEq)] pub struct ResumeArgs { pub path: PathBuf, pub selector: StorageSelector }
#[derive(Clone, Debug, Eq, PartialEq)] pub struct RollbackArgs { pub path: PathBuf, pub selector: StorageSelector }
#[derive(Clone, Debug, Eq, PartialEq)] pub struct CapabilitiesArgs { pub json: bool }

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum KeystoreCommand { New(NewKeystoreArgs), Import(ImportKeystoreArgs), List(ListKeystoreArgs), Update(UpdateKeystoreArgs) }
#[derive(Clone, Debug, Eq, PartialEq)] pub struct NewKeystoreArgs { pub keystore_dir: PathBuf, pub json: bool, pub password_file: Option<PathBuf>, pub sm2: bool }
#[derive(Clone, Debug, Eq, PartialEq)] pub struct ImportKeystoreArgs { pub keystore_dir: PathBuf, pub json: bool, pub key_file: Option<PathBuf>, pub password_file: Option<PathBuf>, pub sm2: bool, pub force: bool }
#[derive(Clone, Debug, Eq, PartialEq)] pub struct ListKeystoreArgs { pub keystore_dir: PathBuf, pub json: bool }
#[derive(Clone, Debug, Eq, PartialEq)] pub struct UpdateKeystoreArgs { pub address: String, pub keystore_dir: PathBuf, pub json: bool, pub password_file: Option<PathBuf>, pub sm2: bool }


pub fn help_output(target: HelpTarget) -> CommandOutput {
    let (stdout,stderr,logical_exit)=match target {
        HelpTarget::Root=>(crate::help::ROOT_STDOUT,crate::help::ROOT_STDERR,crate::help::ROOT_LOGICAL_EXIT),
        HelpTarget::Db=>(crate::help::DB_STDOUT,crate::help::DB_STDERR,crate::help::DB_LOGICAL_EXIT),
        HelpTarget::Keystore=>(crate::help::KEYSTORE_STDOUT,crate::help::KEYSTORE_STDERR,crate::help::KEYSTORE_LOGICAL_EXIT),
        HelpTarget::DbCommand(DbCommandName::Lite)=>(crate::help::LITE_STDOUT,crate::help::LITE_STDERR,crate::help::LITE_LOGICAL_EXIT),
        HelpTarget::DbCommand(DbCommandName::Copy)=>(crate::help::DB_COPY_STDOUT,crate::help::DB_COPY_STDERR,crate::help::DB_COPY_LOGICAL_EXIT),
        HelpTarget::DbCommand(DbCommandName::Move)=>(crate::help::DB_MOVE_STDOUT,crate::help::DB_MOVE_STDERR,crate::help::DB_MOVE_LOGICAL_EXIT),
        HelpTarget::DbCommand(DbCommandName::Root)=>(crate::help::DB_ROOT_STDOUT,crate::help::DB_ROOT_STDERR,crate::help::DB_ROOT_LOGICAL_EXIT),
        HelpTarget::DbCommand(DbCommandName::Archive)=>(crate::help::DB_ARCHIVE_STDOUT,crate::help::DB_ARCHIVE_STDERR,crate::help::DB_ARCHIVE_LOGICAL_EXIT),
        HelpTarget::DbCommand(DbCommandName::Convert)=>(crate::help::DB_CONVERT_STDOUT,crate::help::DB_CONVERT_STDERR,crate::help::DB_CONVERT_LOGICAL_EXIT),
        HelpTarget::KeystoreCommand(KeystoreCommandName::New)=>(crate::help::KEYSTORE_NEW_STDOUT,crate::help::KEYSTORE_NEW_STDERR,crate::help::KEYSTORE_NEW_LOGICAL_EXIT),
        HelpTarget::KeystoreCommand(KeystoreCommandName::Import)=>(crate::help::KEYSTORE_IMPORT_STDOUT,crate::help::KEYSTORE_IMPORT_STDERR,crate::help::KEYSTORE_IMPORT_LOGICAL_EXIT),
        HelpTarget::KeystoreCommand(KeystoreCommandName::List)=>(crate::help::KEYSTORE_LIST_STDOUT,crate::help::KEYSTORE_LIST_STDERR,crate::help::KEYSTORE_LIST_LOGICAL_EXIT),
        HelpTarget::KeystoreCommand(KeystoreCommandName::Update)=>(crate::help::KEYSTORE_UPDATE_STDOUT,crate::help::KEYSTORE_UPDATE_STDERR,crate::help::KEYSTORE_UPDATE_LOGICAL_EXIT),
        HelpTarget::DbCommand(name)=>return CommandOutput::stdout(rust_only_help(name)),
    };CommandOutput{stdout:stdout.to_vec(),stderr:stderr.to_vec(),logical_exit}
}
pub fn help_bytes(target: HelpTarget) -> &'static [u8] {let output=match target{HelpTarget::Root=>(crate::help::ROOT_STDOUT,crate::help::ROOT_STDERR),HelpTarget::Db=>(crate::help::DB_STDOUT,crate::help::DB_STDERR),HelpTarget::Keystore=>(crate::help::KEYSTORE_STDOUT,crate::help::KEYSTORE_STDERR),HelpTarget::DbCommand(DbCommandName::Copy)=>(crate::help::DB_COPY_STDOUT,crate::help::DB_COPY_STDERR),HelpTarget::DbCommand(DbCommandName::Move)=>(crate::help::DB_MOVE_STDOUT,crate::help::DB_MOVE_STDERR),HelpTarget::DbCommand(DbCommandName::Root)=>(crate::help::DB_ROOT_STDOUT,crate::help::DB_ROOT_STDERR),HelpTarget::DbCommand(DbCommandName::Archive)=>(crate::help::DB_ARCHIVE_STDOUT,crate::help::DB_ARCHIVE_STDERR),HelpTarget::DbCommand(DbCommandName::Convert)=>(crate::help::DB_CONVERT_STDOUT,crate::help::DB_CONVERT_STDERR),HelpTarget::DbCommand(DbCommandName::Lite)=>(crate::help::LITE_STDOUT,crate::help::LITE_STDERR),HelpTarget::KeystoreCommand(KeystoreCommandName::New)=>(crate::help::KEYSTORE_NEW_STDOUT,crate::help::KEYSTORE_NEW_STDERR),HelpTarget::KeystoreCommand(KeystoreCommandName::Import)=>(crate::help::KEYSTORE_IMPORT_STDOUT,crate::help::KEYSTORE_IMPORT_STDERR),HelpTarget::KeystoreCommand(KeystoreCommandName::List)=>(crate::help::KEYSTORE_LIST_STDOUT,crate::help::KEYSTORE_LIST_STDERR),HelpTarget::KeystoreCommand(KeystoreCommandName::Update)=>(crate::help::KEYSTORE_UPDATE_STDOUT,crate::help::KEYSTORE_UPDATE_STDERR),HelpTarget::DbCommand(name)=>(rust_only_help(name),&[] as &[u8])};if output.0.is_empty(){output.1}else{output.0}}
pub fn version_output(target:VersionTarget)->CommandOutput{match target{VersionTarget::Db=>CommandOutput{stdout:crate::help::DB_VERSION_STDOUT.to_vec(),stderr:crate::help::DB_VERSION_STDERR.to_vec(),logical_exit:crate::help::DB_VERSION_LOGICAL_EXIT},VersionTarget::Keystore=>CommandOutput{stdout:crate::help::KEYSTORE_VERSION_STDOUT.to_vec(),stderr:crate::help::KEYSTORE_VERSION_STDERR.to_vec(),logical_exit:crate::help::KEYSTORE_VERSION_LOGICAL_EXIT}}}
pub fn version_bytes(target: VersionTarget) -> &'static [u8] { match target { VersionTarget::Db => crate::help::DB_VERSION_STDOUT, VersionTarget::Keystore => crate::help::KEYSTORE_VERSION_STDOUT } }
fn rust_only_help(name:DbCommandName)->&'static [u8]{match name{DbCommandName::Convert=>b"Usage: tron-toolkit db convert [SOURCE] [DESTINATION]\n",DbCommandName::Archive=>b"Usage: tron-toolkit db archive [OPTIONS]\n",DbCommandName::Copy=>b"Usage: tron-toolkit db cp [SOURCE] [DESTINATION] STORAGE_SELECTOR\n",DbCommandName::Checkpoint=>b"Usage: tron-toolkit db checkpoint SOURCE DESTINATION STORAGE_SELECTOR\n",DbCommandName::Move=>b"Usage: tron-toolkit db mv SOURCE DESTINATION STORAGE_SELECTOR\n",DbCommandName::Root=>b"Usage: tron-toolkit db root [PATH] --db NAME STORAGE_SELECTOR\n",DbCommandName::Inspect=>b"Usage: tron-toolkit db inspect [PATH] [--json]\n",DbCommandName::Backup=>b"Usage: tron-toolkit db backup SOURCE DIRECTORY --name NAME STORAGE_SELECTOR\n",DbCommandName::Migrate=>b"Usage: tron-toolkit db migrate PATH --target-schema N STORAGE_SELECTOR\n",DbCommandName::Resume=>b"Usage: tron-toolkit db resume PATH STORAGE_SELECTOR\n",DbCommandName::Rollback=>b"Usage: tron-toolkit db rollback PATH STORAGE_SELECTOR\n",DbCommandName::Capabilities=>b"Usage: tron-toolkit db capabilities [--json]\n",DbCommandName::Lite=>crate::help::LITE_STDERR}}
pub fn parse(args: &[OsString], cwd: &Path) -> Result<ParsedCommand, ParseFailure> {
    if args.is_empty() { return Ok(ParsedCommand::Help(HelpTarget::Root)); }
    let head = text(&args[0], ROOT_USAGE)?;
    match head.as_str() {
        "help" => parse_help(&args[1..]),
        "db" => parse_db(&args[1..], cwd),
        "keystore" => parse_keystore(&args[1..], cwd),
        _ => fail(ROOT_USAGE, format!("unknown command: {head}")),
    }
}

fn parse_help(args: &[OsString]) -> Result<ParsedCommand, ParseFailure> {
    if args.is_empty() { return Ok(ParsedCommand::Help(HelpTarget::Root)); }
    let first = text(&args[0], ROOT_USAGE)?;
    match first.as_str() {
        "db" if args.len() == 1 => Ok(ParsedCommand::Help(HelpTarget::Db)),
        "keystore" if args.len() == 1 => Ok(ParsedCommand::Help(HelpTarget::Keystore)),
        "db" if args.len() == 2 => db_name(&text(&args[1], DB_USAGE)?).map(|name| ParsedCommand::Help(HelpTarget::DbCommand(name))),
        "keystore" if args.len() == 2 => keystore_name(&text(&args[1], KEYSTORE_USAGE)?).map(|name| ParsedCommand::Help(HelpTarget::KeystoreCommand(name))),
        _ => fail(ROOT_USAGE, "invalid help target"),
    }
}

fn parse_db(args: &[OsString], cwd: &Path) -> Result<ParsedCommand, ParseFailure> {
    if args.is_empty() { return fail(DB_USAGE, "missing db command"); }
    let first = text(&args[0], DB_USAGE)?;
    if matches!(first.as_str(), "-h"|"--help") { return only(args, ParsedCommand::Help(HelpTarget::Db), DB_USAGE); }
    if matches!(first.as_str(), "-V"|"--version") { return only(args, ParsedCommand::Version(VersionTarget::Db), DB_USAGE); }
    let name = db_name(&first)?;
    let tail = &args[1..];
    if tail.iter().any(|v| v.to_str().is_some_and(|s| matches!(s,"-h"|"--help"))) { return Ok(ParsedCommand::Help(HelpTarget::DbCommand(name))); }
    let command = match name {
        DbCommandName::Convert => { let (p,_) = scan(tail, &[] , false, DB_USAGE)?; if p.len()>2{return fail(DB_USAGE,"too many paths")}; DbCommand::Convert(ConvertArgs{source:p.first().cloned().unwrap_or_else(||cwd.join("output-directory/database")),destination:p.get(1).cloned().unwrap_or_else(||cwd.join("output-directory-dst/database"))}) },
        DbCommandName::Inspect => { let (p,o)=scan(tail,&["--json"],false,DB_USAGE)?; if p.len()>1{return fail(DB_USAGE,"too many paths")}; DbCommand::Inspect(InspectArgs{path:p.first().cloned().unwrap_or_else(||cwd.join("output-directory/database")),json:o.flag("--json")}) },
        DbCommandName::Capabilities => { let (p,o)=scan(tail,&["--json"],false,DB_USAGE)?; if !p.is_empty(){return fail(DB_USAGE,"unexpected path")}; DbCommand::Capabilities(CapabilitiesArgs{json:o.flag("--json")}) },
        DbCommandName::Archive => { let (p,o)=scan(tail,&["-d","--database-directory","-b","--batch-size","-m","--manifest-size"],true,DB_USAGE)?; if !p.is_empty(){return fail(DB_USAGE,"unexpected path")}; DbCommand::Archive(ArchiveArgs{database_directory:o.path_any(&["-d","--database-directory"]).unwrap_or_else(||cwd.join("output-directory/database")),batch_size:o.parse_any(&["-b","--batch-size"],80000)?,manifest_size_mib:o.parse_any(&["-m","--manifest-size"],0)?,selector:o.selector()?}) },
        DbCommandName::Copy => { let (p,o)=scan(tail,&[],true,DB_USAGE)?; if p.len()>2{return fail(DB_USAGE,"too many paths")}; DbCommand::Copy(CopyArgs{source:p.first().cloned().unwrap_or_else(||cwd.join("output-directory/database")),destination:p.get(1).cloned().unwrap_or_else(||cwd.join("output-directory-cp/database")),selector:o.selector()?}) },
        DbCommandName::Checkpoint => { let (p,o)=scan(tail,&[],true,DB_USAGE)?; require_paths(&p,2,DB_USAGE)?; DbCommand::Checkpoint(CheckpointArgs{source:p[0].clone(),destination:p[1].clone(),selector:o.selector()?}) },
        DbCommandName::Lite => { let (p,o)=scan(tail,&["-o","--operate","-t","--type","-fn","--fn-data-path","-ds","--dataset-path","--exclude-historical-balance"],true,DB_USAGE)?; if !p.is_empty(){return fail(DB_USAGE,"unexpected path")}; let operation=match o.text_any(&["-o","--operate"]).as_deref().unwrap_or("split"){"split"=>LiteOperation::Split,"merge"=>LiteOperation::Merge,_=>return fail(DB_USAGE,"invalid lite operation")}; let kind=match o.text_any(&["-t","--type"]).as_deref().unwrap_or("snapshot"){"snapshot"=>LiteKind::Snapshot,"history"=>LiteKind::History,_=>return fail(DB_USAGE,"invalid lite type")}; DbCommand::Lite(LiteArgs{operation,kind,fullnode_data_path:o.path_any(&["-fn","--fn-data-path"]).ok_or_else(||pf(DB_USAGE,"missing --fn-data-path"))?,dataset_path:o.path_any(&["-ds","--dataset-path"]).ok_or_else(||pf(DB_USAGE,"missing --dataset-path"))?,exclude_historical_balance:o.flag("--exclude-historical-balance"),selector:o.selector()?}) },
        DbCommandName::Move => { let (p,o)=scan(tail,&["-d","--database-directory","-c","--config"],true,DB_USAGE)?; let compat=o.has_any(&["-d","--database-directory","-c","--config"]); if compat { if !p.is_empty()||o.has_selector(){return fail(DB_USAGE,"move modes conflict")}; DbCommand::Move(MoveArgs::JavaCompatibility{database_directory:o.path_any(&["-d","--database-directory"]).unwrap_or_else(||cwd.join("output-directory")),config:o.path_any(&["-c","--config"]).unwrap_or_else(||cwd.join("config.conf"))}) } else { require_paths(&p,2,DB_USAGE)?; DbCommand::Move(MoveArgs::Rust{source:p[0].clone(),destination:p[1].clone(),selector:o.selector()?}) } },
        DbCommandName::Root => { let (p,o)=scan(tail,&["--db","--json"],true,DB_USAGE)?; if p.len()>1{return fail(DB_USAGE,"too many paths")}; let stores=o.texts("--db"); if stores.is_empty(){return fail(DB_USAGE,"missing --db")}; DbCommand::Root(RootArgs{path:p.first().cloned().unwrap_or_else(||cwd.join("output-directory/database")),stores,json:o.flag("--json"),selector:o.selector()?}) },
        DbCommandName::Backup => { let (p,o)=scan(tail,&["--name"],true,DB_USAGE)?; require_paths(&p,2,DB_USAGE)?; let name=o.text_any(&["--name"]).ok_or_else(||pf(DB_USAGE,"missing --name"))?; if !normal_name(&name){return fail(DB_USAGE,"invalid backup name")}; DbCommand::Backup(BackupArgs{source:p[0].clone(),backup_directory:p[1].clone(),name,selector:o.selector()?}) },
        DbCommandName::Migrate => { let (p,o)=scan(tail,&["--target-schema"],true,DB_USAGE)?; require_paths(&p,1,DB_USAGE)?; DbCommand::Migrate(MigrateArgs{path:p[0].clone(),target_schema:o.parse_required("--target-schema")?,selector:o.selector()?}) },
        DbCommandName::Resume => { let (p,o)=scan(tail,&[],true,DB_USAGE)?; require_paths(&p,1,DB_USAGE)?; DbCommand::Resume(ResumeArgs{path:p[0].clone(),selector:o.selector()?}) },
        DbCommandName::Rollback => { let (p,o)=scan(tail,&[],true,DB_USAGE)?; require_paths(&p,1,DB_USAGE)?; DbCommand::Rollback(RollbackArgs{path:p[0].clone(),selector:o.selector()?}) },
    };
    Ok(ParsedCommand::Db(absolutize_db(command,cwd)))
}

fn parse_keystore(args:&[OsString],cwd:&Path)->Result<ParsedCommand,ParseFailure>{
    if args.is_empty(){return fail(KEYSTORE_USAGE,"missing keystore command")}
    let first=text(&args[0],KEYSTORE_USAGE)?;
    if matches!(first.as_str(),"-h"|"--help"){return only(args,ParsedCommand::Help(HelpTarget::Keystore),KEYSTORE_USAGE)}
    if matches!(first.as_str(),"-V"|"--version"){return only(args,ParsedCommand::Version(VersionTarget::Keystore),KEYSTORE_USAGE)}
    let name=keystore_name(&first)?;
    if args[1..].iter().any(|v|v.to_str().is_some_and(|s|matches!(s,"-h"|"--help"))){return Ok(ParsedCommand::Help(HelpTarget::KeystoreCommand(name)))}
    let allowed:&[&str]=match name{KeystoreCommandName::New=>&["--keystore-dir","--json","--password-file","--sm2"],KeystoreCommandName::Import=>&["--keystore-dir","--json","--password-file","--key-file","--sm2","--force"],KeystoreCommandName::List=>&["--keystore-dir","--json"],KeystoreCommandName::Update=>&["--keystore-dir","--json","--password-file","--sm2"]};
    let (p,o)=scan(&args[1..],allowed,false,KEYSTORE_USAGE)?;
    let dir=o.path_any(&["--keystore-dir"]).map(|p|abs(cwd,p)).unwrap_or_else(||cwd.join("Wallet"));
    let cmd=match name{
        KeystoreCommandName::New=>{if !p.is_empty(){return fail(KEYSTORE_USAGE,"unexpected argument")};KeystoreCommand::New(NewKeystoreArgs{keystore_dir:dir,json:o.flag("--json"),password_file:o.path_any(&["--password-file"]),sm2:o.flag("--sm2")})},
        KeystoreCommandName::Import=>{if !p.is_empty(){return fail(KEYSTORE_USAGE,"unexpected argument")};KeystoreCommand::Import(ImportKeystoreArgs{keystore_dir:dir,json:o.flag("--json"),key_file:o.path_any(&["--key-file"]),password_file:o.path_any(&["--password-file"]),sm2:o.flag("--sm2"),force:o.flag("--force")})},
        KeystoreCommandName::List=>{if !p.is_empty(){return fail(KEYSTORE_USAGE,"unexpected argument")};KeystoreCommand::List(ListKeystoreArgs{keystore_dir:dir,json:o.flag("--json")})},
        KeystoreCommandName::Update=>{require_paths(&p,1,KEYSTORE_USAGE)?;KeystoreCommand::Update(UpdateKeystoreArgs{address:p[0].to_str().ok_or_else(||pf(KEYSTORE_USAGE,"address is not UTF-8"))?.to_owned(),keystore_dir:dir,json:o.flag("--json"),password_file:o.path_any(&["--password-file"]),sm2:o.flag("--sm2")})},
    };Ok(ParsedCommand::Keystore(absolutize_keystore(cmd,cwd)))
}

#[derive(Default)] struct Opts(Vec<(String,Option<OsString>)>);
impl Opts{
 fn flag(&self,n:&str)->bool{self.0.iter().any(|(k,_)|k==n)}
 fn has_any(&self,n:&[&str])->bool{n.iter().any(|x|self.flag(x))}
 fn path_any(&self,n:&[&str])->Option<PathBuf>{self.0.iter().find(|(k,_)|n.contains(&k.as_str())).and_then(|(_,v)|v.clone()).map(PathBuf::from)}
 fn text_any(&self,n:&[&str])->Option<String>{self.0.iter().find(|(k,_)|n.contains(&k.as_str())).and_then(|(_,v)|v.as_ref()).and_then(|v|v.to_str()).map(str::to_owned)}
 fn texts(&self,n:&str)->Vec<String>{self.0.iter().filter(|(k,_)|k==n).filter_map(|(_,v)|v.as_ref()?.to_str().map(str::to_owned)).collect()}
 fn parse_any<T:std::str::FromStr>(&self,n:&[&str],default:T)->Result<T,ParseFailure>{match self.text_any(n){Some(v)=>v.parse().map_err(|_|pf(DB_USAGE,"invalid integer")),None=>Ok(default)}}
 fn parse_required<T:std::str::FromStr>(&self,n:&str)->Result<T,ParseFailure>{self.text_any(&[n]).ok_or_else(||pf(DB_USAGE,format!("missing {n}")))?.parse().map_err(|_|pf(DB_USAGE,"invalid integer"))}
 fn has_selector(&self)->bool{self.has_any(&["--backend","--schema-version","--network","--genesis","--feature"])}
 fn selector(&self)->Result<StorageSelector,ParseFailure>{let network=self.text_any(&["--network"]).filter(|v|!v.is_empty()).ok_or_else(||pf(DB_USAGE,"missing --network"))?;let genesis=self.text_any(&["--genesis"]).filter(|v|!v.is_empty()).ok_or_else(||pf(DB_USAGE,"missing --genesis"))?;let backend=self.text_any(&["--backend"]).unwrap_or_else(||"rustlog-v1".into()).parse().map_err(|_|pf(DB_USAGE,"invalid backend"))?;let mut features=vec!["rustlog-v1".into()];features.extend(self.texts("--feature"));Ok(StorageSelector{backend,schema_version:self.parse_any(&["--schema-version"],1)?,network,genesis,features})}
}
fn scan(args:&[OsString],specific:&[&str],selector:bool,usage:&'static str)->Result<(Vec<PathBuf>,Opts),ParseFailure>{let mut p=Vec::new();let mut o=Opts::default();let mut i=0;let mut end=false;while i<args.len(){let raw=&args[i];let s=raw.to_str();if !end&&s==Some("--"){end=true;i+=1;continue}if !end&&s.is_some_and(|v|v.starts_with('-')){let s=s.unwrap();let (name,attached)=s.split_once('=').map_or((s,None),|(a,b)|(a,Some(OsString::from(b))));if attached.is_some()&&name.starts_with('-')&&!name.starts_with("--"){return fail(usage,"short options do not accept attached values")}let flag=matches!(name,"--json"|"--sm2"|"--force"|"--exclude-historical-balance");let allowed=specific.contains(&name)||(selector&&matches!(name,"--backend"|"--schema-version"|"--network"|"--genesis"|"--feature"));if !allowed{return fail(usage,format!("unknown option: {name}"))}if o.0.iter().any(|(k,_)|k==name)&&name!="--feature"&&name!="--db"{return fail(usage,format!("duplicate option: {name}"))}if flag{if attached.is_some(){return fail(usage,"boolean flag takes no value")}o.0.push((name.into(),None));}else{let value=match attached{Some(v)=>v,None=>{i+=1;args.get(i).cloned().ok_or_else(||pf(usage,format!("missing value for {name}")))?}};o.0.push((name.into(),Some(value)));}}else{p.push(PathBuf::from(raw));}i+=1}Ok((p,o))}
fn db_name(v:&str)->Result<DbCommandName,ParseFailure>{match v{"convert"=>Ok(DbCommandName::Convert),"archive"=>Ok(DbCommandName::Archive),"cp"|"copy"=>Ok(DbCommandName::Copy),"checkpoint"=>Ok(DbCommandName::Checkpoint),"lite"=>Ok(DbCommandName::Lite),"mv"|"move"=>Ok(DbCommandName::Move),"root"=>Ok(DbCommandName::Root),"inspect"=>Ok(DbCommandName::Inspect),"backup"=>Ok(DbCommandName::Backup),"migrate"=>Ok(DbCommandName::Migrate),"resume"=>Ok(DbCommandName::Resume),"rollback"=>Ok(DbCommandName::Rollback),"capabilities"=>Ok(DbCommandName::Capabilities),_=>fail(DB_USAGE,"unknown db command")}}
fn keystore_name(v:&str)->Result<KeystoreCommandName,ParseFailure>{match v{"new"=>Ok(KeystoreCommandName::New),"import"=>Ok(KeystoreCommandName::Import),"list"=>Ok(KeystoreCommandName::List),"update"=>Ok(KeystoreCommandName::Update),_=>fail(KEYSTORE_USAGE,"unknown keystore command")}}
fn require_paths(p:&[PathBuf],n:usize,u:&'static str)->Result<(),ParseFailure>{if p.len()==n{Ok(())}else{fail(u,"wrong number of paths")}}
fn normal_name(n:&str)->bool{!n.is_empty()&&n!="."&&n!=".."&&!n.contains('/')&&!n.contains('\\')&&!Path::new(n).is_absolute()}
fn only<T>(args:&[OsString],v:T,u:&'static str)->Result<T,ParseFailure>{if args.len()==1{Ok(v)}else{fail(u,"unexpected argument")}}
fn text(v:&OsString,u:&'static str)->Result<String,ParseFailure>{v.to_str().map(str::to_owned).ok_or_else(||pf(u,"text argument is not UTF-8"))}
fn pf(u:&'static str,d:impl Into<String>)->ParseFailure{ParseFailure{detail:d.into(),usage:u}}
fn fail<T>(u:&'static str,d:impl Into<String>)->Result<T,ParseFailure>{Err(pf(u,d))}
fn abs(cwd:&Path,path:PathBuf)->PathBuf{if path.is_absolute(){path}else{cwd.join(path)}}
fn absolutize_db(mut c:DbCommand,cwd:&Path)->DbCommand{match &mut c{DbCommand::Convert(a)=>{a.source=abs(cwd,a.source.clone());a.destination=abs(cwd,a.destination.clone())},DbCommand::Archive(a)=>a.database_directory=abs(cwd,a.database_directory.clone()),DbCommand::Copy(a)=>{a.source=abs(cwd,a.source.clone());a.destination=abs(cwd,a.destination.clone())},DbCommand::Checkpoint(a)=>{a.source=abs(cwd,a.source.clone());a.destination=abs(cwd,a.destination.clone())},DbCommand::Lite(a)=>{a.fullnode_data_path=abs(cwd,a.fullnode_data_path.clone());a.dataset_path=abs(cwd,a.dataset_path.clone())},DbCommand::Move(MoveArgs::Rust{source,destination,..})=>{*source=abs(cwd,source.clone());*destination=abs(cwd,destination.clone())},DbCommand::Move(MoveArgs::JavaCompatibility{database_directory,config})=>{*database_directory=abs(cwd,database_directory.clone());*config=abs(cwd,config.clone())},DbCommand::Root(a)=>a.path=abs(cwd,a.path.clone()),DbCommand::Inspect(a)=>a.path=abs(cwd,a.path.clone()),DbCommand::Backup(a)=>{a.source=abs(cwd,a.source.clone());a.backup_directory=abs(cwd,a.backup_directory.clone())},DbCommand::Migrate(a)=>a.path=abs(cwd,a.path.clone()),DbCommand::Resume(a)=>a.path=abs(cwd,a.path.clone()),DbCommand::Rollback(a)=>a.path=abs(cwd,a.path.clone()),DbCommand::Capabilities(_)=>{}}c}
fn absolutize_keystore(mut c:KeystoreCommand,cwd:&Path)->KeystoreCommand{match &mut c{KeystoreCommand::New(a)=>{a.keystore_dir=abs(cwd,a.keystore_dir.clone());if let Some(p)=a.password_file.take(){a.password_file=Some(abs(cwd,p))}},KeystoreCommand::Import(a)=>{a.keystore_dir=abs(cwd,a.keystore_dir.clone());if let Some(p)=a.password_file.take(){a.password_file=Some(abs(cwd,p))}if let Some(p)=a.key_file.take(){a.key_file=Some(abs(cwd,p))}},KeystoreCommand::List(a)=>a.keystore_dir=abs(cwd,a.keystore_dir.clone()),KeystoreCommand::Update(a)=>{a.keystore_dir=abs(cwd,a.keystore_dir.clone());if let Some(p)=a.password_file.take(){a.password_file=Some(abs(cwd,p))}}}c}
