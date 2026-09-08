use std::fs::{File, OpenOptions};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use rustix::termios::{self, LocalModes, OptionalActions, Termios};

use rand_core::{OsRng, RngCore};
use time::OffsetDateTime;
use tron_config::toolkit::PlatformFacts;
use tron_crypto::CryptoEngine;
use tron_toolkit::capability::ProductionDbServices;
use tron_toolkit::error::{ErrorCategory, ToolkitError};
use tron_toolkit::io::{Clock, KeyProvider, SecretPrompt, SecretSource, ToolkitIo};
use tron_toolkit::keystore::CryptoKeystoreServices;
use tron_toolkit::{run_with, RuntimeServices};
use zeroize::Zeroizing;

fn main() {
    let cwd=match std::env::current_dir(){Ok(v)=>v,Err(e)=>exit_error(e.to_string())};
    let args:Vec<_>=std::env::args_os().skip(1).collect();
    let platform=PlatformFacts::new(std::env::consts::OS,std::env::consts::ARCH,target());
    let mut io=SystemIo;
    let clock=SystemClock;
    let mut keys=SystemKeys;
    let mut db=ProductionDbServices::new(platform.clone());
    let mut keystore=CryptoKeystoreServices;
    let outcome=run_with(&args,&cwd,&platform,&mut io,RuntimeServices{db:&mut db,keystore:&mut keystore,clock:&clock,keys:&mut keys});
    std::process::exit(outcome.logical_exit & 255);
}

fn target()->&'static str{
    #[cfg(all(target_os="linux",target_arch="x86_64"))] { "x86_64-unknown-linux-gnu" }
    #[cfg(all(target_os="linux",target_arch="aarch64"))] { "aarch64-unknown-linux-gnu" }
    #[cfg(all(target_os="macos",target_arch="x86_64"))] { "x86_64-apple-darwin" }
    #[cfg(all(target_os="macos",target_arch="aarch64"))] { "aarch64-apple-darwin" }
    #[cfg(not(any(all(target_os="linux",target_arch="x86_64"),all(target_os="linux",target_arch="aarch64"),all(target_os="macos",target_arch="x86_64"),all(target_os="macos",target_arch="aarch64"))))] { "unsupported" }
}
fn exit_error(detail:String)->!{let _=writeln!(io::stderr(),"error[operation_failure]: {detail}");std::process::exit(1)}
struct SystemClock;
impl Clock for SystemClock{fn now_utc(&self)->OffsetDateTime{OffsetDateTime::now_utc()}}
struct SystemKeys;
impl KeyProvider for SystemKeys{
 fn generate_private_key(&mut self,engine:CryptoEngine)->Result<Zeroizing<[u8;32]>,ToolkitError>{Ok(Zeroizing::new(tron_crypto::PrivateKey::generate(engine).private_bytes()))}
 fn fill_entropy(&mut self,destination:&mut[u8])->Result<(),ToolkitError>{OsRng.try_fill_bytes(destination).map_err(|e|categorized(e.to_string()))}
}
struct SystemIo;
impl ToolkitIo for SystemIo{
 fn write_stdout(&mut self,bytes:&[u8])->io::Result<()>{io::stdout().write_all(bytes)}
 fn write_stderr(&mut self,bytes:&[u8])->io::Result<()>{io::stderr().write_all(bytes)}
 fn read_secret(&mut self,prompt:SecretPrompt,source:SecretSource<'_>)->Result<Zeroizing<Vec<u8>>,ToolkitError>{match source{
  SecretSource::File(path)=>if prompt==SecretPrompt::PrivateKey{tron_crypto::keystore::read_private_key_file(path).map_err(|e|categorized(e.to_string()))}else{tron_crypto::keystore::read_password_file(path).map(|s|Zeroizing::new(s.into_bytes())).map_err(|e|categorized(e.to_string()))},
  SecretSource::Tty=>read_tty_secret(prompt)
 }}
}
fn categorized(detail:String)->ToolkitError{ToolkitError::Categorized{category:ErrorCategory::KeystoreInput,detail}}

struct EchoGuard<'a>{file:&'a File,original:Termios}
impl<'a> EchoGuard<'a>{fn disable(file:&'a File)->Result<Self,ToolkitError>{let original=termios::tcgetattr(file).map_err(|e|categorized(e.to_string()))?;let mut hidden=original.clone();hidden.local_modes.remove(LocalModes::ECHO);termios::tcsetattr(file,OptionalActions::Now,&hidden).map_err(|e|categorized(e.to_string()))?;Ok(Self{file,original})}}
impl Drop for EchoGuard<'_>{fn drop(&mut self){let _=termios::tcsetattr(self.file,OptionalActions::Now,&self.original);}}
fn read_tty_secret(prompt:SecretPrompt)->Result<Zeroizing<Vec<u8>>,ToolkitError>{
 let flags=(rustix::fs::OFlags::NOFOLLOW|rustix::fs::OFlags::CLOEXEC).bits() as i32;
 let file=OpenOptions::new().read(true).write(true).custom_flags(flags).open("/dev/tty").map_err(|e|categorized(e.to_string()))?;
 let _guard=EchoGuard::disable(&file)?;
 let first=read_tty_line(&file,match prompt{SecretPrompt::NewPassword|SecretPrompt::ImportPassword=>"Enter password: ",SecretPrompt::OldPassword=>"Enter current password: ",SecretPrompt::UpdatedPassword=>"Enter new password: ",SecretPrompt::PrivateKey=>"Enter private key (hex): "},if prompt==SecretPrompt::PrivateKey{"Input cancelled."}else{"Password input cancelled."})?;
 if matches!(prompt,SecretPrompt::NewPassword|SecretPrompt::ImportPassword|SecretPrompt::UpdatedPassword){let second=read_tty_line(&file,match prompt{SecretPrompt::UpdatedPassword=>"Confirm new password: ",_=>"Confirm password: "},"Password input cancelled.")?;if *first!=*second{return Err(parity(match prompt{SecretPrompt::UpdatedPassword=>"New passwords do not match.\n",_=>"Passwords do not match.\n"}))}}
 Ok(first)
}
fn read_tty_line(file:&File,prompt:&str,cancel:&str)->Result<Zeroizing<Vec<u8>>,ToolkitError>{let mut out=&*file;out.write_all(prompt.as_bytes()).map_err(|e|categorized(e.to_string()))?;out.flush().map_err(|e|categorized(e.to_string()))?;let mut bytes=Zeroizing::new(Vec::new());let count=BufReader::new(file).take(1025).read_until(b'\n',&mut bytes).map_err(|e|categorized(e.to_string()))?;out.write_all(b"\n").map_err(|e|categorized(e.to_string()))?;if count==0{return Err(parity(&format!("{cancel}\n")))}if bytes.len()>1024{return Err(categorized("secret input exceeds 1024 bytes".into()))}while matches!(bytes.last(),Some(b'\n'|b'\r')){bytes.pop();}Ok(bytes)}
fn parity(stderr:&str)->ToolkitError{ToolkitError::Parity{code:1,stdout:Vec::new(),stderr:stderr.as_bytes().to_vec()}}
