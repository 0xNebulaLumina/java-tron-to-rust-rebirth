use std::io;
use std::path::Path;

use time::OffsetDateTime;
use tron_config::toolkit::PlatformFacts;
use tron_crypto::CryptoEngine;
use zeroize::Zeroizing;

use crate::error::ToolkitError;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SecretPrompt { NewPassword, ImportPassword, OldPassword, UpdatedPassword, PrivateKey }
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SecretSource<'a> { Tty, File(&'a Path) }

pub trait ToolkitIo {
    fn write_stdout(&mut self, bytes: &[u8]) -> io::Result<()>;
    fn write_stderr(&mut self, bytes: &[u8]) -> io::Result<()>;
    fn read_secret(&mut self, prompt: SecretPrompt, source: SecretSource<'_>) -> Result<Zeroizing<Vec<u8>>, ToolkitError>;
}
pub trait Clock { fn now_utc(&self) -> OffsetDateTime; }
pub trait KeyProvider {
    fn generate_private_key(&mut self, engine: CryptoEngine) -> Result<Zeroizing<[u8; 32]>, ToolkitError>;
    fn fill_entropy(&mut self, destination: &mut [u8]) -> Result<(), ToolkitError>;
}
pub struct CommandContext<'a> {
    pub cwd: &'a Path,
    pub platform: &'a PlatformFacts,
    pub io: &'a mut dyn ToolkitIo,
    pub clock: &'a dyn Clock,
    pub keys: &'a mut dyn KeyProvider,
}
