pub mod archive;
pub mod inspect;
pub mod lite;
pub mod migration;
pub mod root;
pub mod transfer;

use crate::cli::*;
use crate::error::{CommandOutput, ToolkitError};
use crate::io::CommandContext;

pub trait DbServices {
    fn convert(&mut self, args: &ConvertArgs) -> Result<CommandOutput, ToolkitError>;
    fn archive(&mut self, args: &ArchiveArgs) -> Result<CommandOutput, ToolkitError>;
    fn copy(&mut self, args: &CopyArgs) -> Result<CommandOutput, ToolkitError>;
    fn checkpoint(&mut self, args: &CheckpointArgs) -> Result<CommandOutput, ToolkitError>;
    fn lite(&mut self, args: &LiteArgs) -> Result<CommandOutput, ToolkitError>;
    fn move_store(&mut self, args: &MoveArgs) -> Result<CommandOutput, ToolkitError>;
    fn root(&mut self, args: &RootArgs) -> Result<CommandOutput, ToolkitError>;
    fn inspect(&mut self, args: &InspectArgs) -> Result<CommandOutput, ToolkitError>;
    fn backup(&mut self, args: &BackupArgs) -> Result<CommandOutput, ToolkitError>;
    fn migrate(&mut self, args: &MigrateArgs) -> Result<CommandOutput, ToolkitError>;
    fn resume(&mut self, args: &ResumeArgs) -> Result<CommandOutput, ToolkitError>;
    fn rollback(&mut self, args: &RollbackArgs) -> Result<CommandOutput, ToolkitError>;
    fn capabilities(&mut self, args: &CapabilitiesArgs) -> Result<CommandOutput, ToolkitError>;
}

pub trait DbDispatcher {
    fn dispatch(&mut self, command: DbCommand, context: &mut CommandContext<'_>) -> Result<CommandOutput, ToolkitError>;
}

pub struct ServiceDbDispatcher<'a>(pub &'a mut dyn DbServices);
impl DbDispatcher for ServiceDbDispatcher<'_> {
    fn dispatch(&mut self, command: DbCommand, _context: &mut CommandContext<'_>) -> Result<CommandOutput, ToolkitError> {
        match command {
            DbCommand::Convert(args) => self.0.convert(&args),
            DbCommand::Archive(args) => self.0.archive(&args),
            DbCommand::Copy(args) => self.0.copy(&args),
            DbCommand::Checkpoint(args) => self.0.checkpoint(&args),
            DbCommand::Lite(args) => self.0.lite(&args),
            DbCommand::Move(args) => self.0.move_store(&args),
            DbCommand::Root(args) => self.0.root(&args),
            DbCommand::Inspect(args) => self.0.inspect(&args),
            DbCommand::Backup(args) => self.0.backup(&args),
            DbCommand::Migrate(args) => self.0.migrate(&args),
            DbCommand::Resume(args) => self.0.resume(&args),
            DbCommand::Rollback(args) => self.0.rollback(&args),
            DbCommand::Capabilities(args) => self.0.capabilities(&args),
        }
    }
}
