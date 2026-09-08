//! Operational and keystore toolkit composition-root boundary.
//!
//! C000 reserves this crate; toolkit behavior arrives under C027.

pub mod cli;
pub mod capability;
pub mod db;
pub mod error;
mod help;
pub mod io;
pub mod keystore;

use std::ffi::OsString;
use std::path::Path;

use tron_config::toolkit::PlatformFacts;

use crate::db::DbDispatcher;
use crate::error::{CommandOutcome, CommandOutput};
use crate::io::{Clock, CommandContext, KeyProvider, ToolkitIo};
use crate::keystore::KeystoreServices;

pub struct RuntimeServices<'a> {
    pub db: &'a mut dyn db::DbServices,
    pub keystore: &'a mut dyn KeystoreServices,
    pub clock: &'a dyn Clock,
    pub keys: &'a mut dyn KeyProvider,
}

pub fn run_with(
    args_os: &[OsString],
    cwd: &Path,
    platform: &PlatformFacts,
    io: &mut dyn ToolkitIo,
    services: RuntimeServices<'_>,
) -> CommandOutcome {
    let parsed = match cli::parse(args_os, cwd) {
        Ok(parsed) => parsed,
        Err(failure) => return finish(io, CommandOutput::stderr(format!("{}\n{}", failure.detail, failure.usage).into_bytes(), 2)),
    };
    let mut context = CommandContext { cwd, platform, io, clock: services.clock, keys: services.keys };
    let output = match parsed {
        cli::ParsedCommand::Help(target) => cli::help_output(target),
        cli::ParsedCommand::Version(target) => cli::version_output(target),
        cli::ParsedCommand::Db(command) => db::ServiceDbDispatcher(services.db).dispatch(command, &mut context).unwrap_or_else(|error| error.into_output()),
        cli::ParsedCommand::Keystore(command) => keystore::dispatch(command, &mut context, services.keystore).unwrap_or_else(|error| error.into_output()),
    };
    finish(context.io, output)
}

fn finish(io: &mut dyn ToolkitIo, output: CommandOutput) -> CommandOutcome {
    let logical_exit = output.logical_exit;
    let stdout = output.stdout;
    let stderr = output.stderr;
    if let Err(error) = io.write_stdout(&stdout) { return CommandOutcome { logical_exit: 1, stdout: Vec::new(), stderr: format!("error[operation_failure]: {error}\n").into_bytes() }; }
    if let Err(error) = io.write_stderr(&stderr) { return CommandOutcome { logical_exit: 1, stdout, stderr: format!("error[operation_failure]: {error}\n").into_bytes() }; }
    CommandOutcome { logical_exit, stdout, stderr }
}
