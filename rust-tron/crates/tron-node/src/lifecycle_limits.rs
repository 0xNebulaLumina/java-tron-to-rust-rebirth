//! Family-specific C025 application, legacy keystore, Solidity replica, and transport behavior.

use std::{collections::VecDeque, sync::{Arc, atomic::{AtomicBool, Ordering}}, time::Duration};

use tron_apis::server::{GrpcServerPlan, ServerConfigError, ServerMode};
use tron_config::{NodeMode, RpcConfig};

/// The validated plaintext gRPC transport policy used by the production API server.
pub fn grpc_transport_policy(rpc: &RpcConfig, mode: ServerMode) -> Result<GrpcServerPlan, ServerConfigError> {
    GrpcServerPlan::from_config(mode, rpc, false, false)
}

/// Observable transcript of the deprecated `--keystore-factory` REPL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LegacyKeystoreTranscript {
    pub stderr: String,
    pub stdout: String,
}

/// Runs the compatibility-only legacy keystore command dispatcher without constructing node services.
#[must_use]
pub fn run_legacy_keystore_factory(input: &str) -> LegacyKeystoreTranscript {
    let mut stdout = String::new();
    let stderr = "--keystore-factory is deprecated; use Toolkit.jar keystore instead\n".to_owned();
    for line in input.lines() {
        let command = line.trim();
        if command.is_empty() { continue; }
        match command.to_ascii_lowercase().as_str() {
            "help" => stdout.push_str("GenKeystore\nImportPrivateKey\nExit\n"),
            "exit" | "quit" => { stdout.push_str("Exit\n"); break; }
            "genkeystore" => stdout.push_str("Please input password\n"),
            "importprivatekey" => stdout.push_str("Please input private key\n"),
            _ => stdout.push_str(&format!("Invalid cmd: {command}\n")),
        }
    }
    LegacyKeystoreTranscript { stderr, stdout }
}

/// A narrow client boundary for the Java Solidity-node pull loop.
pub trait SoliditySource: Send {
    type Block: Clone + Send;
    fn block(&mut self, number: i64) -> Result<Option<(i64, Self::Block)>, String>;
    fn last_solidity_block(&mut self) -> Result<i64, String>;
    fn shutdown(&mut self);
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SolidityReplicaError { Closing, Source(String) }

/// Pulls and queues FullNode blocks for a Solidity node while preserving shutdown races and retries.
pub struct SolidityReplica<S: SoliditySource> {
    source: S,
    running: Arc<AtomicBool>,
    queue: VecDeque<S::Block>,
}
impl<S: SoliditySource> SolidityReplica<S> {
    #[must_use] pub fn new(source: S) -> Self { Self { source, running: Arc::new(AtomicBool::new(true)), queue: VecDeque::new() } }
    #[must_use] pub fn running_handle(&self) -> Arc<AtomicBool> { self.running.clone() }
    #[must_use] pub fn is_running(&self) -> bool { self.running.load(Ordering::Acquire) }
    pub fn on_context_closed(&self) { self.running.store(false, Ordering::Release); }
    pub fn fetch_block(&mut self, number: i64, retry_delay: Duration) -> Result<S::Block, SolidityReplicaError> {
        while self.is_running() {
            match self.source.block(number) {
                Ok(Some((actual, block))) if actual == number => return Ok(block),
                Ok(_) | Err(_) if self.is_running() => std::thread::sleep(retry_delay),
                Err(_) | Ok(_) => break,
            }
        }
        Err(SolidityReplicaError::Closing)
    }
    pub fn last_solidity_block(&mut self, retry_delay: Duration) -> i64 {
        while self.is_running() {
            match self.source.last_solidity_block() {
                Ok(number) => return number,
                Err(_) if self.is_running() => std::thread::sleep(retry_delay),
                Err(_) => break,
            }
        }
        0
    }
    pub fn enqueue(&mut self, block: S::Block) { self.queue.push_back(block); }
    pub fn process_next(&mut self, mut process: impl FnMut(S::Block) -> Result<(), String>) -> Result<bool, String> {
        let Some(block) = self.queue.pop_front() else { return Ok(false); };
        process(block)?;
        Ok(true)
    }
    pub fn close(&mut self) { self.on_context_closed(); self.source.shutdown(); self.queue.clear(); }
}

#[must_use]
pub fn program_mode(solidity: bool, keystore_factory: bool) -> NodeMode {
    if keystore_factory { NodeMode::KeystoreFactory } else if solidity { NodeMode::Solidity } else { NodeMode::Full }
}

#[must_use]
pub fn program_version() -> &'static str { env!("CARGO_PKG_VERSION") }
