use std::{collections::BTreeMap, io::{BufRead, BufReader, Read, Write}, path::PathBuf, process::{Child, ChildStdin, Command, Stdio}, sync::mpsc::{self, Receiver, SyncSender}, thread::{self, JoinHandle}, time::{Duration, Instant}};

use serde::{Deserialize, Serialize};

use crate::events::EventTrigger;

pub const MIN_PLUGIN_VERSION: &str = "3.0.0";
pub const MAX_PENDING_SIZE: usize = 50_000;
pub const PLUGIN_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
pub const PLUGIN_IO_TIMEOUT: Duration = Duration::from_secs(2);
pub const MAX_HANDSHAKE_BYTES: usize = 8 * 1024;
pub const PLUGIN_WRITE_QUEUE: usize = 64;

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TriggerConfig { pub trigger_name: String, pub enabled: bool, pub topic: String, pub redundancy: bool, pub eth_compatible: bool, pub solidified: bool }

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PluginConfig { pub version: u32, pub start_sync_block_num: i64, pub plugin_path: PathBuf, pub server_address: String, pub db_config: String, #[serde(default)] pub triggers: Vec<TriggerConfig> }

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct EventModes { pub enabled: bool, pub redundancy: bool, pub eth_compatible: bool, pub solidified: bool, pub topic: String }
impl PluginConfig {
    pub fn mode(&self, name: &str) -> EventModes {
        self.triggers.iter().rev().find(|trigger| trigger.trigger_name.eq_ignore_ascii_case(name)).map(|trigger| EventModes {
            enabled: trigger.enabled,
            redundancy: trigger.enabled && trigger.redundancy,
            eth_compatible: trigger.enabled && trigger.eth_compatible,
            solidified: trigger.enabled && trigger.solidified,
            topic: trigger.topic.clone(),
        }).unwrap_or_default()
    }

    pub fn accepts(&self, event: &EventTrigger, history: bool, solidified: bool) -> bool {
        let mode = self.mode(event_config_name(event));
        if !mode.enabled || (history && event.block_number().is_none_or(|height| height < self.start_sync_block_num)) { return false; }
        match event {
            EventTrigger::Block(_) | EventTrigger::Transaction(_) => mode.solidified == solidified,
            EventTrigger::ContractLog(_) | EventTrigger::ContractEvent(_) => !solidified,
            EventTrigger::Solidity(_) | EventTrigger::SolidityLog(_) | EventTrigger::SolidityEvent(_) => solidified,
        }
    }
    pub fn event_json(&self, event: &EventTrigger) -> Result<String, serde_json::Error> {
        configured_json(event, self.mode(event_config_name(event)).eth_compatible)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum PluginError {
    #[error("plugin executable does not exist: {0}")] Missing(String),
    #[error("plugin I/O failed: {0}")] Io(#[from] std::io::Error),
    #[error("plugin operation timed out: {0}")] Timeout(&'static str),
    #[error("plugin handshake exceeds {0} bytes")] HandshakeTooLarge(usize),
    #[error("invalid plugin response: {0}")] Protocol(String),
    #[error("plugin version {found} is older than required {required}")] Version { found: String, required: &'static str },
    #[error("plugin process exited")] Exited,
    #[error("plugin shutdown failed: {0}")] Shutdown(String),
}

#[derive(Deserialize)] struct Hello { version: String }
#[derive(Serialize)] #[serde(tag = "command", rename_all = "camelCase")] enum Request<'a> { Configure { server_address: &'a str, db_config: &'a str, topics: &'a BTreeMap<u8, String> }, Start, Event { topic: &'a str, json: &'a str }, Pending, Stop }

type WriteReply = SyncSender<Result<(), String>>;
enum WriteCommand { Line(Vec<u8>, WriteReply), Close }

pub struct ProcessPlugin { child: Child, writes: SyncSender<WriteCommand>, writer: Option<JoinHandle<()>>, version: String, topics: BTreeMap<u8, String>, triggers: BTreeMap<u8, TriggerConfig>, running: bool }
impl ProcessPlugin {
    pub fn start(config: &PluginConfig) -> Result<Self, PluginError> {
        if !config.plugin_path.is_file() { return Err(PluginError::Missing(config.plugin_path.display().to_string())); }
        let mut child = spawn_child(config)?;
        let result = Self::finish_start(config, &mut child);
        match result {
            Ok((writes, writer, version, topics, triggers)) => Ok(Self { child, writes, writer: Some(writer), version, topics, triggers, running: true }),
            Err(error) => { terminate_and_reap(&mut child); Err(error) }
        }
    }

    fn finish_start(config: &PluginConfig, child: &mut Child) -> Result<(SyncSender<WriteCommand>, JoinHandle<()>, String, BTreeMap<u8, String>, BTreeMap<u8, TriggerConfig>), PluginError> {
        let input = child.stdin.take().ok_or_else(|| PluginError::Protocol("plugin stdin unavailable".into()))?;
        let output = child.stdout.take().ok_or_else(|| PluginError::Protocol("plugin stdout unavailable".into()))?;
        let (hello_tx, hello_rx) = mpsc::sync_channel(1);
        let reader = thread::spawn(move || { let _ = hello_tx.send(read_handshake(output)); });
        let line = match hello_rx.recv_timeout(PLUGIN_HANDSHAKE_TIMEOUT) {
            Ok(result) => { reader.join().map_err(|_| PluginError::Protocol("handshake reader panicked".into()))?; result? }
            Err(_) => { terminate_and_reap(child); let _ = reader.join(); return Err(PluginError::Timeout("handshake")); }
        };
        let hello: Hello = serde_json::from_slice(&line).map_err(|e| PluginError::Protocol(e.to_string()))?;
        if compare_versions(&hello.version, MIN_PLUGIN_VERSION).is_lt() { return Err(PluginError::Version { found: hello.version, required: MIN_PLUGIN_VERSION }); }
        let triggers: BTreeMap<_, _> = config.triggers.iter().filter_map(|trigger| event_type(&trigger.trigger_name).map(|kind| (kind, trigger.clone()))).collect();
        let topics = triggers.iter().map(|(&kind, trigger)| (kind, trigger.topic.clone())).collect();
        let (writes, writer) = spawn_writer(input);
        let startup = send_line(&writes, &Request::Configure { server_address: &config.server_address, db_config: &config.db_config, topics: &topics })
            .and_then(|()| send_line(&writes, &Request::Start));
        if let Err(error) = startup { terminate_and_reap(child); let _ = writes.try_send(WriteCommand::Close); let _ = writer.join(); return Err(error); }
        Ok((writes, writer, hello.version, topics, triggers))
    }

    fn send(&mut self, request: &Request<'_>) -> Result<(), PluginError> {
        if self.child.try_wait()?.is_some() { return Err(PluginError::Exited); }
        match send_line(&self.writes, request) { Ok(()) => Ok(()), Err(error) => { self.running = false; terminate_and_reap(&mut self.child); let _ = self.writes.try_send(WriteCommand::Close); join_writer(&mut self.writer); Err(error) } }
    }
    pub fn publish(&mut self, event: &EventTrigger) -> Result<(), PluginError> {
        let Some(config) = self.triggers.get(&event_type(event_config_name(event)).expect("event names are exhaustive")) else { return Ok(()); };
        if !config.enabled { return Ok(()); }
        let json = configured_json(event, config.eth_compatible).map_err(|error| PluginError::Protocol(error.to_string()))?;
        let topic = config.topic.clone();
        self.send(&Request::Event { topic: &topic, json: &json })
    }
    pub fn pending_probe(&mut self) -> Result<(), PluginError> { self.send(&Request::Pending) }
    pub fn is_busy(pending_sizes: impl IntoIterator<Item = usize>) -> bool { pending_sizes.into_iter().try_fold(0usize, |sum, value| sum.checked_add(value)).is_none_or(|sum| sum >= MAX_PENDING_SIZE) }
    pub fn version(&self) -> &str { &self.version }
    pub fn topics(&self) -> &BTreeMap<u8, String> { &self.topics }
    pub fn shutdown(&mut self) -> Result<(), PluginError> {
        if self.writer.is_none() { return Ok(()); }
        let mut failures = Vec::new();
        if self.running { if let Err(error) = send_line(&self.writes, &Request::Stop) { failures.push(format!("Stop send: {error}")); } }
        self.running = false;
        if !self.child.wait_timeout(PLUGIN_IO_TIMEOUT)? {
            if let Err(error) = self.child.kill() { failures.push(format!("kill: {error}")); }
            if let Err(error) = self.child.wait() { failures.push(format!("wait: {error}")); }
        }
        let _ = self.writes.try_send(WriteCommand::Close);
        join_writer(&mut self.writer);
        if failures.is_empty() { Ok(()) } else { Err(PluginError::Shutdown(failures.join("; "))) }
    }
}
impl Drop for ProcessPlugin { fn drop(&mut self) { let _ = self.shutdown(); } }

fn read_handshake(output: impl Read) -> Result<Vec<u8>, PluginError> {
    let mut bytes = Vec::new();
    let count = BufReader::new(output).take((MAX_HANDSHAKE_BYTES + 1) as u64).read_until(b'\n', &mut bytes)?;
    if count == 0 { return Err(PluginError::Exited); }
    if count > MAX_HANDSHAKE_BYTES { return Err(PluginError::HandshakeTooLarge(MAX_HANDSHAKE_BYTES)); }
    if !bytes.ends_with(b"\n") { return Err(PluginError::Protocol("plugin handshake missing newline".into())); }
    Ok(bytes)
}
fn spawn_child(config: &PluginConfig) -> Result<Child, PluginError> {
    let deadline = Instant::now() + Duration::from_millis(250);
    loop {
        match Command::new(&config.plugin_path).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::inherit()).spawn() {
            Ok(child) => return Ok(child),
            Err(error) if error.raw_os_error() == Some(26) && Instant::now() < deadline => thread::sleep(Duration::from_millis(10)),
            Err(error) => return Err(PluginError::Io(error)),
        }
    }
}
fn spawn_writer(mut input: ChildStdin) -> (SyncSender<WriteCommand>, JoinHandle<()>) {
    let (tx, rx): (SyncSender<WriteCommand>, Receiver<WriteCommand>) = mpsc::sync_channel(PLUGIN_WRITE_QUEUE);
    let join = thread::spawn(move || while let Ok(command) = rx.recv() { match command { WriteCommand::Line(bytes, reply) => { let result = input.write_all(&bytes).and_then(|_| input.flush()).map_err(|e| e.to_string()); let failed = result.is_err(); let _ = reply.send(result); if failed { break; } }, WriteCommand::Close => break } });
    (tx, join)
}
fn send_line(writes: &SyncSender<WriteCommand>, request: &Request<'_>) -> Result<(), PluginError> {
    let mut bytes = serde_json::to_vec(request).map_err(|e| PluginError::Protocol(e.to_string()))?; bytes.push(b'\n');
    let (reply_tx, reply_rx) = mpsc::sync_channel(1);
    writes.try_send(WriteCommand::Line(bytes, reply_tx)).map_err(|error| match error { mpsc::TrySendError::Full(_) => PluginError::Protocol("plugin write queue is full".into()), mpsc::TrySendError::Disconnected(_) => PluginError::Exited })?;
    reply_rx.recv_timeout(PLUGIN_IO_TIMEOUT).map_err(|_| PluginError::Timeout("write"))?.map_err(PluginError::Protocol)
}
fn terminate_and_reap(child: &mut Child) { if child.try_wait().ok().flatten().is_none() { let _ = child.kill(); } let _ = child.wait(); }
fn join_writer(writer: &mut Option<JoinHandle<()>>) { if let Some(join) = writer.take() { let _ = join.join(); } }
trait WaitTimeout { fn wait_timeout(&mut self, timeout: Duration) -> std::io::Result<bool>; }
impl WaitTimeout for Child { fn wait_timeout(&mut self, timeout: Duration) -> std::io::Result<bool> { let start = Instant::now(); loop { if self.try_wait()?.is_some() { return Ok(true); } if start.elapsed() >= timeout { return Ok(false); } thread::sleep(Duration::from_millis(10)); } } }
fn event_type(name: &str) -> Option<u8> { match name.to_ascii_lowercase().as_str() { "block" => Some(0), "transaction" => Some(1), "contractlog" => Some(2), "contractevent" => Some(3), "solidity" => Some(4), "solidityevent" => Some(5), "soliditylog" => Some(6), _ => None } }
fn event_config_name(event: &EventTrigger) -> &'static str { match event { EventTrigger::Block(_) => "block", EventTrigger::Transaction(_) => "transaction", EventTrigger::ContractLog(_) => "contractlog", EventTrigger::ContractEvent(_) => "contractevent", EventTrigger::Solidity(_) => "solidity", EventTrigger::SolidityLog(_) => "soliditylog", EventTrigger::SolidityEvent(_) => "solidityevent" } }
fn configured_json(event: &EventTrigger, eth_compatible: bool) -> Result<String, serde_json::Error> {
    let mut value = serde_json::to_value(match event { EventTrigger::Block(value) => serde_json::to_value(value)?, EventTrigger::Transaction(value) => serde_json::to_value(value)?, EventTrigger::ContractLog(value) | EventTrigger::SolidityLog(value) => serde_json::to_value(value)?, EventTrigger::ContractEvent(value) | EventTrigger::SolidityEvent(value) => serde_json::to_value(value)?, EventTrigger::Solidity(value) => serde_json::to_value(value)? })?;
    if eth_compatible {
        if let EventTrigger::Transaction(transaction) = event {
            if !transaction.contract_type.eq_ignore_ascii_case("CreateSmartContract") {
                value["contractAddress"] = serde_json::Value::Null;
            }
        }
    }
    serde_json::to_string(&value)
}
fn compare_versions(left: &str, right: &str) -> std::cmp::Ordering { fn parts(value: &str) -> impl Iterator<Item = u64> + '_ { value.split(['.', '-', '+']).map(|v| v.parse().unwrap_or(0)) } let mut l = parts(left); let mut r = parts(right); loop { match (l.next(), r.next()) { (None, None) => return std::cmp::Ordering::Equal, (a, b) => { let ordering = a.unwrap_or(0).cmp(&b.unwrap_or(0)); if !ordering.is_eq() { return ordering; } } } } }
