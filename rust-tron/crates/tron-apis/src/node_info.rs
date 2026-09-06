use std::collections::BTreeMap;
use tron_protocol::protocol::{NodeInfo, NodeList, node_info};

#[derive(Clone, Debug, Default, PartialEq)]
pub struct NodeInfoSnapshot {
    pub begin_sync_num: i64,
    pub block: String,
    pub solidity_block: String,
    pub current_connect_count: i32,
    pub active_connect_count: i32,
    pub passive_connect_count: i32,
    pub total_flow: i64,
    pub peers: Vec<node_info::PeerInfo>,
    pub config: node_info::ConfigNodeInfo,
    pub machine: node_info::MachineInfo,
    pub cheat_witnesses: BTreeMap<String, String>,
}
impl NodeInfoSnapshot {
    #[must_use]
    pub fn into_proto(self) -> NodeInfo {
        NodeInfo {
            begin_sync_num: self.begin_sync_num,
            block: self.block,
            solidity_block: self.solidity_block,
            current_connect_count: self.current_connect_count,
            active_connect_count: self.active_connect_count,
            passive_connect_count: self.passive_connect_count,
            total_flow: self.total_flow,
            peer_info_list: self.peers,
            config_node_info: Some(self.config),
            machine_info: Some(self.machine),
            cheat_witness_info_map: self.cheat_witnesses,
        }
    }
}
pub trait NetworkSnapshot: Send + Sync {
    fn nodes(&self) -> NodeList;
    fn node_info(&self, head_block: u64, solidity_block: u64) -> NodeInfoSnapshot;
}

#[derive(Clone, Debug)]
pub struct DisconnectedNetworkSnapshot {
    pub config: node_info::ConfigNodeInfo,
    pub machine: node_info::MachineInfo,
}

impl Default for DisconnectedNetworkSnapshot {
    fn default() -> Self {
        Self {
            config: node_info::ConfigNodeInfo {
                code_version: env!("CARGO_PKG_VERSION").into(),
                support_constant: true,
                ..Default::default()
            },
            machine: node_info::MachineInfo {
                thread_count: i32::try_from(std::thread::available_parallelism().map_or(1, usize::from)).unwrap_or(i32::MAX),
                cpu_count: i32::try_from(std::thread::available_parallelism().map_or(1, usize::from)).unwrap_or(i32::MAX),
                os_name: std::env::consts::OS.into(),
                ..Default::default()
            },
        }
    }
}

impl NetworkSnapshot for DisconnectedNetworkSnapshot {
    fn nodes(&self) -> NodeList { NodeList { nodes: Vec::new() } }
    fn node_info(&self, head_block: u64, solidity_block: u64) -> NodeInfoSnapshot {
        NodeInfoSnapshot {
            begin_sync_num: i64::try_from(solidity_block).unwrap_or(i64::MAX),
            block: head_block.to_string(),
            solidity_block: solidity_block.to_string(),
            config: self.config.clone(),
            machine: self.machine.clone(),
            ..Default::default()
        }
    }
}

pub trait NodeInfoSource: Send + Sync {
    fn snapshot(&self) -> NodeInfoSnapshot;
}
#[derive(Clone)]
pub struct NodeInfoService<S> {
    source: S,
}
impl<S: NodeInfoSource> NodeInfoService<S> {
    #[must_use]
    pub const fn new(source: S) -> Self {
        Self { source }
    }
    #[must_use]
    pub fn get_node_info(&self) -> NodeInfo {
        self.source.snapshot().into_proto()
    }
}
