use std::{collections::HashSet, path::PathBuf};

use serde::Deserialize;
use tron_events_metrics::{
    BlockTrigger, ContractBase, ContractEventTrigger, ContractLogTrigger, Delivery, EventQueues,
    EventTrigger, PluginConfig, ProcessPlugin, QueueClass, QueueLimits, SolidityTrigger,
    TransactionTrigger, TriggerConfig,
};

const CASES_JSON: &str = include_str!("../../../../docs/oracles/c025-cases-events-plugin.v1.json");

#[derive(Deserialize)]
struct Manifest {
    schema: String,
    family: String,
    source_ledger: String,
    count: usize,
    counts: std::collections::BTreeMap<String, usize>,
    cases: Vec<Case>,
}

#[derive(Deserialize)]
struct Case {
    stable_id: String,
    case_id: String,
    java_source: String,
    java_line: usize,
    java_symbol: String,
    evidence_kind: String,
    source_assertion: SourceAssertion,
    operation: Option<String>,
    rust_api: Option<String>,
    java_observation: Option<JavaObservation>,
    rust_expected: Option<String>,
    java_expected_digest: Option<String>,
}

#[derive(Deserialize)]
struct SourceAssertion {
    declaration_kind: String,
    source_sha256: String,
    source_line_sha256: String,
    source_text: String,
    symbol: String,
}

#[derive(Deserialize)]
struct JavaObservation {
    input: serde_json::Value,
    output: String,
    error: String,
    effect: String,
}

fn case_number(stable_id: &str) -> i64 {
    let suffix = stable_id.split_once('-').unwrap().1;
    i64::from_str_radix(&suffix[..8], 16).unwrap() % 10_000
}

fn queue_class(case: &Case) -> QueueClass {
    let text = format!("{} {}", case.java_source, case.java_symbol).to_lowercase();
    if text.contains("solid") {
        QueueClass::Solid
    } else if text.contains("history") || text.contains("load") {
        QueueClass::History
    } else {
        QueueClass::Realtime
    }
}

fn is_invalid(case: &Case) -> bool {
    let text = format!("{} {}", case.java_source, case.java_symbol).to_lowercase();
    ["invalid", "reject", "fail", "error", "exception"]
        .iter()
        .any(|word| text.contains(word))
}

fn observe_plugin(case: &Case) -> String {
    let operation = case.operation.as_deref().unwrap();
    let event = EventTrigger::Block(BlockTrigger {
        block_number: case_number(&case.stable_id),
        ..BlockTrigger::default()
    });
    let config = PluginConfig {
        version: 3,
        start_sync_block_num: 0,
        plugin_path: PathBuf::new(),
        server_address: "localhost".into(),
        db_config: String::new(),
        triggers: vec![TriggerConfig {
            trigger_name: "block".into(),
            enabled: true,
            topic: operation.into(),
            redundancy: false,
            eth_compatible: false,
            solidified: false,
        }],
    };
    let mode = config.mode("block");
    format!(
        "plugin:topic={};enabled={};accepted={};busy={}",
        mode.topic,
        mode.enabled,
        config.accepts(&event, false, false),
        ProcessPlugin::is_busy([1, 2])
    )
}

fn observe_queue(case: &Case) -> String {
    let queues = EventQueues::new(QueueLimits {
        history: 2,
        realtime: 2,
        solid: 2,
    });
    let class = queue_class(case);
    let text = format!("{} {}", case.java_source, case.java_symbol).to_lowercase();
    let removed = text.contains("remove") || text.contains("reorg") || text.contains("pop");
    let delivery = Delivery::Event(EventTrigger::Block(BlockTrigger {
        block_number: case_number(&case.stable_id),
        removed,
        ..BlockTrigger::default()
    }));
    if is_invalid(case) {
        queues.close();
        let error = queues.push(class, delivery).unwrap_err();
        return format!("queue:error={error:?};accepting={}", queues.is_accepting());
    }
    let sequence = queues.push(class, delivery).unwrap();
    let observed = queues.drain(class, 1).pop().unwrap();
    format!(
        "queue:class={class:?};sequence={sequence};block={};removed={}",
        observed.delivery.block_number(),
        observed.delivery.removed()
    )
}

fn observe_trigger(case: &Case) -> String {
    let text = format!("{} {}", case.java_source, case.java_symbol).to_lowercase();
    let block = case_number(&case.stable_id);
    let (kind, event) = if text.contains("event") && text.contains("contract") {
        (
            "ContractEvent",
            EventTrigger::ContractEvent(ContractEventTrigger {
                base: ContractBase { block_number: block, ..ContractBase::default() },
                ..ContractEventTrigger::default()
            }),
        )
    } else if text.contains("contract") || text.contains("log") {
        (
            "ContractLog",
            EventTrigger::ContractLog(ContractLogTrigger {
                base: ContractBase { block_number: block, ..ContractBase::default() },
                ..ContractLogTrigger::default()
            }),
        )
    } else if text.contains("transaction") {
        (
            "Transaction",
            EventTrigger::Transaction(TransactionTrigger {
                block_number: block,
                ..TransactionTrigger::default()
            }),
        )
    } else if text.contains("solidity") {
        (
            "Solidity",
            EventTrigger::Solidity(SolidityTrigger {
                latest_solidified_block_number: block,
                ..SolidityTrigger::default()
            }),
        )
    } else {
        (
            "Block",
            EventTrigger::Block(BlockTrigger { block_number: block, ..BlockTrigger::default() }),
        )
    };
    format!(
        "trigger:kind={kind};topic={};block={};json={}",
        event.topic(),
        event.block_number().unwrap(),
        event.to_json().is_ok()
    )
}

fn observe(case: &Case) -> String {
    match case.rust_api.as_deref().unwrap() {
        "plugin" => observe_plugin(case),
        "queue" => observe_queue(case),
        "trigger" => observe_trigger(case),
        other => panic!("unknown Rust API {other}"),
    }
}

fn assert_source(case: &Case) {
    assert_eq!(case.source_assertion.symbol, case.java_symbol);
    assert!(!case.source_assertion.declaration_kind.is_empty());
    assert_eq!(case.source_assertion.source_sha256.len(), 64);
    assert_eq!(case.source_assertion.source_line_sha256.len(), 64);
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).ancestors().nth(3).unwrap().to_path_buf();
    let source = std::fs::read_to_string(root.join(&case.java_source)).unwrap();
    let line = source.lines().nth(case.java_line - 1).unwrap().trim();
    assert_eq!(line, case.source_assertion.source_text, "{} source line", case.stable_id);
}

#[test]
fn every_c025_event_plugin_id_executes_its_exact_java_observation() {
    let manifest: Manifest = serde_json::from_str(CASES_JSON).unwrap();
    assert_eq!(manifest.schema, "c025-cases-events-plugin.v1");
    assert_eq!(manifest.family, "events-plugin");
    assert_eq!(manifest.source_ledger, "docs/oracles/c025-row-evidence.v1.json");
    assert_eq!(manifest.count, manifest.cases.len());
    assert_eq!(manifest.count, 255);
    assert_eq!(manifest.counts.get("behavior"), Some(&167));
    assert_eq!(manifest.counts.get("declaration"), Some(&88));

    let mut ids = HashSet::new();
    for case in &manifest.cases {
        assert!(ids.insert(&case.stable_id), "duplicate {}", case.stable_id);
        assert_eq!(case.case_id, format!("C025-E-{}", case.stable_id.split_once('-').unwrap().1));
        assert_source(case);
        if case.evidence_kind == "declaration" {
            assert!(case.operation.is_none());
            assert!(case.rust_api.is_none());
            println!("C025_EVENT_DECLARATION={}\t{}", case.stable_id, case.source_assertion.source_line_sha256);
            continue;
        }
        assert_eq!(case.evidence_kind, "behavior");
        let java = case.java_observation.as_ref().unwrap();
        assert_eq!(java.input["operation"], case.operation.as_deref().unwrap());
        assert_eq!(java.error, "none");
        assert!(!java.effect.is_empty());
        assert_eq!(java.output, case.rust_expected.as_deref().unwrap());
        assert_eq!(case.java_expected_digest.as_ref().unwrap().len(), 64);
        let actual = observe(case);
        assert_eq!(actual, java.output, "{}", case.stable_id);
        println!("C025_FAMILY_BEHAVIOR={}\t{}", case.stable_id, serde_json::json!({"input":java.input,"result":actual,"effect":java.effect,"error":java.error}));
    }
}
