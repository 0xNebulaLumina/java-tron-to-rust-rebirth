#[cfg(unix)]
mod unix {
    use std::{fs, os::unix::fs::PermissionsExt, path::PathBuf, sync::atomic::{AtomicU64, Ordering}, time::{Duration, Instant, SystemTime, UNIX_EPOCH}};
    use tron_events_metrics::{BlockTrigger, EventTrigger, PluginConfig, PluginError, ProcessPlugin, TransactionTrigger, TriggerConfig, MAX_HANDSHAKE_BYTES};
    static NEXT_SCRIPT: AtomicU64 = AtomicU64::new(0);
    fn unique_path(label: &str) -> PathBuf { std::env::temp_dir().join(format!("c025-plugin-{label}-{}-{}-{}", std::process::id(), SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos(), NEXT_SCRIPT.fetch_add(1, Ordering::Relaxed))) }

    fn script(version: &str) -> PathBuf {
        let path = unique_path("normal");
        fs::write(&path, format!("#!/bin/sh\nprintf '%s\\n' '{{\"version\":\"{version}\"}}'\nwhile IFS= read -r line; do\n  case \"$line\" in *'\"command\":\"stop\"'*) exit 0;; esac\ndone\n")).unwrap();
        let mut permissions = fs::metadata(&path).unwrap().permissions(); permissions.set_mode(0o700); fs::set_permissions(&path, permissions).unwrap(); path
    }
    fn custom_script(body: &str) -> PathBuf {
        let path = unique_path("malicious");
        fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
        let mut permissions = fs::metadata(&path).unwrap().permissions(); permissions.set_mode(0o700); fs::set_permissions(&path, permissions).unwrap(); path
    }
    fn recording_script(output: &PathBuf) -> PathBuf {
        let path = unique_path("recording");
        fs::write(&path, format!("#!/bin/sh\nprintf '%s\\n' '{{\"version\":\"3.0.0\"}}'\nwhile IFS= read -r line; do\n  printf '%s\\n' \"$line\" >> '{}'\n  case \"$line\" in *'\"command\":\"stop\"'*) exit 0;; esac\ndone\n", output.display())).unwrap();
        let mut permissions = fs::metadata(&path).unwrap().permissions(); permissions.set_mode(0o700); fs::set_permissions(&path, permissions).unwrap(); path
    }

    fn trigger(name: &str, enabled: bool, topic: &str) -> TriggerConfig {
        TriggerConfig { trigger_name: name.into(), enabled, topic: topic.into(), ..TriggerConfig::default() }
    }
    fn config(path: PathBuf) -> PluginConfig { PluginConfig { version: 1, start_sync_block_num: 10, plugin_path: path, server_address: "server".into(), db_config: "db".into(), triggers: vec![TriggerConfig { trigger_name: "block".into(), enabled: true, topic: "blocks".into(), redundancy: false, eth_compatible: false, solidified: true }] } }

    #[test]
    fn accepts_version_three_and_configures_before_lifecycle() {
        let path = script("3.0.0"); let mut plugin = ProcessPlugin::start(&config(path.clone())).unwrap();
        assert_eq!(plugin.version(), "3.0.0"); assert_eq!(plugin.topics().get(&0).map(String::as_str), Some("blocks"));
        plugin.shutdown().unwrap(); fs::remove_file(path).unwrap();
    }
    #[test]
    fn publish_uses_custom_topic_and_disabled_trigger_is_silent() {
        let output = unique_path("frames");
        let path = recording_script(&output);
        let mut config = config(path.clone());
        config.triggers.push(trigger("transaction", false, "disabled-transactions"));
        let mut plugin = ProcessPlugin::start(&config).unwrap();
        plugin.publish(&EventTrigger::Block(BlockTrigger { block_number: 7, ..BlockTrigger::default() })).unwrap();
        plugin.publish(&EventTrigger::Transaction(TransactionTrigger { transaction_id: "ignored".into(), ..TransactionTrigger::default() })).unwrap();
        plugin.shutdown().unwrap();
        let frames: Vec<serde_json::Value> = fs::read_to_string(&output).unwrap().lines().map(|line| serde_json::from_str(line).unwrap()).collect();
        assert_eq!(frames[0]["topics"]["0"], "blocks");
        assert_eq!(frames[0]["topics"]["1"], "disabled-transactions");
        assert_eq!(frames.iter().filter(|frame| frame["command"] == "event").count(), 1);
        assert_eq!(frames[2]["topic"], "blocks");
        fs::remove_file(path).unwrap(); fs::remove_file(output).unwrap();
    }

    #[test]
    fn eth_compatible_transaction_matches_java_contract_address_rule() {
        let output = unique_path("eth-frames");
        let path = recording_script(&output);
        let mut config = config(path.clone());
        config.triggers = vec![TriggerConfig { eth_compatible: true, ..trigger("transaction", true, "eth-transactions") }];
        let mut plugin = ProcessPlugin::start(&config).unwrap();
        plugin.publish(&EventTrigger::Transaction(TransactionTrigger { transaction_id: "01".into(), contract_type: "TriggerSmartContract".into(), contract_address: "41deadbeef".into(), transaction_index: 3, cumulative_energy_used: 9, ..TransactionTrigger::default() })).unwrap();
        plugin.shutdown().unwrap();
        let frames: Vec<serde_json::Value> = fs::read_to_string(&output).unwrap().lines().map(|line| serde_json::from_str(line).unwrap()).collect();
        assert_eq!(frames[2]["topic"], "eth-transactions");
        let payload: serde_json::Value = serde_json::from_str(frames[2]["json"].as_str().unwrap()).unwrap();
        assert!(payload["contractAddress"].is_null());
        assert_eq!(payload["transactionIndex"], 3);
        assert_eq!(payload["cumulativeEnergyUsed"], 9);
        fs::remove_file(path).unwrap(); fs::remove_file(output).unwrap();
    }

    #[test]
    fn configured_modes_separate_realtime_solid_history_and_unconfigured() {
        let path = script("3.0.0");
        let mut config = config(path.clone());
        config.start_sync_block_num = 10;
        config.triggers = vec![TriggerConfig { solidified: true, ..trigger("block", true, "solid-blocks") }, trigger("contractlog", true, "logs"), trigger("solidity", true, "solid-head")];
        let block = EventTrigger::Block(BlockTrigger { block_number: 10, ..BlockTrigger::default() });
        let old_block = EventTrigger::Block(BlockTrigger { block_number: 9, ..BlockTrigger::default() });
        let log = EventTrigger::ContractLog(Default::default());
        let solidity = EventTrigger::Solidity(Default::default());
        let transaction = EventTrigger::Transaction(Default::default());
        assert!(!config.accepts(&block, false, false));
        assert!(config.accepts(&block, false, true));
        assert!(!config.accepts(&old_block, true, true));
        assert!(config.accepts(&log, false, false));
        assert!(!config.accepts(&log, false, true));
        assert!(!config.accepts(&solidity, false, false));
        assert!(config.accepts(&solidity, false, true));
        assert!(!config.accepts(&transaction, false, false));
        fs::remove_file(path).unwrap();
    }
    #[test]
    fn redundancy_is_trigger_local_and_disabled_configs_clear_it() {
        let path = script("3.0.0");
        let mut config = config(path.clone());
        config.triggers = vec![
            TriggerConfig { redundancy: true, ..trigger("contractlog", true, "logs") },
            TriggerConfig { redundancy: true, ..trigger("soliditylog", false, "solid-logs") },
            TriggerConfig { redundancy: true, ..trigger("contractevent", true, "events") },
        ];
        assert!(config.mode("contractlog").redundancy);
        assert!(!config.mode("soliditylog").redundancy);
        assert!(config.mode("contractevent").redundancy);
        assert!(!config.mode("missing").redundancy);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn rejects_old_plugin_without_loading_it_in_process() {
        let path = script("2.2.0"); let error = ProcessPlugin::start(&config(path.clone())).err().unwrap();
        assert!(matches!(error, PluginError::Version { .. })); fs::remove_file(path).unwrap();
    }

    #[test]
    fn rejects_handshake_without_newline_and_reaps_child() {
        let path = custom_script("printf '{\"version\":\"3.0.0\"}'");
        let started = Instant::now();
        assert!(matches!(ProcessPlugin::start(&config(path.clone())), Err(PluginError::Protocol(_))));
        assert!(started.elapsed() < Duration::from_secs(2));
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn bounds_malicious_handshake_bytes() {
        let body = format!("head -c {} /dev/zero | tr '\\0' x", MAX_HANDSHAKE_BYTES + 1);
        let path = custom_script(&body);
        assert!(matches!(ProcessPlugin::start(&config(path.clone())), Err(PluginError::HandshakeTooLarge(_))));
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn never_read_plugin_write_is_bounded_and_drop_reaps() {
        let path = custom_script("printf '%s\\n' '{\"version\":\"3.0.0\"}'; exec sleep 30");
        let mut plugin = ProcessPlugin::start(&config(path.clone())).unwrap();
        let started = Instant::now();
        let mut result = Ok(());
        for _ in 0..20_000 { result = plugin.pending_probe(); if result.is_err() { break; } }
        assert!(result.is_err());
        assert!(started.elapsed() < Duration::from_secs(5));
        drop(plugin);
        fs::remove_file(path).unwrap();
    }
}
