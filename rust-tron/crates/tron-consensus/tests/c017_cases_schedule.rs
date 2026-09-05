use std::collections::BTreeSet;

use serde::Deserialize;
use serde_json::Value;
use tron_consensus::{
    java_shuffle, sort_and_truncate_active, sort_witnesses, DposSlot, FixedClock,
    SlotContext,
};
use tron_protocol::protocol::Witness;

#[derive(Deserialize)]
struct Oracle {
    cases: Vec<Case>,
}

#[derive(Deserialize)]
struct Case {
    case_id: String,
    operation: String,
    parameters: Value,
    expected: String,
}

fn number(parameters: &Value, key: &str) -> i64 {
    parameters[key].as_i64().unwrap()
}

fn address(index: u8) -> Vec<u8> {
    [vec![0x41], vec![index; 20]].concat()
}

fn context(genesis: i64, head_time: i64, head_number: i64, maintenance: bool, skip: i64) -> SlotContext {
    SlotContext {
        genesis_time: genesis,
        head_number,
        head_time,
        head_is_maintenance: maintenance,
        maintenance_skip_slots: skip,
    }
}

#[test]
fn retained_schedule_rows_are_executable_and_exact() {
    let oracle: Oracle = serde_json::from_str(include_str!(
        "../../../../docs/oracles/c017-cases-schedule.v1.json"
    ))
    .unwrap();
    let expected_ids: BTreeSet<&str> = [
        "C017-P-AB9DE62A023A40D8",
        "C017-P-831E3B363C61F033",
        "C017-P-84DF7AD533173913",
        "C017-P-F85464EBEE501B7F",
        "C017-P-B5DCA574E178D254",
        "C017-P-1F9C1297E4682A34",
        "C017-P-6097E871859589CD",
        "C017-P-076E68231E15BD10",
        "C017-P-4AB37B283578C2A6",
        "C017-P-E677432B485C2DBA",
        "C017-P-3C35B9C818381115",
        "C017-P-AD6EA6D69C660319",
        "C017-P-1F4C692B8A536D40",
        "C017-P-0C110162A371B74B",
        "C017-T-9C237704A6491D7C",
        "C017-T-DFF7B5D7FDD06605",
    ]
    .into_iter()
    .collect();
    let actual_ids: BTreeSet<&str> = oracle.cases.iter().map(|case| case.case_id.as_str()).collect();
    assert_eq!(actual_ids, expected_ids);
    assert_eq!(oracle.cases.len(), expected_ids.len());

    let mut executed = BTreeSet::new();
    for case in oracle.cases {
        let p = &case.parameters;
        let result = match case.operation.as_str() {
            "get-witnesses" => {
                let count = number(p, "count") as usize;
                let witnesses = (0..count)
                    .map(|i| Witness { address: address(i as u8), vote_count: (count - i) as i64, ..Default::default() })
                    .collect();
                let active = sort_and_truncate_active(witnesses, true);
                format!("active-count={}", active.len())
            }
            "add-witness" => {
                let initial = number(p, "initial_count") as u8;
                let mut active: Vec<_> = (0..initial).map(address).collect();
                active.push(address(number(p, "added") as u8));
                let slots = DposSlot::new(FixedClock(3_000), context(0, 0, 0, false, 0));
                let selected = slots.scheduled_witness(number(p, "slot"), &active).unwrap()[1];
                format!("selected={selected}")
            }
            "head-slot" => {
                let genesis = number(p, "genesis");
                let slots = DposSlot::new(FixedClock(0), context(genesis, number(p, "head_time"), 1, false, 0));
                format!("head-slot={}", slots.absolute_slot(number(p, "head_time")))
            }
            "next-block-slot-time" => {
                let genesis = number(p, "genesis");
                let slots = DposSlot::new(FixedClock(0), context(genesis, number(p, "head_time"), 1, true, number(p, "skip_slots")));
                format!("next-time={}", slots.time(1).unwrap())
            }
            "save-active-witnesses" => {
                let count = number(p, "count") as usize;
                let witnesses = (0..count)
                    .map(|i| Witness { address: address(i as u8), vote_count: (100 - i) as i64, ..Default::default() })
                    .collect();
                let saved = sort_and_truncate_active(witnesses, false);
                format!("saved-count={}", saved.len())
            }
            "get-active-witnesses" => {
                let count = number(p, "count") as u8;
                let active: Vec<_> = (0..count).map(address).collect();
                let slots = DposSlot::new(FixedClock(0), context(0, 0, 0, false, 0));
                let selected = slots.scheduled_witness(number(p, "slot"), &active).unwrap()[1];
                format!("selected={selected}")
            }
            "sort-witness" => {
                let votes = p["votes"].as_array().unwrap();
                let mut witnesses: Vec<_> = votes.iter().enumerate().map(|(i, vote)| Witness {
                    address: address(i as u8), vote_count: vote.as_i64().unwrap(), ..Default::default()
                }).collect();
                sort_witnesses(&mut witnesses, true);
                format!("vote-order={}:{}:{}", witnesses[0].vote_count, witnesses[1].vote_count, witnesses[2].vote_count)
            }
            "dpos-slot-source" | "dpos-slot-package" | "absolute-slot" => {
                let genesis = number(p, "genesis");
                let slots = DposSlot::new(FixedClock(genesis), context(genesis, genesis, 0, false, 0));
                format!("absolute-slot={}", slots.absolute_slot(number(p, "time")))
            }
            "dpos-slot-constructor" => {
                let genesis = number(p, "genesis");
                let slots = DposSlot::new(FixedClock(number(p, "now")), context(genesis, genesis, 0, false, 0));
                format!("slot-zero-time={}", slots.time(0).unwrap())
            }
            "relative-slot" => {
                let genesis = number(p, "genesis");
                let slots = DposSlot::new(FixedClock(genesis), context(genesis, genesis, 0, false, 0));
                format!("slot={}", slots.slot(number(p, "time")).unwrap())
            }
            "slot-time" => {
                let genesis = number(p, "genesis");
                let slots = DposSlot::new(FixedClock(0), context(genesis, number(p, "head_time"), 1, true, number(p, "skip_slots")));
                format!("time={}", slots.time(number(p, "slot")).unwrap())
            }
            "scheduled-witness" => {
                let count = number(p, "count") as u8;
                let active: Vec<_> = (0..count).map(address).collect();
                let slots = DposSlot::new(FixedClock(0), context(number(p, "head_time"), number(p, "head_time"), 0, false, 0));
                let selected = slots.scheduled_witness(number(p, "slot"), &active).unwrap()[1];
                format!("selected={selected}")
            }
            "java-test-slot" => {
                let genesis = number(p, "genesis");
                let slots = DposSlot::new(FixedClock(0), context(genesis, number(p, "head_time"), 1, false, 0));
                format!("slot={}", slots.slot(number(p, "time")).unwrap())
            }
            "java-test-witness-schedule" => {
                let count = number(p, "count") as u8;
                let active: Vec<_> = (0..count).map(address).collect();
                let head_time = number(p, "head_time");
                let slots = DposSlot::new(FixedClock(head_time), context(head_time, head_time, 0, false, 0));
                let selected: Vec<_> = p["slots"].as_array().unwrap().iter().map(|slot| {
                    slots.scheduled_witness(slot.as_i64().unwrap(), &active).unwrap()[1].to_string()
                }).collect();
                let mut shuffled: Vec<u8> = (0..10).collect();
                java_shuffle(&mut shuffled, number(p, "shuffle_time"));
                let shuffled = shuffled.iter().map(u8::to_string).collect::<Vec<_>>().join(":");
                format!("selected={};shuffle={shuffled}", selected.join(":"))
            }
            operation => panic!("unknown schedule operation {operation}"),
        };
        assert_eq!(result, case.expected, "{}", case.case_id);
        println!("{}={result}", case.case_id);
        assert!(executed.insert(case.case_id));
    }
    assert_eq!(executed, expected_ids.into_iter().map(str::to_owned).collect());
    println!("executed_ids={}", executed.into_iter().collect::<Vec<_>>().join(","));
}
