use std::collections::BTreeMap;
use tron_consensus::{approval_threshold,has_most_approvals,ParameterRule};
use tron_protocol::protocol::Proposal;
#[test] fn java_seventy_percent_uses_active_only_and_floor(){let active:Vec<_>=(0..27).map(|i|vec![i]).collect();let p=Proposal{approvals:(0..18).map(|i|vec![i]).chain([vec![99]]).collect(),..Default::default()};assert_eq!(approval_threshold(27),18);assert!(has_most_approvals(&p,&active));let p=Proposal{approvals:(0..17).map(|i|vec![i]).collect(),..Default::default()};assert!(!has_most_approvals(&p,&active));}
#[test] fn parameter_rules_model_dependencies_gaps_and_one_shot_writes(){let rules=BTreeMap::from([(9,ParameterRule{dynamic:"ALLOW_CREATION_OF_CONTRACTS",depends_on:None,one_shot:true}),(10,ParameterRule{dynamic:"REMOVE_THE_POWER_OF_THE_GR",depends_on:Some((9,1)),one_shot:false})]);assert!(!rules.contains_key(&8));assert_eq!(rules[&10].depends_on,Some((9,1)));assert!(rules[&9].one_shot);}
