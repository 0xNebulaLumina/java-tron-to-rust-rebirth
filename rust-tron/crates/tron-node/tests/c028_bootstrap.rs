use tron_node::{bootstrap::{BootstrapArgs,NodeCommand,ProbeKind},build_info::BUILD_IDENTITY};
#[test]
fn fixed_cli_requires_deployment_and_has_stable_commands(){
 assert!(BootstrapArgs::parse(["tron-fullnode".into()]).is_err());
 let p=BootstrapArgs::parse(["tron-fullnode".into(),"preflight".into(),"--deployment-config".into(),"/etc/tron/node.json".into(),"--json".into()]).unwrap();
 assert_eq!(p.command,NodeCommand::Preflight{json:true});
 let p=BootstrapArgs::parse(["tron-solidity".into(),"probe".into(),"--deployment-config".into(),"/etc/tron/node.json".into(),"--kind".into(),"ready".into()]).unwrap();
 assert_eq!(p.command,NodeCommand::Probe{kind:ProbeKind::Ready});
 assert!(BootstrapArgs::parse(["tron-fullnode".into(),"--solidity".into()]).is_err());
 let p=BootstrapArgs::parse(["tron-fullnode".into(),"bootstrap-snapshot".into(),"--deployment-config".into(),"/etc/tron/node.json".into(),"--snapshot".into(),"/srv/tron/snapshot.bin".into(),"--descriptor".into(),"/srv/tron/snapshot.json".into()]).unwrap();
 assert_eq!(p.command,NodeCommand::BootstrapSnapshot{snapshot:"/srv/tron/snapshot.bin".into(),descriptor:"/srv/tron/snapshot.json".into()});
 let p=BootstrapArgs::parse(["tron-fullnode".into(),"export-snapshot".into(),"--deployment-config".into(),"/etc/tron/node.json".into(),"--output".into(),"/srv/tron/export.bin".into()]).unwrap();
 assert_eq!(p.command,NodeCommand::ExportSnapshot{output:"/srv/tron/export.bin".into()});
}
#[test] fn development_identity_is_explicit(){assert_eq!(BUILD_IDENTITY.backend,"rustlog");assert_eq!(BUILD_IDENTITY.backend_format,"rustlog-v1");assert!(!BUILD_IDENTITY.release_id.is_empty());}
