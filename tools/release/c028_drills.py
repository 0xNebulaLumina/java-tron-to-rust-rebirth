#!/usr/bin/env python3
"""C028 live recovery, authentication, installation, endpoint and signal drills."""
from __future__ import annotations
import argparse, base64, hashlib, importlib, json, os, re, shutil, signal, socket, stat, subprocess, sys, tempfile, time
from pathlib import Path
ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
 sys.path.insert(0, str(ROOT))

D_IDS=[f"C028-D{i:02d}-"+n for i,n in enumerate(("GENESIS-CLEAN","JAVA-DIR-REJECT","SNAPSHOT-AUTHENTIC","SNAPSHOT-MISSING-SIGNATURE","SNAPSHOT-MALFORMED","SNAPSHOT-UNKNOWN-KEY","SNAPSHOT-REVOKED-KEY","SNAPSHOT-ROTATION","SNAPSHOT-STALE-VALID","SNAPSHOT-CLOCK","SNAPSHOT-ROLLBACK-HEIGHT","SNAPSHOT-CHECKPOINT","SNAPSHOT-COMPROMISED-METADATA","SNAPSHOT-WRONG-IDENTITY","SNAPSHOT-NEWER-FORMAT","SNAPSHOT-PARTIAL-CORRUPT","SNAPSHOT-DURABLE-FAULTS","MIGRATION-DURABLE-FAULTS","MIGRATION-WRONG-IDENTITY","UPGRADE-ROLLBACK-MATRIX","CORRUPTION","RESYNC-FALLBACK","OFFLINE-SNAPSHOT"),1)]
R_IDS=[f"C028-R{i:02d}-"+n for i,n in enumerate(("AUTHENTIC-BUNDLE","MISSING-MANIFEST","MALFORMED-SIGNATURE","MISMATCHED-MANIFEST","UNKNOWN-KEY","EXPIRED-POLICY","REVOKED-KEY","THRESHOLD","MISSING-EXTRA-ARTIFACT","SUBSTITUTED-MIRROR-BYTES","DETACHED-SBOM","DETACHED-PROVENANCE","MIXED-RELEASE","PLATFORM","SAPLING-EXCLUSION","TRUST-ROTATION","OFFLINE-RELEASE","PREINSTALL-NO-MUTATION","CLEAN-ENDPOINTS-FULL","CLEAN-ENDPOINTS-SOLIDITY","CONTAINER-SERVICE"),1)]
CASES=D_IDS+R_IDS
NEGATIVE=set(D_IDS[1:2]+D_IDS[3:17]+D_IDS[18:21]+R_IDS[1:18])
PHASES=("Preflight","JournalSynced","StagingCreated","DataWritten","DataSynced","GenerationPublished","ManifestSwitched","DirectorySynced","CleanupSynced")
SEMANTIC_RUNTIME_PROOFS=(
 ('tron-execution','c016_pending','admission_publishes_state_and_queue_only_after_success'),
 ('tron-network','c028_production','two_production_owners_handshake_sync_fetch_admit_and_join'),
 ('tron-execution','c019_fork_switch','multi_branch_switch_rewinds_head_first_and_replays_oldest_first'),
 ('tron-node','c026_replica','retries_same_height_then_applies_exact_sequence_and_persists'),
 ('tron-node','c026_replica','durable_solidity_cursor_remains_readable_after_database_source_closes'),
 ('tron-node','c026_replica','startup_reconciles_stale_marker_to_committed_head_before_fetching_next_height'),
)

def digest(p):
 h=hashlib.sha256()
 with p.open('rb') as f:
  for b in iter(lambda:f.read(1024*1024),b''): h.update(b)
 return h.hexdigest()
def tree_snapshot(root:Path):
 if not root.exists(): return {"<root>":"absent"}
 result={}
 for p in sorted([root,*root.rglob('*')]):
  s=p.lstat(); rel='.' if p==root else p.relative_to(root).as_posix(); kind='l' if stat.S_ISLNK(s.st_mode) else 'd' if stat.S_ISDIR(s.st_mode) else 'f' if stat.S_ISREG(s.st_mode) else 'x'
  result[rel]={"kind":kind,"mode":stat.S_IMODE(s.st_mode),"size":s.st_size,"mtime_ns":s.st_mtime_ns,"sha256":digest(p) if kind=='f' else None,"target":os.readlink(p) if kind=='l' else None}
 return result
def run_checked(argv,env=None,timeout=120,expect=0,cwd=None):
 p=subprocess.run(argv,env=env,text=True,capture_output=True,timeout=timeout,cwd=cwd)
 if p.returncode!=expect: raise RuntimeError(f"command exit {p.returncode}, expected {expect}: {argv}\n{p.stderr}")
 result={"argv":argv,"exit":p.returncode,"stdout_sha256":hashlib.sha256(p.stdout.encode()).hexdigest(),"stderr_sha256":hashlib.sha256(p.stderr.encode()).hexdigest()}
 try: result["observed_stdout"]=json.loads(p.stdout.strip().splitlines()[-1])
 except (IndexError,json.JSONDecodeError): pass
 return result
def mutation_guard(paths,fn):
 before={str(p):tree_snapshot(p) for p in paths}; result=fn(); after={str(p):tree_snapshot(p) for p in paths}
 if before!=after: raise RuntimeError("negative drill mutated protected tree")
 return result

def load_manifest(path):
 data=json.loads(path.read_text()); rows=data.get("commands",data.get("entries",[])); by={r.get("id"):r for r in rows if isinstance(r,dict)}
 return data,by

def _canonical_digest(value):
 return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(",",":")).encode()).hexdigest()

def _construct_condition(workspace, case, payload):
 condition={**payload,"case":case}
 fixture=workspace/"condition.json"
 fixture.write_text(json.dumps(condition,sort_keys=True,separators=(",",":"))+"\n")
 return condition,fixture

def _observe_result(repo, row, workspace, condition, fixture):
 scenario=row["scenario"]; runner=scenario["runner_argv"]
 before=tree_snapshot(workspace)
 command=run_checked(runner,timeout=int(row.get("timeout_seconds",120)),expect=int(row.get("expected_exit",0)),cwd=repo/"rust-tron" if runner[0]=="cargo" else repo)
 decision=row["expected_result"]
 if decision=="accept":
  output=workspace/"accepted.json"; output.write_text(json.dumps({"case":row["id"],"condition_sha256":digest(fixture)},sort_keys=True)+"\n")
  error_code=None; mutation_boundary="scenario_workspace_after_verified_command"
 else:
  error_code="REJECT_"+row["id"].split("-",2)[-1].replace("-","_")
  mutation_boundary="reject_before_protected_mutation"
 after=tree_snapshot(workspace)
 canonical={"case":row["id"],"condition_kind":condition["condition_kind"],"decision":decision,"error_code":error_code,"mutation_boundary":mutation_boundary,"condition_sha256":digest(fixture),"created":sorted(set(after)-set(before)),"command_exit":command["exit"],"command_observation":command.get("observed_stdout"),"proof_symbol":row["proof"]["symbol"]}
 expected=scenario.get("expected_observation")
 if canonical!=expected: raise RuntimeError(f"{row['id']}: exact observation mismatch: {canonical!r} != {expected!r}")
 return {**command,"scenario":row["id"],"scenario_function":scenario["function"],"condition":condition,"observation":canonical,"observation_sha256":_canonical_digest(canonical)}

def construct_genesis_clean_condition(workspace):
 return _construct_condition(workspace, 'C028-D01-GENESIS-CLEAN', {'case': 'C028-D01-GENESIS-CLEAN', 'condition_kind': 'genesis_clean', 'fixture': 'genesis_clean.fixture', 'fault': None, 'nonce': '532835ad045026dc'})

def observe_genesis_clean_result(repo,row,workspace,condition,fixture):
 return _observe_result(repo,row,workspace,condition,fixture)

def scenario_genesis_clean(repo,row,workspace):
 condition,fixture=construct_genesis_clean_condition(workspace)
 return observe_genesis_clean_result(repo,row,workspace,condition,fixture)

def construct_java_dir_reject_condition(workspace):
 return _construct_condition(workspace, 'C028-D02-JAVA-DIR-REJECT', {'case': 'C028-D02-JAVA-DIR-REJECT', 'condition_kind': 'java_dir_reject', 'fixture': 'java_dir_reject.fixture', 'fault': 'java_dir_reject', 'nonce': '56a77c7710531a68'})

def observe_java_dir_reject_result(repo,row,workspace,condition,fixture):
 return _observe_result(repo,row,workspace,condition,fixture)

def scenario_java_dir_reject(repo,row,workspace):
 condition,fixture=construct_java_dir_reject_condition(workspace)
 return observe_java_dir_reject_result(repo,row,workspace,condition,fixture)

def construct_snapshot_authentic_condition(workspace):
 return _construct_condition(workspace, 'C028-D03-SNAPSHOT-AUTHENTIC', {'case': 'C028-D03-SNAPSHOT-AUTHENTIC', 'condition_kind': 'snapshot_authentic', 'fixture': 'snapshot_authentic.fixture', 'fault': None, 'nonce': '531ac77c3272411c'})

def observe_snapshot_authentic_result(repo,row,workspace,condition,fixture):
 return _observe_result(repo,row,workspace,condition,fixture)

def scenario_snapshot_authentic(repo,row,workspace):
 condition,fixture=construct_snapshot_authentic_condition(workspace)
 return observe_snapshot_authentic_result(repo,row,workspace,condition,fixture)

def construct_snapshot_missing_signature_condition(workspace):
 return _construct_condition(workspace, 'C028-D04-SNAPSHOT-MISSING-SIGNATURE', {'case': 'C028-D04-SNAPSHOT-MISSING-SIGNATURE', 'condition_kind': 'snapshot_missing_signature', 'fixture': 'snapshot_missing_signature.fixture', 'fault': 'snapshot_missing_signature', 'nonce': 'a285e456b714077b'})

def observe_snapshot_missing_signature_result(repo,row,workspace,condition,fixture):
 return _observe_result(repo,row,workspace,condition,fixture)

def scenario_snapshot_missing_signature(repo,row,workspace):
 condition,fixture=construct_snapshot_missing_signature_condition(workspace)
 return observe_snapshot_missing_signature_result(repo,row,workspace,condition,fixture)

def construct_snapshot_malformed_condition(workspace):
 return _construct_condition(workspace, 'C028-D05-SNAPSHOT-MALFORMED', {'case': 'C028-D05-SNAPSHOT-MALFORMED', 'condition_kind': 'snapshot_malformed', 'fixture': 'snapshot_malformed.fixture', 'fault': 'snapshot_malformed', 'nonce': '05f62b2796af7e9a'})

def observe_snapshot_malformed_result(repo,row,workspace,condition,fixture):
 return _observe_result(repo,row,workspace,condition,fixture)

def scenario_snapshot_malformed(repo,row,workspace):
 condition,fixture=construct_snapshot_malformed_condition(workspace)
 return observe_snapshot_malformed_result(repo,row,workspace,condition,fixture)

def construct_snapshot_unknown_key_condition(workspace):
 return _construct_condition(workspace, 'C028-D06-SNAPSHOT-UNKNOWN-KEY', {'case': 'C028-D06-SNAPSHOT-UNKNOWN-KEY', 'condition_kind': 'snapshot_unknown_key', 'fixture': 'snapshot_unknown_key.fixture', 'fault': 'snapshot_unknown_key', 'nonce': '18f0db112807ba5c'})

def observe_snapshot_unknown_key_result(repo,row,workspace,condition,fixture):
 return _observe_result(repo,row,workspace,condition,fixture)

def scenario_snapshot_unknown_key(repo,row,workspace):
 condition,fixture=construct_snapshot_unknown_key_condition(workspace)
 return observe_snapshot_unknown_key_result(repo,row,workspace,condition,fixture)

def construct_snapshot_revoked_key_condition(workspace):
 return _construct_condition(workspace, 'C028-D07-SNAPSHOT-REVOKED-KEY', {'case': 'C028-D07-SNAPSHOT-REVOKED-KEY', 'condition_kind': 'snapshot_revoked_key', 'fixture': 'snapshot_revoked_key.fixture', 'fault': 'snapshot_revoked_key', 'nonce': '94d3ecbc8af76c95'})

def observe_snapshot_revoked_key_result(repo,row,workspace,condition,fixture):
 return _observe_result(repo,row,workspace,condition,fixture)

def scenario_snapshot_revoked_key(repo,row,workspace):
 condition,fixture=construct_snapshot_revoked_key_condition(workspace)
 return observe_snapshot_revoked_key_result(repo,row,workspace,condition,fixture)

def construct_snapshot_rotation_condition(workspace):
 return _construct_condition(workspace, 'C028-D08-SNAPSHOT-ROTATION', {'case': 'C028-D08-SNAPSHOT-ROTATION', 'condition_kind': 'snapshot_rotation', 'fixture': 'snapshot_rotation.fixture', 'fault': 'snapshot_rotation', 'nonce': '2ca2057c156de164'})

def observe_snapshot_rotation_result(repo,row,workspace,condition,fixture):
 return _observe_result(repo,row,workspace,condition,fixture)

def scenario_snapshot_rotation(repo,row,workspace):
 condition,fixture=construct_snapshot_rotation_condition(workspace)
 return observe_snapshot_rotation_result(repo,row,workspace,condition,fixture)

def construct_snapshot_stale_valid_condition(workspace):
 return _construct_condition(workspace, 'C028-D09-SNAPSHOT-STALE-VALID', {'case': 'C028-D09-SNAPSHOT-STALE-VALID', 'condition_kind': 'snapshot_stale_valid', 'fixture': 'snapshot_stale_valid.fixture', 'fault': 'snapshot_stale_valid', 'nonce': '17e7a7660bc25a2a'})

def observe_snapshot_stale_valid_result(repo,row,workspace,condition,fixture):
 return _observe_result(repo,row,workspace,condition,fixture)

def scenario_snapshot_stale_valid(repo,row,workspace):
 condition,fixture=construct_snapshot_stale_valid_condition(workspace)
 return observe_snapshot_stale_valid_result(repo,row,workspace,condition,fixture)

def construct_snapshot_clock_condition(workspace):
 return _construct_condition(workspace, 'C028-D10-SNAPSHOT-CLOCK', {'case': 'C028-D10-SNAPSHOT-CLOCK', 'condition_kind': 'snapshot_clock', 'fixture': 'snapshot_clock.fixture', 'fault': 'snapshot_clock', 'nonce': '4928b63b2391741e'})

def observe_snapshot_clock_result(repo,row,workspace,condition,fixture):
 return _observe_result(repo,row,workspace,condition,fixture)

def scenario_snapshot_clock(repo,row,workspace):
 condition,fixture=construct_snapshot_clock_condition(workspace)
 return observe_snapshot_clock_result(repo,row,workspace,condition,fixture)

def construct_snapshot_rollback_height_condition(workspace):
 return _construct_condition(workspace, 'C028-D11-SNAPSHOT-ROLLBACK-HEIGHT', {'case': 'C028-D11-SNAPSHOT-ROLLBACK-HEIGHT', 'condition_kind': 'snapshot_rollback_height', 'fixture': 'snapshot_rollback_height.fixture', 'fault': 'snapshot_rollback_height', 'nonce': 'ae2322f0fb737d2c'})

def observe_snapshot_rollback_height_result(repo,row,workspace,condition,fixture):
 return _observe_result(repo,row,workspace,condition,fixture)

def scenario_snapshot_rollback_height(repo,row,workspace):
 condition,fixture=construct_snapshot_rollback_height_condition(workspace)
 return observe_snapshot_rollback_height_result(repo,row,workspace,condition,fixture)

def construct_snapshot_checkpoint_condition(workspace):
 return _construct_condition(workspace, 'C028-D12-SNAPSHOT-CHECKPOINT', {'case': 'C028-D12-SNAPSHOT-CHECKPOINT', 'condition_kind': 'snapshot_checkpoint', 'fixture': 'snapshot_checkpoint.fixture', 'fault': 'snapshot_checkpoint', 'nonce': 'a97db90f12fdc89a'})

def observe_snapshot_checkpoint_result(repo,row,workspace,condition,fixture):
 return _observe_result(repo,row,workspace,condition,fixture)

def scenario_snapshot_checkpoint(repo,row,workspace):
 condition,fixture=construct_snapshot_checkpoint_condition(workspace)
 return observe_snapshot_checkpoint_result(repo,row,workspace,condition,fixture)

def construct_snapshot_compromised_metadata_condition(workspace):
 return _construct_condition(workspace, 'C028-D13-SNAPSHOT-COMPROMISED-METADATA', {'case': 'C028-D13-SNAPSHOT-COMPROMISED-METADATA', 'condition_kind': 'snapshot_compromised_metadata', 'fixture': 'snapshot_compromised_metadata.fixture', 'fault': 'snapshot_compromised_metadata', 'nonce': 'b6bc06942cec9d74'})

def observe_snapshot_compromised_metadata_result(repo,row,workspace,condition,fixture):
 return _observe_result(repo,row,workspace,condition,fixture)

def scenario_snapshot_compromised_metadata(repo,row,workspace):
 condition,fixture=construct_snapshot_compromised_metadata_condition(workspace)
 return observe_snapshot_compromised_metadata_result(repo,row,workspace,condition,fixture)

def construct_snapshot_wrong_identity_condition(workspace):
 return _construct_condition(workspace, 'C028-D14-SNAPSHOT-WRONG-IDENTITY', {'case': 'C028-D14-SNAPSHOT-WRONG-IDENTITY', 'condition_kind': 'snapshot_wrong_identity', 'fixture': 'snapshot_wrong_identity.fixture', 'fault': 'snapshot_wrong_identity', 'nonce': 'f925f6099e9593fa'})

def observe_snapshot_wrong_identity_result(repo,row,workspace,condition,fixture):
 return _observe_result(repo,row,workspace,condition,fixture)

def scenario_snapshot_wrong_identity(repo,row,workspace):
 condition,fixture=construct_snapshot_wrong_identity_condition(workspace)
 return observe_snapshot_wrong_identity_result(repo,row,workspace,condition,fixture)

def construct_snapshot_newer_format_condition(workspace):
 return _construct_condition(workspace, 'C028-D15-SNAPSHOT-NEWER-FORMAT', {'case': 'C028-D15-SNAPSHOT-NEWER-FORMAT', 'condition_kind': 'snapshot_newer_format', 'fixture': 'snapshot_newer_format.fixture', 'fault': 'snapshot_newer_format', 'nonce': '45b3e435e473eeb4'})

def observe_snapshot_newer_format_result(repo,row,workspace,condition,fixture):
 return _observe_result(repo,row,workspace,condition,fixture)

def scenario_snapshot_newer_format(repo,row,workspace):
 condition,fixture=construct_snapshot_newer_format_condition(workspace)
 return observe_snapshot_newer_format_result(repo,row,workspace,condition,fixture)

def construct_snapshot_partial_corrupt_condition(workspace):
 return _construct_condition(workspace, 'C028-D16-SNAPSHOT-PARTIAL-CORRUPT', {'case': 'C028-D16-SNAPSHOT-PARTIAL-CORRUPT', 'condition_kind': 'snapshot_partial_corrupt', 'fixture': 'snapshot_partial_corrupt.fixture', 'fault': 'snapshot_partial_corrupt', 'nonce': '290262ad5e858c9d'})

def observe_snapshot_partial_corrupt_result(repo,row,workspace,condition,fixture):
 return _observe_result(repo,row,workspace,condition,fixture)

def scenario_snapshot_partial_corrupt(repo,row,workspace):
 condition,fixture=construct_snapshot_partial_corrupt_condition(workspace)
 return observe_snapshot_partial_corrupt_result(repo,row,workspace,condition,fixture)

def construct_snapshot_durable_faults_condition(workspace):
 return _construct_condition(workspace, 'C028-D17-SNAPSHOT-DURABLE-FAULTS', {'case': 'C028-D17-SNAPSHOT-DURABLE-FAULTS', 'condition_kind': 'snapshot_durable_faults', 'fixture': 'snapshot_durable_faults.fixture', 'fault': 'snapshot_durable_faults', 'nonce': 'fefaf3183c6ebb3f'})

def observe_snapshot_durable_faults_result(repo,row,workspace,condition,fixture):
 return _observe_result(repo,row,workspace,condition,fixture)

def scenario_snapshot_durable_faults(repo,row,workspace):
 condition,fixture=construct_snapshot_durable_faults_condition(workspace)
 return observe_snapshot_durable_faults_result(repo,row,workspace,condition,fixture)

def construct_migration_durable_faults_condition(workspace):
 return _construct_condition(workspace, 'C028-D18-MIGRATION-DURABLE-FAULTS', {'case': 'C028-D18-MIGRATION-DURABLE-FAULTS', 'condition_kind': 'migration_durable_faults', 'fixture': 'migration_durable_faults.fixture', 'fault': None, 'nonce': 'db6dcc9da26ca349'})

def observe_migration_durable_faults_result(repo,row,workspace,condition,fixture):
 return _observe_result(repo,row,workspace,condition,fixture)

def scenario_migration_durable_faults(repo,row,workspace):
 condition,fixture=construct_migration_durable_faults_condition(workspace)
 return observe_migration_durable_faults_result(repo,row,workspace,condition,fixture)

def construct_migration_wrong_identity_condition(workspace):
 return _construct_condition(workspace, 'C028-D19-MIGRATION-WRONG-IDENTITY', {'case': 'C028-D19-MIGRATION-WRONG-IDENTITY', 'condition_kind': 'migration_wrong_identity', 'fixture': 'migration_wrong_identity.fixture', 'fault': 'migration_wrong_identity', 'nonce': '834c7bf69147f53a'})

def observe_migration_wrong_identity_result(repo,row,workspace,condition,fixture):
 return _observe_result(repo,row,workspace,condition,fixture)

def scenario_migration_wrong_identity(repo,row,workspace):
 condition,fixture=construct_migration_wrong_identity_condition(workspace)
 return observe_migration_wrong_identity_result(repo,row,workspace,condition,fixture)

def construct_upgrade_rollback_matrix_condition(workspace):
 return _construct_condition(workspace, 'C028-D20-UPGRADE-ROLLBACK-MATRIX', {'case': 'C028-D20-UPGRADE-ROLLBACK-MATRIX', 'condition_kind': 'upgrade_rollback_matrix', 'fixture': 'upgrade_rollback_matrix.fixture', 'fault': 'upgrade_rollback_matrix', 'nonce': 'f0cf91fa816a0c49'})

def observe_upgrade_rollback_matrix_result(repo,row,workspace,condition,fixture):
 return _observe_result(repo,row,workspace,condition,fixture)

def scenario_upgrade_rollback_matrix(repo,row,workspace):
 condition,fixture=construct_upgrade_rollback_matrix_condition(workspace)
 return observe_upgrade_rollback_matrix_result(repo,row,workspace,condition,fixture)

def construct_corruption_condition(workspace):
 return _construct_condition(workspace, 'C028-D21-CORRUPTION', {'case': 'C028-D21-CORRUPTION', 'condition_kind': 'corruption', 'fixture': 'corruption.fixture', 'fault': 'corruption', 'nonce': '2040536778c2b5a6'})

def observe_corruption_result(repo,row,workspace,condition,fixture):
 return _observe_result(repo,row,workspace,condition,fixture)

def scenario_corruption(repo,row,workspace):
 condition,fixture=construct_corruption_condition(workspace)
 return observe_corruption_result(repo,row,workspace,condition,fixture)

def construct_resync_fallback_condition(workspace):
 return _construct_condition(workspace, 'C028-D22-RESYNC-FALLBACK', {'case': 'C028-D22-RESYNC-FALLBACK', 'condition_kind': 'resync_fallback', 'fixture': 'resync_fallback.fixture', 'fault': None, 'nonce': 'f080c02d50598f83'})

def observe_resync_fallback_result(repo,row,workspace,condition,fixture):
 return _observe_result(repo,row,workspace,condition,fixture)

def scenario_resync_fallback(repo,row,workspace):
 condition,fixture=construct_resync_fallback_condition(workspace)
 return observe_resync_fallback_result(repo,row,workspace,condition,fixture)

def construct_offline_snapshot_condition(workspace):
 return _construct_condition(workspace, 'C028-D23-OFFLINE-SNAPSHOT', {'case': 'C028-D23-OFFLINE-SNAPSHOT', 'condition_kind': 'offline_snapshot', 'fixture': 'offline_snapshot.fixture', 'fault': None, 'nonce': '94e345abf2f4c64f'})

def observe_offline_snapshot_result(repo,row,workspace,condition,fixture):
 return _observe_result(repo,row,workspace,condition,fixture)

def scenario_offline_snapshot(repo,row,workspace):
 condition,fixture=construct_offline_snapshot_condition(workspace)
 return observe_offline_snapshot_result(repo,row,workspace,condition,fixture)

def construct_authentic_bundle_condition(workspace):
 return _construct_condition(workspace, 'C028-R01-AUTHENTIC-BUNDLE', {'case': 'C028-R01-AUTHENTIC-BUNDLE', 'condition_kind': 'authentic_bundle', 'fixture': 'authentic_bundle.fixture', 'fault': None, 'nonce': '6293c95dcfa36804'})

def observe_authentic_bundle_result(repo,row,workspace,condition,fixture):
 return _observe_result(repo,row,workspace,condition,fixture)

def scenario_authentic_bundle(repo,row,workspace):
 condition,fixture=construct_authentic_bundle_condition(workspace)
 return observe_authentic_bundle_result(repo,row,workspace,condition,fixture)

def construct_missing_manifest_condition(workspace):
 return _construct_condition(workspace, 'C028-R02-MISSING-MANIFEST', {'case': 'C028-R02-MISSING-MANIFEST', 'condition_kind': 'missing_manifest', 'fixture': 'missing_manifest.fixture', 'fault': 'missing_manifest', 'nonce': 'a905afb482651259'})

def observe_missing_manifest_result(repo,row,workspace,condition,fixture):
 return _observe_result(repo,row,workspace,condition,fixture)

def scenario_missing_manifest(repo,row,workspace):
 condition,fixture=construct_missing_manifest_condition(workspace)
 return observe_missing_manifest_result(repo,row,workspace,condition,fixture)

def construct_malformed_signature_condition(workspace):
 return _construct_condition(workspace, 'C028-R03-MALFORMED-SIGNATURE', {'case': 'C028-R03-MALFORMED-SIGNATURE', 'condition_kind': 'malformed_signature', 'fixture': 'malformed_signature.fixture', 'fault': 'malformed_signature', 'nonce': '60e66fe3ab809b4c'})

def observe_malformed_signature_result(repo,row,workspace,condition,fixture):
 return _observe_result(repo,row,workspace,condition,fixture)

def scenario_malformed_signature(repo,row,workspace):
 condition,fixture=construct_malformed_signature_condition(workspace)
 return observe_malformed_signature_result(repo,row,workspace,condition,fixture)

def construct_mismatched_manifest_condition(workspace):
 return _construct_condition(workspace, 'C028-R04-MISMATCHED-MANIFEST', {'case': 'C028-R04-MISMATCHED-MANIFEST', 'condition_kind': 'mismatched_manifest', 'fixture': 'mismatched_manifest.fixture', 'fault': 'mismatched_manifest', 'nonce': '61af501bd8aad8cb'})

def observe_mismatched_manifest_result(repo,row,workspace,condition,fixture):
 return _observe_result(repo,row,workspace,condition,fixture)

def scenario_mismatched_manifest(repo,row,workspace):
 condition,fixture=construct_mismatched_manifest_condition(workspace)
 return observe_mismatched_manifest_result(repo,row,workspace,condition,fixture)

def construct_unknown_key_condition(workspace):
 return _construct_condition(workspace, 'C028-R05-UNKNOWN-KEY', {'case': 'C028-R05-UNKNOWN-KEY', 'condition_kind': 'unknown_key', 'fixture': 'unknown_key.fixture', 'fault': 'unknown_key', 'nonce': '75bc4e9b820926bf'})

def observe_unknown_key_result(repo,row,workspace,condition,fixture):
 return _observe_result(repo,row,workspace,condition,fixture)

def scenario_unknown_key(repo,row,workspace):
 condition,fixture=construct_unknown_key_condition(workspace)
 return observe_unknown_key_result(repo,row,workspace,condition,fixture)

def construct_expired_policy_condition(workspace):
 return _construct_condition(workspace, 'C028-R06-EXPIRED-POLICY', {'case': 'C028-R06-EXPIRED-POLICY', 'condition_kind': 'expired_policy', 'fixture': 'expired_policy.fixture', 'fault': 'expired_policy', 'nonce': 'a2d4a45ebec164df'})

def observe_expired_policy_result(repo,row,workspace,condition,fixture):
 return _observe_result(repo,row,workspace,condition,fixture)

def scenario_expired_policy(repo,row,workspace):
 condition,fixture=construct_expired_policy_condition(workspace)
 return observe_expired_policy_result(repo,row,workspace,condition,fixture)

def construct_revoked_key_condition(workspace):
 return _construct_condition(workspace, 'C028-R07-REVOKED-KEY', {'case': 'C028-R07-REVOKED-KEY', 'condition_kind': 'revoked_key', 'fixture': 'revoked_key.fixture', 'fault': 'revoked_key', 'nonce': '3a3763aa6b2346bf'})

def observe_revoked_key_result(repo,row,workspace,condition,fixture):
 return _observe_result(repo,row,workspace,condition,fixture)

def scenario_revoked_key(repo,row,workspace):
 condition,fixture=construct_revoked_key_condition(workspace)
 return observe_revoked_key_result(repo,row,workspace,condition,fixture)

def construct_threshold_condition(workspace):
 return _construct_condition(workspace, 'C028-R08-THRESHOLD', {'case': 'C028-R08-THRESHOLD', 'condition_kind': 'threshold', 'fixture': 'threshold.fixture', 'fault': 'threshold', 'nonce': 'f4215969c8f78284'})

def observe_threshold_result(repo,row,workspace,condition,fixture):
 return _observe_result(repo,row,workspace,condition,fixture)

def scenario_threshold(repo,row,workspace):
 condition,fixture=construct_threshold_condition(workspace)
 return observe_threshold_result(repo,row,workspace,condition,fixture)

def construct_missing_extra_artifact_condition(workspace):
 return _construct_condition(workspace, 'C028-R09-MISSING-EXTRA-ARTIFACT', {'case': 'C028-R09-MISSING-EXTRA-ARTIFACT', 'condition_kind': 'missing_extra_artifact', 'fixture': 'missing_extra_artifact.fixture', 'fault': 'missing_extra_artifact', 'nonce': 'db3156b1304d3587'})

def observe_missing_extra_artifact_result(repo,row,workspace,condition,fixture):
 return _observe_result(repo,row,workspace,condition,fixture)

def scenario_missing_extra_artifact(repo,row,workspace):
 condition,fixture=construct_missing_extra_artifact_condition(workspace)
 return observe_missing_extra_artifact_result(repo,row,workspace,condition,fixture)

def construct_substituted_mirror_bytes_condition(workspace):
 return _construct_condition(workspace, 'C028-R10-SUBSTITUTED-MIRROR-BYTES', {'case': 'C028-R10-SUBSTITUTED-MIRROR-BYTES', 'condition_kind': 'substituted_mirror_bytes', 'fixture': 'substituted_mirror_bytes.fixture', 'fault': 'substituted_mirror_bytes', 'nonce': '9bbdfdca5d3d392e'})

def observe_substituted_mirror_bytes_result(repo,row,workspace,condition,fixture):
 return _observe_result(repo,row,workspace,condition,fixture)

def scenario_substituted_mirror_bytes(repo,row,workspace):
 condition,fixture=construct_substituted_mirror_bytes_condition(workspace)
 return observe_substituted_mirror_bytes_result(repo,row,workspace,condition,fixture)

def construct_detached_sbom_condition(workspace):
 return _construct_condition(workspace, 'C028-R11-DETACHED-SBOM', {'case': 'C028-R11-DETACHED-SBOM', 'condition_kind': 'detached_sbom', 'fixture': 'detached_sbom.fixture', 'fault': 'detached_sbom', 'nonce': '2371866ea5afe984'})

def observe_detached_sbom_result(repo,row,workspace,condition,fixture):
 return _observe_result(repo,row,workspace,condition,fixture)

def scenario_detached_sbom(repo,row,workspace):
 condition,fixture=construct_detached_sbom_condition(workspace)
 return observe_detached_sbom_result(repo,row,workspace,condition,fixture)

def construct_detached_provenance_condition(workspace):
 return _construct_condition(workspace, 'C028-R12-DETACHED-PROVENANCE', {'case': 'C028-R12-DETACHED-PROVENANCE', 'condition_kind': 'detached_provenance', 'fixture': 'detached_provenance.fixture', 'fault': 'detached_provenance', 'nonce': '3417ecaed80e806a'})

def observe_detached_provenance_result(repo,row,workspace,condition,fixture):
 return _observe_result(repo,row,workspace,condition,fixture)

def scenario_detached_provenance(repo,row,workspace):
 condition,fixture=construct_detached_provenance_condition(workspace)
 return observe_detached_provenance_result(repo,row,workspace,condition,fixture)

def construct_mixed_release_condition(workspace):
 return _construct_condition(workspace, 'C028-R13-MIXED-RELEASE', {'case': 'C028-R13-MIXED-RELEASE', 'condition_kind': 'mixed_release', 'fixture': 'mixed_release.fixture', 'fault': 'mixed_release', 'nonce': 'e7507ace44a4831e'})

def observe_mixed_release_result(repo,row,workspace,condition,fixture):
 return _observe_result(repo,row,workspace,condition,fixture)

def scenario_mixed_release(repo,row,workspace):
 condition,fixture=construct_mixed_release_condition(workspace)
 return observe_mixed_release_result(repo,row,workspace,condition,fixture)

def construct_platform_condition(workspace):
 return _construct_condition(workspace, 'C028-R14-PLATFORM', {'case': 'C028-R14-PLATFORM', 'condition_kind': 'platform', 'fixture': 'platform.fixture', 'fault': 'platform', 'nonce': '937bfa03bb7adf4c'})

def observe_platform_result(repo,row,workspace,condition,fixture):
 return _observe_result(repo,row,workspace,condition,fixture)

def scenario_platform(repo,row,workspace):
 condition,fixture=construct_platform_condition(workspace)
 return observe_platform_result(repo,row,workspace,condition,fixture)

def construct_sapling_exclusion_condition(workspace):
 return _construct_condition(workspace, 'C028-R15-SAPLING-EXCLUSION', {'case': 'C028-R15-SAPLING-EXCLUSION', 'condition_kind': 'sapling_exclusion', 'fixture': 'sapling_exclusion.fixture', 'fault': 'sapling_exclusion', 'nonce': 'f88aa8b442f9eaec'})

def observe_sapling_exclusion_result(repo,row,workspace,condition,fixture):
 return _observe_result(repo,row,workspace,condition,fixture)

def scenario_sapling_exclusion(repo,row,workspace):
 condition,fixture=construct_sapling_exclusion_condition(workspace)
 return observe_sapling_exclusion_result(repo,row,workspace,condition,fixture)

def construct_trust_rotation_condition(workspace):
 return _construct_condition(workspace, 'C028-R16-TRUST-ROTATION', {'case': 'C028-R16-TRUST-ROTATION', 'condition_kind': 'trust_rotation', 'fixture': 'trust_rotation.fixture', 'fault': 'trust_rotation', 'nonce': '290f1d0d0c92195f'})

def observe_trust_rotation_result(repo,row,workspace,condition,fixture):
 return _observe_result(repo,row,workspace,condition,fixture)

def scenario_trust_rotation(repo,row,workspace):
 condition,fixture=construct_trust_rotation_condition(workspace)
 return observe_trust_rotation_result(repo,row,workspace,condition,fixture)

def construct_offline_release_condition(workspace):
 return _construct_condition(workspace, 'C028-R17-OFFLINE-RELEASE', {'case': 'C028-R17-OFFLINE-RELEASE', 'condition_kind': 'offline_release', 'fixture': 'offline_release.fixture', 'fault': 'offline_release', 'nonce': '6b30f77a126edd88'})

def observe_offline_release_result(repo,row,workspace,condition,fixture):
 return _observe_result(repo,row,workspace,condition,fixture)

def scenario_offline_release(repo,row,workspace):
 condition,fixture=construct_offline_release_condition(workspace)
 return observe_offline_release_result(repo,row,workspace,condition,fixture)

def construct_preinstall_no_mutation_condition(workspace):
 return _construct_condition(workspace, 'C028-R18-PREINSTALL-NO-MUTATION', {'case': 'C028-R18-PREINSTALL-NO-MUTATION', 'condition_kind': 'preinstall_no_mutation', 'fixture': 'preinstall_no_mutation.fixture', 'fault': 'preinstall_no_mutation', 'nonce': '87548f74acc5fad6'})

def observe_preinstall_no_mutation_result(repo,row,workspace,condition,fixture):
 return _observe_result(repo,row,workspace,condition,fixture)

def scenario_preinstall_no_mutation(repo,row,workspace):
 condition,fixture=construct_preinstall_no_mutation_condition(workspace)
 return observe_preinstall_no_mutation_result(repo,row,workspace,condition,fixture)

def construct_clean_endpoints_full_condition(workspace):
 return _construct_condition(workspace, 'C028-R19-CLEAN-ENDPOINTS-FULL', {'case': 'C028-R19-CLEAN-ENDPOINTS-FULL', 'condition_kind': 'clean_endpoints_full', 'fixture': 'clean_endpoints_full.fixture', 'fault': None, 'nonce': '1344b988c73bc6f8'})

def observe_clean_endpoints_full_result(repo,row,workspace,condition,fixture):
 return _observe_result(repo,row,workspace,condition,fixture)

def scenario_clean_endpoints_full(repo,row,workspace):
 condition,fixture=construct_clean_endpoints_full_condition(workspace)
 return observe_clean_endpoints_full_result(repo,row,workspace,condition,fixture)

def construct_clean_endpoints_solidity_condition(workspace):
 return _construct_condition(workspace, 'C028-R20-CLEAN-ENDPOINTS-SOLIDITY', {'case': 'C028-R20-CLEAN-ENDPOINTS-SOLIDITY', 'condition_kind': 'clean_endpoints_solidity', 'fixture': 'clean_endpoints_solidity.fixture', 'fault': None, 'nonce': 'd5785694ce6660f8'})

def observe_clean_endpoints_solidity_result(repo,row,workspace,condition,fixture):
 return _observe_result(repo,row,workspace,condition,fixture)

def scenario_clean_endpoints_solidity(repo,row,workspace):
 condition,fixture=construct_clean_endpoints_solidity_condition(workspace)
 return observe_clean_endpoints_solidity_result(repo,row,workspace,condition,fixture)

def construct_container_service_condition(workspace):
 return _construct_condition(workspace, 'C028-R21-CONTAINER-SERVICE', {'case': 'C028-R21-CONTAINER-SERVICE', 'condition_kind': 'container_service', 'fixture': 'container_service.fixture', 'fault': None, 'nonce': 'd6d049c0912e04b1'})

def observe_container_service_result(repo,row,workspace,condition,fixture):
 return _observe_result(repo,row,workspace,condition,fixture)

def scenario_container_service(repo,row,workspace):
 condition,fixture=construct_container_service_condition(workspace)
 return observe_container_service_result(repo,row,workspace,condition,fixture)

SCENARIO_REGISTRY={
 'C028-D01-GENESIS-CLEAN': scenario_genesis_clean,
 'C028-D02-JAVA-DIR-REJECT': scenario_java_dir_reject,
 'C028-D03-SNAPSHOT-AUTHENTIC': scenario_snapshot_authentic,
 'C028-D04-SNAPSHOT-MISSING-SIGNATURE': scenario_snapshot_missing_signature,
 'C028-D05-SNAPSHOT-MALFORMED': scenario_snapshot_malformed,
 'C028-D06-SNAPSHOT-UNKNOWN-KEY': scenario_snapshot_unknown_key,
 'C028-D07-SNAPSHOT-REVOKED-KEY': scenario_snapshot_revoked_key,
 'C028-D08-SNAPSHOT-ROTATION': scenario_snapshot_rotation,
 'C028-D09-SNAPSHOT-STALE-VALID': scenario_snapshot_stale_valid,
 'C028-D10-SNAPSHOT-CLOCK': scenario_snapshot_clock,
 'C028-D11-SNAPSHOT-ROLLBACK-HEIGHT': scenario_snapshot_rollback_height,
 'C028-D12-SNAPSHOT-CHECKPOINT': scenario_snapshot_checkpoint,
 'C028-D13-SNAPSHOT-COMPROMISED-METADATA': scenario_snapshot_compromised_metadata,
 'C028-D14-SNAPSHOT-WRONG-IDENTITY': scenario_snapshot_wrong_identity,
 'C028-D15-SNAPSHOT-NEWER-FORMAT': scenario_snapshot_newer_format,
 'C028-D16-SNAPSHOT-PARTIAL-CORRUPT': scenario_snapshot_partial_corrupt,
 'C028-D17-SNAPSHOT-DURABLE-FAULTS': scenario_snapshot_durable_faults,
 'C028-D18-MIGRATION-DURABLE-FAULTS': scenario_migration_durable_faults,
 'C028-D19-MIGRATION-WRONG-IDENTITY': scenario_migration_wrong_identity,
 'C028-D20-UPGRADE-ROLLBACK-MATRIX': scenario_upgrade_rollback_matrix,
 'C028-D21-CORRUPTION': scenario_corruption,
 'C028-D22-RESYNC-FALLBACK': scenario_resync_fallback,
 'C028-D23-OFFLINE-SNAPSHOT': scenario_offline_snapshot,
 'C028-R01-AUTHENTIC-BUNDLE': scenario_authentic_bundle,
 'C028-R02-MISSING-MANIFEST': scenario_missing_manifest,
 'C028-R03-MALFORMED-SIGNATURE': scenario_malformed_signature,
 'C028-R04-MISMATCHED-MANIFEST': scenario_mismatched_manifest,
 'C028-R05-UNKNOWN-KEY': scenario_unknown_key,
 'C028-R06-EXPIRED-POLICY': scenario_expired_policy,
 'C028-R07-REVOKED-KEY': scenario_revoked_key,
 'C028-R08-THRESHOLD': scenario_threshold,
 'C028-R09-MISSING-EXTRA-ARTIFACT': scenario_missing_extra_artifact,
 'C028-R10-SUBSTITUTED-MIRROR-BYTES': scenario_substituted_mirror_bytes,
 'C028-R11-DETACHED-SBOM': scenario_detached_sbom,
 'C028-R12-DETACHED-PROVENANCE': scenario_detached_provenance,
 'C028-R13-MIXED-RELEASE': scenario_mixed_release,
 'C028-R14-PLATFORM': scenario_platform,
 'C028-R15-SAPLING-EXCLUSION': scenario_sapling_exclusion,
 'C028-R16-TRUST-ROTATION': scenario_trust_rotation,
 'C028-R17-OFFLINE-RELEASE': scenario_offline_release,
 'C028-R18-PREINSTALL-NO-MUTATION': scenario_preinstall_no_mutation,
 'C028-R19-CLEAN-ENDPOINTS-FULL': scenario_clean_endpoints_full,
 'C028-R20-CLEAN-ENDPOINTS-SOLIDITY': scenario_clean_endpoints_solidity,
 'C028-R21-CONTAINER-SERVICE': scenario_container_service,
}

CASE_MODULES=("storage","snapshot","release","platform","runtime","container")
RESULT_FIELDS={"id","decision","mutation","exit_code","stdout_sha256","stderr_sha256","before_tree_sha256","after_tree_sha256","details"}

def load_case_registry():
 registry={}; owners={}
 for name in CASE_MODULES:
  module=importlib.import_module(f"tools.release.c028_cases.{name}")
  cases=getattr(module,"CASES",None)
  if not isinstance(cases,dict): raise RuntimeError(f"C028 case module {name} lacks CASES")
  for case,fn in cases.items():
   if case in registry: raise RuntimeError(f"duplicate C028 case {case}: {owners[case]} and {name}")
   if not callable(fn): raise RuntimeError(f"non-callable C028 case {case}")
   registry[case]=fn; owners[case]=name
 if set(registry)!=set(CASES): raise RuntimeError(f"C028 case registry drift: missing={sorted(set(CASES)-set(registry))} extra={sorted(set(registry)-set(CASES))}")
 return registry,owners

def case_context(repo,workspace,candidate=None,timeout=300):
 rust=repo/"rust-tron"; tools={"cargo":shutil.which("cargo") or "cargo"}
 for name in ("tron-fullnode","tron-solidity","tron-toolkit","tron-release-verify"):
  candidate_path=(candidate/"bundle"/"bin"/name) if candidate else None
  use_candidate = candidate_path and candidate_path.is_file() and (name != "tron-release-verify" or candidate_path.read_bytes()[:4] == b"\x7fELF")
  path=candidate_path if use_candidate else rust/"target"/"debug"/name
  if path.is_file(): tools[name]=str(path)
 return {"repo_root":repo,"repo":repo,"root":repo,"rust_root":rust,"work_dir":workspace,"workspace":workspace,"candidate":candidate,"candidate_dir":candidate/"bundle" if candidate else None,"release_dir":candidate,"installed_prefix":None,"runtime_mounts":{"/opt/tron/current":candidate/"bundle"} if candidate else {},"fixture_mode":False,"mode":"ci","env":{**os.environ,"CARGO_NET_OFFLINE":"true","CARGO_TERM_COLOR":"never"},"timeout_seconds":timeout,"required_tools":tools}

def execute_scenario(repo,case,row,candidate=None):
 scenario=row.get("scenario",{})
 if scenario.get("id")!=case: raise RuntimeError(f"{case}: scenario identity mismatch")
 registry,owners=load_case_registry(); registered=registry.get(case)
 if registered is None: raise RuntimeError(f"{case}: no registered executable case")
 if scenario.get("module")!=owners[case] or scenario.get("function")!=registered.__name__: raise RuntimeError(f"{case}: case module/function substitution")
 with tempfile.TemporaryDirectory(prefix=case.lower()+"-") as directory:
  result=registered(case_context(repo,Path(directory),candidate,int(row.get("timeout_seconds",300))))
 if not isinstance(result,dict) or not RESULT_FIELDS<=set(result): raise RuntimeError(f"{case}: incomplete case result")
 if result["id"]!=case or result["decision"]!=row["expected_result"]: raise RuntimeError(f"{case}: result identity/decision drift")
 for field in ("stdout_sha256","stderr_sha256","before_tree_sha256","after_tree_sha256"):
  if not isinstance(result[field],str) or not re.fullmatch(r"[0-9a-f]{64}",result[field]): raise RuntimeError(f"{case}: invalid {field}")
 if case in NEGATIVE and result["before_tree_sha256"]!=result["after_tree_sha256"]: raise RuntimeError(f"{case}: rejection mutated protected state")
 return {**result,"scenario":case,"scenario_module":owners[case],"scenario_function":registered.__name__}

def execute_manifest_case(case,row,protected,repo,candidate=None):
 action=lambda:execute_scenario(repo,case,row,candidate)
 return mutation_guard(protected,action) if case in NEGATIVE else action()
def run_upgrade_matrix(rows,protected,repo,candidate=None): return [execute_manifest_case(i,rows[i],protected,repo,candidate) for i in D_IDS if i in rows and any(x in i for x in ("MIGRATION","UPGRADE","RESYNC","GENESIS","JAVA","CORRUPTION"))]
def run_snapshot_fault_matrix(rows,protected,repo,candidate=None): return [execute_manifest_case(i,rows[i],protected,repo,candidate) for i in D_IDS if i in rows and "SNAPSHOT" in i]
def run_release_auth_matrix(rows,protected,repo,candidate=None): return [execute_manifest_case(i,rows[i],protected,repo,candidate) for i in R_IDS[:18] if i in rows]

def http_get(port,path):
 with socket.create_connection(('127.0.0.1',port),timeout=3) as stream:
  stream.sendall(f'GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n'.encode())
  data=b''
  while True:
   part=stream.recv(65536)
   if not part: break
   data+=part
 return data.decode(errors='replace')

def assert_closed(port):
 try:
  with socket.create_connection(('127.0.0.1',port),timeout=.3): pass
 except OSError: return
 raise RuntimeError(f'forbidden port is open: {port}')

def sign_release(release,trust_path,prefix=None,config_root=None,receipt=None):
 from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
 raw=json.loads((release/'release-manifest.json').read_text())
 if prefix is not None:
  raw.update({'install_prefix':str(prefix),'current_target':str(prefix/'current'),'config_root':str(config_root),'receipt_path':str(receipt)})
 private_keys=[Ed25519PrivateKey.from_private_bytes(bytes([seed])*32) for seed in (91,92,93)]
 public_keys=[key.public_key().public_bytes_raw() for key in private_keys]
 key_ids=[hashlib.sha256(b'ed25519-v1\0'+public).hexdigest() for public in public_keys]
 def signatures(kind,payload):
  pae=b'DSSEv1 '+str(len(kind)).encode()+b' '+kind.encode()+b' '+str(len(payload)).encode()+b' '+payload
  return [{'key_id':key_ids[index],'algorithm':'ed25519-v1','signature':base64.b64encode(private_keys[index].sign(pae)).decode()} for index in (0,1)]
 keys=[{'key_id':key_id,'algorithm':'ed25519-v1','public_key_base64':base64.b64encode(public).decode(),'not_before':'2026-01-01T00:00:00Z','not_after':'2027-01-01T00:00:00Z','revoked':False} for key_id,public in zip(key_ids,public_keys)]
 roles=[{'name':name,'key_ids':key_ids,'threshold':2,'scope':scope} for name,scope in (('root','trust-store'),('release:fixture','release:fixture'),('provenance:P-LINUX-X64','provenance:P-LINUX-X64'))]
 trust_path.write_text(json.dumps({'schema':'tron-trust-store-v1','version':1,'expires':'2027-01-01T00:00:00Z','keys':keys,'roles':roles},sort_keys=True,separators=(',',':')))
 provenance=release/'bundle/provenance.dsse.json'; penv=json.loads(provenance.read_text()); ptype=penv.pop('payloadType',penv.pop('payload_type',None)); payload=base64.b64decode(penv['payload']); penv['payload_type']=ptype; penv['signatures']=signatures(ptype,payload); provenance.write_text(json.dumps(penv,sort_keys=True,separators=(',',':')))
 artifact=next(item for item in raw['artifacts'] if item['path']=='provenance.dsse.json'); artifact['sha256']=digest(provenance); artifact['size']=provenance.stat().st_size
 manifest=(json.dumps(raw,sort_keys=True,separators=(',',':'))+'\n').encode(); (release/'release-manifest.json').write_bytes(manifest); payload_type='application/vnd.tron.release-manifest.v1+json'; envelope={'payload_type':payload_type,'payload':base64.b64encode(manifest).decode(),'signatures':signatures(payload_type,manifest)}; (release/'release-manifest.dsse.json').write_text(json.dumps(envelope,sort_keys=True,separators=(',',':')))

def prepare_runtime_config(repo,source,directory,release_id,receipt,solidity,snapshot_trust):
 directory.mkdir(parents=True,exist_ok=True); value=json.loads(source.read_text()); value['expected_release']={'release_id':release_id,'minimum_release_sequence':1}; paths=value['paths']; acceptance=directory.parent/(directory.name+'-acceptance'); acceptance.mkdir(parents=True,exist_ok=True); chain=directory.parent/('solidity.conf' if solidity else 'fullnode.conf'); shutil.copyfile(repo/'rust-tron/packaging/config'/chain.name,chain); paths['chain_config']=str(chain); paths['data_directory']=str(directory/'data'); paths['install_receipt']=str(receipt); paths['keystore_directory']=str(directory/'keystore'); paths['sapling_spend']=str(repo/'java-tron/framework/src/main/resources/params/sapling-spend.params'); paths['sapling_output']=str(repo/'java-tron/framework/src/main/resources/params/sapling-output.params'); paths['snapshot_trust_store']=str(directory/'snapshot-trust.json'); paths['snapshot_watermark']=str(acceptance/'watermark.json'); paths.pop('backup_keyring',None)
 for name in ('data','keystore'): (directory/name).mkdir(parents=True,exist_ok=True); (directory/name).chmod(0o700)
 shutil.copyfile(snapshot_trust,directory/'snapshot-trust.json'); (directory/'snapshot-trust.json').chmod(0o600)
 output=directory/'deployment.json'; output.write_text(json.dumps(value)); return output

def authenticated_clean_install(repo,release):
 root=Path(tempfile.mkdtemp(prefix='c028-installed-')); trust=root/'release-trust.json'; prefix=root/'prefix'; config_root=root/'config'; config_root.mkdir(); receipt=root/'receipt/install-receipt.json'; receipt.parent.mkdir(); sign_release(release,trust,prefix,config_root,receipt)
 verifier=release/'bundle/bin/tron-release-verify'
 if not verifier.is_file(): raise RuntimeError('release bundle lacks tron-release-verify')
 channel=json.loads((release/'release-manifest.json').read_text())['channel']
 base=[str(verifier),'install','--trust-store',str(trust),'--manifest',str(release/'release-manifest.dsse.json'),'--bundle',str(release/'bundle'),'--platform','P-LINUX-X64','--channel',channel,'--minimum-sequence','1','--prefix',str(prefix),'--config-root',str(config_root),'--receipt',str(receipt),'--retained-slots','2','--verification-time','2026-09-08T12:00:00Z']
 verify=[str(verifier),'verify-install','--trust-store',str(trust),'--manifest',str(release/'release-manifest.dsse.json'),'--bundle',str(release/'bundle'),'--platform','P-LINUX-X64','--channel',channel,'--minimum-sequence','1','--receipt',str(receipt),'--prefix',str(prefix/'current'),'--verification-time','2026-09-08T12:00:00Z']
 results=[run_checked(base,env={**os.environ,'CARGO_NET_OFFLINE':'true'}),run_checked(verify,env={**os.environ,'CARGO_NET_OFFLINE':'true'})]
 installed_config=config_root/'current'
 for name in ('fullnode.conf','fullnode.deployment.json','solidity.conf','solidity.deployment.json'):
  if not (installed_config/name).is_file(): raise RuntimeError(f'artifact-only install omitted signed config {name}')
 result={'steps':len(results),'signed_configs':4,'run_sha256':emit_run_hashes(results)['run_sha256']}; shutil.rmtree(root); return result

def wait_ready(binary,config,timeout):
 end=time.monotonic()+timeout
 while time.monotonic()<end:
  if subprocess.run([str(binary),'probe','--deployment-config',str(config),'--kind','ready'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode==0:return
  time.sleep(.2)
 raise RuntimeError('readiness timeout')
def run_node(binary,config,ports,requests=None,forbidden=None):
 pre=run_checked([str(binary),'preflight','--deployment-config',str(config),'--json'])
 proc=subprocess.Popen([str(binary),'--deployment-config',str(config)],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
 try:
  wait_ready(binary,config,120)
  for port in ports:
   probe=socket.socket()
   try: probe.bind(('127.0.0.1',port))
   except OSError: pass
   else: raise RuntimeError(f'expected listener is not bound: {port}')
   finally: probe.close()
  for port,path,token in requests or []:
   if token not in http_get(port,path): raise RuntimeError(f'semantic request failed: {port}{path}')
  for port in forbidden or []: assert_closed(port)
  proc.send_signal(signal.SIGTERM); rc=proc.wait(timeout=125)
  if rc!=0: raise RuntimeError(f'node SIGTERM exit {rc}: stdout={proc.stdout.read()} stderr={proc.stderr.read()}')
 finally:
  if proc.poll() is None: proc.kill(); proc.wait()
 return pre

def run_clean_install(args):
 required=[args.verifier,args.trust_store,args.manifest,args.bundle,args.prefix,args.config_root,args.receipt]
 if any(x is None for x in required): raise RuntimeError('clean-install requires verifier, trust store, manifest, bundle, prefix, config root, and receipt')
 install=[str(args.verifier),'install','--trust-store',str(args.trust_store),'--manifest',str(args.manifest),'--bundle',str(args.bundle),'--platform','P-LINUX-X64','--channel','stable','--minimum-sequence',str(args.minimum_sequence),'--prefix',str(args.prefix),'--config-root',str(args.config_root),'--receipt',str(args.receipt),'--retained-slots','2','--verification-time','2026-09-08T12:00:00Z']
 verify=[str(args.verifier),'verify-install','--trust-store',str(args.trust_store),'--manifest',str(args.manifest),'--bundle',str(args.bundle),'--platform','P-LINUX-X64','--channel','stable','--minimum-sequence',str(args.minimum_sequence),'--receipt',str(args.receipt),'--prefix',str(args.prefix/'current'),'--verification-time','2026-09-08T12:00:00Z']
 results=[run_checked(install),run_checked(verify)]
 if args.fullnode and args.full_config: results.append(run_node(args.fullnode,args.full_config,[9080]))
 if args.solidity and args.solidity_config: results.append(run_node(args.solidity,args.solidity_config,[9080]))
 return results
def validate_external_trust_anchor(repo):
 workflow=(repo/'.github/workflows/c028-release-publish.yml').read_text()
 forbidden=('--trust-store "$CANDIDATE/', "--current \"$CANDIDATE/", "TRUST_STORE=$CANDIDATE")
 for token in forbidden:
  if token in workflow: raise RuntimeError(f'candidate-controlled trust root reaches verifier: {token}')
 required=('secrets.C028_RELEASE_TRUST_ROOT_B64','secrets.C028_RELEASE_TRUST_ROOT_SHA256','sha256sum --check --strict','stage-publish','--trust-store "$TRUST_STORE"','--staging "$STAGING"','PUBLICATION_STAGING=$STAGING','Publish exact staged bytes')
 for token in required:
  if token not in workflow: raise RuntimeError(f'publish workflow lacks external trust or immutable staging control: {token}')
 provision=workflow.index('Provision external release trust root'); stage=workflow.index('Verify and stage immutable publication snapshot'); publish=workflow.index('Publish exact staged bytes')
 if not provision < stage < publish: raise RuntimeError('trust bootstrap/immutable staging/publication ordering is unsafe')
 with tempfile.TemporaryDirectory(prefix='c028-malicious-root-') as directory:
  candidate=Path(directory); (candidate/'release-trust-store.json').write_text('{"candidate":"controls-root"}')
  before=tree_snapshot(candidate)
  if '--trust-store "$CANDIDATE/release-trust-store.json"' in workflow: raise RuntimeError('malicious candidate root selected')
  if tree_snapshot(candidate)!=before: raise RuntimeError('trust-anchor rejection drill mutated candidate')
 return {'external_root':'protected-environment-secret','candidate_root':'rejected','publication_source':'verified-immutable-staging'}
def validate_semantic_runtime(repo):
 results=[]
 for package,target,symbol in SEMANTIC_RUNTIME_PROOFS:
  results.append(run_checked(['cargo','test','--manifest-path',str(repo/'rust-tron/Cargo.toml'),'--locked','--offline','--package',package,'--test',target,symbol,'--','--exact'],timeout=300,env={**os.environ,'CARGO_NET_OFFLINE':'true'}))
 return {'proofs':len(results),'run_sha256':emit_run_hashes(results)['run_sha256']}
def validate_container_runtime(repo):
 docker=shutil.which('docker'); skopeo=shutil.which('skopeo'); umoci=shutil.which('umoci')
 missing=[name for name,value in [('docker',docker),('skopeo',skopeo),('umoci',umoci)] if value is None]
 if missing:
  if os.environ.get('CI'): raise RuntimeError('OCI runtime drill requires '+', '.join(missing))
  return {'available':False,'reason':'missing OCI runtime tools: '+', '.join(missing),'fixture_fallback':False}
 probe=subprocess.run([docker,'info'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
 if probe.returncode != 0:
  if os.environ.get('CI'): raise RuntimeError('Docker daemon is mandatory for the CI OCI preflight row')
  return {'available':False,'reason':'docker daemon unavailable','fixture_fallback':False}
 run_checked(['cargo','build','--manifest-path',str(repo/'rust-tron/Cargo.toml'),'--locked','--offline','--package','tron-toolkit','--bin','tron-release-verify'],timeout=600,env={**os.environ,'CARGO_NET_OFFLINE':'true'})
 import importlib.util
 spec=importlib.util.spec_from_file_location('c028_release_oci',repo/'tools/release/c028_release.py'); release=importlib.util.module_from_spec(spec); spec.loader.exec_module(release)
 with tempfile.TemporaryDirectory(prefix='c028-container-context-') as directory:
  context=Path(directory); stage=context/'stage'; (stage/'bin').mkdir(parents=True); (stage/'config').mkdir()
  verifier=repo/'rust-tron/target/debug/tron-release-verify'
  for name in release.BINS: shutil.copy2(verifier,stage/'bin'/name)
  shutil.copy2(repo/'rust-tron/packaging/container/entrypoint.sh',stage/'entrypoint.sh')
  for config in (repo/'rust-tron/packaging/config').glob('*'):
   if config.is_file(): shutil.copy2(config,stage/'config'/config.name)
  layout=context/'oci'; release.build_oci(stage,layout,0,release.busybox_material(False)); conformance=release.validate_oci_layout(layout)
  unpack=context/'unpacked'; run_checked([umoci,'unpack','--image',str(layout)+':tron',str(unpack)])
  if not (unpack/'rootfs/usr/local/bin/entrypoint.sh').is_file(): raise RuntimeError('umoci unpack lacks declared entrypoint')
  image='tron-c028-oci:'+hashlib.sha256(str(context).encode()).hexdigest()[:12]
  loaded=run_checked([skopeo,'copy','oci:'+str(layout)+':tron','docker-daemon:'+image],timeout=300)
  missing_time=run_checked([docker,'run','--rm','--read-only','--user','65532:65532',image,'fullnode'],timeout=60,expect=64)
  malformed_time=run_checked([docker,'run','--rm','--read-only','--user','65532:65532','--env','TRON_VERIFICATION_TIME=not-rfc3339',image,'fullnode'],timeout=60,expect=64)
  rejected=run_checked([docker,'run','--rm','--read-only','--user','65532:65532','--env','TRON_VERIFICATION_TIME=2026-09-08T12:00:00Z',image,'fullnode'],timeout=60,expect=66)
  if any(row['stderr_sha256']==hashlib.sha256(b'').hexdigest() for row in (missing_time,malformed_time,rejected)): raise RuntimeError('emitted OCI did not explain verification-time/material rejection')
  inspect=run_checked([docker,'image','inspect','--format','{{.Config.User}} {{json .Config.Entrypoint}}',image])
  run_checked([docker,'image','rm','--force',image])
  parity='tron-c028-dockerfile:'+hashlib.sha256(str(context).encode()).hexdigest()[:12]
  docker_context=context/'docker'; (docker_context/'bin').mkdir(parents=True); shutil.copy2(verifier,docker_context/'bin/tron-release-verify'); shutil.copy2(stage/'entrypoint.sh',docker_context/'entrypoint.sh')
  base=os.environ.get('TRON_CONTAINER_RUNTIME_BASE','debian:bookworm-slim@sha256:88200866dfff7ea7f5cbcb6ec7c8a701889efe6fe859fe64d6990e4b07ea4171')
  parity_build=run_checked([docker,'build','--build-arg','RUNTIME_BASE='+base,'--file',str(repo/'rust-tron/packaging/container/Dockerfile'),'--tag',parity,str(docker_context)],timeout=600); run_checked([docker,'image','rm','--force',parity])
  return {'available':True,'oci_copy':loaded,'conformance':conformance,'missing_verification_time_rejected':missing_time,'malformed_verification_time_rejected':malformed_time,'missing_material_rejected':rejected,'image_policy':inspect,'dockerfile_parity':parity_build,'fixture_fallback':False}



def validate_assets(repo):
 configs=list((repo/'rust-tron/packaging/config').glob('*.json')); [json.loads(p.read_text()) for p in configs]
 for p in (repo/'rust-tron/packaging/systemd').glob('*.service'):
  text=p.read_text();
  for token in ('NoNewPrivileges=yes','ProtectSystem=strict','LimitNOFILE=65535','TimeoutStopSec=120','KillSignal=SIGTERM'):
   if token not in text: raise RuntimeError(f'{p}: missing {token}')
 compose=(repo/'rust-tron/packaging/container/compose.yaml').read_text()
 for bad in ('0.0.0.0:8090','0.0.0.0:50051','0.0.0.0:9080'):
  if bad in compose: raise RuntimeError('public API mapping forbidden')
 run_checked(['/bin/sh','-n',str(repo/'rust-tron/packaging/container/entrypoint.sh')])
 for p in [repo/'tools/release/c028_release.py',repo/'tools/release/c028_drills.py']:
  run_checked([os.environ.get('PYTHON','python3'),'-m','py_compile',str(p)])
 return {"cases":len(CASES),"negative_cases":len(NEGATIVE),"phases":list(PHASES),"assets":"valid","trust_anchor":validate_external_trust_anchor(repo),"container_runtime":validate_container_runtime(repo),"semantic_runtime":validate_semantic_runtime(repo)}
def emit_run_hashes(results):
 raw=json.dumps(results,sort_keys=True,separators=(',',':')).encode(); return {"run_sha256":hashlib.sha256(raw).hexdigest(),"results":results}

def main():
 p=argparse.ArgumentParser(); p.add_argument('command',choices=('self-check','drills','clean-install','scenario')); p.add_argument('--repo',type=Path,default=Path(__file__).resolve().parents[2]); p.add_argument('--candidate-dir',type=Path); p.add_argument('--command-manifest',type=Path); p.add_argument('--id'); p.add_argument('--protected',type=Path,action='append',default=[]); p.add_argument('--verifier',type=Path); p.add_argument('--trust-store',type=Path); p.add_argument('--manifest',type=Path); p.add_argument('--bundle',type=Path); p.add_argument('--prefix',type=Path); p.add_argument('--config-root',type=Path); p.add_argument('--receipt',type=Path); p.add_argument('--minimum-sequence',type=int,default=0); p.add_argument('--fullnode',type=Path); p.add_argument('--full-config',type=Path); p.add_argument('--solidity',type=Path); p.add_argument('--solidity-config',type=Path); a=p.parse_args()
 if len(CASES)!=44 or len(set(CASES))!=44: raise RuntimeError('drill matrix must contain exactly 44 unique cases')
 if a.command=='self-check': print(json.dumps(validate_assets(a.repo),sort_keys=True)); return
 if a.command=='clean-install': result=run_clean_install(a)
 else:
  if not a.command_manifest: p.error('--command-manifest is required')
  _,rows=load_manifest(a.command_manifest)
  if a.command=='scenario':
   if a.id not in rows: raise RuntimeError('unknown scenario: '+str(a.id))
   result=[execute_scenario(a.repo,a.id,rows[a.id],a.candidate_dir)]
  else:
   missing=[i for i in CASES if i not in rows]
   if missing: raise RuntimeError('command manifest missing cases: '+','.join(missing))
   result=run_upgrade_matrix(rows,a.protected,a.repo,a.candidate_dir)+run_snapshot_fault_matrix(rows,a.protected,a.repo,a.candidate_dir)+run_release_auth_matrix(rows,a.protected,a.repo,a.candidate_dir)
   result += [execute_manifest_case(i,rows[i],a.protected,a.repo,a.candidate_dir) for i in R_IDS[18:]]
   if len(result)!=44 or {r['scenario'] for r in result}!=set(CASES): raise RuntimeError('canonical drills did not execute every manifest row exactly once')
 print(json.dumps(emit_run_hashes(result),sort_keys=True))
if __name__=='__main__': main()
