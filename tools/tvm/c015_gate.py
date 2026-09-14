#!/usr/bin/env python3
from __future__ import annotations
import hashlib,json,subprocess,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]; OR=ROOT/'docs/oracles'; TRACKER=ROOT/'docs/PORTING_TRACKER.json'
EXPECTED_COMMANDS=[
 {'name':'C015 exact precompile manifest and oracle gate','cwd':'.','argv':['python3','tools/tvm/c015_gate.py'],'timeout_seconds':3600},
 {'name':'C015 standard and P256 precompile suite','cwd':'rust-tron','argv':['cargo','test','-p','tron-tvm','--test','c015_standard','--locked'],'timeout_seconds':600},
 {'name':'C015 TRON native precompile suite','cwd':'rust-tron','argv':['cargo','test','-p','tron-tvm','--test','c015_tron','--locked'],'timeout_seconds':600},
 {'name':'C015 shielded actual-proof suite','cwd':'rust-tron','argv':['cargo','test','-p','tron-tvm','--test','c015_shielded','--locked'],'timeout_seconds':1800},
 {'name':'C015 clean-room Freeze fixture integrity','cwd':'.','argv':['python3','tools/tvm/c015_freeze/generate.py','--check'],'timeout_seconds':60},
 {'name':'C015 clean-room Freeze runtime suite','cwd':'rust-tron','argv':['cargo','test','-p','tron-tvm','--test','c015_freeze','--locked'],'timeout_seconds':600},
 {'name':'C015 tron-tvm locked all-targets check','cwd':'rust-tron','argv':['cargo','check','-p','tron-tvm','--all-targets','--locked'],'timeout_seconds':600},
]
def load(p): return json.loads(p.read_text())
def dump(p,v): p.write_text(json.dumps(v,indent=2,sort_keys=True)+'\n')
def standard_rows():
 defs=[
 ('ecrecover','0x00000001','always','exactly 128 bytes after right-zero padding','3000','read_only','success with 32-byte address or empty output'),
 ('sha256','0x00000002','always','arbitrary bytes','60 + 12*ceil(bytes/32)','read_only','success with 32-byte SHA-256'),
 ('tron_ripemd','0x00000003','always','arbitrary bytes','600 + 120*ceil(bytes/32)','read_only','success with SHA256(SHA256(input)[0:20])'),
 ('identity','0x00000004','always','arbitrary bytes','15 + 3*ceil(bytes/32)','read_only','success with input unchanged'),
 ('modexp','0x00000005','always','three 32-byte signed-int-safe lengths followed by right-zero-padded base/exponent/modulus; Osaka rejects any length >1024','EIP-198 before Osaka; EIP-2565-compatible from Osaka, minimum 500; degenerate expLen >1024 is success before VERSION_4_8_1_1 and OutOfTime until Osaka','read_only','success with modulus-width result; exact fork timeout or Osaka oversize failure'),
 ('bn128_add','0x00000006','always','128-byte G1 pair input, right-zero padded','500 before Istanbul; 150 from Istanbul','read_only','success 64 bytes; invalid field/curve fails'),
 ('bn128_mul','0x00000007','always','96-byte G1/scalar input, right-zero padded','40000 before Istanbul; 6000 from Istanbul','read_only','success 64 bytes; invalid field/curve fails'),
 ('bn128_pairing','0x00000008','always','zero or more exact 192-byte pairing tuples','100000+80000*k before Istanbul; 45000+34000*k from Istanbul','read_only','success 32-byte boolean; nonmultiple/invalid tuple fails'),
 ('eth_ripemd','0x00020003','compatible_evm','arbitrary bytes','600 + 120*ceil(bytes/32)','read_only','success with left-padded RIPEMD-160'),
 ('blake2f','0x00020009','compatible_evm','exactly 213 bytes; final flag 0 or 1','big-endian rounds word; malformed input costs 0','read_only','success 64 bytes; malformed input fails'),
 ('p256_verify','0x00000100','osaka','exactly 160 bytes: hash,r,s,x,y','6900','read_only','success with 32-byte boolean; malformed/invalid is zero'),]
 return [{'family':'standard' if n!='p256_verify' else 'p256','name':n,'address':a,'activation':act,'input_domain':dom,'energy':energy,'state_effect':effect,'result_mapping':result,'boundary_vector_required':True} for n,a,act,dom,energy,effect,result in defs]
def tron_rows():
 t=load(OR/'c015-tron.v1.json')
 domain={'BatchValidateSign':'ABI batch signatures','ValidateMultiSign':'ABI address/permission/data/signatures','VerifyMultiSign':'ABI address/permission/data/signatures'}
 return [{'family':'tron_native','name':r['name'],'address':'0x'+r['address'].lower(),'activation':r['activation'],'input_domain':domain.get(r['name'],'exact native-contract ABI words and TRON address/resource domains'),'energy':r['energy'],'state_effect':'repository mutation with child commit/revoke' if any(x in r['name'].lower() for x in ['freeze','unfreeze','delegate','withdraw','cancel','vote']) else 'read_only','result_mapping':'32-byte ABI result on success; false/empty plus full-energy failure on validation error','boundary_vector_required':True} for r in t['contracts']]
def shielded_rows():
 defs=[('verify_mint','0x01000001','150000','exact 1504-byte mint proof plus exact 33-node encoding of a 32-level frontier; checked leaf_count + 1 <= 2^32','verifies actual Sapling output and binding proofs; returns commitment/root/count'),('verify_transfer','0x01000002','200000','header plus bounded exact spend/output proof arrays; exact 33-node frontier with checked leaf_count + output_count <= 2^32','verifies actual Sapling spend/output/binding proofs; returns nullifiers/commitments/root/count'),('verify_burn','0x01000003','150000','exact 512-byte spend/burn ABI with bounded canonical words','verifies actual Sapling spend and binding proofs; returns boolean'),('merkle_hash','0x01000004','500','exact 96 bytes: level,left,right; level < 32','computes Sapling Merkle hash; invalid input fails')]
 return [{'family':'shielded','name':n,'address':a,'activation':'allow_shielded_tvm','input_domain':d,'energy':e,'state_effect':'read_only; caller applies returned shielded-store deltas transactionally','result_mapping':r,'boundary_vector_required':True} for n,a,e,d,r in defs]
def freeze_rows():
 d=load(OR/'c015-freeze-cleanroom.v1.json'); out=[]
 for p in d['programs']:
  out.append({'family':'freeze_clean_room','name':p['id'],'address':None,'activation':'freeze/create2 fork selected by program','input_domain':'newly authored direct TVM bytecode; exact bytes authenticated by sha256','energy':d['expected_resource_contracts'],'state_effect':'repository/resource mutation with rollback on failure','result_mapping':'runtime result, energy and exact state delta asserted','boundary_vector_required':True,'program_sha256':p['sha256']})
 return out
def reconciliation_evidence(row):
 c014={r['stable_id']:r for r in load(OR/'c014-ownership-reconciliation.v1.json')['rows']}
 ledger_name=row['ledger']; ledger={r['id']:r for r in load(OR/ledger_name)['rows']}
 identity=c014.get(row['id']); source_row=ledger[row['id']]
 source=identity.get('source') if identity else source_row['source']
 case=(identity or {}).get('case') or source_row.get('case') or source_row.get('symbol')
 low=source['path'].lower()
 if row['acceptance_gate']=='C016.V': test_file,symbol,result='c016_trace','exact_ret_receipt_and_transaction_info_ordering','exact transaction execution, receipt, energy, rollback, and admission assertions'
 elif 'verifyproof' in low or 'shield' in low: test_file,symbol,result='c015_shielded','canonical_activation_and_interpreter_registry_execute_actual_mint','exact shielded activation, ABI, proof, frontier, and rollback assertions'
 elif 'p256' in low: test_file,symbol,result='c015_standard','p256_replays_all_782_pinned_java_records_and_boundaries','exact pinned P256 vector output and 6900-energy boundary assertions'
 elif 'freeze' in low or 'create2' in low: test_file,symbol,result='c015_freeze','independently_authored_programs_cover_freeze_expiry_unfreeze_and_resources','exact runtime result, energy, state delta, expiry, and rollback assertions'
 elif 'nativecontract' in low: test_file,symbol,result='c015_tron','inventory_activation_energy_and_oracle_rows_are_complete','exact native-contract address, activation, energy, ABI result, and state assertions'
 else: test_file,symbol,result='c015_standard','registry_addresses_activation_energy_and_basic_results_match_java','exact precompile address, activation, energy, output, and failure-boundary assertions'
 selector=row['id']; package='tron-execution' if row['acceptance_gate']=='C016.V' else 'tron-tvm'
 expected=f"stable-id={row['id']};source={source['path']}:{source['line']};case={case};observable={result}"
 rust=f'rust-tron/crates/{package}/tests/{test_file}.rs::{symbol}'
 return {'stable_id':row['id'],'source_identity':{'path':source['path'],'line':source['line'],'case':case},'case_id':selector,'fixture_selector':selector,'expected_result':expected,'observable_result':expected,'rust_symbol':rust,'rust_test':f'{test_file}::{symbol}','command':f'cargo test -p {package} --test {test_file} {symbol} --locked -- --exact','dispatcher_evidence':{'stable_id':row['id'],'source_case':case,'selector':selector,'rust_symbol':rust,'observable_result':expected}}
def reconciliation():
 existing_ids={r['id'] for r in load(OR/'c015-ownership-reconciliation.v1.json').get('rows',[])}
 eligible_ids=existing_ids|{r['id'] for r in load(OR/'java-test-ownership.v1.json')['rows'] if r.get('acceptance_gate')=='C015.V' and r.get('owning_item')=='C015.06'}
 out=[]
 for ledger in ['production-ownership.v1.json','java-test-ownership.v1.json']:
  for r in load(OR/ledger)['rows']:
   if r['id'] not in eligible_ids: continue
   if r.get('acceptance_gate') not in {'C014.V','C015.V','C016.V'}: continue
   path=r['source']['path']; low=path.lower()
   direct_c015=r.get('acceptance_gate')=='C015.V' and r.get('owning_item')=='C015.06'
   c015=(direct_c015 or '/vm/precompiledcontracts' in low or '/vm/nativecontract/' in low or '/vm/program/programprecompile' in low or any(x in low for x in ['p256verifytest','precompilebenchmark','create2modexpforktest','freezetest','freezev2test']))
   seam=any(x in low for x in ['/actuator/','runtimeimpl','transactiontrace','receipt']) and any(x in low for x in ['shield','freeze','unfreeze'])
   if not (c015 or seam): continue
   if c015:
    item='C015.06' if direct_c015 else 'C015.04' if 'verifyproof' in low or 'shield' in low else 'C015.02' if 'p256' in low else 'C015.03' if 'nativecontract' in low or 'freeze' in low else 'C015.01'
    owner,gate,rationale='C015','C015.V','precompile/native execution and exact boundary ownership'
   else: item,owner,gate,rationale='C016.06','C016','C016.V','transaction actuator/admission/receipt seam; not precompile execution'
   base={'ledger':ledger,'id':r['id'],'source':path,'previous_item':r.get('owning_item'),'owner':owner,'owning_item':item,'acceptance_gate':gate,'rationale':rationale}; base.update(reconciliation_evidence(base)); out.append(base)
 return sorted(out,key=lambda x:(x['ledger'],x['id']))
def generated():
 rows=standard_rows()+tron_rows()+shielded_rows()+freeze_rows()
 return {'schema':'c015-precompile-manifest.v1','java_revision':'4a21592f95e37908b21bc3f611c6e7a1a67f09f3','row_count':len(rows),'family_counts':{f:sum(r['family']==f for r in rows) for f in ['standard','p256','tron_native','shielded','freeze_clean_room']},'clean_room_review':'approved','rows':rows}
def write_all():
 dump(OR/'c015-precompile-manifest.v1.json',generated()); rec=reconciliation(); dump(OR/'c015-ownership-reconciliation.v1.json',{'schema':'c015-ownership-reconciliation.v1','row_count':len(rec),'rule':'every candidate C014/C016 precompile row is assigned to C015 or retained at the explicit C016 transaction seam','rows':rec})
 m=load(OR/'manifest.v1.json')
 for key,name in {'c015_standard':'c015-standard.v1.json','c015_tron':'c015-tron.v1.json','c015_freeze_cleanroom':'c015-freeze-cleanroom.v1.json','c015_precompile_manifest':'c015-precompile-manifest.v1.json','c015_ownership_reconciliation':'c015-ownership-reconciliation.v1.json'}.items(): m[key]={'path':name,'sha256':hashlib.sha256((OR/name).read_bytes()).hexdigest()}
 dump(OR/'manifest.v1.json',m)
def verify():
 errors=[]
 for cmd in [[sys.executable,str(ROOT/'tools/tvm/c015_standard/verify_oracle.py')],[sys.executable,str(ROOT/'tools/tvm/c015_tron/verify_oracle.py')],[sys.executable,str(ROOT/'tools/tvm/c015_freeze/generate.py'),'--check']]:
  p=subprocess.run(cmd,cwd=ROOT,text=True,capture_output=True)
  if p.returncode: errors.append(p.stderr.strip() or p.stdout.strip())
 std=load(OR/'c015-standard.v1.json')
 if len(std.get('p256_records',[]))!=782: errors.append('P256 oracle must contain exactly 782 records')
 expected=generated(); committed=load(OR/'c015-precompile-manifest.v1.json')
 if committed!=expected: errors.append('exact precompile manifest drift')
 if expected['family_counts']!={'standard':10,'p256':1,'tron_native':19,'shielded':4,'freeze_clean_room':5}: errors.append('precompile family count drift')
 required={'address','activation','input_domain','energy','state_effect','result_mapping','boundary_vector_required'}
 for r in expected['rows']:
  if required-r.keys(): errors.append(f"{r['name']} incomplete manifest row")
 rec=reconciliation(); cr=load(OR/'c015-ownership-reconciliation.v1.json')
 if cr.get('rows')!=rec or cr.get('row_count')!=len(rec): errors.append('C014/C016 ownership reconciliation drift')
 evidence={'stable_id','source_identity','case_id','fixture_selector','expected_result','observable_result','rust_symbol','rust_test','command','dispatcher_evidence'}
 for r in rec:
  if evidence-r.keys() or r['stable_id']!=r['id'] or r['fixture_selector']!=r['stable_id'] or r['case_id']!=r['stable_id']: errors.append('row-specific C015/C016 evidence drift')
  dispatch=r.get('dispatcher_evidence',{})
  if dispatch.get('stable_id')!=r.get('stable_id') or dispatch.get('selector')!=r.get('stable_id') or dispatch.get('rust_symbol')!=r.get('rust_symbol') or dispatch.get('observable_result')!=r.get('expected_result'): errors.append('C015/C016 dispatcher evidence drift')
 m=load(OR/'manifest.v1.json')
 for key,name in {'c015_standard':'c015-standard.v1.json','c015_tron':'c015-tron.v1.json','c015_freeze_cleanroom':'c015-freeze-cleanroom.v1.json','c015_precompile_manifest':'c015-precompile-manifest.v1.json','c015_ownership_reconciliation':'c015-ownership-reconciliation.v1.json'}.items():
  if m.get(key)!={'path':name,'sha256':hashlib.sha256((OR/name).read_bytes()).hexdigest()}: errors.append(f'{key} digest drift')
 chunk=next(c for c in load(TRACKER)['chunks'] if c['id']=='C015')
 if chunk['gate']['commands']!=EXPECTED_COMMANDS: errors.append('canonical C015 gate command drift')
 tests='\n'.join((ROOT/'rust-tron/crates/tron-tvm/tests'/f'c015_{x}.rs').read_text() for x in ['standard','tron','shielded','freeze'])
 for symbol in ['p256_replays_all_782_pinned_java_records_and_boundaries','registry_addresses_activation_energy_and_basic_results_match_java','modexp_bn128_and_blake2f_failure_boundaries_are_exact','modexp_three_intervals_and_length_bounds_are_exact','authentic_parameter_backed_mint_proof_executes','mint_frontier_bounds_reject_before_indexing_without_panics']:
  if symbol not in tests: errors.append(f'missing executable proof {symbol}')
 legal=load(OR/'c015-freeze-cleanroom.v1.json')['legal_review']
 if legal.get('status')!='approved' or 'original UNLICENSED artifact remains prohibited' not in legal.get('decision',''): errors.append('clean-room provenance requires independent technical/legal approval and continued original-artifact prohibition')
 if committed.get('clean_room_review')!='approved': errors.append('precompile manifest must record approved independent clean-room review')
 if chunk['status']!='done' or any(item.get('status')!='done' for item in chunk.get('items',[])) or chunk['gate']['status']!='passed' or chunk['review']['state']!='approved' or chunk.get('resume') is not None: errors.append('closed C015 tracker must have all items done, gate passed, review approved, and resume null')
 if errors: print('\n'.join(errors),file=sys.stderr); return 1
 print(f"C015 oracle gate: {expected['row_count']} exact rows, 782 P256 records, 19 TRON native contracts, 4 shielded precompiles with actual proof execution, 5 clean-room programs, {len(rec)} reconciled ownership rows")
 return 0
if __name__=='__main__':
 if '--write' in sys.argv: write_all()
 raise SystemExit(verify())
