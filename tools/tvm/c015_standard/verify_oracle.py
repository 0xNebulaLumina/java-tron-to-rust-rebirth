#!/usr/bin/env python3
import hashlib,json,pathlib,sys
ROOT=pathlib.Path(__file__).resolve().parents[3]
SOURCE=ROOT/'java-tron/framework/src/test/resources/precompiles/p256verify_test_vectors.json'
ORACLE=ROOT/'docs/oracles/c015-standard.v1.json'
def main():
    source=json.loads(SOURCE.read_text())
    oracle=json.loads(ORACLE.read_text())
    digest=hashlib.sha256(SOURCE.read_bytes()).hexdigest()
    assert oracle['java_revision']=='4a21592f95e37908b21bc3f611c6e7a1a67f09f3'
    assert oracle['java_source_sha256']==digest
    assert oracle['p256_records']==source
    assert len(source)==782
    assert all(row['Gas']==6900 and len(bytes.fromhex(row['Input']))==160 for row in source)
    assert oracle['modexp_vectors']==[
        {'id':'pre_version_4_8_1_1','base_len':0,'exp_len':1025,'mod_len':0,'osaka':False,'version_4_8_1_1':False,'energy':0,'result':'success','output':''},
        {'id':'version_4_8_1_1_to_osaka','base_len':0,'exp_len':1025,'mod_len':0,'osaka':False,'version_4_8_1_1':True,'energy':0,'result':'out_of_time','output':''},
        {'id':'osaka','base_len':0,'exp_len':1025,'mod_len':0,'osaka':True,'version_4_8_1_1':True,'energy':254208,'result':'precompiled_contract','output':''},
    ]
    print(f'c015-standard: {len(source)} pinned Java records, sha256={digest}')
if __name__=='__main__':
    try: main()
    except (AssertionError,KeyError,ValueError) as error:
        print(f'c015-standard oracle mismatch: {error}',file=sys.stderr);sys.exit(1)
