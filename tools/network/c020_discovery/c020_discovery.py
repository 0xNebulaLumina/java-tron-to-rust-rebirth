#!/usr/bin/env python3
"""Authenticate the pinned libp2p jar, validate C020 oracle, and run Rust replay."""
import argparse, hashlib, json, pathlib, subprocess, sys
ROOT=pathlib.Path(__file__).resolve().parents[3]
ORACLE=ROOT/'docs/oracles/c020-discovery.v1.json'
EXPECTED='01df0a95ec660a6349575a17a454d3f96afa2ac602a467bded66afe0ea69ac30'
def main():
 p=argparse.ArgumentParser();p.add_argument('--jar',type=pathlib.Path);p.add_argument('--capture',type=pathlib.Path);p.add_argument('--no-test',action='store_true');a=p.parse_args()
 data=json.loads(ORACLE.read_text());assert data['schema']=='c020-discovery.v1';assert data['artifact']['sha256']==EXPECTED
 assert data['wire']['minimum_bytes']==2 and data['wire']['maximum_bytes']==2047
 assert data['persistence']['json_key']=='peers' and data['persistence']['maximum']==30
 if a.jar:
  raw=a.jar.read_bytes();assert len(raw)==390984,'unexpected jar size';assert hashlib.sha256(raw).hexdigest()==EXPECTED,'unauthenticated jar'
 if a.capture:
  capture=json.loads(a.capture.read_text());assert capture['artifact_sha256']==EXPECTED
  for packet in capture['datagrams']:
   raw=bytes.fromhex(packet['hex']);assert 2<=len(raw)<=2047;assert packet['direction'] in ('java-to-rust','rust-to-java')
 if not a.no_test:subprocess.run(['cargo','test','-p','tron-network','--test','c020_discovery'],cwd=ROOT/'rust-tron',check=True)
 print('C020 discovery oracle and Rust replay passed')
if __name__=='__main__':main()
