#!/usr/bin/env python3
"""Bounded UDP proxy and authenticated C020 discovery capture verifier."""
import argparse,hashlib,json,socket,time

def addr(value):
    host,port=value.rsplit(':',1);return host,int(port)
def verify(path,artifact):
    doc=json.load(open(path));rows=[r for r in doc['captures'] if r['transport']=='udp']
    expected={'udp-java-to-rust-ping':1,'udp-rust-to-java-pong':2,'udp-java-neighbours':4}
    if {r['id'] for r in rows}!=set(expected): raise SystemExit('expected Java Ping, Pong, and Neighbours UDP captures')
    for row in rows:
        body=bytes.fromhex(row['hex'])
        if not 2<=len(body)<=2047 or len(body)!=row['size'] or hashlib.sha256(body).hexdigest()!=row['sha256']:
            raise SystemExit('UDP capture mismatch: '+row['id'])
        if body[0]!=expected[row['id']]: raise SystemExit('UDP capture type mismatch: '+row['id'])
        if row.get('source_ip')!='127.0.0.1' or b'127.0.0.1' not in body:
            raise SystemExit('UDP declared/captured source mismatch: '+row['id'])
        if bytes([127,0,0,1]) in body: raise SystemExit('unproven binary endpoint encoding: '+row['id'])
    if artifact!='01df0a95ec660a6349575a17a454d3f96afa2ac602a467bded66afe0ea69ac30': raise SystemExit('libp2p artifact hash mismatch')
    print('UDP_CAPTURE_VERIFY_OK')
def main():
    p=argparse.ArgumentParser();p.add_argument('--listen',default='127.0.0.1:0');p.add_argument('--forward');p.add_argument('--count',type=int);p.add_argument('--direction',choices=['java-to-rust','rust-to-java']);p.add_argument('--output');p.add_argument('--verify-catalog');p.add_argument('--artifact-sha256',default='01df0a95ec660a6349575a17a454d3f96afa2ac602a467bded66afe0ea69ac30');a=p.parse_args()
    if a.verify_catalog: verify(a.verify_catalog,a.artifact_sha256);return
    if not all((a.forward,a.count,a.direction,a.output)): p.error('--forward, --count, --direction and --output are required')
    s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind(addr(a.listen));s.settimeout(10);print(f'{s.getsockname()[0]}:{s.getsockname()[1]}',flush=True);rows=[]
    for _ in range(a.count):
        data,source=s.recvfrom(2048)
        if not 2<=len(data)<=2047:raise SystemExit(f'invalid discovery datagram length {len(data)}')
        rows.append({'direction':a.direction,'source':f'{source[0]}:{source[1]}','timestamp_ns':time.time_ns(),'hex':data.hex()});s.sendto(data,addr(a.forward))
    json.dump({'schema':'c020-udp-capture.v1','artifact_sha256':a.artifact_sha256,'datagrams':rows},open(a.output,'w'),sort_keys=True,separators=(',',':'))
if __name__=='__main__':main()
