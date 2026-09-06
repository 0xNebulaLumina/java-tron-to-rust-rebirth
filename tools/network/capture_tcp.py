#!/usr/bin/env python3
"""Bidirectional localhost TCP capture proxy and C020 capture verifier."""
import argparse,hashlib,json,socket,threading,time

def endpoint(value):
    host,port=value.rsplit(':',1);return host,int(port)
def pump(source,destination,direction,rows):
    while True:
        data=source.recv(65536)
        if not data: break
        rows.append({'direction':direction,'timestamp_ns':time.time_ns(),'hex':data.hex()})
        destination.sendall(data)
    try: destination.shutdown(socket.SHUT_WR)
    except OSError: pass
def verify(path):
    rows=[r for r in json.load(open(path))['captures'] if r['transport']=='tcp']
    if len(rows)!=2: raise SystemExit('expected two TCP captures')
    for row in rows:
        body=bytes.fromhex(row['hex'])
        if len(body)!=row['size'] or hashlib.sha256(body).hexdigest()!=row['sha256']:
            raise SystemExit('TCP capture mismatch: '+row['id'])
    print('TCP_CAPTURE_VERIFY_OK')
def main():
    p=argparse.ArgumentParser();p.add_argument('--listen');p.add_argument('--forward');p.add_argument('--output');p.add_argument('--verify-catalog');a=p.parse_args()
    if a.verify_catalog: verify(a.verify_catalog);return
    if not all((a.listen,a.forward,a.output)): p.error('--listen, --forward and --output are required')
    rows=[]
    with socket.socket() as server:
        server.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);server.bind(endpoint(a.listen));server.listen(1);client,_=server.accept()
        with client,socket.create_connection(endpoint(a.forward)) as upstream:
            threads=[threading.Thread(target=pump,args=(client,upstream,'initiator-to-listener',rows)),threading.Thread(target=pump,args=(upstream,client,'listener-to-initiator',rows))]
            [t.start() for t in threads];[t.join() for t in threads]
    with open(a.output,'w') as out: json.dump({'schema':'c020-tcp-capture.v1','streams':rows},out,sort_keys=True,separators=(',',':'))
if __name__=='__main__':main()
