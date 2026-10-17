"""Loopback-only evidence: DNS ownership/TTL/framing and actual CONNECT authority."""
import argparse
import ipaddress
import json
import socket
import ssl
import struct
import subprocess
import threading
import time
from pathlib import Path

def name(host):
    return b''.join(bytes([len(label)]) + label.encode() for label in host.split('.')) + b'\0'

def query(host='cdn.platform.openai.com', ident=17, ipv6=False):
    return struct.pack('!6H', ident, 0x100, 1, 0, 0, 0) + name(host) + struct.pack('!2H', 28 if ipv6 else 1, 1)

def answer(q, ip='198.51.100.20', ttl=60, owner=b'\xc0\x0c', alias=None):
    address = ipaddress.ip_address(ip)
    rr = owner + struct.pack('!HHIH', 28 if address.version == 6 else 1, 1, ttl, len(address.packed)) + address.packed
    if alias:
        target = name(alias)
        rr = b'\xc0\x0c' + struct.pack('!HHIH', 5, 1, ttl, len(target)) + target + name(alias) + struct.pack('!HHIH', 1, 1, ttl, 4) + address.packed
    return q[:2] + struct.pack('!5H', 0x8180, 1, 2 if alias else 1, 0, 0) + q[12:] + rr

def hello(host):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    if host is None:
        context.check_hostname = False
    inbound, outbound = ssl.MemoryBIO(), ssl.MemoryBIO()
    obj = context.wrap_bio(inbound, outbound, server_hostname=host)
    try:
        obj.do_handshake()
    except ssl.SSLWantReadError:
        pass
    return outbound.read()

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--harness', required=True)
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    passed = []
    def check(label, condition):
        assert condition, label
        passed.append(label)
    stopped=subprocess.run([args.harness,'gate-stop'],capture_output=True,check=True,timeout=3)
    check('startup cancellation stays closed',not json.loads(stopped.stdout)['allowed'])
    def cache(lines):
        proc = subprocess.run([args.harness, 'cache'], input=('\n'.join(lines)+'\n').encode(), capture_output=True, timeout=5, check=True)
        return [json.loads(x) for x in proc.stdout.decode().splitlines() if x.startswith('{')]
    def observe(q, r): return ['q'+q.hex(), 'r'+r.hex()]
    q = query(); r = answer(q)
    check('matched UDP answer', cache(observe(q,r)+['4198.51.100.20'])[0]['host'] == 'cdn.platform.openai.com')
    check('unsolicited response rejected', not cache(['r'+r.hex(),'4198.51.100.20'])[0]['found'])
    bad = bytearray(r); bad[1] ^= 1
    check('transaction ID checked', not cache(observe(q,bad)+['4198.51.100.20'])[0]['found'])
    check('question checked', not cache(observe(q,answer(query('other.example')))+['4198.51.100.20'])[0]['found'])
    check('zero TTL not retained', not cache(observe(q,answer(q,ttl=0))+['4198.51.100.20'])[0]['found'])
    check('TTL expires', not cache(observe(q,answer(q,ttl=1))+['w1100','4198.51.100.20'])[0]['found'])
    check('unrelated owner rejected', not cache(observe(q,answer(q,owner=name('unrelated.example')))+['4198.51.100.20'])[0]['found'])
    check('CNAME preserved', cache(observe(q,answer(q,alias='edge.example'))+['4198.51.100.20'])[0]['host'] == 'cdn.platform.openai.com')
    q2 = query('other.example',18)
    check('shared CDN IP is ambiguous', not cache(observe(q,r)+observe(q2,answer(q2))+['4198.51.100.20'])[0]['found'])
    q6=query(ipv6=True)
    check('IPv6 answer', cache(observe(q6,answer(q6,'2001:db8::9'))+['62001:db8::9'])[0]['found'])
    check('truncated answer rejected', not cache(observe(q,r[:-1])+['4198.51.100.20'])[0]['found'])
    frame=lambda p: struct.pack('!H',len(p))+p
    a,b=frame(q),frame(r)
    lines=['u'+a[:1].hex(),'u'+a[1:9].hex(),'u'+a[9:].hex(),'d'+b[:1].hex(),'d'+b[1:13].hex(),'d'+b[13:].hex(),'4198.51.100.20']
    check('TCP fragmented framing',cache(lines)[0]['found'])
    check('TCP coalesced messages',cache(['u'+(a+frame(q2)).hex(),'d'+(b+frame(answer(q2,'198.51.100.21'))).hex(),'4198.51.100.20','4198.51.100.21'])[1]['found'])
    def inspect(kind,data):
        p=subprocess.run([args.harness,'inspect',kind],input=data,capture_output=True,check=True,timeout=3)
        return json.loads(p.stdout)
    tls=hello('cdn.platform.openai.com')
    check('real TLS ClientHello SNI',inspect('tls',tls)['host']=='cdn.platform.openai.com')
    for cut in (1,4,5,len(tls)-1):
        check('partial TLS '+str(cut),inspect('tls',tls[:cut])['result']==0)
    payload=tls[5:]; multi=b''.join(b'\x16\x03\x03'+struct.pack('!H',len(x))+x for x in (payload[:17],payload[17:]))
    check('multiple TLS records',inspect('tls',multi)['result']==1)
    check('HTTP Host',inspect('http',b'GET / HTTP/1.1\r\nHost: cdn.platform.openai.com:80\r\n\r\n')['result']==1)
    check('duplicate HTTP Host rejected',inspect('http',b'GET / HTTP/1.1\r\nHost: a.example\r\nHost: b.example\r\n\r\n')['result']==-1)
    check('invalid HTTP hostname rejected',inspect('http',b'GET / HTTP/1.1\r\nHost: bad/name\r\n\r\n')['result']==-1)
    for dest,prefix,use_cache in ((443,tls,False),(80,b'GET / HTTP/1.1\r\nHost: cdn.platform.openai.com\r\n\r\n',False),
                                  (443,hello(None),True),(80,b'GET / HTTP/1.0\r\n\r\n',True)):
        server=socket.socket(); server.bind(('127.0.0.1',0)); server.listen()
        command=[args.harness,'forward',str(server.getsockname()[1]),str(dest)]
        if use_cache:
            command.append('cached-domain')
        proc=subprocess.Popen(command,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        port=json.loads(proc.stdout.readline())['port']
        result={}
        def upstream():
            try:
                sock,_=server.accept(); sock.settimeout(4)
                data=b''
                while not data.endswith(b'\r\n\r\n'): data+=sock.recv(1)
                result['authority']=data.split(b'\r\n')[0]
                sock.sendall(b'HTTP/1.1 200 OK\r\n\r\n')
                data=b''
                while len(data)<len(prefix):
                    block=sock.recv(len(prefix)-len(data))
                    if not block: break
                    data+=block
                result['payload']=data; sock.sendall(data); sock.shutdown(socket.SHUT_WR); sock.close()
            except BaseException as error: result['error']=repr(error)
        thread=threading.Thread(target=upstream); thread.start()
        client=socket.create_connection(('127.0.0.1',port)); client.settimeout(4)
        started=time.monotonic()
        client.sendall(prefix[:7]); time.sleep(.03); client.sendall(prefix[7:]); client.shutdown(socket.SHUT_WR)
        echoed=b''
        while True:
            block=client.recv(65536)
            if not block: break
            echoed+=block
        client.close(); thread.join(5); proc.communicate(timeout=5); server.close()
        case=str(dest)+(' DNS fallback' if use_cache else '')
        check('CONNECT domain '+case, result.get('authority')==f'CONNECT cdn.platform.openai.com:{dest} HTTP/1.1'.encode())
        check('first request waits for ready '+case,time.monotonic()-started >= .17)
        check('byte-exact forwarding '+case,result.get('payload')==prefix and echoed==prefix and proc.returncode==0)
    Path(args.output).write_text(json.dumps({'passed':len(passed),'cases':passed},indent=2),encoding='utf-8')
    print(json.dumps({'domain_tests_passed':len(passed)}))

if __name__=='__main__': main()
