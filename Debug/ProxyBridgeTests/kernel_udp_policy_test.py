"""Reproduce unsupported-node UDP fallthrough with pinned Mihomo, loopback only.

No live proxy/configuration, WinDivert, external destinations, or private data.
The legacy rule must reach a local destination; the terminal REJECT must not.
"""
import argparse
import hashlib
import json
from pathlib import Path
import socket
import struct
import subprocess
import tempfile
import time


def exact(stream, count):
    value = b''
    while len(value) < count:
        piece = stream.recv(count - len(value))
        if not piece:
            raise EOFError('Fixture control closed')
        value += piece
    return value


def run(core, kind, terminal_reject):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as destination, \
            socket.socket() as reservation, tempfile.TemporaryDirectory(prefix='udp-policy-', dir=Path(core).parent) as scratch:
        assert Path(scratch).resolve().parent == Path(core).resolve().parent
        destination.bind(('127.0.0.1', 0))
        destination.settimeout(.6)
        reservation.bind(('127.0.0.1', 0))
        port = reservation.getsockname()[1]
        config = {'mixed-port': port, 'bind-address': '127.0.0.1', 'allow-lan': False,
                  'mode': 'rule', 'log-level': 'silent', 'tun': {'enable': False},
                  'dns': {'enable': False}, 'proxies': [{'name': 'CODEX', 'type': kind,
                      'server': '127.0.0.1', 'port': 9, 'udp': False}],
                  'rules': ['MATCH,CODEX'] + (['MATCH,REJECT'] if terminal_reject else [])}
        path = Path(scratch) / 'fixture.json'
        path.write_text(json.dumps(config), encoding='utf-8')
        reservation.close()
        child = subprocess.Popen([core, '-d', scratch, '-f', str(path)],
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                 creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
        try:
            deadline = time.monotonic() + 5
            control = None
            while control is None:
                if child.poll() is not None:
                    raise RuntimeError('Fixture kernel exited')
                try:
                    control = socket.create_connection(('127.0.0.1', port), timeout=.3)
                except OSError:
                    if time.monotonic() > deadline:
                        raise TimeoutError('Fixture kernel startup')
                    time.sleep(.02)
            with control, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
                control.settimeout(2)
                control.sendall(b'\x05\x01\x00')
                assert exact(control, 2) == b'\x05\x00'
                control.sendall(b'\x05\x03\x00\x01' + bytes(6))
                assert exact(control, 4) == b'\x05\x00\x00\x01'
                address = exact(control, 6)
                relay = (socket.inet_ntoa(address[:4]), struct.unpack('!H', address[4:])[0])
                assert relay[0] == '127.0.0.1'
                packet = b'\0\0\0\x01' + socket.inet_aton('127.0.0.1')
                packet += struct.pack('!H', destination.getsockname()[1]) + b'udp-policy-fixture'
                sender.sendto(packet, relay)
                reached = False
                try:
                    payload, _ = destination.recvfrom(2048)
                    reached = payload == b'udp-policy-fixture'
                except socket.timeout:
                    pass
                return {'node_type': kind, 'terminal_reject': terminal_reject,
                        'direct_destination_reached': reached, 'pass': reached != terminal_reject}
        finally:
            child.terminate()
            child.wait(timeout=5)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--core', required=True)
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    core = str(Path(args.core).resolve())
    assert hashlib.sha256(Path(core).read_bytes()).hexdigest() == '3c107d54ef1b895e4980b53f517d52f3c1137101fa2637347c9ce343fc50d7b2'
    results = [run(core, kind, reject) for kind in ('http', 'socks5') for reject in (False, True)]
    Path(args.output).write_text(json.dumps(results, indent=2), encoding='utf-8')
    print(json.dumps(results))
    raise SystemExit(0 if all(item['pass'] for item in results) else 1)
