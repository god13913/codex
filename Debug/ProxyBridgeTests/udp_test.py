"""Exercise real SOCKS5 UDP transport with a local mock; never opens WinDivert."""
import argparse
import concurrent.futures
import hashlib
import json
import socket
import struct
import subprocess
import threading
import time
import tempfile
from pathlib import Path


def read_exact(stream, size):
    data = b""
    while len(data) < size:
        part = stream.recv(size - len(data))
        if not part:
            raise EOFError()
        data += part
    return data


def run_case(harness, mode, core=None):
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen()
    listener.settimeout(5)
    port = listener.getsockname()[1]
    checked_auth = []
    peers = []
    errors = []
    all_received = threading.Barrier(4)

    def association(stream):
        try:
            with stream, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as relay:
                stream.settimeout(4)
                version, count = read_exact(stream, 2)
                methods = read_exact(stream, count)
                assert version == 5 and 2 in methods
                stream.sendall(b"\x05\x02")
                assert read_exact(stream, 1) == b"\x01"
                user = read_exact(stream, read_exact(stream, 1)[0])
                password = read_exact(stream, read_exact(stream, 1)[0])
                checked_auth.append(user == b"user" and password == b"pass")
                if mode == "reject_auth":
                    stream.sendall(b"\x01\x01")
                    return
                stream.sendall(b"\x01\x00")
                assert read_exact(stream, 10) == b"\x05\x03\x00\x01" + b"\0" * 6
                relay.bind(("127.0.0.1", 0))
                relay.settimeout(4)
                reply = b"\x05\x00\x00\x01" + socket.inet_aton("127.0.0.1") + struct.pack("!H", relay.getsockname()[1])
                if mode == "split_handshake":
                    for byte in reply:
                        stream.sendall(bytes([byte]))
                        time.sleep(.003)
                else:
                    stream.sendall(reply)
                packet, sender = relay.recvfrom(65535)
                peers.append(sender)
                assert packet[:3] == b"\0\0\0" and packet[3] in (1, 4)
                prefix = 10 if packet[3] == 1 else 22
                payload = packet[prefix:]
                if mode == "no_upstream_udp":
                    stream.recv(1)
                    return
                all_received.wait(3)
                # Deliberately reorder responses to clients using the same destination.
                time.sleep({b"one": .18, b"two": .01, b"three": .07, b"four": .12}[payload])
                # Invalid frames must be discarded without reaching an application.
                if not core:
                    relay.sendto(b"\x01" + packet[1:], sender)
                    relay.sendto(packet[:2] + b"\x01" + packet[3:], sender)
                relay.sendto(packet, sender)
                stream.recv(1)
        except (EOFError, OSError, threading.BrokenBarrierError):
            pass
        except Exception as error:
            errors.append(type(error).__name__)

    def serve():
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            try:
                for _ in range(4):
                    stream, _ = listener.accept()
                    pool.submit(association, stream)
            except OSError as error:
                errors.append('upstream_accept_' + type(error).__name__)
            finally:
                listener.close()

    worker = threading.Thread(target=serve, daemon=True)
    kernel = None
    startup_ms = 0
    scratch = tempfile.TemporaryDirectory(prefix="codex-udp-fixture-", dir=Path(harness).resolve().parent)
    try:
        if core:
            started = time.monotonic()
            with socket.socket() as reservation:
                reservation.bind(("127.0.0.1", 0))
                mixed_port = reservation.getsockname()[1]
            config = {"mixed-port": mixed_port, "bind-address": "127.0.0.1", "allow-lan": False,
                      "authentication": ["user:pass"], "skip-auth-prefixes": [], "log-level": "silent",
                      "dns": {"enable": False}, "tun": {"enable": False},
                      "proxies": [{"name": "CODEX", "type": "socks5", "server": "127.0.0.1", "port": port,
                                   "username": "user", "password": "pass", "udp": True}], "rules": ["MATCH,CODEX", "MATCH,REJECT"]}
            config_path = Path(scratch.name) / "fixture.json"
            config_path.write_text(json.dumps(config), encoding="utf-8")
            kernel = subprocess.Popen([core, "-d", scratch.name, "-f", str(config_path)],
                                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                      creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
            deadline = time.monotonic() + 5
            while True:
                if kernel.poll() is not None:
                    raise RuntimeError("pinned kernel exited during fixture startup")
                try:
                    with socket.create_connection(("127.0.0.1", mixed_port), timeout=.1):
                        break
                except OSError:
                    if time.monotonic() >= deadline:
                        raise RuntimeError("pinned kernel fixture did not start")
                    time.sleep(.02)
            port = mixed_port
            startup_ms = round((time.monotonic() - started) * 1000)
        # The upstream accepts application traffic only after the kernel is ready.
        # Cold kernel startup must not consume the fixture's accept timeout.
        worker.start()
        result = subprocess.run([harness, "udp", str(port)], capture_output=True, text=True, timeout=9)
    finally:
        if kernel:
            kernel.terminate()
            kernel.wait(timeout=5)
        scratch.cleanup()
    worker.join(5)
    rows = [json.loads(line) for line in result.stdout.splitlines() if line.startswith("{")]
    actual = sorted((row["udp_reply_port"], bytes.fromhex(row["data"])) for row in rows if "udp_reply_port" in row)
    expected = [] if mode in ("reject_auth", "no_upstream_udp") else [(45000, b"one"), (45000, b"three"), (45001, b"two"), (45002, b"four")]
    summary = rows[-1] if rows else {}
    passed = (result.returncode == 0 and summary.get("stopped") and actual == expected and
              len(checked_auth) == 4 and all(checked_auth) and not errors)
    if expected:
        passed = passed and len(set(peers)) == 4
    return {"name": mode, "pass": bool(passed), "responses": len(actual), "associations": len(checked_auth), "upstream_datagrams": len(peers), "kernel_startup_ms": startup_ms, "errors": errors}


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--harness", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--core", help="Also exercise the pinned Mihomo mixed listener and SOCKS5 upstream")
    args = parser.parse_args()
    filtered = subprocess.run([args.harness, "capture-filter"], capture_output=True, text=True, timeout=5)
    details = json.loads(filtered.stdout)
    results = [{"name": "wfp_reinjected_udp_capture", "pass": filtered.returncode == 0 and
                details["failures"] == 0 and details["old_rejects_injected_quic"], **details}]
    results += [run_case(args.harness, mode) for mode in ("normal", "split_handshake", "reject_auth", "no_upstream_udp")]
    if args.core:
        core = str(Path(args.core).resolve())
        assert hashlib.sha256(Path(core).read_bytes()).hexdigest() == "3c107d54ef1b895e4980b53f517d52f3c1137101fa2637347c9ce343fc50d7b2"
        for mode in ("normal", "split_handshake", "reject_auth", "no_upstream_udp"):
            row = run_case(args.harness, mode, core)
            row["name"] = "pinned_mihomo_" + row["name"]
            results.append(row)
    with open(args.output, "w", encoding="utf-8") as stream:
        json.dump(results, stream, indent=2)
    print(json.dumps(results))
    raise SystemExit(0 if all(row["pass"] for row in results) else 1)
