"""Local-only failure injection; no driver, desktop settings, or external network."""
import argparse
import concurrent.futures
import ctypes
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import sys
import threading
import time


def dll_probe(path, port):
    directory = os.add_dll_directory(str(Path(path).parent))
    dll = ctypes.WinDLL(path)
    add = dll.ProxyBridge_AddProxyConfig
    add.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_uint16,
                    ctypes.c_char_p, ctypes.c_char_p, ctypes.c_int]
    add.restype = ctypes.c_uint32
    probe = dll.ProxyBridge_TestProxyConfig
    probe.argtypes = [ctypes.c_uint32, ctypes.c_char_p, ctypes.c_uint16,
                      ctypes.c_void_p, ctypes.c_size_t]
    cfg = add(0, b"127.0.0.1", port, b"", b"", 0)
    buf = ctypes.create_string_buffer(256)
    start = time.monotonic()
    rc = probe(cfg, b"127.0.0.1", 443, buf, len(buf))
    print(json.dumps({"rc": rc, "ms": round((time.monotonic()-start)*1000)}))
    directory.close()


def listener():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    s.listen()
    s.settimeout(3)
    return s


def http_case(args, name, parts, success, family=4, tail=b"", min_ms=0, max_ms=1600, installed=False, auth=False):
    server = listener()
    requests = []

    def serve():
        try:
            with server.accept()[0] as s:
                s.settimeout(2)
                request = b""
                while b"\r\n\r\n" not in request:
                    data = s.recv(4096)
                    if not data:
                        return
                    request += data
                requests.append(request)
                for delay, data in parts:
                    time.sleep(delay)
                    s.sendall(data)
        except (OSError, TimeoutError):
            pass
        finally:
            server.close()

    t = threading.Thread(target=serve, daemon=True)
    t.start()
    port = server.getsockname()[1]
    command = ([sys.executable, "-B", __file__, "--probe-dll", args.installed_dll, str(port)]
               if installed else [args.harness, "http", str(port), str(family), "450"])
    if auth:
        command.append("auth")
    result = subprocess.run(command, capture_output=True, text=True, timeout=4)
    t.join(2)
    if result.returncode:
        raise AssertionError(f"child exit {result.returncode}: {result.stderr[:200]}")
    value = json.loads(result.stdout)
    passed = ((value["rc"] == 0) == success and min_ms <= value["ms"] < max_ms)
    if not installed and success:
        passed = passed and bytes.fromhex(value["tail"]) == tail
    if not installed:
        passed = passed and value["restored_timeout"] == 450
    authority = b"[::1]:443" if family == 6 else b"127.0.0.1:443"
    passed = passed and bool(requests) and requests[0].startswith(b"CONNECT " + authority + b" HTTP/1.1\r\n")
    if auth:
        passed = passed and b"Proxy-Authorization: Basic dXNlcjpwYXNz\r\n" in requests[0]
    return {"name": name, "pass": passed, **value}


def receive_all(s):
    data = bytearray()
    while True:
        chunk = s.recv(65536)
        if not chunk:
            return bytes(data)
        data.extend(chunk)


def relay_case(args, kind):
    p = subprocess.Popen([args.harness, "relay", "350" if kind.startswith("cancel") else "0"],
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    sockets = []
    start = time.monotonic()
    try:
        ports = json.loads(p.stdout.readline())["ports"]
        sockets = [socket.create_connection(("127.0.0.1", port), timeout=3) for port in ports]
        app, peer = sockets
        assert json.loads(p.stdout.readline())["accepted"]
        for s in sockets:
            s.settimeout(3)
        if kind == "cancel_idle":
            passed = p.wait(timeout=2) == 0 and app.recv(1) == b""
        elif kind == "cancel_backpressure":
            peer.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1024)
            def flood():
                try:
                    app.sendall(b"x" * (16 * 1024 * 1024))
                except OSError:
                    pass
            t = threading.Thread(target=flood, daemon=True)
            t.start()
            passed = p.wait(timeout=2) == 0
            t.join(1)
        elif kind == "reset":
            app.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("hh", 1, 0))
            app.close()
            passed = p.wait(timeout=2) == 0
        else:
            first, second = (app, peer) if kind == "client_fin" else (peer, app)
            first.sendall(b"request")
            first.shutdown(socket.SHUT_WR)
            passed = receive_all(second) == b"request"
            time.sleep(.1)
            payload = bytes(range(256)) * 4096  # 1 MiB after the opposite FIN.
            error = []
            def send_tail():
                try:
                    second.sendall(payload)
                    second.shutdown(socket.SHUT_WR)
                except OSError as e:
                    error.append(type(e).__name__)
            t = threading.Thread(target=send_tail, daemon=True)
            t.start()
            received = receive_all(first)
            t.join(3)
            passed = passed and received == payload and not error and not t.is_alive()
            passed = p.wait(timeout=2) == 0 and passed
        return {"name": "relay_" + kind, "pass": passed, "ms": round((time.monotonic()-start)*1000)}
    finally:
        for s in sockets:
            s.close()
        if p.poll() is None:
            p.kill()
        p.communicate(timeout=3)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--harness")
    parser.add_argument("--output")
    parser.add_argument("--fixed", action="store_true")
    parser.add_argument("--installed-dll")
    parser.add_argument("--probe-dll", nargs=2)
    args = parser.parse_args()
    if args.probe_dll:
        dll_probe(args.probe_dll[0], int(args.probe_dll[1]))
        return
    rows = []

    def run(name, function, *values, **kw):
        try:
            row = function(args, *values, **kw)
        except Exception as e:
            row = {"name": name, "pass": False, "error": str(e)[:240]}
        rows.append(row)
        print(json.dumps(row), flush=True)

    header = b"HTTP/1.1 200 Connection established\r\n\r\n"
    for family in (4, 6):
        cases = [
            ("whole", [(0, header)], True, {}),
            ("basic_auth", [(0, header)], True, {"auth": True}),
            ("split_status", [(0, b"HTTP/1."), (.12, b"1 200 OK\r\n\r\n")], True, {"min_ms": 90}),
            ("split_headers", [(0, b"HTTP/1.1 200 OK\r\nX-Test: "), (.12, b"yes\r\n\r\n")], True, {"min_ms": 90}),
            ("bytewise", [(.002, bytes([b])) for b in header], True, {}),
            ("tunnel_tail", [(0, header + b"tunnel-first-bytes")], True, {"tail": b"tunnel-first-bytes"}),
            ("split_terminator_tail", [(0, header[:-1]), (.12, b"\nfirst-data")], True, {"min_ms": 90, "tail": b"first-data"}),
            ("http10", [(0, b"HTTP/1.0 200 OK\r\n\r\n")], True, {}),
            ("other_2xx", [(0, b"HTTP/1.1 204 No Content\r\n\r\n")], True, {}),
            ("auth_reject", [(0, b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n")], False, {}),
            ("invalid_status", [(0, b"HTTP/1.1 2000 Bad\r\n\r\n")], False, {}),
            ("invalid_version", [(0, b"BAD/1.1 200 OK\r\n\r\n")], False, {}),
            ("truncated", [(0, b"HTTP/1.1 200 OK\r\nX: incomplete")], False, {}),
            ("oversized", [(0, b"HTTP/1.1 200 OK\r\nX: " + b"a" * 20000)], False, {}),
            ("drip_deadline", [(.09, bytes([b])) for b in header], False, {"min_ms": 300, "max_ms": 1000}),
            ("silent_timeout", [(1.2, header)], False, {"min_ms": 300, "max_ms": 1000}),
        ]
        for name, parts, success, options in cases:
            run(f"http{family}_{name}", http_case, f"http{family}_{name}", parts, success, family=family, **options)
    for kind in ("client_fin", "proxy_fin", "reset", "cancel_idle", "cancel_backpressure"):
        run("relay_" + kind, relay_case, kind)
    # Several independent relays exercise thread ownership and cleanup together.
    def parallel_relay(i):
        return relay_case(args, "client_fin" if i % 2 else "proxy_fin")
    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
        try:
            values = list(pool.map(parallel_relay, range(6)))
            rows.append({"name": "parallel_relays", "pass": all(v["pass"] for v in values)})
        except Exception as e:
            rows.append({"name": "parallel_relays", "pass": False, "error": str(e)[:240]})
    if args.fixed:
        result = subprocess.run([args.harness, "tracking"], capture_output=True, text=True, timeout=3)
        rows.append({"name": "tracking_lifecycle", "pass": result.returncode == 0,
                     "detail": result.stdout.strip(), "error": result.stderr.strip()})
    installed_rows = []
    if args.installed_dll:
        for name, parts, minimum in [
            ("whole", [(0, header)], 0),
            ("split_status", [(0, b"HTTP/1."), (.12, b"1 200 OK\r\n\r\n")], 90),
            ("split_headers", [(0, b"HTTP/1.1 200 OK\r\nX: "), (.12, b"ok\r\n\r\n")], 90),
        ]:
            installed_rows.append(http_case(args, "installed_" + name, parts, True, min_ms=minimum, installed=True))
    result = {"fixed": args.fixed, "tests": rows, "installed_baseline": installed_rows,
              "passed": sum(r["pass"] for r in rows), "total": len(rows)}
    Path(args.output).write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(json.dumps({k: result[k] for k in ("fixed", "passed", "total")}))
    if args.fixed and not all(r["pass"] for r in rows):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
