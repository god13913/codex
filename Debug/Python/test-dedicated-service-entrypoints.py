"""Test compiled service entry points with an isolated home and a loopback-only proxy.

Uses fixture credentials; does not read the user's Codex home, launch Mihomo, load
WinDivert, or send requests to an external service.
"""
import argparse
import base64
import http.client
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import threading
import time


PASSWORD = "a" * 64


def exact(stream, count):
    result = b""
    while len(result) < count:
        part = stream.recv(count - len(result))
        if not part:
            raise EOFError()
        result += part
    return result


class FixtureProxy:
    def __init__(self, reject):
        self.reject = reject
        self.authenticated = threading.Event()
        self.probes = 0
        self.requests = 0
        self.blocked_tunnels = 0
        self.errors = []
        self.stop = threading.Event()
        self.listener = socket.socket()
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen()
        self.listener.settimeout(.1)
        self.port = self.listener.getsockname()[1]
        self.worker = threading.Thread(target=self.serve, daemon=True)
        self.worker.start()

    def serve(self):
        while not self.stop.is_set():
            try:
                stream, _ = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self.connection, args=(stream,), daemon=True).start()

    def connection(self, stream):
        stage = "initial-read"
        try:
            with stream:
                stream.settimeout(5)
                first = stream.recv(1)
                if not first:  # Bare local listener check.
                    return
                if first == b"\x05":
                    stage = "local-socks-authentication"
                    assert exact(stream, 2) == b"\x01\x02"
                    stream.sendall(b"\x05\x02")
                    assert exact(stream, 2) == b"\x01\x05"
                    assert exact(stream, 5) == b"codex"
                    length = exact(stream, 1)[0]
                    assert exact(stream, length) == PASSWORD.encode()
                    self.probes += 1
                    stream.sendall(b"\x01\x01" if self.reject else b"\x01\x00")
                    self.authenticated.set()
                    try:
                        assert not stream.recv(1), "authentication probe requested a destination"
                    except ConnectionResetError:
                        pass
                    return
                data = first
                while not data.endswith(b"\r\n\r\n"):
                    data += exact(stream, 1)
                    assert len(data) < 16384
                text = data.decode("ascii")
                stage = "http-" + text.split(" ", 1)[0]
                headers = dict((key.lower(), value) for key, value in
                               (line.split(": ", 1) for line in text.split("\r\n")[1:] if ": " in line))
                expected = base64.b64encode(("codex:" + PASSWORD).encode()).decode()
                assert headers.get("proxy-authorization", "").split(" ") == ["Basic", expected]
                if text.startswith("CONNECT "):
                    # app-server may bootstrap HTTPS services. Prove that these
                    # connections use the lease, then refuse them locally.
                    self.blocked_tunnels += 1
                    stream.sendall(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                    return
                assert text.startswith("POST http://service.test/v1/responses HTTP/1.1\r\n")
                assert headers.get("authorization") == "Bearer fixture-api-key"
                exact(stream, int(headers.get("content-length", "0")))
                self.requests += 1
                body = b'data: {"fixture":true}\n\n'
                stream.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nConnection: close\r\nContent-Length: " +
                               str(len(body)).encode() + b"\r\n\r\n" + body)
        except Exception as error:
            self.errors.append(type(error).__name__ + ":" + stage)

    def close(self):
        self.stop.set()
        self.listener.close()
        self.worker.join(2)


def run_case(runtime, entry, reject):
    fixture = FixtureProxy(reject)
    with tempfile.TemporaryDirectory(prefix="service-fixture-", dir=runtime.parent) as root:
        home = Path(root)
        settings = home / "dedicated-proxy"
        settings.mkdir()
        (settings / "settings.json").write_text(json.dumps({"enabled": True, "mode": "node", "updated_at": 0,
            "last_error": None, "proxy_port": fixture.port, "proxy_password": PASSWORD}), encoding="utf-8")
        env = os.environ.copy()
        env["CODEX_HOME"] = str(home)
        env["OTEL_SDK_DISABLED"] = "true"
        # A working inherited proxy would hide a missing dedicated-client setting.
        # Port 1 is deliberately unusable; successful requests must use the lease.
        for key in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"):
            env[key] = "http://127.0.0.1:1"
        env["NO_PROXY"] = "localhost,127.0.0.1,::1"
        env.pop("CODEX_CLI_PATH", None)
        # Avoid inherited real auth inputs. These cases use fixture stdin only.
        for key in list(env):
            if key.upper() in ("OPENAI_API_KEY", "CODEX_API_KEY", "CODEX_ACCESS_TOKEN", "CODEX_THREAD_ID"):
                env.pop(key)
        info = home / "server-info.json"
        proxy_args = ["--server-info", str(info), "--upstream-url", "http://service.test/v1/responses"]
        commands = {
            "responses-binary": [str(runtime / "codex-responses-api-proxy.exe"), *proxy_args],
            "responses-hidden": [str(runtime / "codex.exe"), "responses-api-proxy", *proxy_args],
            "cloud": [str(runtime / "codex.exe"), "cloud", "list", "--json"],
            "remote-exec": [str(runtime / "codex.exe"), "exec-server", "--remote", "https://service.test", "--environment-id", "fixture"],
            "app-server-binary": [str(runtime / "codex-app-server.exe")],
            "app-server-cli": [str(runtime / "codex.exe"), "app-server"],
        }
        process = subprocess.Popen(commands[entry], cwd=home, env=env, stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        stderr = b""
        observed = False
        response_ok = False
        try:
            if entry.startswith("responses"):
                process.stdin.write(b"fixture-api-key\n")
                process.stdin.flush()
            observed = fixture.authenticated.wait(5)
            if reject:
                _, stderr = process.communicate(timeout=5)
                response_ok = process.returncode != 0 and not info.exists()
            elif entry.startswith("responses"):
                deadline = time.monotonic() + 6
                while not info.is_file() and process.poll() is None and time.monotonic() < deadline:
                    time.sleep(.02)
                port = json.loads(info.read_text(encoding="utf-8"))["port"]
                client = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
                client.request("POST", "/v1/responses", body=b"{}", headers={"Content-Type": "application/json"})
                response = client.getresponse()
                response_ok = response.status == 200 and b'"fixture":true' in response.read()
                client.close()
            else:
                # Empty isolated account state may stop cloud/remote registration.
                # This case verifies that startup obtained the local lease first.
                time.sleep(.2)
                if process.poll() is not None:
                    _, stderr = process.communicate(timeout=1)
                response_ok = b"dedicated proxy unavailable" not in stderr and b"dedicated proxy could not start" not in stderr
        finally:
            if process.poll() is None:
                process.terminate()
                process.communicate(timeout=5)
            fixture.close()
        passed = observed and fixture.probes == 1 and response_ok and not fixture.errors
        if reject:
            passed = passed and fixture.requests == 0 and fixture.blocked_tunnels == 0
        elif entry.startswith("responses"):
            passed = passed and fixture.requests == 1
        return {"entry": entry, "reject_auth": reject, "pass": passed, "local_auth_probes": fixture.probes,
                "proxied_requests": fixture.requests, "blocked_startup_tunnels": fixture.blocked_tunnels,
                "fixture_errors": fixture.errors}


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--runtime", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    runtime = Path(args.runtime).resolve()
    results = []
    for entry in ("responses-binary", "responses-hidden", "cloud", "remote-exec", "app-server-binary", "app-server-cli"):
        for reject in (False, True):
            row = run_case(runtime, entry, reject)
            results.append(row)
            print(json.dumps(row), flush=True)
    Path(args.output).write_text(json.dumps(results, indent=2), encoding="utf-8")
    raise SystemExit(0 if all(row["pass"] for row in results) else 1)
