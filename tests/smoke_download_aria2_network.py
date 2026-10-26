#!/usr/bin/env python3
"""Genuine aria2 HTTP artifact smoke inside the existing restricted CI bridge.

Only fetches an immutable public README from this repository. No user URLs,
storage credentials, cloud writes, Workflow Task dispatch or downloader service.
Runs in the same private-egress-denying bridge as the socket CI tests, with
a loopback-only ephemeral RPC port and a per-run random RPC secret.
"""
import hashlib
import http.server
import json
import os
from pathlib import Path
import re
import secrets
import socket
import subprocess
import sys
import threading
import tempfile
import time
from urllib.request import ProxyHandler, Request, build_opener

sys.path.insert(0, "/spec51")
from download_aria2_readonly import Aria2Reader
from download_source import verify_snapshot

repo_url = os.environ.get("PUBLIC_FIXTURE_URL", "")
expected = os.environ.get("PUBLIC_FIXTURE_SHA256", "")
gateway = os.environ.get("HOST_GATEWAY", "")
if (not re.fullmatch(r"https://raw\.githubusercontent\.com/lirtual/session-actions/[0-9a-f]{40}/README\.md", repo_url)
        or not re.fullmatch(r"[0-9a-f]{64}", expected)
        or not re.fullmatch(r"172\.(?:1[6-9]|2[0-9]|3[01])\.\d{1,3}\.\d{1,3}", gateway)):
    raise SystemExit("FIXTURE_CONFIG_UNVERIFIED")

# The container must be unable to access the host fixture or metadata service.
for host, port in ((gateway, 18081), ("169.254.169.254", 80)):
    try:
        with socket.create_connection((host, port), timeout=2):
            raise SystemExit("PRIVATE_EGRESS_UNSAFE")
    except OSError:
        pass

secret = secrets.token_hex(24)
gid = secrets.token_hex(8)
client = build_opener(ProxyHandler({}))

def rpc(method, *args):
    request_id = secrets.token_hex(8)
    body = json.dumps({
        "jsonrpc": "2.0", "id": request_id, "method": method,
        "params": ["token:" + secret, *args],
    }).encode()
    request = Request("http://127.0.0.1:6800/jsonrpc", method="POST", data=body,
                      headers={"Content-Type":"application/json"})
    with client.open(request, timeout=3) as response:
        if response.status != 200:
            raise AssertionError("RPC_BAD_STATUS")
        payload = json.loads(response.read(1024 * 1024))
    if (payload.get("id") != request_id or
            payload.get("jsonrpc") != "2.0" or "error" in payload):
        raise AssertionError("RPC_BAD_RESPONSE")
    return payload["result"]

with tempfile.TemporaryDirectory(prefix="sa51-aria2-public-") as directory:
    argv = ["aria2c", "--no-conf", "--enable-rpc=true",
            "--rpc-listen-all=false", "--rpc-listen-port=6800",
            "--rpc-secret=" + secret, "--disable-ipv6=true",
            "--enable-dht=false", "--follow-torrent=false",
            "--follow-metalink=false", "--auto-file-renaming=false",
            "--allow-overwrite=false", "--continue=false",
            "--file-allocation=none", "--max-tries=1",
            "--max-connection-per-server=1", "--split=1",
            "--max-concurrent-downloads=1",
            "--console-log-level=error", "--dir=" + directory]
    process = subprocess.Popen(argv, stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL, env={"PATH":os.environ["PATH"]})
    try:
        for i in range(60):
            if process.poll() is not None:
                raise AssertionError("ARIA2_EXITED")
            try:
                rpc("aria2.getGlobalStat")
                break
            except Exception:
                time.sleep(.1)
        else:
            raise AssertionError("RPC_NOT_READY")

        submitted = rpc("aria2.addUri", [repo_url], {
            "gid": gid, "dir": directory, "out": "README.md",
            "max-tries": "1", "split": "1",
            "follow-torrent": "false", "follow-metalink": "false",
            "auto-file-renaming": "false", "allow-overwrite": "false",
            "continue": "false", "max-connection-per-server": "1",
        })
        if submitted != gid:
            raise AssertionError("GID_MISMATCH")
        for i in range(150):
            detail = rpc("aria2.tellStatus", gid, ["gid", "status"])
            if detail["status"] == "complete":
                break
            if detail["status"] in ("error", "removed"):
                raise AssertionError("DOWNLOAD_NOT_COMPLETE")
            time.sleep(.15)
        else:
            raise AssertionError("DOWNLOAD_TIMEOUT")

        snapshot = Aria2Reader(secret, time.monotonic() + 25).read_closed([gid])
        status = snapshot["sources"][0]["status"]
        uris = snapshot["sources"][0]["uris"]
        if uris != [{"uri": repo_url, "status": "used"}]:
            raise AssertionError("PUBLIC_SOURCE_URI_UNVERIFIED")
        manifest = verify_snapshot(directory, gid, status, snapshot["sources"][0]["files"])
        if (status.get("dir") != directory or
                manifest["file_count"] != 1 or
                manifest["files"][0]["relative_path"] != "README.md" or
                manifest["files"][0]["sha256"] != expected):
            raise AssertionError("PUBLIC_FIXTURE_INTEGRITY_FAILED")
        # Follow a real HTTP 302 from the loopback fixture toward the
        # host-only address. Docker bridge isolation must reject the resulting
        # private request even after aria2's redirect processing.
        class RedirectPrivate(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(302)
                self.send_header("Location", "http://" + gateway + ":18081/")
                self.end_headers()

            def log_message(self, *_):
                pass

        with http.server.ThreadingHTTPServer(("127.0.0.1", 18101), RedirectPrivate) as server:
            worker = threading.Thread(target=server.serve_forever, daemon=True)
            worker.start()
            try:
                redirect_gid = secrets.token_hex(8)
                second = rpc("aria2.addUri", ["http://127.0.0.1:18101/redirect"], {
                    "gid": redirect_gid, "dir": directory, "out": "redirect.txt",
                    "max-tries": "1", "connect-timeout": "2",
                    "timeout": "3", "split": "1",
                    "follow-torrent": "false", "follow-metalink": "false",
                })
                if second != redirect_gid:
                    raise AssertionError("REDIRECT_GID_MISMATCH")
                for i in range(60):
                    result = rpc("aria2.tellStatus", redirect_gid, ["gid", "status"])
                    if result["status"] == "error":
                        break
                    if result["status"] in ("complete", "removed"):
                        raise AssertionError("PRIVATE_REDIRECT_EGRESS_UNSAFE")
                    time.sleep(.1)
                else:
                    raise AssertionError("PRIVATE_REDIRECT_NEVER_REJECTED")
                if ((Path(directory) / "redirect.txt").exists() and
                        b"PRIVATE_FIXTURE" in (Path(directory) / "redirect.txt").read_bytes()):
                    raise AssertionError("PRIVATE_REDIRECT_LEAKED_FIXTURE")
            finally:
                server.shutdown()
                worker.join(timeout=4)

        print("RESTRICTED_BRIDGE_REAL_ARIA2_PUBLIC_FIXTURE_OK")
        print("RESTRICTED_BRIDGE_REAL_ARIA2_PRIVATE_REDIRECT_DENIED")
    finally:
        process.terminate()
        try:
            process.wait(timeout=4)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=4)
