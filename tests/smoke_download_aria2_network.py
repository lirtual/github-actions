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
from download_source import verify_snapshot, verify_http_source_uris
from download_stage import stage_from_reader, StageUnverified

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
gids = [secrets.token_hex(8), secrets.token_hex(8)]
if gids[0] == gids[1]:
    raise SystemExit("GID_COLLISION")
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
            "--max-concurrent-downloads=2",
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

        # Two independent immutable source allocations in ONE aria2 process,
        # both submitted before waiting. This tests batch-GID ownership and
        # two-active scheduling capability (not proven overlapping time).
        roots = [os.path.join(directory, f"source-{index}") for index in range(2)]
        for root in roots:
            os.mkdir(root)
        for gid, root in zip(gids, roots):
            submitted = rpc("aria2.addUri", [repo_url], {
                "gid": gid, "dir": root, "out": "README.md",
                "max-tries": "1", "split": "1",
                "follow-torrent": "false", "follow-metalink": "false",
                "auto-file-renaming": "false", "allow-overwrite": "false",
                "continue": "false", "max-connection-per-server": "1",
            })
            if submitted != gid:
                raise AssertionError("GID_MISMATCH")
        for i in range(150):
            states = [rpc("aria2.tellStatus", gid, ["gid", "status"])
                      for gid in gids]
            if all(s["status"] == "complete" for s in states):
                break
            if any(s["status"] in ("error", "removed") for s in states):
                raise AssertionError("DOWNLOAD_NOT_COMPLETE")
            time.sleep(.15)
        else:
            raise AssertionError("DOWNLOAD_TIMEOUT")

        snapshot = Aria2Reader(secret, time.monotonic() + 25).read_closed(gids)
        for gid, root, source in zip(gids, roots, snapshot["sources"]):
            status = source["status"]
            verify_http_source_uris(source["files"], repo_url)
            manifest = verify_snapshot(root, gid, status, source["files"])
            if (status.get("dir") != root or
                    manifest["file_count"] != 1 or
                    manifest["files"][0]["relative_path"] != "README.md" or
                    manifest["files"][0]["sha256"] != expected):
                raise AssertionError("PUBLIC_FIXTURE_INTEGRITY_FAILED")

        batch = {
            "downloads": [
                {"url": repo_url, "destination_path": f"/Koofr/spec51-ci-{i}"}
                for i in range(2)
            ],
            "project_purpose": "CI-only test of associated repository download stage",
            "duration_minutes": 1,
        }
        batch_json = json.dumps(batch, separators=(",", ":"))
        allocations = [{"gid": gid, "root": root, "url": repo_url}
                       for gid, root in zip(gids, roots)]
        # Fake OpenList mount: synthetic credentials and no provider connection.
        # stage_from_reader returns in-memory intents, never makes uploads.
        storages = [{
            "mount_path": "/Koofr", "driver": "WebDav", "disabled": False,
            "status": "work",
            "addition": json.dumps({
                "address": "https://app.koofr.net/dav/Koofr",
                "username": "ci-only@example.invalid",
                "password": "synthetic-ci-never-transmitted",
                "root_folder_path": "/", "vendor": "other",
                "tls_insecure_skip_verify": False,
            }),
        }]

        class CapturedReader:
            def __init__(self, evidence):
                self.evidence = evidence
            def read_closed(self, requested):
                if requested != gids:
                    raise AssertionError("SOURCE_ORDER_MISMATCH")
                return self.evidence

        intents = stage_from_reader(batch_json, allocations, storages,
                                    CapturedReader(snapshot))
        if (len(intents) != 2 or
                {i["destination_parent"] for i in intents} !=
                {"/spec51-ci-0", "/spec51-ci-1"} or
                any(i["sha256"] != expected for i in intents)):
            raise AssertionError("MULTI_SOURCE_STAGING_INTEGRITY_FAILED")
        # One compromised source must invalidate the WHOLE batch pre-upload.
        changed = json.loads(json.dumps(snapshot))
        changed["sources"][1]["files"][0]["uris"][0]["uri"] = "https://unexpected.invalid/file"
        try:
            stage_from_reader(batch_json, allocations, storages,
                              CapturedReader(changed))
        except StageUnverified:
            pass
        else:
            raise AssertionError("MULTI_SOURCE_MISMATCH_NOT_REJECTED")
        print("REAL_ARIA2_TWO_SOURCE_BATCH_STAGE_NO_UPLOAD_OK")
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
