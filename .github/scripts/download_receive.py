#!/usr/bin/env python3
"""Spec #51 isolated aria2 receiver, for an already-restricted Docker network.

No cloud configuration or host Docker socket. Only public HTTP(S) batch sources.
Returns a private local receipt AFTER GID, URL and exact file-tree closure.
This does not set up an egress firewall; caller must arm the proven bridge.
"""
import json
import math
import os
from pathlib import Path
import secrets
import subprocess
import sys
import time
import urllib.request

from download_aria2_readonly import Aria2Reader
from download_batch import InvalidBatch, validate
from download_source import SourceUnverified, verify_http_source_uris, verify_snapshot


class DownloadUnverified(Exception):
    pass


def _rpc(secret, method, *args):
    body = json.dumps({
        "jsonrpc": "2.0", "id": secrets.token_hex(12),
        "method": "aria2." + method, "params": ["token:" + secret, *args],
    }, separators=(",", ":")).encode()
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    request = urllib.request.Request(
        "http://127.0.0.1:6800/jsonrpc", method="POST", data=body,
        headers={"Content-Type": "application/json"})
    with opener.open(request, timeout=4) as reply:
        data = json.loads(reply.read(1024 * 1024))
    if "error" in data or "result" not in data or data.get("jsonrpc") != "2.0":
        raise DownloadUnverified("ARIA2_UNVERIFIED")
    return data["result"]


def receive(batch_json, workspace, deadline):
    """Called only inside an isolated, already firewall-restricted container."""
    try:
        batch = validate(batch_json)
    except InvalidBatch:
        raise DownloadUnverified("BATCH_INVALID") from None
    # Use a caller-controlled empty disposable volume, not the project tree.
    work = Path(workspace)
    if (not work.is_absolute() or work.is_symlink() or not work.is_dir() or
            list(work.iterdir())):
        raise DownloadUnverified("WORKSPACE_UNVERIFIED")
    secret = secrets.token_hex(32)
    gids = [secrets.token_hex(8) for _ in batch["downloads"]]
    if len(set(gids)) != len(gids):
        raise DownloadUnverified("GID_COLLISION")
    roots = [work / ("source-" + str(i)) for i in range(len(gids))]
    for root in roots:
        root.mkdir(mode=0o700)
    command = [
        "aria2c", "--no-conf", "--enable-rpc=true",
        "--rpc-listen-all=false", "--rpc-listen-port=6800",
        "--rpc-secret=" + secret,
        "--disable-ipv6=true", "--enable-dht=false",
        "--follow-torrent=false", "--follow-metalink=false",
        "--auto-file-renaming=false", "--allow-overwrite=false",
        "--continue=false", "--file-allocation=none",
        "--max-tries=1", "--max-connection-per-server=1",
        "--split=1", "--max-concurrent-downloads=2",
        "--console-log-level=error", "--dir=" + str(work),
    ]
    process = subprocess.Popen(command, stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL,
                               env={"PATH": os.environ.get("PATH", "")})
    try:
        for _ in range(50):
            if process.poll() is not None:
                raise DownloadUnverified("ARIA2_EXITED")
            try:
                _rpc(secret, "getGlobalStat")
                break
            except (OSError, ValueError, DownloadUnverified):
                time.sleep(0.1)
        else:
            raise DownloadUnverified("ARIA2_NOT_READY")
        for gid, root, link in zip(gids, roots, batch["downloads"]):
            submitted = _rpc(secret, "addUri", [link["url"]], {
                "gid": gid, "dir": str(root),
                "max-tries": "1", "split": "1",
                "follow-torrent": "false", "follow-metalink": "false",
                "allow-overwrite": "false", "auto-file-renaming": "false",
                "continue": "false",
            })
            if submitted != gid:
                raise DownloadUnverified("GID_MISMATCH")
        while True:
            if process.poll() is not None:
                raise DownloadUnverified("ARIA2_EXITED")
            if time.monotonic() >= deadline:
                raise DownloadUnverified("DOWNLOAD_TIMEOUT")
            status = [_rpc(secret, "tellStatus", gid, ["gid", "status"])
                      for gid in gids]
            if any(row.get("status") in ("error", "removed")
                   for row in status):
                raise DownloadUnverified("DOWNLOAD_FAILED")
            if all(row.get("status") == "complete" for row in status):
                break
            time.sleep(0.2)
        snapshot = Aria2Reader(secret, min(deadline, time.monotonic()+45)).read_closed(gids)
        manifests = []
        for gid, root, link, record in zip(
                gids, roots, batch["downloads"], snapshot["sources"]):
            if record["status"].get("dir") != str(root):
                raise DownloadUnverified("SOURCE_DIR_MISMATCH")
            verify_http_source_uris(record["files"], link["url"])
            manifests.append(verify_snapshot(
                str(root), gid, record["status"], record["files"]))
        return {"sources": len(gids),
                "files": sum(m["file_count"] for m in manifests),
                "bytes": sum(m["total_bytes"] for m in manifests)}
    finally:
        process.terminate()
        try:
            process.wait(timeout=4)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()


def main():
    try:
        deadline = float(os.environ.get("DOWNLOAD_DEADLINE", "nan"))
        remaining = deadline - time.monotonic()
        if not math.isfinite(deadline) or not 0 < remaining <= 19800:
            raise DownloadUnverified("INVALID_DEADLINE")
        result = receive(os.environ.get("BATCH_JSON", ""),
                         os.environ.get("DOWNLOAD_WORKSPACE", ""), deadline)
        print("RESTRICTED_ARIA2_BATCH_CLOSED",
              "sources=" + str(result["sources"]),
              "files=" + str(result["files"]))
        return 0
    except (DownloadUnverified, InvalidBatch, SourceUnverified,
            OSError, ValueError, KeyError, TypeError, OverflowError) as error:
        # All user and URL strings are suppressed.
        print("DOWNLOAD_UNVERIFIED", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
