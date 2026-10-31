#!/usr/bin/env python3
"""Optional, SHA-256 pinned, job-private RCA Session bootstrap. Never pairs a personal device."""
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import sys
import tarfile
import urllib.request
import zipfile

REPOSITORY = "lirtual/remote-control-agent"
LIMIT = 180 * 1024 * 1024
UNPACKED_LIMIT = 250 * 1024 * 1024
COUNT_LIMIT = 200
TAG = re.compile(r"v0\.[1-9][0-9]*\.[0-9]+(?:-[a-z0-9][a-z0-9.-]*)?\Z")
DIGEST = re.compile(r"[0-9a-f]{64}\Z")


class BootstrapError(Exception):
    pass


def member_path(name):
    if not name or name.startswith(("/", "\\")) or "\\" in name or ":" in name or "\x00" in name:
        raise BootstrapError("Unsafe archive member")
    stripped = name.rstrip("/")
    parts = PurePosixPath(stripped).parts
    if not parts or any(p in ("", ".", "..") for p in name.split("/") if p != "") or "//" in name:
        raise BootstrapError("Unsafe archive member")
    if len(name) > 256:
        raise BootstrapError("Long archive member")
    return stripped


def unpack_reviewed(archive, dest, windows):
    seen = set()
    total = 0
    if windows:
        with zipfile.ZipFile(archive) as z:
            infos = z.infolist()
            if len(infos) > COUNT_LIMIT:
                raise BootstrapError("Too many archive members")
            for info in infos:
                name = member_path(info.filename)
                if name in seen:
                    raise BootstrapError("Duplicate archive member")
                seen.add(name)
                mode = info.external_attr >> 16
                if stat.S_IFMT(mode) not in (0, stat.S_IFREG, stat.S_IFDIR) or info.file_size < 0:
                    raise BootstrapError("Unsupported archive entry")
                total += info.file_size
                if total > UNPACKED_LIMIT:
                    raise BootstrapError("Archive size exceeded")
            z.extractall(dest)
    else:
        with tarfile.open(archive, mode="r:gz") as tf:
            members = tf.getmembers()
            if len(members) > COUNT_LIMIT:
                raise BootstrapError("Too many archive members")
            for entry in members:
                name = member_path(entry.name)
                if name in seen:
                    raise BootstrapError("Duplicate archive member")
                seen.add(name)
                if not (entry.isfile() or entry.isdir()) or entry.size < 0:
                    raise BootstrapError("Unsupported archive entry")
                total += entry.size
                if total > UNPACKED_LIMIT:
                    raise BootstrapError("Archive size exceeded")
            tf.extractall(dest, filter="data")


def download_pinned(url, archive, sha, opener=urllib.request.urlopen):
    h = hashlib.sha256()
    size = 0
    with opener(urllib.request.Request(url, headers={"User-Agent": "github-actions-session-rca"}), timeout=20) as response:
        final_url = response.geturl()
        if not final_url.startswith("https://"):
            raise BootstrapError("Release download must remain HTTPS")
        with archive.open("xb") as f:
            while True:
                chunk = response.read(1024 * 1024)
                if not chunk:
                    break
                size += len(chunk)
                if size > LIMIT:
                    raise BootstrapError("Release asset exceeds limit")
                h.update(chunk)
                f.write(chunk)
    if not size or h.hexdigest() != sha:
        raise BootstrapError("Pinned release digest mismatch")


def start(env=os.environ, opener=urllib.request.urlopen, launch=subprocess.Popen):
    tag = env.get("SESSION_RCA_RELEASE_TAG", "").strip()
    sha = env.get("SESSION_RCA_RELEASE_SHA256", "").strip()
    if not tag and not sha:
        print("Session RCA not configured; SSH/RDP remains available.")
        return False
    if not TAG.fullmatch(tag) or not DIGEST.fullmatch(sha):
        raise BootstrapError("Incomplete or invalid Session RCA immutable release pin")
    windows = sys.platform == "win32"
    workflow = "windows" if windows else "ubuntu"
    if (env.get("GITHUB_ACTIONS") != "true" or env.get("RUNNER_ENVIRONMENT") != "github-hosted"
        or env.get("GITHUB_WORKFLOW") != workflow or env.get("GITHUB_REPOSITORY") != "lirtual/github-actions"
        or not env.get("ATTEMPT_ID") or not env.get("WORKFLOW_ACTION_OIDC_AUDIENCE")
        or not env.get("ACTIONS_ID_TOKEN_REQUEST_URL") or not env.get("ACTIONS_ID_TOKEN_REQUEST_TOKEN")):
        raise BootstrapError("Unreviewed physical Session environment")
    temp = env.get("RUNNER_TEMP", "")
    if not temp or not Path(temp).is_absolute():
        raise BootstrapError("Missing job-scoped runtime directory")
    target = "windows-x64" if windows else "linux-x64-glibc"
    extension = "zip" if windows else "tar.gz"
    name = f"remote-control-agent-{tag}-{target}.{extension}"
    url = f"https://github.com/{REPOSITORY}/releases/download/{tag}/{name}"
    stage = Path(temp) / "session-rca-reviewed-release"
    stage.mkdir(mode=0o700, exist_ok=False)
    archive = stage / name
    download_pinned(url, archive, sha, opener)
    unpack_reviewed(archive, stage, windows)
    manifest = json.loads((stage / "bundle.json").read_text(encoding="utf-8"))
    if (manifest.get("version") != tag or manifest.get("target") != target or
        manifest.get("name") != "remote-control-agent" or manifest.get("device_protocol") != 2 or
        manifest.get("upgrade_profile") != "paired-full-v1"):
        raise BootstrapError("Unreviewed Session RCA release identity")
    node = stage / "bin" / ("node.exe" if windows else "node")
    entry = stage / "apps" / "remote-control-agent" / "src" / ("session-rca-windows.js" if windows else "session-rca-main.js")
    if not node.is_file() or node.is_symlink() or not entry.is_file() or entry.is_symlink():
        raise BootstrapError("Release lacks Session-only foreground executable")
    flags = subprocess.CREATE_NEW_PROCESS_GROUP if windows else 0
    process = launch([str(node), str(entry)], cwd=str(stage), env=dict(env),
                     stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                     creationflags=flags, start_new_session=not windows)
    print(f"Session RCA job-scoped foreground Agent launched (pid {process.pid}); online admission remains authoritative.")
    return True


def main():
    try:
        start()
    except (BootstrapError, OSError, ValueError, zipfile.BadZipFile, tarfile.TarError, json.JSONDecodeError) as exc:
        # Never print external HTTP errors, OIDC tokens, private keys or OS paths.
        print("Session RCA unavailable (optional bootstrap rejected); SSH/RDP remains available.")
        return 0
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
