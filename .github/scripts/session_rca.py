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
import time
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



def confirm_windows_registration(process, timeout=45):
    # Only the OIDC-bearing one-shot parent is observed. Its zero exit means
    # transport spawn was accepted, NOT that WSS connected or remains online.
    # Never capture stdout/stderr, tokens, paths or raw OS errors.
    try:
        exit_code = process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        # An overdue registration parent must not retain the GitHub OIDC
        # request credential. Reap it without extending the optional Step.
        try:
            process.kill()
        except ProcessLookupError:
            pass
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            raise BootstrapError("Windows RCA registration cleanup unconfirmed.") from None
        raise BootstrapError("Windows RCA registration timed out.") from None
    if exit_code != 0:
        raise BootstrapError("Windows RCA registration exited unsuccessfully.")
    print("Session RCA Windows registration exited successfully; WSS online is not yet confirmed.")



def observe_windows_transport(parent_pid, executable, *, run=subprocess.run,
                              delay=time.sleep):
    """One bounded native process snapshot; status is not proof of WSS online."""
    if not isinstance(parent_pid, int) or parent_pid <= 0:
        return "unknown"
    # The entry is the SHA-pinned, already verified Node executable. Match
    # both its exact native image path and the transport-only argv marker.
    safe_path = str(executable).replace("'", "''")
    script = (
        "$ErrorActionPreference='Stop'; "
        f"$expected='{safe_path}'; "
        f"$children=@(Get-CimInstance Win32_Process -Filter 'ParentProcessId = {parent_pid}' -ErrorAction Stop); "
        "$found=$false; "
        "foreach($child in $children){ "
        "if([string]::Equals($child.ExecutablePath,$expected,"
        "[StringComparison]::OrdinalIgnoreCase) -and "
        "$child.CommandLine -match '(?i)(?:^|\\s)--session-transport(?:\\s|$)'){"
        "$found=$true} }; "
        "if($found){'alive'}else{'exited'}"
    )
    try:
        delay(3)
        ps = Path(os.environ.get("SystemRoot", "C:\\Windows")) / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"
        result = run([str(ps), "-NoProfile", "-NonInteractive", "-Command", script],
                     stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=10)
        if result.returncode != 0:
            return "unknown"
        value = result.stdout.decode("utf-8", "replace").strip()
        return value if value in ("alive", "exited") else "unknown"
    except (OSError, subprocess.TimeoutExpired):
        return "unknown"



# Read only a fixed checkpoint from the Agent's existing Windows job-private
# store. Unknown/untrusted content is never reproduced in Actions logs.
TRANSPORT_STAGES = frozenset({
    "pending", "entered", "store_ready", "pem_ready", "identity_ready", "signed_recovered", "receipts_ready",
    "challenge_start", "challenge_ok", "challenge_rejected",
    "wss_start", "wss_open", "wss_error", "wss_policy", "wss_timeout",
    "connected",
})


def observe_windows_child_stage(runner_temp, delay=time.sleep):
    stage = Path(runner_temp) / "session-rca" / "transport-stage"
    try:
        if stage.parent.is_symlink() or stage.is_symlink() or not stage.is_file():
            return "unknown"
        # A single 12s snapshot can report "entered" before native ACL
        # verification finishes. Only early stages receive bounded retries.
        early = {"pending", "entered", "store_ready", "pem_ready"}
        for wait in (12, 8, 8):
            delay(wait)
            with stage.open("rb") as handle:
                raw = handle.read(65)
            if len(raw) > 64 or not raw.endswith(b"\n"):
                return "unknown"
            value = raw[:-1].decode("ascii")
            if value not in TRANSPORT_STAGES:
                return "unknown"
            if value not in early:
                return value
        return value
    except (OSError, UnicodeError):
        return "unknown"


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
    if windows:
        confirm_windows_registration(process)
        # No raw process/command-line data is logged, only a fixed snapshot.
        # A live child is not necessarily authenticated to the WSS server.
        state = observe_windows_transport(process.pid, node)
        print(f"Session RCA Windows credential-free transport: {state}; WSS admission remains authoritative.")
        stage_status = observe_windows_child_stage(temp)
        print(f"Session RCA Windows child stage: {stage_status}; WSS admission remains authoritative.")
    return True


def main():
    try:
        start()
    except (BootstrapError, OSError, ValueError, zipfile.BadZipFile, tarfile.TarError, json.JSONDecodeError):
        # Mark this optional Step as failed, while continue-on-error preserves Hold.
        # Never print external HTTP errors, OIDC tokens, private keys or OS paths.
        print("Session RCA unavailable (optional bootstrap rejected); SSH/RDP remains available.")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
