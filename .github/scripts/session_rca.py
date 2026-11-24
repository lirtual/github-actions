#!/usr/bin/env python3
"""Optional Session RCA bootstrap: immutable Release by default, pinned Rust source for acceptance."""
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import sys
import time
import tarfile
import urllib.request
import zipfile

from session_action import discover_audience

REPOSITORY = "lirtual/mcp-workers"
# Advance only with a reviewed Candidate source change and matching Workflow approval.
CANDIDATE_COMMIT = "f968f1788d4d512407559dc1a046bcd748d16640"
CANDIDATE_TIMEOUT_SECONDS = 180
WINDOWS_CANDIDATE_TIMEOUT_SECONDS = 600
LIMIT = 180 * 1024 * 1024
UNPACKED_LIMIT = 250 * 1024 * 1024
COUNT_LIMIT = 200
# Complete versions may be GitHub prereleases; -rc / other suffixed tags cannot auto-run.
TAG = re.compile(r"v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\Z")
DIGEST = re.compile(r"[0-9a-f]{64}\Z")
RELEASE_PAGE_SIZE = 100
RELEASE_PAGE_LIMIT = 5
RELEASE_RESPONSE_LIMIT = 8 * 1024 * 1024


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




def resolve_latest_release(target, extension, opener=urllib.request.urlopen):
    """Find the highest complete immutable Release, then verify its exact asset."""
    eligible = []
    for page in range(1, RELEASE_PAGE_LIMIT + 1):
        url = (f"https://api.github.com/repos/{REPOSITORY}/releases"
               f"?per_page={RELEASE_PAGE_SIZE}&page={page}")
        request = urllib.request.Request(url, headers={
            "User-Agent": "github-actions-session-rca",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        })
        with opener(request, timeout=8) as response:
            if response.geturl() != url:
                raise BootstrapError("Unexpected GitHub Releases API redirect")
            raw = response.read(RELEASE_RESPONSE_LIMIT + 1)
        if len(raw) > RELEASE_RESPONSE_LIMIT:
            raise BootstrapError("Release metadata exceeds limit")
        releases = json.loads(raw)
        if not isinstance(releases, list) or len(releases) > RELEASE_PAGE_SIZE:
            raise BootstrapError("Invalid Release metadata")
        for release in releases:
            if not isinstance(release, dict):
                raise BootstrapError("Invalid Release entry")
            tag = release.get("tag_name")
            if (isinstance(tag, str) and len(tag) <= 32
                    and TAG.fullmatch(tag) and release.get("draft") is False):
                eligible.append((tuple(map(int, tag[1:].split("."))), tag, release))
        if len(releases) < RELEASE_PAGE_SIZE:
            break
    else:
        raise BootstrapError("Release listing pagination incomplete")
    if not eligible:
        raise BootstrapError("No eligible full Release")
    _, tag, release = max(eligible, key=lambda row: row[0])
    if release.get("immutable") is not True:
        raise BootstrapError("Latest Release is not immutable")
    name = f"remote-control-agent-{tag}-{target}.{extension}"
    url = f"https://github.com/{REPOSITORY}/releases/download/{tag}/{name}"
    assets = release.get("assets")
    if not isinstance(assets, list):
        raise BootstrapError("Release assets unavailable")
    matches = [asset for asset in assets
               if isinstance(asset, dict) and asset.get("name") == name]
    if len(matches) != 1:
        raise BootstrapError("Matching Release asset missing or ambiguous")
    asset = matches[0]
    digest = asset.get("digest")
    size = asset.get("size")
    if (asset.get("state") != "uploaded" or
            asset.get("browser_download_url") != url or
            not isinstance(digest, str) or not digest.startswith("sha256:") or
            not DIGEST.fullmatch(digest[7:]) or
            type(size) is not int or not 0 < size <= LIMIT):
        raise BootstrapError("Unverified Release asset")
    return tag, digest[7:], url


def confirm_linux_registration(process, timeout=45):
    # Candidate parent exits after one-shot OIDC registration and detached
    # credential-free transport spawn. A live child still requires Worker evidence.
    try:
        exit_code = process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        try:
            process.kill()
        except ProcessLookupError:
            pass
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            raise BootstrapError("Linux RCA registration cleanup unconfirmed.") from None
        raise BootstrapError("Linux RCA registration timed out.") from None
    if exit_code != 0:
        raise BootstrapError("Linux RCA registration exited unsuccessfully.")
    print("Session RCA Linux registration exited successfully; WSS online is not yet confirmed.")


def _candidate_build_env(source=os.environ):
    # Cargo build scripts and git must never inherit the Runner OIDC request
    # credential, Action tokens, or arbitrary Workflow-provided environment.
    allowed = ("HOME", "USER", "LOGNAME", "LANG", "LC_ALL", "TMPDIR",
               "RUNNER_TEMP", "CARGO_HOME", "RUSTUP_HOME", "TEMP", "TMP",
               "USERPROFILE", "SystemRoot", "WINDIR", "COMSPEC", "PATHEXT",
               "APPDATA", "LOCALAPPDATA", "PROGRAMDATA", "ProgramFiles",
               "ProgramFiles(x86)", "PROCESSOR_ARCHITECTURE", "NUMBER_OF_PROCESSORS")
    result = {key: source[key] for key in allowed if source.get(key)}
    home = result.get("HOME") or result.get("USERPROFILE") or str(Path.home())
    cargo_home = result.get("CARGO_HOME") or str(Path(home) / ".cargo")
    cargo_bin = str(Path(cargo_home) / "bin")
    result["HOME"] = home
    result["PATH"] = os.pathsep.join((cargo_bin, source.get("PATH") or os.defpath))
    return result


def build_linux_candidate(runner_temp, *, run=subprocess.run, source_env=os.environ):
    """Build the exact reviewed Rust Session Candidate without passing OIDC to build tools."""
    if sys.platform != "linux":
        raise BootstrapError("Linux-only Candidate build is unsupported on this platform.")
    root = Path(runner_temp) / "session-rca-rust-candidate"
    root.mkdir(mode=0o700, exist_ok=False)
    source = root / "source"
    build_env = _candidate_build_env(source_env)

    def execute(args, *, cwd=None, timeout=CANDIDATE_TIMEOUT_SECONDS, capture=False):
        try:
            result = run(args, cwd=cwd, env=build_env,
                         stdin=subprocess.DEVNULL,
                         stdout=subprocess.PIPE if capture else subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL, timeout=timeout, check=False)
        except (OSError, subprocess.SubprocessError):
            raise BootstrapError("Pinned Rust Candidate build command failed.") from None
        if result.returncode != 0:
            raise BootstrapError("Pinned Rust Candidate build command failed.")
        return result

    repo_url = f"https://github.com/{REPOSITORY}.git"
    execute(["git", "-c", "credential.helper=", "clone", "--quiet",
             "--no-checkout", "--no-tags", "--filter=blob:none", repo_url, str(source)])
    execute(["git", "-c", "credential.helper=", "-C", str(source),
             "fetch", "--quiet", "--no-tags", "--depth=1", "origin", CANDIDATE_COMMIT])
    execute(["git", "-C", str(source), "checkout", "--quiet", "--detach", CANDIDATE_COMMIT])
    revision = execute(["git", "-C", str(source), "rev-parse", "HEAD"], capture=True)
    if revision.stdout.decode("ascii", "strict").strip() != CANDIDATE_COMMIT:
        raise BootstrapError("Rust Candidate source pin mismatch.")

    package = source / "apps/remote-control-mcp-worker/agent"
    rust_project = package / "native-rust"
    execute(["cargo", "+1.100.0", "build", "--locked", "--bin",
             "rca-session-linux-candidate"], cwd=rust_project, timeout=CANDIDATE_TIMEOUT_SECONDS)
    candidate = rust_project / "target/debug/rca-session-linux-candidate"
    candidate_entry = root / "rca-session-linux-candidate"
    shutil.copyfile(candidate, candidate_entry)
    candidate_entry.chmod(0o700)

    supervisor_source = package / "scripts/session-supervisor.c"
    supervisor = root / "session-supervisor"
    execute(["cc", "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror",
             "-fstack-protector-strong", "-D_FORTIFY_SOURCE=2",
             "-Wl,-z,relro,-z,now", str(supervisor_source), "-o", str(supervisor)],
            cwd=package)
    supervisor.chmod(0o700)
    if (not candidate_entry.is_file() or candidate_entry.is_symlink()
            or not supervisor.is_file() or supervisor.is_symlink()):
        raise BootstrapError("Rust Candidate build output is invalid.")
    return candidate_entry


def build_windows_candidate(runner_temp, *, run=subprocess.run, source_env=os.environ):
    """Build the pinned Windows Session Candidate without Runner credentials."""
    if sys.platform != "win32":
        raise BootstrapError("Windows-only Candidate build is unsupported on this platform.")
    root = Path(runner_temp) / "session-rca-rust-candidate"
    root.mkdir(exist_ok=False)
    source = root / "source"
    build_env = _candidate_build_env(source_env)

    def execute(args, *, cwd=None, capture=False):
        try:
            result = run(args, cwd=cwd, env=build_env, stdin=subprocess.DEVNULL,
                         stdout=subprocess.PIPE if capture else subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL, timeout=WINDOWS_CANDIDATE_TIMEOUT_SECONDS,
                         check=False)
        except (OSError, subprocess.SubprocessError):
            raise BootstrapError("Pinned Windows Rust Candidate build command failed.") from None
        if result.returncode != 0:
            raise BootstrapError("Pinned Windows Rust Candidate build command failed.")
        return result

    repo_url = f"https://github.com/{REPOSITORY}.git"
    execute(["git", "-c", "credential.helper=", "clone", "--quiet", "--no-checkout",
             "--no-tags", "--filter=blob:none", repo_url, str(source)])
    execute(["git", "-c", "credential.helper=", "-C", str(source), "fetch", "--quiet",
             "--no-tags", "--depth=1", "origin", CANDIDATE_COMMIT])
    execute(["git", "-C", str(source), "checkout", "--quiet", "--detach", CANDIDATE_COMMIT])
    revision = execute(["git", "-C", str(source), "rev-parse", "HEAD"], capture=True)
    if revision.stdout.decode("ascii", "strict").strip() != CANDIDATE_COMMIT:
        raise BootstrapError("Windows Rust Candidate source pin mismatch.")

    rust_project = source / "apps/remote-control-mcp-worker/agent/native-rust"
    execute(["cargo", "+1.100.0", "build", "--locked", "--bin",
             "rca-session-windows-candidate"], cwd=rust_project)
    candidate = rust_project / "target/debug/rca-session-windows-candidate.exe"
    candidate_entry = root / "rca-session-windows-candidate.exe"
    if not candidate.is_file() or candidate.is_symlink():
        raise BootstrapError("Windows Rust Candidate build output is invalid.")
    shutil.copyfile(candidate, candidate_entry)
    if not candidate_entry.is_file() or candidate_entry.is_symlink():
        raise BootstrapError("Windows Rust Candidate staging failed.")
    return candidate_entry


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
    # The entry is the SHA-pinned, already verified Rust executable. Match
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
BOOTSTRAP_SPAWNED = False
# Static phase names only: never log exception text, URLs, credentials or filesystem paths.
BOOTSTRAP_PHASE = "environment"

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



def launch_native(executable, registration_env, temp, windows, launch):
    global BOOTSTRAP_SPAWNED
    flags = subprocess.CREATE_NEW_PROCESS_GROUP if windows else 0
    process = launch([str(executable)], cwd=str(executable.parent), env=registration_env,
                     stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                     stderr=subprocess.DEVNULL, creationflags=flags,
                     start_new_session=not windows)
    BOOTSTRAP_SPAWNED = True
    print(f"Session RCA Rust Candidate launched (pid {process.pid}); Worker online admission remains authoritative.")
    if windows:
        confirm_windows_registration(process)
        state = observe_windows_transport(process.pid, executable)
        stage = observe_windows_child_stage(temp, delay=lambda _seconds: None)
        print(f"Session RCA Windows Candidate stage: {stage}; WSS admission remains authoritative.")
        if state != "alive":
            raise BootstrapError("Windows RCA Candidate transport liveness unconfirmed.")
        print("Session RCA Windows credential-free transport: alive; WSS admission remains authoritative.")
    else:
        confirm_linux_registration(process)
    return True


def start(env=os.environ, opener=urllib.request.urlopen, launch=subprocess.Popen,
          select_release=resolve_latest_release, build_candidate=build_linux_candidate,
          build_windows_candidate_fn=build_windows_candidate):
    global BOOTSTRAP_PHASE, BOOTSTRAP_SPAWNED
    BOOTSTRAP_PHASE = "environment"
    windows = sys.platform == "win32"
    workflow = "windows" if windows else "ubuntu"
    if (env.get("GITHUB_ACTIONS") != "true" or env.get("RUNNER_ENVIRONMENT") != "github-hosted"
        or env.get("GITHUB_WORKFLOW") != workflow or env.get("GITHUB_REPOSITORY") != "autoactions/github-actions"
        or not env.get("ATTEMPT_ID")
        or not env.get("ACTIONS_ID_TOKEN_REQUEST_URL") or not env.get("ACTIONS_ID_TOKEN_REQUEST_TOKEN")):
        raise BootstrapError("Unreviewed physical Session environment")
    temp = env.get("RUNNER_TEMP", "")
    if not temp or not Path(temp).is_absolute():
        raise BootstrapError("Missing job-scoped runtime directory")
    agent = env.get("SESSION_RCA_AGENT", "release")
    if agent not in ("release", "rust-candidate"):
        raise BootstrapError("Unsupported Session RCA implementation selection")
    # Use the already-reviewed Claim discovery contract, not a new repository variable.
    # Override any ambient audience; only the short-lived registration parent receives it.
    BOOTSTRAP_PHASE = "audience"
    registration_env = dict(env)
    registration_env["WORKFLOW_ACTION_OIDC_AUDIENCE"] = discover_audience(
        env.get("WORKFLOW_ACTION_CLAIM_URL", ""))
    if not windows:
        # GitHub Runner's GITHUB_ACTIONS=true is inherited by RCA commands;
        # distinguish the reviewed RCA child without changing the Runner.
        home = Path(env.get("HOME") or Path.home())
        registration_env["SESSION_ACTION_RCA"] = "1"
        registration_env["BASH_ENV"] = str(home / ".config/session-actions/rca-env.bash")
        registration_env["PATH"] = os.pathsep.join((
            str(home / ".local/bin"),
            str(home / ".local/session-actions/npm/bin"),
            env.get("PATH") or os.defpath,
        ))
        # Only an activated private RCA shell is selected. Without it, retain
        # the original Runner shell so optional CLI setup cannot block RCA.
        shell = home / ".config/session-actions/rca-shell"
        if os.name == "posix":
            try:
                info = shell.lstat()
                if (stat.S_ISREG(info.st_mode) and
                    stat.S_IMODE(info.st_mode) == 0o700 and
                    info.st_uid == os.getuid()):
                    registration_env["SHELL"] = str(shell)
            except OSError:
                pass
    if agent == "rust-candidate":
        BOOTSTRAP_PHASE = "candidate_build"
        executable = build_windows_candidate_fn(temp) if windows else build_candidate(temp)
        BOOTSTRAP_PHASE = "candidate_launch"
        return launch_native(executable, registration_env, temp, windows, launch)

    target = "windows-x64" if windows else "linux-x64-glibc"
    extension = "zip" if windows else "tar.gz"
    BOOTSTRAP_PHASE = "release_lookup"
    tag, sha, url = select_release(target, extension, opener)
    if not TAG.fullmatch(tag) or not DIGEST.fullmatch(sha):
        raise BootstrapError("Unverified Release selection")
    name = f"remote-control-agent-{tag}-{target}.{extension}"
    if url != f"https://github.com/{REPOSITORY}/releases/download/{tag}/{name}":
        raise BootstrapError("Unexpected Release download URL")
    BOOTSTRAP_PHASE = "asset_download"
    stage = Path(temp) / "session-rca-reviewed-release"
    stage.mkdir(mode=0o700, exist_ok=False)
    archive = stage / name
    download_pinned(url, archive, sha, opener)
    BOOTSTRAP_PHASE = "asset_unpack"
    unpack_reviewed(archive, stage, windows)
    BOOTSTRAP_PHASE = "bundle_check"
    manifest = json.loads((stage / "bundle.json").read_text(encoding="utf-8"))
    if (manifest.get("version") != tag or manifest.get("target") != target or
        manifest.get("name") != "remote-control-agent" or manifest.get("device_protocol") != 2 or
        manifest.get("upgrade_profile") != "paired-full-v1"):
        raise BootstrapError("Unreviewed Session RCA release identity")
    expected_runtime = "rust-standard-windows-v1" if windows else "rust-standard-linux-v1"
    if (manifest.get("artifact_profile") != "rust-native-only-v1" or
            manifest.get("artifact_schema") != 1 or manifest.get("agent_runtime") != expected_runtime or
            manifest.get("session_runtime") != "rust-session-v1" or manifest.get("modules") != [] or
            "node" in manifest or "upgrade_protocol" in manifest or
            (stage / "bin" / ("node.exe" if windows else "node")).exists()):
        raise BootstrapError("Unreviewed native Session Release profile")
    build = stage / "apps/remote-control-agent/.build"
    executable = build / ("rca-session-windows-candidate.exe" if windows else "rca-session-linux-candidate")
    required = [executable] if windows else [executable, build / "session-supervisor"]
    if any(not path.is_file() or path.is_symlink() for path in required):
        raise BootstrapError("Release lacks reviewed native Session entry")
    if not windows:
        for path in required:
            path.chmod(0o700)
    BOOTSTRAP_PHASE = "process_launch"
    return launch_native(executable, registration_env, temp, windows, launch)


def main():
    try:
        start()
    except (BootstrapError, OSError, ValueError, zipfile.BadZipFile, tarfile.TarError, json.JSONDecodeError):
        # Known pre-spawn failure, not the ambiguous case where a child may live.
        if not BOOTSTRAP_SPAWNED and sys.platform != "win32" and \
           os.environ.get("GITHUB_ACTIONS") == "true" and \
           os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted" and \
           os.environ.get("GITHUB_WORKFLOW") == "ubuntu" and \
           os.environ.get("GITHUB_REPOSITORY") == "autoactions/github-actions":
            try:
                marker = Path(os.environ["RUNNER_TEMP"]) / "session-rca-known-failed"
                flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
                fd = os.open(marker, flags, 0o600)
                with os.fdopen(fd, "wb") as handle:
                    handle.write(b"failed\n")
                    handle.flush()
                    os.fsync(handle.fileno())
            except OSError:
                pass  # Missing marker conservatively disables SSH-only early stop.
        # Mark this optional Step as failed, while continue-on-error preserves Hold.
        # Never print external HTTP errors, OIDC tokens, private keys or OS paths.
        print(f"Session RCA unavailable at phase={BOOTSTRAP_PHASE}; SSH/RDP remains available.")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
