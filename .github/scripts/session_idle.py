"""Ubuntu hosted Session idle policy: local process evidence, no new service."""
import getpass
import json
import os
from pathlib import Path
import re
import socket
import stat
import struct
import subprocess
import time

def idle_timeout_ms():
    """Validate the Ubuntu Session idle threshold (1-300 minutes)."""
    raw = os.getenv("SESSION_IDLE_MINUTES", "30")
    if not raw.isascii() or not raw.isdecimal() or len(raw) > 3:
        raise ValueError("invalid session idle minutes")
    minutes = int(raw)
    if not 1 <= minutes <= 300:
        raise ValueError("invalid session idle minutes")
    return minutes * 60 * 1000


def reviewed_runner():
    return (os.getenv("GITHUB_ACTIONS") == "true"
            and os.getenv("RUNNER_ENVIRONMENT") == "github-hosted"
            and os.getenv("GITHUB_WORKFLOW") == "ubuntu"
            and os.getenv("GITHUB_REPOSITORY") == "autoactions/github-actions"
            and os.getenv("ATTEMPT_ID")
            and os.getenv("GITHUB_RUN_ID", "").isdecimal()
            and os.getenv("GITHUB_RUN_ATTEMPT", "").isdecimal())


def private_object(file, kind, mode):
    try:
        st = file.lstat()
        return (st.st_uid == os.getuid() and stat.S_IMODE(st.st_mode) == mode
                and ((kind == "directory" and stat.S_ISDIR(st.st_mode))
                     or (kind == "socket" and stat.S_ISSOCK(st.st_mode))
                     or (kind == "file" and stat.S_ISREG(st.st_mode) and st.st_nlink == 1)))
    except OSError:
        return False


def control_path():
    if not reviewed_runner():
        return None
    directory = Path(os.environ["RUNNER_TEMP"]) / "session-rca"
    sock = directory / "upgrade.sock"  # Existing owner-private Agent control socket.
    if not private_object(directory, "directory", 0o700):
        return None
    return sock if private_object(sock, "socket", 0o600) else None


def exchange(command):
    """Bounded private IPC. Invalid/absent replies never imply idle."""
    location = control_path()
    if not location or command not in ("idle-status", "idle-freeze", "release"):
        return None
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
            conn.settimeout(2)
            conn.connect(str(location))
            if hasattr(socket, "SO_PEERCRED"):
                _, uid, _ = struct.unpack("3i", conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
                if uid != os.getuid():
                    return None
            conn.sendall((command + "\n").encode("ascii"))
            raw = b""
            while not raw.endswith(b"\n") and len(raw) <= 650:
                part = conn.recv(651 - len(raw))
                if not part:
                    return None
                raw += part
            if len(raw) > 650:
                return None
            return raw[:-1].decode("ascii")
    except (OSError, UnicodeError, ValueError):
        return None


def read_agent():
    try:
        state = json.loads(exchange("idle-status"))
        keys = {"attempt_id", "github_run_id", "github_run_attempt",
                "observed_at_ms", "last_activity_ms", "state"}
        if not isinstance(state, dict) or set(state) != keys:
            return None
        now = int(time.time() * 1000)
        last = state["last_activity_ms"]
        if (state["attempt_id"] != os.environ["ATTEMPT_ID"]
                or type(state["github_run_id"]) is not int
                or state["github_run_id"] != int(os.environ["GITHUB_RUN_ID"])
                or type(state["github_run_attempt"]) is not int
                or state["github_run_attempt"] != int(os.environ["GITHUB_RUN_ATTEMPT"])
                or state["state"] not in ("idle", "busy", "unknown")
                or type(state["observed_at_ms"]) is not int
                or not now - 15000 <= state["observed_at_ms"] <= now + 3000
                or (last is not None and (type(last) is not int or last < 0 or last > now + 3000))):
            return None
        return state
    except (TypeError, ValueError, KeyError, OverflowError):
        return None


def known_bootstrap_failure():
    """Only definitive pre-spawn failures may use SSH-only idle policy."""
    if not reviewed_runner() or os.getenv("SESSION_RCA_OUTCOME") != "failure":
        return False
    marker = Path(os.environ["RUNNER_TEMP"]) / "session-rca-known-failed"
    try:
        return private_object(marker, "file", 0o600) and marker.read_bytes() == b"failed\n"
    except OSError:
        return False


def ssh_state(final=False):
    """Detect authenticated OpenSSH sessions including @notty, never bare TCP.

    After ingress shutdown any unclassified sshd child is still uncertain:
    an already accepted pre-auth child could complete authentication.
    """
    try:
        rows = subprocess.run(["ps", "-eo", "user=,comm=,args="],
                              capture_output=True, text=True, check=True, timeout=4).stdout
        authenticated = re.compile(r"^sshd(?:-session)?:\s+" + re.escape(getpass.getuser()) + r"@\S+")
        ambiguous = False
        for row in rows.splitlines():
            fields = row.strip().split(None, 2)
            if len(fields) < 3 or fields[1] not in ("sshd", "sshd-session"):
                continue
            if authenticated.match(fields[2]):
                return "busy"
            if final:
                ambiguous = True
        return "unknown" if ambiguous else "clear"
    except (OSError, subprocess.SubprocessError, UnicodeError, ValueError):
        return "unknown"


def systemctl(*args):
    return subprocess.run(["sudo", "-n", "systemctl", *args],
                          capture_output=True, check=True, timeout=15)


def stop_ssh_ingress():
    """Stop both service and socket, but only where SSH children survive stop."""
    try:
        mode = subprocess.run(["systemctl", "show", "ssh.service",
                               "--property=KillMode", "--value"],
                              capture_output=True, text=True, check=True, timeout=5).stdout.strip()
        if mode not in ("process", "none"):
            return False
        systemctl("stop", "ssh.socket", "ssh.service")
        listeners = subprocess.run(["ss", "-H", "-ltn", "( sport = :22 )"],
                                   capture_output=True, text=True, check=True, timeout=5).stdout
        return not listeners.strip()
    except (OSError, subprocess.SubprocessError):
        return False


def restore_ssh_ingress():
    try:
        systemctl("start", "ssh.socket", "ssh.service")
        return True
    except (OSError, subprocess.SubprocessError):
        return False


def prepare_idle_stop(ready_ms, now_ms, known_failure):
    """Freeze RCA admissions, stop SSH ingress, then validate both again."""
    idle_ms = idle_timeout_ms()
    frozen = False
    ssh_touched = False
    success = False
    try:
        if not known_failure:
            if exchange("idle-freeze") != "ready":
                return False
            frozen = True
            fresh = read_agent()
            if (not fresh or fresh["state"] != "idle"
                    or now_ms - max(ready_ms, fresh["last_activity_ms"] or ready_ms) < idle_ms):
                return False
        ssh_touched = True  # Restore even after a partially successful stop.
        if not stop_ssh_ingress() or ssh_state(final=True) != "clear":
            return False
        if not known_failure:
            fresh = read_agent()
            if (not fresh or fresh["state"] != "idle"
                    or int(time.time() * 1000) -
                    max(ready_ms, fresh["last_activity_ms"] or ready_ms) < idle_ms):
                return False
        success = True
        return True
    finally:
        if not success:
            if ssh_touched:
                restore_ssh_ingress()
            if frozen:
                exchange("release")


def hold_until(end_sec, ready_ms):
    """Never extends the absolute deadline captured by the Job's first step."""
    idle_ms = idle_timeout_ms()
    failed = known_bootstrap_failure()
    last_busy_ms = ready_ms
    while time.time() < end_sec:
        now_ms = int(time.time() * 1000)
        agent = {"state": "idle", "last_activity_ms": None} if failed else read_agent()
        ssh = ssh_state()
        if agent is None or agent["state"] != "idle" or ssh != "clear":
            last_busy_ms = now_ms
        elif now_ms - max(ready_ms, last_busy_ms, agent["last_activity_ms"] or ready_ms) >= idle_ms:
            try:
                if prepare_idle_stop(max(ready_ms, last_busy_ms), now_ms, failed):
                    return "idle"
            except Exception:
                pass  # Unknown local state is not evidence for early stop.
            last_busy_ms = int(time.time() * 1000)
        time.sleep(min(10, max(0, end_sec - time.time())))
    return "deadline"
