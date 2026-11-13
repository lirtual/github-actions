#!/usr/bin/env python3
"""Session Actions GitHub Runner protocol; Python standard library only.

Never print GitHub identity tokens or response bodies. The Workflow MCP
verifies signed OIDC identity and the immutable GitHub physical Run before
accepting claim or ready.
"""
import json
import http.client
import urllib.error
import os
import pathlib
import re
import stat
import sys
import time
import urllib.parse
import urllib.request

UUID = re.compile(r"^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$", re.I)
AUDIENCE = re.compile(r"^workflow-github-[a-z0-9:-]{4,120}$")
MAX_MINUTES = 300


class SafeProtocolError(ValueError):
    """Whitelisted diagnostic text only; never include transport inputs."""


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    # Never forward GitHub's short-lived Bearer JWT or accept a fake success
    # body from a redirected endpoint.
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


OPENER = urllib.request.build_opener(_NoRedirect())


def discover_audience(claim):
    # Use the exact trusted Claim origin; discovery cannot redirect to another host.
    target = urllib.parse.urlsplit(claim)
    if not (target.scheme == "https" and target.hostname and target.username is None
            and target.password is None and target.path == "/github/action/claim"
            and not target.query and not target.fragment):
        raise SafeProtocolError("configuration_invalid")
    request = urllib.request.Request(claim[:-len("/claim")] + "/config", method="GET",
                                     headers={"User-Agent":"lirtual-github-action-oidc-discovery/1.0"})
    try:
        with OPENER.open(request, timeout=10) as response:
            if response.status != 200:
                raise ValueError("unexpected status")
            raw = response.read(257)
        if len(raw) > 256:
            raise ValueError("unexpected length")
        data = json.loads(raw)
        audience = data.get("audience") if type(data) is dict and set(data) == {"audience"} else None
        if not isinstance(audience, str) or not AUDIENCE.fullmatch(audience):
            raise ValueError("invalid audience")
        return audience
    except urllib.error.HTTPError as failure:
        failure.close()
        raise SafeProtocolError("audience_discovery_unavailable") from None
    except Exception:
        # Avoid reflecting HTTP bodies, endpoint addresses or response exceptions.
        raise SafeProtocolError("audience_discovery_unavailable") from None


def configuration():
    attempt = os.getenv("ATTEMPT_ID", "")
    dispatch = os.getenv("DISPATCH_ID", "")
    capability = os.getenv("CAPABILITY_ID", "")
    claim = os.getenv("WORKFLOW_ACTION_CLAIM_URL", "")
    target = urllib.parse.urlsplit(claim)
    if not (UUID.fullmatch(attempt) and UUID.fullmatch(dispatch)
            and capability == "github.action"
            and target.scheme == "https" and target.hostname
            and target.username is None and target.password is None
            and target.path == "/github/action/claim" and not target.query
            and not target.fragment):
        raise SafeProtocolError("configuration_invalid")
    return attempt, discover_audience(claim), claim


def github_token(audience):
    url = os.getenv("ACTIONS_ID_TOKEN_REQUEST_URL", "")
    secret = os.getenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "")
    target = urllib.parse.urlsplit(url)
    if target.scheme != "https" or not target.hostname or not secret:
        raise SafeProtocolError("oidc_credentials_unavailable")
    separator = "&" if "?" in url else "?"
    request = urllib.request.Request(
        url + separator + urllib.parse.urlencode({"audience": audience}),
        headers={"Authorization": "Bearer " + secret},
    )
    try:
        with OPENER.open(request, timeout=15) as response:
            data = json.load(response)
    except urllib.error.HTTPError as failure:
        code = failure.code
        failure.close()
        raise SafeProtocolError("oidc_request_http_" + str(code)) from None
    except Exception as failure:
        # Never print an exception message: it may contain an OIDC URL or token.
        raise SafeProtocolError("oidc_request_" + type(failure).__name__) from None
    jwt = data.get("value")
    if not isinstance(jwt, str) or not jwt:
        raise SafeProtocolError("oidc_token_missing")
    return jwt


def signed_status_payload(attempt, stage):
    payload = {"attemptId": attempt}
    if stage != "ready":
        return payload
    # This is the exact job-snapshotted effective duration, not a caller
    # override. The signed physical Ready is the first/only D1 freeze.
    if (os.getenv("GITHUB_REPOSITORY") == "autoactions/github-actions" and
            os.getenv("GITHUB_WORKFLOW") in ("ubuntu", "windows")):
        payload["durationMinutes"] = session_duration_minutes()
    # The tunnel script is the sole source; never take a caller input or
    # synthesize a public URL. Tailnet-only Sessions have no such file.
    temp = pathlib.Path(os.environ["RUNNER_TEMP"]).resolve(strict=True)
    locator = temp / "session-tunnel-url"
    if locator.is_symlink():
        raise SafeProtocolError("session_locator_invalid")
    if locator.exists():
        if not locator.is_file() or locator.stat().st_size > 180:
            raise SafeProtocolError("session_locator_invalid")
        value = locator.read_text(encoding="ascii").strip()
        if not re.fullmatch(r"https://[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.trycloudflare\.com/?", value):
            raise SafeProtocolError("session_locator_invalid")
        payload["sessionUrl"] = value
    return payload


def assert_status(stage):
    attempt, audience, claim = configuration()
    url = claim if stage == "claim" else claim[:-len("/claim")] + "/ready"
    expected = "claimed" if stage == "claim" else "ready"
    if stage not in ("claim", "ready"):
        raise ValueError("invalid protocol operation")
    # Retry only transient 503 or an ambiguous POST transport/response loss.
    # The Worker independently re-verifies the same physical signed owner
    # before returning already_claimed / already_ready. HTTP 403 fails closed.
    attempts = 12  # Claim waits for D1 dispatch ACK; Ready waits for physical status.
    for retry in range(attempts):
        jwt = github_token(audience)
        request = urllib.request.Request(
            url, method="POST",
            data=json.dumps(signed_status_payload(attempt, stage)).encode("utf-8"),
            headers={"Authorization": "Bearer " + jwt, "Content-Type": "application/json"},
        )
        try:
            with OPENER.open(request, timeout=20) as response:
                result = json.load(response)
                # HTTP response may be lost after D1 already committed Ready.
                # An immutable GitHub OIDC identity and physical owner are still
                # reverified by the Worker before it returns already_ready.
                allowed = {expected, "already_ready" if stage == "ready" else "already_claimed"}
                if response.status != 200 or result not in tuple({"result": value} for value in allowed):
                    raise ValueError("signed " + stage + " not accepted")
            print("Signed GitHub Session " + stage + " acknowledged")
            return
        except urllib.error.HTTPError as failure:
            code = failure.code
            failure.close()
            if code != 503:
                raise SafeProtocolError(stage + "_request_http_" + str(code)) from None
        except (OSError, http.client.IncompleteRead, json.JSONDecodeError):
            # The server may already have committed its D1 CAS before the
            # connection broke or the HTTP 200 JSON body was truncated.
            # A replay is harmless only because the Worker requires the same
            # signed physical owner and checks cancellation/terminal fences.
            pass
        if retry == attempts - 1:
            raise ValueError("signed " + stage + " unavailable")
        time.sleep(5)
    raise ValueError("signed " + stage + " unavailable")


def start_file():
    temp = pathlib.Path(os.environ["RUNNER_TEMP"]).resolve()
    return temp / "session-action-start"


def recorded_start():
    # The workflow's first step stamps the start BEFORE checkout and setup;
    # never allow a later step to reset or extend the Session deadline.
    location = start_file()
    if location.is_symlink() or not location.is_file():
        raise ValueError("missing job start timestamp")
    raw = location.read_text(encoding="ascii").strip()
    if not raw.isdecimal() or len(raw) > 11:
        raise ValueError("invalid job start timestamp")
    started = int(raw)
    now = int(time.time())
    if started <= 0 or started < now - 360 * 60 or started > now + 30:
        raise ValueError("session start timestamp invalid")
    return started


def session_duration_minutes():
    """Validate the job-snapshotted effective duration before opening access."""
    raw = os.getenv("DURATION_MINUTES", "")
    if not raw.isdecimal() or len(raw) > 3:
        raise ValueError("invalid session duration")
    minutes = int(raw)
    if not 1 <= minutes <= MAX_MINUTES:
        raise ValueError("invalid session duration")
    return minutes


def start():
    # Validate the first-step marker and the effective duration before Claim.
    recorded_start()
    session_duration_minutes()
    if os.getenv("GITHUB_WORKFLOW") == "ubuntu":
        from session_idle import idle_timeout_ms
        idle_timeout_ms()  # Reject invalid repository settings before Claim.


def mark_ready():
    # Only Ubuntu's signed Ready establishes the idle clock. Windows is unchanged.
    if os.getenv("GITHUB_WORKFLOW") != "ubuntu":
        return
    marker = start_file().with_name("session-action-ready")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(marker, flags, 0o600)
    with os.fdopen(fd, "w", encoding="ascii") as handle:
        handle.write(str(int(time.time())) + "\n")
        handle.flush()
        os.fsync(handle.fileno())


def ready_timestamp():
    marker = start_file().with_name("session-action-ready")
    try:
        st = marker.lstat()
        if not (stat.S_ISREG(st.st_mode) and st.st_nlink == 1 and
                st.st_uid == os.getuid() and stat.S_IMODE(st.st_mode) == 0o600):
            return None
        text = marker.read_text(encoding="ascii").strip()
        stamp = int(text) if text.isdecimal() and len(text) <= 11 else 0
        return stamp if recorded_start() <= stamp <= int(time.time()) + 3 else None
    except (OSError, ValueError, UnicodeError):
        return None


def hold():
    minutes = session_duration_minutes()
    start_time = recorded_start()
    end = start_time + 60 * minutes
    print("Session bounded hold started; GitHub Job timeout remains authoritative")
    if os.getenv("GITHUB_WORKFLOW") == "ubuntu":
        from session_idle import hold_until, reviewed_runner
        ready = ready_timestamp()
        if reviewed_runner() and ready is not None:
            outcome = hold_until(end, ready * 1000)
            if outcome == "idle":
                print("Ubuntu Session confirmed idle; normal cleanup follows")
                return
    while time.time() < end:
        time.sleep(min(10, max(0, end - time.time())))
    print("Session lifetime reached; shutting down")


def main():
    try:
        if len(sys.argv) != 2:
            raise ValueError("expected start, claim, ready, or hold")
        mode = sys.argv[1]
        if mode == "start":
            start()
        elif mode == "claim":
            assert_status(mode)
        elif mode == "ready":
            assert_status(mode)
            mark_ready()
        elif mode == "hold":
            hold()
        else:
            raise ValueError("invalid operation")
    except SafeProtocolError as failure:
        # SafeProtocolError carries only constant stages and numeric HTTP codes.
        # Never echo the URL, JWT, credential, server body or traceback.
        print("Session Action protocol step failed: " +
              (sys.argv[1] if len(sys.argv) > 1 else "invalid") +
              " (" + str(failure) + ")", file=sys.stderr)
        raise SystemExit(1)
    except Exception:
        print("Session Action protocol step failed: " +
              (sys.argv[1] if len(sys.argv) > 1 else "invalid"), file=sys.stderr)
        raise SystemExit(1)


if __name__ == "__main__":
    main()
