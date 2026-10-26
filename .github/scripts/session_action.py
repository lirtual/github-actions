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
import subprocess
import sys
import time
import urllib.parse
import urllib.request

UUID = re.compile(r"^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$", re.I)
AUDIENCE = re.compile(r"^workflow-github-[a-z0-9:-]{4,120}$")
MAX_MINUTES = 330


class SafeProtocolError(ValueError):
    """Whitelisted diagnostic text only; never include transport inputs."""


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    # Never forward GitHub's short-lived Bearer JWT or accept a fake success
    # body from a redirected endpoint.
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


OPENER = urllib.request.build_opener(_NoRedirect())


def configuration():
    attempt = os.getenv("ATTEMPT_ID", "")
    dispatch = os.getenv("DISPATCH_ID", "")
    capability = os.getenv("CAPABILITY_ID", "")
    audience = os.getenv("WORKFLOW_ACTION_OIDC_AUDIENCE", "")
    claim = os.getenv("WORKFLOW_ACTION_CLAIM_URL", "")
    url = urllib.parse.urlsplit(claim)
    if not (UUID.fullmatch(attempt) and UUID.fullmatch(dispatch)
            and capability == "github.action" and AUDIENCE.fullmatch(audience)
            and url.scheme == "https" and url.hostname and url.username is None
            and url.password is None and url.path == "/github/action/claim"
            and not url.query and not url.fragment):
        raise SafeProtocolError("configuration_invalid")
    return attempt, audience, claim


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


UU_KEY = "uu.credentials"
UU_ID = re.compile(r"^[0-9]{9}$")
UU_CODE = re.compile(r"^(?=.*[A-Za-z])(?=.*[0-9])[A-Za-z0-9]{8}$")
UU_SHARE_URL = re.compile(r"^https://uuyc\.163\.com/invite/[0-9a-fA-F]{32}$")


def observed_uu(path, refreshed=True):
    # A failed UI refresh invalidates the previous sample even if a stale
    # credential file remains on disk (e.g. after subprocess timeout).
    if not refreshed:
        return "unavailable", None
    try:
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 1024:
            return "unavailable", None
        sample = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(sample, dict):
            return "unavailable", None
        if sample.get("status") != "ready":
            return "unavailable", None
        keys = set(sample)
        allowed = {"status", "device_id", "verification_code"}
        if keys != allowed and keys != allowed | {"share_url"}:
            return "unavailable", None
        device_id, code = sample["device_id"], sample["verification_code"]
        if (not isinstance(device_id, str) or not UU_ID.fullmatch(device_id)
                or not isinstance(code, str) or not UU_CODE.fullmatch(code)):
            return "unavailable", None
        value = {"device_id": device_id, "verification_code": code}
        # A malformed optional URL is omitted; the independent ID/code still
        # work. Unknown fields remain rejected by the strict allowlist above.
        share_url = sample.get("share_url")
        if isinstance(share_url, str) and UU_SHARE_URL.fullmatch(share_url):
            value["share_url"] = share_url
        return "ready", value
    except (OSError, UnicodeError, ValueError, TypeError):
        return "unavailable", None


def next_uu_sequence(attempt):
    """Durable per-Attempt/key sequence, atomically advanced before sending."""
    temp = pathlib.Path(os.environ["RUNNER_TEMP"]).resolve(strict=True)
    location = temp / "session-uu-sequence.json"
    if location.is_symlink():
        raise SafeProtocolError("sequence_invalid")
    previous = 0
    if location.exists():
        if not location.is_file() or location.stat().st_size > 256:
            raise SafeProtocolError("sequence_invalid")
        saved = json.loads(location.read_text(encoding="ascii"))
        if not isinstance(saved, dict) or set(saved) != {"attemptId", "key", "sequence"}:
            raise SafeProtocolError("sequence_invalid")
        if saved["attemptId"] == attempt and saved["key"] == UU_KEY:
            previous = saved["sequence"]
            if not isinstance(previous, int) or isinstance(previous, bool) or not 0 <= previous < 9007199254740991:
                raise SafeProtocolError("sequence_invalid")
    value = previous + 1
    import tempfile
    with tempfile.NamedTemporaryFile(mode="w", encoding="ascii", prefix="session-seq-",
                                     suffix=".tmp", dir=temp, delete=False) as temporary:
        candidate = pathlib.Path(temporary.name)
        try:
            json.dump({"attemptId": attempt, "key": UU_KEY, "sequence": value}, temporary)
            temporary.flush()
            os.fsync(temporary.fileno())
        except Exception:
            candidate.unlink(missing_ok=True)
            raise
    try:
        os.replace(candidate, location)
    finally:
        candidate.unlink(missing_ok=True)
    return value


def report_uu_observation(path, refreshed=True):
    """Best-effort OIDC report; never print data, tokens, URLs or response bodies."""
    attempt, audience, claim = configuration()
    status, value = observed_uu(path, refreshed)
    payload = {"attemptId": attempt, "key": UU_KEY,
               "sequence": next_uu_sequence(attempt), "status": status}
    if status == "ready":
        payload["value"] = value
    wire = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    url = claim[:-len("/claim")] + "/session-data"
    # Retry the SAME observation (same sequence and bytes) after response loss.
    # A subsequent UI observation advances the sequence regardless of content.
    for retry in range(2):
        jwt = github_token(audience)
        request = urllib.request.Request(
            url, data=wire, method="POST",
            headers={"Authorization": "Bearer " + jwt, "Content-Type": "application/json"},
        )
        try:
            with OPENER.open(request, timeout=10) as response:
                result = json.load(response)
                if response.status != 200 or result not in (
                    {"result": "recorded"}, {"result": "already_recorded"}
                ):
                    raise SafeProtocolError("session_data_rejected")
                return
        except urllib.error.HTTPError as failure:
            code = failure.code
            failure.close()
            if code != 503:
                raise SafeProtocolError("session_data_http_" + str(code)) from None
            if retry == 1:
                # Distinguish Worker HTTP 503 from transport uncertainty.
                raise SafeProtocolError("session_data_http_503") from None
        except (OSError, http.client.IncompleteRead, json.JSONDecodeError):
            pass
    raise SafeProtocolError("session_data_unavailable")


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


def start():
    # Validate the first-step marker without overwriting it.
    recorded_start()


def hold():
    raw = os.getenv("DURATION_MINUTES", "")
    if not raw.isdecimal() or len(raw) > 3:
        raise ValueError("invalid session duration")
    minutes = int(raw)
    if not 1 <= minutes <= MAX_MINUTES:
        raise ValueError("invalid session duration")
    start_time = recorded_start()
    end = start_time + 60 * minutes
    print("Session bounded hold started; GitHub Job timeout remains authoritative")
    # The existing Windows Session hold process shares the interactive Runner desktop.
    # Refresh UIA credentials only when UU successfully started; never log the code.
    uu_script = pathlib.Path(".github/scripts/windows-uu.ps1")
    uu_path = pathlib.Path(os.getenv("LOCALAPPDATA") or ".") / "session-actions" / "uu-remote.json"
    # Missing/failed optional UU capture is reported as an explicit unavailable
    # tombstone; do not silently skip the signed producer.
    uu_enabled = os.name == "nt" and uu_script.is_file()
    next_refresh = time.monotonic() + 30 if uu_enabled else None
    def report_optional_uu(refreshed=True):
        try:
            report_uu_observation(uu_path, refreshed)
        except SafeProtocolError as failure:
            # Only allow fixed error codes into GitHub logs; never values,
            # request bodies, tokens, URLs or arbitrary exception messages.
            code = str(failure)
            if not re.fullmatch(r"(?:session_data_http_[0-9]{3}|session_data_rejected|session_data_unavailable|oidc_request_http_[0-9]{3})", code):
                code = "unavailable"
            print("SESSION_RUNTIME_DATA_REPORT_FAILED " + code, flush=True)
        except Exception:
            print("SESSION_RUNTIME_DATA_REPORT_FAILED unavailable", flush=True)
    if uu_enabled:
        report_optional_uu()
    while time.time() < end:
        if uu_enabled and time.monotonic() >= next_refresh:
            refreshed = False
            try:
                completed = subprocess.run(
                    ["pwsh", "-NoProfile", "-NonInteractive", "-File",
                     str(uu_script), "-Refresh"],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                    check=False, timeout=15,
                )
                refreshed = completed.returncode == 0
            except (OSError, subprocess.TimeoutExpired):
                pass
            # The Worker retains any last accepted observation for at most
            # 90 seconds; a failed upload cannot extend its TTL.
            report_optional_uu(refreshed)
            next_refresh = time.monotonic() + 30
        remaining = max(0, end - time.time())
        until_refresh = max(0, next_refresh - time.monotonic()) if uu_enabled else 10
        time.sleep(min(10, remaining, until_refresh))
    print("Session lifetime reached; shutting down")


def main():
    try:
        if len(sys.argv) != 2:
            raise ValueError("expected start, claim, ready, or hold")
        mode = sys.argv[1]
        if mode == "start":
            start()
        elif mode in ("claim", "ready"):
            assert_status(mode)
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
