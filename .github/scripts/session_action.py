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
            data=json.dumps({"attemptId": attempt}).encode("utf-8"),
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


def start():
    location = start_file()
    if location.exists():
        raise ValueError("session start already recorded")
    # First application step after a minimal pinned checkout. The GitHub job
    # timeout is still the hard limit including checkout and preparation.
    fd = os.open(str(location), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="ascii") as output:
        output.write(str(int(time.time())))


def hold():
    raw = os.getenv("DURATION_MINUTES", "")
    if not raw.isdecimal() or len(raw) > 3:
        raise ValueError("invalid session duration")
    minutes = int(raw)
    if not 1 <= minutes <= MAX_MINUTES:
        raise ValueError("invalid session duration")
    start_time = int(start_file().read_text(encoding="ascii").strip())
    now = int(time.time())
    if start_time < now - 8 * 3600 or start_time > now + 30:
        raise ValueError("session start timestamp invalid")
    end = start_time + 60 * minutes
    print("Session bounded hold started; GitHub Job timeout remains authoritative")
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
