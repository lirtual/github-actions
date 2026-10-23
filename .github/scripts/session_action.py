#!/usr/bin/env python3
"""Session Actions GitHub Runner protocol; Python standard library only.

Never print GitHub identity tokens or response bodies. The Workflow MCP
verifies signed OIDC identity and the immutable GitHub physical Run before
accepting claim or ready.
"""
import json
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
        raise ValueError("Session Action identity or endpoint not configured")
    return attempt, audience, claim


def github_token(audience):
    url = os.getenv("ACTIONS_ID_TOKEN_REQUEST_URL", "")
    secret = os.getenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "")
    target = urllib.parse.urlsplit(url)
    if target.scheme != "https" or not target.hostname or not secret:
        raise ValueError("GitHub OIDC credentials unavailable")
    separator = "&" if "?" in url else "?"
    request = urllib.request.Request(
        url + separator + urllib.parse.urlencode({"audience": audience}),
        headers={"Authorization": "Bearer " + secret},
    )
    with urllib.request.urlopen(request, timeout=15) as response:
        data = json.load(response)
    jwt = data.get("value")
    if not isinstance(jwt, str) or not jwt:
        raise ValueError("GitHub identity token unavailable")
    return jwt


def assert_status(stage):
    attempt, audience, claim = configuration()
    url = claim if stage == "claim" else claim[:-len("/claim")] + "/ready"
    expected = "claimed" if stage == "claim" else "ready"
    if stage not in ("claim", "ready"):
        raise ValueError("invalid protocol operation")
    # The GitHub physical Run may not yet be visible in the REST API when
    # signed Ready first arrives. Retry only HTTP 503 (temporarily
    # unconfirmed/unavailable), with a finite budget and a freshly issued
    # GitHub OIDC JWT each time. HTTP 403 is a definitive denial.
    attempts = 12 if stage == "ready" else 1
    for retry in range(attempts):
        jwt = github_token(audience)
        request = urllib.request.Request(
            url, method="POST",
            data=json.dumps({"attemptId": attempt}).encode("utf-8"),
            headers={"Authorization": "Bearer " + jwt, "Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(request, timeout=20) as response:
                result = json.load(response)
                # HTTP response may be lost after D1 already committed Ready.
                # An immutable GitHub OIDC identity and physical owner are still
                # reverified by the Worker before it returns already_ready.
                allowed = {expected, "already_ready"} if stage == "ready" else {expected}
                if response.status != 200 or result not in tuple({"result": value} for value in allowed):
                    raise ValueError("signed " + stage + " not accepted")
            print("Signed GitHub Session " + stage + " acknowledged")
            return
        except urllib.error.HTTPError as failure:
            failure.close()
            if failure.code != 503 or retry == attempts - 1:
                raise ValueError("signed " + stage + " denied") from None
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
    except Exception:
        # Never log a token, secret, physical URL response, or traceback.
        print("Session Action protocol step failed: " +
              (sys.argv[1] if len(sys.argv) > 1 else "invalid"), file=sys.stderr)
        raise SystemExit(1)


if __name__ == "__main__":
    main()
