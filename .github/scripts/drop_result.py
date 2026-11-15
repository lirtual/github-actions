#!/usr/bin/env python3
"""Send only a Runner-sealed Drop claim to the signed Task result callback.

The Cloudflare claim URL is never present in this process's argv, env,
stdout, logs, or HTTP response. Unknown POST outcomes are not blindly retried.
"""
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request

from session_action import OPENER, SafeProtocolError, configuration, github_token

PREVIEW = re.compile(r"https://(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+workers\.dev/?\Z")
SEALED = re.compile(r"[A-Za-z0-9_-]{250,3600}\Z")


def deliver_sealed_result():
    raw = sys.stdin.buffer.read(4097)
    if len(raw) > 4096:
        raise SafeProtocolError("drop_result_too_large")
    result = json.loads(raw)
    if type(result) is not dict or set(result) != {
        "drop_claim_v", "preview_url", "expires_at", "sealed_claim"
    } or result["drop_claim_v"] != 1:
        raise SafeProtocolError("drop_result_invalid")
    preview, expiry, sealed = result["preview_url"], result["expires_at"], result["sealed_claim"]
    now = int(time.time() * 1000)
    if (not isinstance(preview, str) or len(preview) > 240 or
            not PREVIEW.fullmatch(preview) or type(expiry) is not int or
            expiry <= now or expiry > now + 3600000 or
            not isinstance(sealed, str) or not SEALED.fullmatch(sealed)):
        raise SafeProtocolError("drop_result_invalid")
    attempt, audience, claim = configuration()
    token = github_token(audience)
    target = claim[:-len("/claim")] + "/result"
    request = urllib.request.Request(
        target, method="POST",
        data=json.dumps({"attemptId": attempt, "result": result}, separators=(",", ":")).encode("utf-8"),
        headers={"Authorization": "Bearer " + token, "Content-Type": "application/json"},
    )
    try:
        with OPENER.open(request, timeout=20) as response:
            code = response.status
            body = response.read(257)
        if code != 200 or len(body) > 256 or json.loads(body) not in (
            {"result": "recorded"}, {"result": "already_recorded"}
        ):
            raise SafeProtocolError("drop_result_unacknowledged")
    except urllib.error.HTTPError as failure:
        status = failure.code
        failure.close()
        raise SafeProtocolError("drop_result_http_" + str(status)) from None
    except Exception:
        # A lost reply after POST is Unknown; do not resubmit another claim.
        raise SafeProtocolError("drop_result_unknown") from None
    print("Drop sealed result acknowledged")


if __name__ == "__main__":
    try:
        deliver_sealed_result()
    except Exception:
        print("Drop sealed result delivery failed", file=sys.stderr)
        raise SystemExit(1)
