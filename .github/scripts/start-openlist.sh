#!/usr/bin/env bash
set -euo pipefail

if [[ -z "${SESSION_SERVICE_PASSWORD:-}" ||
      "$SESSION_SERVICE_PASSWORD" == *$'\n'* ||
      "$SESSION_SERVICE_PASSWORD" == *$'\r'* ]]; then
  echo 'SESSION_SERVICE_PASSWORD must be a non-empty single-line password' >&2
  exit 1
fi
# No local SQLite fallback: OpenList requires an approved external MySQL URI.
umask 077
mkdir -p "$RUNNER_TEMP/openlist-data"
python3 .github/scripts/openlist-db-config.py "$RUNNER_TEMP/openlist-data/config.json"
unset OPENLIST_DATABASE_URI
export OPENLIST_ADMIN_PASSWORD="$SESSION_SERVICE_PASSWORD"
unset SESSION_SERVICE_PASSWORD

# Pin the same OpenList runtime image for initialization and service.
image='openlistteam/openlist@sha256:c555c6e1c8af2aead38ed12ec761ac077fdf046d19cf033414be8e056aec6b64'
mount="type=bind,source=$RUNNER_TEMP/openlist-data,target=/opt/openlist/data"
# Ensure persistent MySQL can be reached and set the native admin password.
# Suppress all CLI diagnostic output: driver connection errors may embed credentials.
if ! docker run --rm --user "$(id -u):$(id -g)" \
    --mount "$mount" --env OPENLIST_ADMIN_PASSWORD \
    --entrypoint /bin/sh "$image" -c \
    './openlist admin >/dev/null 2>&1 && ./openlist admin set "$OPENLIST_ADMIN_PASSWORD" >/dev/null 2>&1' \
    >/dev/null 2>&1; then
  echo 'OpenList external MySQL initialization failed' >&2
  exit 1
fi

docker run --detach --rm --name session-openlist \
  --user "$(id -u):$(id -g)" \
  --publish 127.0.0.1:5244:5244 \
  --mount "$mount" \
  --env OPENLIST_ADMIN_PASSWORD \
  "$image" >/dev/null
ready=false
for _ in $(seq 1 45); do
  if curl --fail --silent --max-time 2 http://127.0.0.1:5244/ >/dev/null; then
    ready=true
    break
  fi
  sleep 2
done
test "$ready" = true
# Ready must mean the configured ephemeral admin can actually log in.
python3 - <<'PY'
import json
import os
import time
import urllib.error
import urllib.request

password = os.environ["OPENLIST_ADMIN_PASSWORD"]
url = "http://127.0.0.1:5244/api/auth/login"
payload = json.dumps({"username": "admin", "password": password}).encode()
for attempt in range(10):
    try:
        request = urllib.request.Request(
            url, data=payload, headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=4) as response:
            result = json.load(response)
        if result.get("code") == 200 and (result.get("data") or {}).get("token"):
            print("OpenList admin login validated")
            break
    except (OSError, ValueError, TypeError):
        pass
    if attempt != 9:
        time.sleep(2)
else:
    raise SystemExit("OpenList admin login verification failed")
PY
