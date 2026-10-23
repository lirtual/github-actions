#!/usr/bin/env bash
set -euo pipefail
CHROME="$(command -v google-chrome || command -v chromium || true)"
test -n "$CHROME"
mkdir -p "$RUNNER_TEMP/chrome-profile"
"$CHROME" --headless=new --disable-gpu \
  --remote-debugging-address=127.0.0.1 --remote-debugging-port=9222 \
  --user-data-dir="$RUNNER_TEMP/chrome-profile" about:blank \
  >"$RUNNER_TEMP/chrome-session.log" 2>&1 &
echo "$!" > "$RUNNER_TEMP/session-service.pid"
ready=false
for _ in $(seq 1 30); do
  if curl --fail --silent --max-time 2 http://127.0.0.1:9222/json/version >/dev/null; then
    ready=true
    break
  fi
  sleep 2
done
test "$ready" = true
