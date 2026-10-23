#!/usr/bin/env bash
set -euo pipefail
VERSION=4.140.0
TARBALL="$RUNNER_TEMP/code-server.tar.gz"
curl --fail --location --retry 2 \
  "https://github.com/coder/code-server/releases/download/v$VERSION/code-server-$VERSION-linux-amd64.tar.gz" \
  --output "$TARBALL"
tar -xzf "$TARBALL" -C "$RUNNER_TEMP"
BIN="$RUNNER_TEMP/code-server-$VERSION-linux-amd64/bin/code-server"
"$BIN" --version >/dev/null
"$BIN" --auth none --bind-addr 127.0.0.1:8080 \
  >"$RUNNER_TEMP/code-server-session.log" 2>&1 &
echo "$!" > "$RUNNER_TEMP/session-service.pid"
ready=false
for _ in $(seq 1 45); do
  if curl --fail --silent --max-time 2 http://127.0.0.1:8080/ >/dev/null; then
    ready=true
    break
  fi
  sleep 2
done
test "$ready" = true
