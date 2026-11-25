#!/usr/bin/env bash
set -euo pipefail
# The loopback service has no separate login. External access is granted only
# through the email-OTP protected Quick Tunnel verified before signed Ready.
VERSION=4.140.0
TARBALL="$RUNNER_TEMP/code-server.tar.gz"
curl --fail --location --retry 2 \
  "https://github.com/coder/code-server/releases/download/v$VERSION/code-server-$VERSION-linux-amd64.tar.gz" \
  --output "$TARBALL"
# Official pinned v4.140.0 linux-amd64 archive, confirmed across independent Runner downloads.
printf '%s  %s\n' '864c5d01c808ade57e4d12c708717be7a187219fded60428f263b9e2da9f6b48' "$TARBALL" | sha256sum -c -
tar -xzf "$TARBALL" -C "$RUNNER_TEMP"
BIN="$RUNNER_TEMP/code-server-$VERSION-linux-amd64/bin/code-server"
"$BIN" --version >/dev/null
"$BIN" --auth none --bind-addr 127.0.0.1:8080 \
  >"$RUNNER_TEMP/code-server-session.log" 2>&1 &
echo "$!" > "$RUNNER_TEMP/session-service.pid"
ready=false
for _ in $(seq 1 45); do
  status="$(curl --silent --max-time 2 --output /dev/null --write-out '%{http_code}' http://127.0.0.1:8080/ || true)"
  if [[ "$status" == 200 ]]; then
    ready=true
    break
  fi
  sleep 2
done
test "$ready" = true
