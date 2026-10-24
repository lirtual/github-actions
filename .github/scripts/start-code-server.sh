#!/usr/bin/env bash
set -euo pipefail
if [[ -z "${SESSION_SERVICE_PASSWORD:-}" ||
      "$SESSION_SERVICE_PASSWORD" == *$'\n'* ||
      "$SESSION_SERVICE_PASSWORD" == *$'\r'* ]]; then
  echo 'SESSION_SERVICE_PASSWORD must be a non-empty single-line password' >&2
  exit 1
fi
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
PASSWORD="$SESSION_SERVICE_PASSWORD" "$BIN" --auth password --bind-addr 127.0.0.1:8080 \
  >"$RUNNER_TEMP/code-server-session.log" 2>&1 &
echo "$!" > "$RUNNER_TEMP/session-service.pid"
ready=false
for _ in $(seq 1 45); do
  status="$(curl --silent --max-time 2 --output /dev/null --write-out '%{http_code}' http://127.0.0.1:8080/ || true)"
  if [[ "$status" == 302 || "$status" == 303 ]]; then
    ready=true
    break
  fi
  if [[ "$status" == 200 ]]; then
    echo 'code-server must require a login' >&2
    exit 1
  fi
  sleep 2
done
test "$ready" = true
