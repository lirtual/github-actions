#!/usr/bin/env bash
set -euo pipefail
if [[ -z "${SESSION_SERVICE_PASSWORD:-}" || "$SESSION_SERVICE_PASSWORD" == *$'\n'* || "$SESSION_SERVICE_PASSWORD" == *$'\r'* ]]; then
  echo 'SESSION_SERVICE_PASSWORD must be a non-empty single-line password' >&2
  exit 1
fi

# Reuse the original tsvc web-accessible Chrome image, pinned by immutable digest.
credential="$RUNNER_TEMP/session-service-password"
umask 077
printf '%s' "$SESSION_SERVICE_PASSWORD" > "$credential"
unset SESSION_SERVICE_PASSWORD
mkdir -p "$RUNNER_TEMP/chrome-config"
docker run --detach --rm --name session-chrome \
  --publish 127.0.0.1:3000:3000 \
  --shm-size 1g \
  --env 'START_DOCKER=false' \
  --env 'CUSTOM_USER=admin' \
  --env 'FILE__PASSWORD=/run/secrets/session-service-password' \
  --mount "type=bind,source=$credential,target=/run/secrets/session-service-password,readonly" \
  --mount "type=bind,source=$RUNNER_TEMP/chrome-config,target=/config" \
  lscr.io/linuxserver/chrome@sha256:49a019a04b8d38422609d3c586636293417f61886704d516b7d5233cb4bd0b12 >/dev/null

# A public Cloudflare Tunnel must never front an unauthenticated Chrome GUI.
ready=false
for _ in $(seq 1 90); do
  status="$(curl --silent --output /dev/null --write-out '%{http_code}' --max-time 3 http://127.0.0.1:3000/ || true)"
  if [[ "$status" == 401 ]]; then
    ready=true
    break
  fi
  if [[ "$status" =~ ^2[0-9][0-9]$ ]]; then
    echo 'Chrome unexpectedly allows anonymous access' >&2
    exit 1
  fi
  sleep 2
done
test "$ready" = true
