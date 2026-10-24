#!/usr/bin/env bash
set -euo pipefail
# The Chrome GUI is bound to loopback; the OTP-protected Quick Tunnel is
# its only externally accessible authentication boundary.
# Reuse the original tsvc web-accessible Chrome image, pinned by immutable digest.
mkdir -p "$RUNNER_TEMP/chrome-config"
image='lscr.io/linuxserver/chrome@sha256:49a019a04b8d38422609d3c586636293417f61886704d516b7d5233cb4bd0b12'
# The upstream registry may briefly rate-limit anonymous GitHub Runners.
for attempt in 1 2 3; do
  if docker pull "$image" > /dev/null 2>&1; then
    break
  fi
  if [[ "$attempt" == 3 ]]; then
    echo 'Pinned Chrome image could not be fetched' >&2
    exit 1
  fi
  sleep 5
done
docker run --detach --rm --name session-chrome \
  --publish 127.0.0.1:3000:3000 \
  --shm-size 1g \
  --env 'START_DOCKER=false' \
  --mount "type=bind,source=$RUNNER_TEMP/chrome-config,target=/config" \
  "$image" >/dev/null

# Confirm the local GUI is reachable. No remote access exists until the
# *separately verified* email-OTP Cloudflare Tunnel is started.
ready=false
for _ in $(seq 1 90); do
  status="$(curl --silent --output /dev/null --write-out '%{http_code}' --max-time 3 http://127.0.0.1:3000/ || true)"
  if [[ "$status" == 200 ]]; then
    ready=true
    break
  fi
  sleep 2
done
test "$ready" = true
