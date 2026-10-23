#!/usr/bin/env bash
set -euo pipefail
test -n "$OPENLIST_ADMIN_PASSWORD"
mkdir -p "$RUNNER_TEMP/openlist-data"
docker run --detach --rm --name session-openlist \
  --user "$(id -u):$(id -g)" \
  --publish 127.0.0.1:5244:5244 \
  --volume "$RUNNER_TEMP/openlist-data:/opt/openlist/data" \
  --env OPENLIST_ADMIN_PASSWORD \
  openlistteam/openlist:v4.2.6 >/dev/null
ready=false
for _ in $(seq 1 45); do
  if curl --fail --silent --max-time 2 http://127.0.0.1:5244/ >/dev/null; then
    ready=true
    break
  fi
  sleep 2
done
test "$ready" = true
