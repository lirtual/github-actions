#!/usr/bin/env bash
set -euo pipefail

service="${SESSION_SERVICE:-}"
case "$service" in
  chrome) port=3000 ;;
  code-server) port=8080 ;;
  openlist) port=5244 ;;
  *) echo 'Unknown tunnel service' >&2; exit 1 ;;
esac

# Pinned official cloudflared 2026.8.2 linux-amd64 from the reviewed tsvc implementation.
binary="$RUNNER_TEMP/cloudflared"
curl --fail --location --proto '=https' --retry 3 --silent --show-error --tlsv1.2 \
  'https://github.com/cloudflare/cloudflared/releases/download/2026.8.2/cloudflared-linux-amd64' \
  --output "$binary"
printf '%s  %s\n' 'fcfb02b575a52ca1af2e3267af4e1517bcdeb30ac48c834c69abaed3c0576ad2' "$binary" |
  sha256sum --check --status
chmod 0700 "$binary"
"$binary" --version | grep -Fq '2026.8.2'

log="$RUNNER_TEMP/session-tunnel.log"
"$binary" tunnel --no-autoupdate --url "http://127.0.0.1:$port" >"$log" 2>&1 &
pid=$!
printf '%s\n' "$pid" >"$RUNNER_TEMP/session-tunnel.pid"
url=''
for _ in $(seq 1 60); do
  kill -0 "$pid" 2>/dev/null || { echo 'Cloudflare Tunnel exited before Ready' >&2; exit 1; }
  candidate="$(grep -Eo 'https://[a-z0-9-]+\.trycloudflare\.com' "$log" | head -n 1 || true)"
  if [[ -n "$candidate" ]]; then
    # Reject transient Cloudflare 502/530 and errors before announcing Ready.
    status="$(curl --silent --show-error --max-time 4 --output /dev/null --write-out '%{http_code}' "$candidate/" 2>/dev/null || true)"
    case "$status" in
      200|301|302|303|307|308|401|403)
        url="$candidate"
        break ;;
    esac
  fi
  sleep 2
done
if [[ -z "$url" ]]; then
  echo 'Cloudflare Tunnel never became reachable' >&2
  exit 1
fi
printf '%s\n' "$url" >"$RUNNER_TEMP/session-tunnel-url"
printf '### %s Session\n\nTunnel: %s\n\nUse SESSION_SERVICE_PASSWORD to log in. The tunnel expires with the GitHub Job.\n' "$service" "$url" >> "$GITHUB_STEP_SUMMARY"
echo 'Cloudflare Tunnel is ready; locator recorded in the GitHub Job summary'
