#!/usr/bin/env bash
set -euo pipefail

service="${SESSION_SERVICE:-}"
case "$service" in
  chrome) port=3000 ;;
  code-server) port=8080 ;;
  openlist) port=5244 ;;
  *) echo 'Unknown tunnel service' >&2; exit 1 ;;
esac

# A protected Quick Tunnel requires exactly one owner mailbox; never downgrade to public.
allowed_mail="${SESSION_TUNNEL_ALLOWED_EMAIL:-}"
if [[ ! "$allowed_mail" =~ ^[A-Za-z0-9._+%-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,63}$ ]]; then
  echo 'SESSION_TUNNEL_ALLOWED_EMAIL must be one explicit email address' >&2
  exit 1
fi
unset SESSION_TUNNEL_ALLOWED_EMAIL

# Official immutable cloudflared 2026.10.3 linux-amd64 with protected Quick Tunnel support.
binary="$RUNNER_TEMP/cloudflared"
curl --fail --location --proto '=https' --retry 3 --silent --show-error --tlsv1.2 \
  'https://github.com/cloudflare/cloudflared/releases/download/2026.10.3/cloudflared-linux-amd64' \
  --output "$binary"
printf '%s  %s\n' '053b80b0a23031a038fdbf3c073f59f82b8f1f152aa67971d7383ffafc0dbab0' "$binary" |
  sha256sum --check --status
chmod 0700 "$binary"
"$binary" --version | grep -Fq '2026.10.3'
"$binary" tunnel --help 2>&1 | grep -Fq -- '--allowed-mail'

log="$RUNNER_TEMP/session-tunnel.log"
"$binary" tunnel --no-autoupdate --url "http://127.0.0.1:$port" --allowed-mail "$allowed_mail" >"$log" 2>&1 &
pid=$!
printf '%s\n' "$pid" >"$RUNNER_TEMP/session-tunnel.pid"
url=''
for _ in $(seq 1 60); do
  kill -0 "$pid" 2>/dev/null || { echo 'Cloudflare Tunnel exited before Ready' >&2; exit 1; }
  candidate="$(grep -Eo 'https://[a-z0-9-]+\.trycloudflare\.com' "$log" | head -n 1 || true)"
  if [[ -n "$candidate" ]]; then
    # Creation succeeded only with --allowed-mail; the unauthenticated
    # HTTPS response is now Cloudflare's email-OTP gate, not the origin app.
    status="$(curl --silent --show-error --max-time 4 --output /dev/null --write-out '%{http_code}' "$candidate/" 2>/dev/null || true)"
    case "$status" in
      200|301|302|303|401|403)
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
printf '### %s Session\n\nTunnel: %s\n\nComplete the email one-time PIN gate, then use SESSION_SERVICE_PASSWORD to log in. The tunnel expires with the GitHub Job.\n' "$service" "$url" >> "$GITHUB_STEP_SUMMARY"
echo 'Cloudflare Tunnel is ready; locator recorded in the GitHub Job summary'
