#!/usr/bin/env bash
set -euo pipefail

service="${SESSION_SERVICE:-}"
case "$service" in
  chrome) port=3000 ;;
  code-server) port=8080 ;;
  openlist) port=5244 ;;
  *) echo 'Unknown tunnel service' >&2; exit 1 ;;
esac

# Only chrome and code-server require the email gate. OpenList handles its own
# login and guest permissions, so its temporary Tunnel must allow public routes.
allowed_mail=''
if [[ "$service" != openlist ]]; then
  allowed_mail="${SESSION_TUNNEL_ALLOWED_EMAIL:-}"
  if [[ ! "$allowed_mail" =~ ^[A-Za-z0-9._+%-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,63}$ ]]; then
    echo 'SESSION_TUNNEL_ALLOWED_EMAIL must be one explicit email address' >&2
    exit 1
  fi
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
if [[ "$service" != openlist ]]; then
  "$binary" tunnel --help 2>&1 | grep -Fq -- '--allowed-mail'
fi

log="$RUNNER_TEMP/session-tunnel.log"
if [[ "$service" == openlist ]]; then
  "$binary" tunnel --no-autoupdate --url "http://127.0.0.1:$port" >"$log" 2>&1 &
else
  "$binary" tunnel --no-autoupdate --url "http://127.0.0.1:$port" --allowed-mail "$allowed_mail" >"$log" 2>&1 &
fi
pid=$!
printf '%s\n' "$pid" >"$RUNNER_TEMP/session-tunnel.pid"
url=''
for _ in $(seq 1 60); do
  kill -0 "$pid" 2>/dev/null || { echo 'Cloudflare Tunnel exited before Ready' >&2; exit 1; }
  candidate="$(grep -Eo 'https://[a-z0-9-]+\.trycloudflare\.com' "$log" | head -n 1 || true)"
  if [[ -n "$candidate" ]]; then
    if [[ "$service" == openlist ]]; then
      # A public Tunnel is Ready only when the actual OpenList public API is
      # reachable anonymously. An OTP redirect or generic HTTP 200 cannot pass.
      if curl --fail --silent --show-error --max-time 4 "$candidate/api/public/settings" 2>/dev/null |
        python3 -c 'import json,sys; r=json.load(sys.stdin); sys.exit(0 if isinstance(r,dict) and r.get("code")==200 and isinstance(r.get("data"),dict) else 1)' 2>/dev/null; then
        url="$candidate"
        break
      fi
    else
      # Protected sessions must redirect anonymous GETs to the OTP broker.
      headers="$RUNNER_TEMP/session-tunnel-headers"
      status="$(curl --silent --show-error --max-time 4 --dump-header "$headers" --output /dev/null --write-out '%{http_code}' "$candidate/" 2>/dev/null || true)"
      location="$(awk 'tolower($1) == "location:" { gsub(/\r/, "", $2); print $2 }' "$headers" 2>/dev/null | tail -n 1 || true)"
      if [[ "$status" == 302 && "$location" == https://login.trycloudflare.com/authorize\?* ]]; then
        url="$candidate"
        break
      fi
    fi
  fi
  sleep 2
done
if [[ -z "$url" ]]; then
  echo 'Cloudflare Tunnel access check never became reachable' >&2
  exit 1
fi
printf '%s\n' "$url" >"$RUNNER_TEMP/session-tunnel-url"
if [[ "$service" == openlist ]]; then
  printf '### %s Session\n\nTunnel: %s\n\nOpenList handles user login and guest permissions; this public URL has no Cloudflare email gate. The tunnel expires with the GitHub Job.\n' "$service" "$url" >> "$GITHUB_STEP_SUMMARY"
else
  printf '### %s Session\n\nTunnel: %s\n\nThe email one-time PIN is the only access gate. The tunnel expires with the GitHub Job.\n' "$service" "$url" >> "$GITHUB_STEP_SUMMARY"
fi
echo 'Cloudflare Tunnel is ready; locator recorded in the GitHub Job summary'
