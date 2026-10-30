#!/usr/bin/env bash
# Strict disposable GitHub-hosted Ubuntu downloader network boundary.
# The firewall MUST be armed before launching any downloader.
set -euo pipefail

if [[ ! "$ATTEMPT_ID" =~ ^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-8][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$ ]]; then
  echo 'DOWNLOAD_NETWORK_DENIED invalid_attempt' >&2
  exit 1
fi
suffix="$(printf '%s' "$ATTEMPT_ID" | cut -c1-8 | tr '[:upper:]' '[:lower:]')"
network="sa51-$suffix"
bridge="sa51$suffix"
forward="SA51F$suffix"
input="SA51I$suffix"
mode="$1"

cleanup() {
  sudo -n iptables -D DOCKER-USER -i "$bridge" -j "$forward" 2>/dev/null || true
  sudo -n iptables -D INPUT -i "$bridge" -j "$input" 2>/dev/null || true
  sudo -n iptables -F "$forward" 2>/dev/null || true
  sudo -n iptables -X "$forward" 2>/dev/null || true
  sudo -n iptables -F "$input" 2>/dev/null || true
  sudo -n iptables -X "$input" 2>/dev/null || true
  docker network rm "$network" >/dev/null 2>&1 || true
  # A cleanup operation must not return success with a still-live firewall
  # hook, dedicated chain or network. This is also the hosted CI clean gate.
  if sudo -n iptables -C DOCKER-USER -i "$bridge" -j "$forward" 2>/dev/null ||
     sudo -n iptables -C INPUT -i "$bridge" -j "$input" 2>/dev/null ||
     sudo -n iptables -S "$forward" >/dev/null 2>&1 ||
     sudo -n iptables -S "$input" >/dev/null 2>&1 ||
     docker network inspect "$network" >/dev/null 2>&1; then
    echo 'DOWNLOAD_NETWORK_CLEANUP_FAILED' >&2
    return 1
  fi
}

case "$mode" in
  cleanup)
    cleanup
    exit 0
    ;;
  setup) ;;
  *)
    echo 'DOWNLOAD_NETWORK_DENIED invalid_operation' >&2
    exit 1
    ;;
esac

# No Docker daemon nftables/backend fallback, and no default bridge fallback.
# If these rules cannot be installed, the whole Task must remain unavailable.
command -v docker >/dev/null
command -v sudo >/dev/null
sudo -n iptables -S DOCKER-USER >/dev/null
sudo -n iptables -S INPUT >/dev/null
if docker network inspect "$network" >/dev/null 2>&1; then
  echo 'DOWNLOAD_NETWORK_DENIED stale_network' >&2
  exit 1
fi
if sudo -n iptables -S "$forward" >/dev/null 2>&1 ||
   sudo -n iptables -S "$input" >/dev/null 2>&1; then
  echo 'DOWNLOAD_NETWORK_DENIED stale_rules' >&2
  exit 1
fi

armed=false
on_failure() {
  if [[ "$armed" == true ]]; then cleanup; fi
}
trap on_failure EXIT
armed=true
docker network create --driver bridge --ipv6=false \
  --opt "com.docker.network.bridge.name=$bridge" \
  --opt "com.docker.network.bridge.enable_icc=false" \
  "$network" >/dev/null

if [[ "$(docker network inspect -f '{{.EnableIPv6}}' "$network")" != false ||
      "$(docker network inspect -f '{{index .Options "com.docker.network.bridge.name"}}' "$network")" != "$bridge" ]]; then
  echo 'DOWNLOAD_NETWORK_DENIED network_mismatch' >&2
  exit 1
fi
# Construct complete chains before inserting their jump hooks.
sudo -n iptables -N "$forward"
sudo -n iptables -A "$forward" -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN
for cidr in \
  0.0.0.0/8 10.0.0.0/8 100.64.0.0/10 127.0.0.0/8 \
  169.254.0.0/16 172.16.0.0/12 192.0.0.0/24 192.0.2.0/24 \
  192.168.0.0/16 198.18.0.0/15 198.51.100.0/24 \
  203.0.113.0/24 224.0.0.0/4 240.0.0.0/4; do
  sudo -n iptables -A "$forward" -d "$cidr" -j REJECT
done
# Both containers require DNS and public HTTP(S) only. Deny arbitrary UDP,
# non-web TCP ports, and other protocols even when the destination is public.
# This is a protocol boundary, NOT a provider-host allowlist for rclone.
# Both payload containers use the same explicitly configured resolver.
# Denying alternative public DNS ports prevents accidental resolver drift; it
# does not prevent DoH over HTTPS and is not an FQDN egress allowlist.
sudo -n iptables -A "$forward" -d 1.1.1.1/32 -p udp --dport 53 -j RETURN
sudo -n iptables -A "$forward" -d 1.1.1.1/32 -p tcp --dport 53 -j RETURN
sudo -n iptables -A "$forward" -p tcp -m multiport --dports 80,443 -j RETURN
sudo -n iptables -A "$forward" -j REJECT
sudo -n iptables -N "$input"
sudo -n iptables -A "$input" -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN
sudo -n iptables -A "$input" -j REJECT

sudo -n iptables -I DOCKER-USER 1 -i "$bridge" -j "$forward"
sudo -n iptables -I INPUT 1 -i "$bridge" -j "$input"
sudo -n iptables -C DOCKER-USER -i "$bridge" -j "$forward"
sudo -n iptables -C INPUT -i "$bridge" -j "$input"
armed=false
trap - EXIT
echo "DOWNLOAD_NETWORK_ARMED=$network"
