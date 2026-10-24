#!/usr/bin/env bash
# Use the existing Ubuntu GitHub Runner account with password SSH over Tailscale.
set -euo pipefail

if [[ -z "${SESSION_SYSTEM_PASSWORD:-}" ||
      "$SESSION_SYSTEM_PASSWORD" == *$'\n'* ||
      "$SESSION_SYSTEM_PASSWORD" == *$'\r'* ]]; then
  echo 'SESSION_SYSTEM_PASSWORD must be a non-empty single-line password' >&2
  exit 1
fi
account="$(id -un)"
if [[ "$(id -u)" -eq 0 || ! "$account" =~ ^[a-z_][a-z0-9_-]*$ ]]; then
  echo 'Expected an ordinary existing Ubuntu Runner account' >&2
  exit 1
fi

tailnet_ip="$(tailscale ip -4)"
if [[ ! "$tailnet_ip" =~ ^100\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\.([0-9]{1,3})\.([0-9]{1,3})$ ]]; then
  echo 'Expected one Tailnet IPv4 address' >&2
  exit 1
fi
if [[ ! -x /usr/sbin/sshd ]]; then
  echo 'OpenSSH server is unavailable on this Ubuntu Runner' >&2
  exit 1
fi

# Tailscale SSH intercepts port 22 and does not validate account passwords.
# Use ordinary OpenSSH on the Tailnet IP instead, with network ACLs still enforced.
sudo tailscale set --ssh=false
if ! sudo grep -Eq '^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config.d/\*\.conf' /etc/ssh/sshd_config; then
  echo 'OpenSSH config does not include its standard drop-in directory' >&2
  exit 1
fi
sudo tee /etc/ssh/sshd_config.d/00-session-actions.conf >/dev/null <<EOF
PasswordAuthentication yes
PubkeyAuthentication no
KbdInteractiveAuthentication no
AuthenticationMethods password
PermitRootLogin no
AllowUsers $account
ListenAddress $tailnet_ip
EOF
sudo /usr/sbin/sshd -t
effective="$(sudo /usr/sbin/sshd -T)"
for setting in \
  'passwordauthentication yes' \
  'pubkeyauthentication no' \
  'kbdinteractiveauthentication no' \
  'authenticationmethods password' \
  "allowusers $account" \
  "listenaddress $tailnet_ip:22"; do
  if ! grep -Fxq "$setting" <<< "$effective"; then
    echo 'OpenSSH effective configuration differs from the restricted policy' >&2
    exit 1
  fi
done

# chpasswd applies the image's actual local password policy. Never log the secret.
printf '%s:%s\n' "$account" "$SESSION_SYSTEM_PASSWORD" | sudo chpasswd
unset SESSION_SYSTEM_PASSWORD
sudo systemctl restart ssh
if ! sudo ss -ltn '( sport = :22 )' | grep -Fq "$tailnet_ip:22"; then
  echo 'OpenSSH is not listening on the Tailnet address' >&2
  exit 1
fi
echo 'Tailnet-restricted Ubuntu password SSH is ready'
