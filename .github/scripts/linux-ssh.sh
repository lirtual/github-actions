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
# GitHub's fresh Ubuntu image may have ssh.socket without an sshd runtime dir.
sudo install -d -m 0755 /run/sshd
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
# Ubuntu 24.04 uses systemd socket activation; its stock ssh.socket binds
# wildcard addresses even if sshd_config specifies ListenAddress.
# A Runner-local override limits the actual systemd socket to Tailnet IPv4.
sudo install -d -m 0755 /run/systemd/system/ssh.socket.d
printf '[Socket]\nListenStream=\nListenStream=%s:22\n' "$tailnet_ip" |
  sudo tee /run/systemd/system/ssh.socket.d/00-session-actions.conf >/dev/null
sudo systemctl daemon-reload
sudo systemctl restart ssh.socket
sudo systemctl restart ssh.service
# Reject any wildcard, public-interface, or additional SSH listener.
ssh_listeners="$(sudo ss -H -ltn '( sport = :22 )' | awk '{print $4}')"
if [[ "$ssh_listeners" != "$tailnet_ip:22" ]]; then
  echo 'OpenSSH listener is not exclusively bound to the Tailnet address' >&2
  exit 1
fi
echo 'Tailnet-restricted Ubuntu password SSH is ready'
