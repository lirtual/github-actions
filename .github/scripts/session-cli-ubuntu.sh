#!/usr/bin/env bash
# Optional post-Claim CLI preparation for disposable, interactive Ubuntu Sessions.
set -euo pipefail
umask 077

state="$HOME/.config/session-actions"
profile="$HOME/.bashrc"
npm_prefix="$HOME/.local/session-actions/npm"
begin='# session-actions login begin'
end='# session-actions login end'

case "${1:-}" in
  install)
    if command -v cf >/dev/null 2>&1; then
      echo 'cf command already exists; installation skipped to avoid a collision'
      exit 0
    fi
    if ! command -v node >/dev/null 2>&1 || ! command -v npm >/dev/null 2>&1 ||
       ! node -e 'const a=process.versions.node.split(".").map(Number);process.exit((a[0]===22&&a[1]>=18)||(a[0]>=23)?0:1)'; then
      echo 'Pinned cf CLI requires newer Node.js; optional installation skipped'
      exit 0
    fi
    mkdir -p "$npm_prefix"
    if timeout 75s npm install --global --prefix "$npm_prefix" --ignore-scripts --no-audit --no-fund cf@1.0.0-beta.14 >/dev/null 2>&1 &&
       "$npm_prefix/bin/cf" --version >/dev/null 2>&1; then
      echo 'Pinned cf CLI installed'
    else
      echo 'Optional cf CLI installation unavailable'
    fi
    ;;
  activate)
    # A missing identity must not fall back to the ephemeral Runner hostname.
    git config --global user.useConfigOnly true
    if [[ -n "${GIT_USER_NAME:-}" ]]; then
      git config --global user.name "$GIT_USER_NAME"
    else
      git config --global --unset-all user.name >/dev/null 2>&1 || true
    fi
    if [[ -n "${GIT_USER_EMAIL:-}" ]]; then
      git config --global user.email "$GIT_USER_EMAIL"
    else
      git config --global --unset-all user.email >/dev/null 2>&1 || true
    fi

    # Git stores only gh's helper command; never a PAT or credential-store entry.
    if [[ -n "${GH_TOKEN:-}" ]] && command -v gh >/dev/null 2>&1; then
      if ! gh auth setup-git --hostname github.com --force >/dev/null 2>&1; then
        echo 'Optional GitHub Git helper configuration unavailable'
      fi
    fi

    mkdir -p "$state"
    chmod 700 "$state"
    rm -f "$state/credentials.bash"
    if [[ -n "${GH_TOKEN:-}" || -n "${CLOUDFLARE_API_TOKEN:-}" ]]; then
      {
        if [[ -n "${GH_TOKEN:-}" ]]; then printf 'export GH_TOKEN=%q\n' "$GH_TOKEN"; fi
        if [[ -n "${CLOUDFLARE_API_TOKEN:-}" ]]; then
          printf 'export CLOUDFLARE_API_TOKEN=%q\n' "$CLOUDFLARE_API_TOKEN"
          if [[ -n "${CLOUDFLARE_ACCOUNT_ID:-}" ]]; then
            printf 'export CLOUDFLARE_ACCOUNT_ID=%q\n' "$CLOUDFLARE_ACCOUNT_ID"
          fi
        fi
      } > "$state/credentials.bash"
      chmod 600 "$state/credentials.bash"
    fi
    touch "$profile"
    if ! grep -Fxq "$begin" "$profile"; then
      cat >> "$profile" <<'PROFILE'
# session-actions login begin
if [[ "${GITHUB_ACTIONS:-}" != true && -f "$HOME/.config/session-actions/credentials.bash" ]]; then
  . "$HOME/.config/session-actions/credentials.bash"
fi
if [[ -x "$HOME/.local/session-actions/npm/bin/cf" ]]; then
  export PATH="$HOME/.local/session-actions/npm/bin:$PATH"
fi
# session-actions login end
PROFILE
    fi
    echo 'Optional Ubuntu Session CLI activation complete'
    ;;
  cleanup)
    if [[ -f "$profile" ]]; then
      sed -i '/^# session-actions login begin$/,/^# session-actions login end$/d' "$profile"
    fi
    rm -f "$state/credentials.bash"
    rmdir "$state" 2>/dev/null || true
    echo 'Ubuntu Session CLI credential material removed'
    ;;
  *)
    echo 'Usage: session-cli-ubuntu.sh install|activate|cleanup' >&2
    exit 2
    ;;
esac
