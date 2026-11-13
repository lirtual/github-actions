#!/usr/bin/env bash
# Optional post-Claim CLI preparation for disposable, interactive Ubuntu Sessions.
set -euo pipefail
umask 077

state="$HOME/.config/session-actions"
profile="$HOME/.bashrc"
npm_prefix="$HOME/.local/session-actions/npm"
rca_env="$state/rca-env.bash"
rca_shell="$state/rca-shell"
begin='# session-actions login begin'
end='# session-actions login end'

case "${1:-}" in
  install)
    # All tools are optional: a package registry outage must not block the Session.
    if ! command -v cf >/dev/null 2>&1; then
      if command -v node >/dev/null 2>&1 && command -v npm >/dev/null 2>&1 &&
         node -e 'const a=process.versions.node.split(".").map(Number);process.exit((a[0]===22&&a[1]>=18)||(a[0]>=23)?0:1)'; then
        mkdir -p "$npm_prefix"
        if timeout 60s npm install --global --prefix "$npm_prefix" --ignore-scripts --no-audit --no-fund cf@1.0.0-beta.14 >/dev/null 2>&1 &&
           "$npm_prefix/bin/cf" --version >/dev/null 2>&1; then
          echo 'Pinned cf CLI installed'
        else
          echo 'Optional cf CLI installation unavailable'
        fi
      else
        echo 'Pinned cf CLI requires newer Node.js; optional installation skipped'
      fi
    fi
    if ! command -v uv >/dev/null 2>&1; then
      if command -v pipx >/dev/null 2>&1 &&
         timeout 60s env PIPX_HOME="$HOME/.local/session-actions/pipx" PIPX_BIN_DIR="$HOME/.local/bin" pipx install 'uv==0.13.7' >/dev/null 2>&1 &&
         "$HOME/.local/bin/uv" --version >/dev/null 2>&1; then
        echo 'Pinned uv installed'
      else
        echo 'Optional uv installation unavailable'
      fi
    fi
    if ! command -v rg >/dev/null 2>&1; then
      if command -v sudo >/dev/null 2>&1 &&
         timeout 35s sudo -n env DEBIAN_FRONTEND=noninteractive apt-get install -y -qq ripgrep >/dev/null 2>&1 &&
         command -v rg >/dev/null 2>&1; then
        echo 'ripgrep installed'
      else
        echo 'Optional ripgrep installation unavailable'
      fi
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
    # Only the reviewed Session RCA child receives BASH_ENV; ordinary Actions
    # steps never auto-import Session credentials.
    cat > "$rca_env" <<'PROFILE'
if [[ "${SESSION_ACTION_RCA:-}" == "1" && -f "$HOME/.config/session-actions/credentials.bash" ]]; then
  . "$HOME/.config/session-actions/credentials.bash"
fi
PROFILE
    chmod 600 "$rca_env"
    # RCA launches this private shell for its first command. The ordinary
    # Bash startup hook can be skipped by the managed command entrypoint.
    # Resolve credentials only inside this short-lived command process.
    cat > "$rca_shell" <<'SHELL'
#!/bin/bash
if [[ $# -ne 2 || "$1" != "-c" ]]; then exit 125; fi
if [[ "${GITHUB_ACTIONS:-}" == true &&
      "${GITHUB_REPOSITORY:-}" == "autoactions/github-actions" &&
      "${SESSION_ACTION_RCA:-}" == "1" &&
      -f "$HOME/.config/session-actions/rca-env.bash" ]]; then
  . "$HOME/.config/session-actions/rca-env.bash"
else
  unset GH_TOKEN CLOUDFLARE_API_TOKEN CLOUDFLARE_ACCOUNT_ID BASH_ENV SESSION_ACTION_RCA
fi
exec /bin/bash -c "$2"
SHELL
    chmod 700 "$rca_shell"
    touch "$profile"
    if ! grep -Fxq "$begin" "$profile"; then
      cat >> "$profile" <<'PROFILE'
# session-actions login begin
if [[ ( "${GITHUB_ACTIONS:-}" != true || "${SESSION_ACTION_RCA:-}" == "1" ) && -f "$HOME/.config/session-actions/credentials.bash" ]]; then
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
    rm -f "$state/credentials.bash" "$rca_env" "$rca_shell"
    rmdir "$state" 2>/dev/null || true
    echo 'Ubuntu Session CLI credential material removed'
    ;;
  *)
    echo 'Usage: session-cli-ubuntu.sh install|activate|cleanup' >&2
    exit 2
    ;;
esac
