#!/usr/bin/env bash
# Spec #51: source network isolation + separate authorized rclone upload.
# Called only AFTER verified GitHub OIDC Claim and bounded input validation.
# This is a candidate runtime; download.yml remains fail-closed until released.
set -euo pipefail
umask 077

deny() { echo "DOWNLOAD_UNAVAILABLE: runtime_preflight" >&2; exit 2; }
[[ ${RUNNER_TEMP:-} == /* && -d "$RUNNER_TEMP" ]] || deny
[[ ${ATTEMPT_ID:-} =~ ^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-8][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$ ]] || deny
[[ ${DOWNLOAD_TASK_ROOT:-} =~ ^downloads/run-[1-9][0-9]{0,19}-[1-9][0-9]{0,19}-[a-f0-9]{32}$ ]] || deny
[[ -n ${BATCH_JSON:-} && -n ${DOWNLOAD_REMOTE_NAME:-} && -n ${DOWNLOAD_RCLONE_CONFIG_B64:-} ]] || deny
[[ ${GITHUB_RUN_ID:-} =~ ^[1-9][0-9]{0,19}$ && ${GITHUB_RUN_ATTEMPT:-} =~ ^[1-9][0-9]{0,19}$ ]] || deny
[[ "$DOWNLOAD_TASK_ROOT" == downloads/run-"$GITHUB_RUN_ID"-"$GITHUB_RUN_ATTEMPT"-* ]] || deny
for binary in docker python3 base64 sha256sum sudo; do command -v "$binary" >/dev/null || deny; done

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
python3 "$repo/.github/scripts/download_batch.py" >/dev/null || deny
# No user-provided relative/absolute paths are interpolated into shell commands.
task_dir="$(mktemp -d "$RUNNER_TEMP/spec51-task.XXXXXXXX")"
chmod 700 "$task_dir"
mkdir -m 700 "$task_dir/sources" "$task_dir/downloads"
config="$task_dir/rclone.conf"
image="sa51-runtime-${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}"
network_armed=0
cleanup() {
  local status=$?
  trap - EXIT INT TERM
  if ((network_armed)); then
    ATTEMPT_ID="$ATTEMPT_ID" bash "$repo/.github/scripts/download-network.sh" cleanup || status=1
  fi
  docker image rm --force "$image" >/dev/null 2>&1 || true
  rm -rf -- "$task_dir" || status=1
  if ((status)); then echo 'DOWNLOAD_FAILED_OR_UNKNOWN' >&2; fi
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# Register cleanup BEFORE decoding secret material or starting side effects.
# Task-wide time budget is constrained by validated input and physical job cap.
DOWNLOAD_SECONDS="$(python3 - <<'PYCODE'
import json,os
v=json.loads(os.environ['BATCH_JSON']); minutes=v.get('duration_minutes',300)
if type(minutes) is not int or not 1 <= minutes <= 330: raise SystemExit(2)
print(max(1,minutes*60 - 120))
PYCODE
)"
export DOWNLOAD_SECONDS
printf '%s' "$DOWNLOAD_RCLONE_CONFIG_B64" | base64 --decode > "$config" || deny
chmod 600 "$config"
unset DOWNLOAD_RCLONE_CONFIG_B64

# Fixed, digest-pinned Python base; both payload tools use the same throwaway
# image. Alpine packages are currently unpinned: production release still
# requires version/digest closure; do not mistake passing CI for such evidence.
docker build --quiet --tag "$image" - <<'DOCKER'
FROM python:3.12-alpine@sha256:b658b05ce9c4eb97ec6fc19424818a1f31993659c2b505a532f470e83807815d
RUN apk add --no-cache "aria2=1.37.0-r2" "rclone=1.74.1-r3"
DOCKER

# The x86_64 runner must use the exact binary builds verified by CI.
# An Alpine package change or other architecture is a fail-closed error.
docker run --rm --network none --entrypoint sh "$image" -c \
  'printf "%s\n" \
    "0bbbf651a55faa76c027bdf6a0ae5dcea1b87ba17c077d0285a2199558dad0cb  /usr/bin/aria2c" \
    "63f6ccc732c9a8a86995a8293b1c4df1f6bd9abe5b40e1321f9e2920591572d5  /usr/bin/rclone" | sha256sum -c -s' || deny

bash "$repo/.github/scripts/download-network.sh" setup
network_armed=1
suffix="$(printf '%s' "$ATTEMPT_ID" | cut -c1-8 | tr '[:upper:]' '[:lower:]')"
network="sa51-$suffix"

# No token, rclone config, host home, Docker socket, or GitHub metadata is
# available to untrusted HTTP(S) download content.
docker run --rm --network "$network" --dns 1.1.1.1 \
  --sysctl net.ipv6.conf.all.disable_ipv6=1 \
  --cap-drop ALL --security-opt no-new-privileges:true \
  --pids-limit 128 --memory 512m --read-only --user "$(id -u):$(id -g)" \
  --tmpfs /tmp:rw,nosuid,nodev,size=32m \
  --env HOME=/tmp --env BATCH_JSON \
  --env DOWNLOAD_WORKSPACE=/work --env DOWNLOAD_SECONDS \
  --volume "$task_dir/sources:/work:rw" \
  --volume "$repo/.github/scripts:/spec51:ro" \
  "$image" python /spec51/download_receive.py

# Full source closure is proven before upload; the producer exited and its
# root is mounted read-only. The uploader alone can read the OAuth config.
# It cannot access private/metadata addresses, the host or Docker socket.
docker run --rm --network "$network" --dns 1.1.1.1 \
  --sysctl net.ipv6.conf.all.disable_ipv6=1 \
  --cap-drop ALL --security-opt no-new-privileges:true \
  --pids-limit 128 --memory 512m --read-only --user "$(id -u):$(id -g)" \
  --tmpfs /tmp:rw,nosuid,nodev,size=32m \
  --env HOME=/tmp --env BATCH_JSON \
  --env DOWNLOAD_REMOTE_NAME --env DOWNLOAD_TASK_ROOT --env DOWNLOAD_SECONDS \
  --env DOWNLOAD_RCLONE_CONFIG=/spec51-secret/rclone.conf \
  --env DOWNLOAD_SOURCES_DIR=/work/sources \
  --volume "$task_dir/sources:/work/sources:ro" \
  --volume "$task_dir/downloads:/work/downloads:rw" \
  --volume "$config:/spec51-secret/rclone.conf:rw" \
  --volume "$repo/.github/scripts:/spec51:ro" \
  --workdir /work "$image" python /spec51/download_upload.py

echo 'DOWNLOAD_TASK_FULLY_VERIFIED'
