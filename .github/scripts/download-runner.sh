#!/usr/bin/env bash
# Spec #51: source network isolation + separate authorized rclone upload.
# Called only AFTER verified GitHub OIDC Claim and bounded input validation.
# Production admission is controlled by the Owner-approved Workflow MCP plan.
set -euo pipefail
umask 077

deny() { echo "DOWNLOAD_UNAVAILABLE: runtime_preflight" >&2; exit 2; }
[[ ${RUNNER_TEMP:-} == /* && -d "$RUNNER_TEMP" ]] || deny
repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# Production obtains inputs from the GitHub-owned event file; the full URLs
# must not appear in Actions step environment banners.
if [[ -z ${BATCH_JSON:-} ]]; then
  BATCH_JSON="$(PYTHONPATH="$repo/.github/scripts" python3 -c 'from download_batch import load_batch_json; print(load_batch_json(), end="")')"
fi
export BATCH_JSON
[[ ${ATTEMPT_ID:-} =~ ^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-8][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$ ]] || deny
[[ -n ${BATCH_JSON:-} && -n ${DOWNLOAD_REMOTE_NAME:-} && -n ${DOWNLOAD_RCLONE_CONFIG_B64:-} ]] || deny
[[ -n ${DOWNLOAD_REMOTE_BASE_DIR:-} ]] || deny
[[ ${GITHUB_RUN_ID:-} =~ ^[1-9][0-9]{0,19}$ && ${GITHUB_RUN_ATTEMPT:-} =~ ^[1-9][0-9]{0,19}$ ]] || deny
# Validate the Owner-configured remote base before any download or secret use.
PYTHONPATH="$repo/.github/scripts" python3 - <<'PYBASE' || deny
import os
from download_destination import approved_base_dir
approved_base_dir(os.environ.get("DOWNLOAD_REMOTE_BASE_DIR"))
PYBASE
for binary in docker python3 base64 sha256sum sudo timeout; do command -v "$binary" >/dev/null || deny; done

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
# Establish ONE kernel monotonic deadline for setup, source download, cloud
# upload and readback. Reserve a bounded cleanup window without making valid
# 1- or 2-minute Tasks impossible.
DOWNLOAD_DEADLINE="$(python3 - <<'PYCODE'
import json, os, time
v=json.loads(os.environ['BATCH_JSON'])
minutes=v.get('duration_minutes',300)
if type(minutes) is not int or not 1 <= minutes <= 330: raise SystemExit(2)
reserve=min(120, max(5, minutes * 6))
print("%.6f" % (time.monotonic() + minutes * 60 - reserve))
PYCODE
)"
export DOWNLOAD_DEADLINE
# Bound blocking setup as well as transfer/readback by the same Task deadline.
# GNU timeout stops a stuck Docker CLI with time reserved for normal cleanup.
run_before_deadline() {
  local remaining
  remaining="$(python3 - <<'PYTIME'
import os
import time
seconds = float(os.environ["DOWNLOAD_DEADLINE"]) - time.monotonic()
if seconds <= 1:
    raise SystemExit(124)
print(f"{seconds:.3f}s")
PYTIME
  )" || return 124
  timeout --signal=TERM --kill-after=5s "$remaining" "$@"
}
# Fail before any download when the ephemeral workspace is already exhausted;
# subsequent I/O failures still fail closed without inventing a file-size cap.
python3 - <<'PYCODE' || deny
import os
v=os.statvfs(os.environ['RUNNER_TEMP'])
if v.f_bavail * v.f_frsize < 64*1024*1024 or v.f_favail < 1024:
    raise SystemExit(2)
PYCODE
printf '%s' "$DOWNLOAD_RCLONE_CONFIG_B64" | base64 --decode > "$config" || deny
chmod 600 "$config"
unset DOWNLOAD_RCLONE_CONFIG_B64

# Fixed base digest and locked Alpine package versions; verify actual
# aria2/rclone binary hashes before starting either payload container.
run_before_deadline docker build --quiet --tag "$image" - <<'DOCKER'
FROM python:3.12-alpine@sha256:b658b05ce9c4eb97ec6fc19424818a1f31993659c2b505a532f470e83807815d
RUN apk add --no-cache "aria2=1.37.0-r2" "rclone=1.74.1-r3"
DOCKER

# The x86_64 runner must use the exact binary builds verified by CI.
# An Alpine package change or other architecture is a fail-closed error.
run_before_deadline docker run --rm --network none --entrypoint sh "$image" -c \
  'printf "%s\n" \
    "0bbbf651a55faa76c027bdf6a0ae5dcea1b87ba17c077d0285a2199558dad0cb  /usr/bin/aria2c" \
    "63f6ccc732c9a8a86995a8293b1c4df1f6bd9abe5b40e1321f9e2920591572d5  /usr/bin/rclone" | sha256sum -c -s' || deny

run_before_deadline bash "$repo/.github/scripts/download-network.sh" setup
network_armed=1
suffix="$(printf '%s' "$ATTEMPT_ID" | cut -c1-8 | tr '[:upper:]' '[:lower:]')"
network="sa51-$suffix"

# No token, rclone config, host home, Docker socket, or GitHub metadata is
# available to untrusted HTTP(S) download content.
run_before_deadline docker run --rm --network "$network" --dns 1.1.1.1 \
  --sysctl net.ipv6.conf.all.disable_ipv6=1 \
  --cap-drop ALL --security-opt no-new-privileges:true \
  --pids-limit 128 --memory 512m --read-only --user "$(id -u):$(id -g)" \
  --tmpfs /tmp:rw,nosuid,nodev,size=32m \
  --env HOME=/tmp --env BATCH_JSON \
  --env DOWNLOAD_WORKSPACE=/work --env DOWNLOAD_DEADLINE \
  --volume "$task_dir/sources:/work:rw" \
  --volume "$repo/.github/scripts:/spec51:ro" \
  "$image" python /spec51/download_receive.py

# Full source closure is proven before upload; the producer exited and its
# root is mounted read-only. The uploader alone can read the OAuth config.
# It cannot access private/metadata addresses, the host or Docker socket.
run_before_deadline docker run --rm --network "$network" --dns 1.1.1.1 \
  --sysctl net.ipv6.conf.all.disable_ipv6=1 \
  --cap-drop ALL --security-opt no-new-privileges:true \
  --pids-limit 128 --memory 512m --read-only --user "$(id -u):$(id -g)" \
  --tmpfs /tmp:rw,nosuid,nodev,size=32m \
  --env HOME=/tmp --env BATCH_JSON \
  --env DOWNLOAD_REMOTE_NAME --env DOWNLOAD_REMOTE_BASE_DIR \
  --env DOWNLOAD_DEADLINE \
  --env DOWNLOAD_RCLONE_CONFIG=/spec51-secret/rclone.conf \
  --env DOWNLOAD_SOURCES_DIR=/work/sources \
  --volume "$task_dir/sources:/work/sources:ro" \
  --volume "$task_dir/downloads:/work/downloads:rw" \
  --volume "$config:/spec51-secret/rclone.conf:rw" \
  --volume "$repo/.github/scripts:/spec51:ro" \
  --workdir /work "$image" python /spec51/download_upload.py

echo 'DOWNLOAD_TASK_FULLY_VERIFIED'
