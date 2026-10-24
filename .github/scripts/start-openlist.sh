#!/usr/bin/env bash
set -euo pipefail

if [[ -z "${SESSION_SERVICE_PASSWORD:-}" ||
      "$SESSION_SERVICE_PASSWORD" == *$'\n'* ||
      "$SESSION_SERVICE_PASSWORD" == *$'\r'* ]]; then
  echo 'SESSION_SERVICE_PASSWORD must be a non-empty single-line password' >&2
  exit 1
fi
# No local SQLite fallback: OpenList requires an approved external MySQL URI.
umask 077
mkdir -p "$RUNNER_TEMP/openlist-data"
python3 .github/scripts/openlist-db-config.py "$RUNNER_TEMP/openlist-data/config.json"
# Read-only schema guard before OpenList CLI can create tables or reset admin.
# Reuse the MySQL client provided by the GitHub-hosted Ubuntu Runner.
python3 - "$RUNNER_TEMP/openlist-data/config.json" "$RUNNER_TEMP/openlist-data/database-ca.pem" <<'PY'
import json
import os
import re
import subprocess
import sys
from pathlib import Path

try:
    config = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))["database"]
    name = config["name"]
    if not re.fullmatch(r"[A-Za-z0-9_]{1,64}", name):
        raise ValueError("unsafe schema name")
    # Credentials stay in subprocess environment, never command-line arguments or logs.
    env = {
        "PATH": os.environ.get("PATH", ""),
        "HOME": os.environ["RUNNER_TEMP"],
        "MYSQL_PWD": config["password"],
    }
    client = [
        "mysql", "--no-defaults", "--protocol=TCP",
        "--host=" + config["host"], "--port=" + str(config["port"]),
        "--user=" + config["user"], "--connect-timeout=8",
        "--ssl-mode=VERIFY_IDENTITY", "--ssl-ca=" + sys.argv[2],
        "--database=information_schema", "--batch", "--skip-column-names",
    ]

    def read(query):
        result = subprocess.run(
            client + ["--execute=" + query], env=env, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, timeout=15,
            check=False,
        )
        if result.returncode != 0:
            raise ValueError("read-only schema inspection unavailable")
        return result.stdout.strip()

    if read("SELECT COUNT(*) FROM information_schema.schemata "
            "WHERE schema_name='" + name + "'") != "1":
        raise ValueError("target schema does not exist")
    # Treat all views as unexpected, even if they have OpenList-like names.
    rows = read("SELECT table_name, table_type FROM information_schema.tables "
                "WHERE table_schema='" + name + "' ORDER BY table_name LIMIT 257").splitlines()
    if len(rows) > 256:
        raise ValueError("too many database objects")
    tables = []
    for row in rows:
        parts = row.split("\t")
        if len(parts) != 2 or not parts[0].startswith("x_") or parts[1] != "BASE TABLE":
            raise ValueError("unexpected tables or views")
        tables.append(parts[0])
    # A lone x_users table is not proof that this is an OpenList database.
    # The pinned OpenList v4.2.6 migrates these three core models together.
    if tables and not {"x_users", "x_storages", "x_setting_items"}.issubset(tables):
        raise ValueError("incomplete or unrecognized existing OpenList schema")
except (OSError, ValueError, KeyError, IndexError, TypeError,
        subprocess.TimeoutExpired):
    print("OpenList MySQL read-only preflight failed; initialization refused", file=sys.stderr)
    sys.exit(1)
print("OpenList MySQL read-only preflight passed")
PY
unset OPENLIST_DATABASE_URI OPENLIST_DATABASE_CA
export OPENLIST_ADMIN_PASSWORD="$SESSION_SERVICE_PASSWORD"
unset SESSION_SERVICE_PASSWORD

# Pin the same OpenList runtime image for initialization and service.
image='openlistteam/openlist@sha256:c555c6e1c8af2aead38ed12ec761ac077fdf046d19cf033414be8e056aec6b64'
mount="type=bind,source=$RUNNER_TEMP/openlist-data,target=/opt/openlist/data"
# Ensure persistent MySQL can be reached and set the native admin password.
# Suppress all CLI diagnostic output: driver connection errors may embed credentials.
if ! docker run --rm --user "$(id -u):$(id -g)" \
    --mount "$mount" --env OPENLIST_ADMIN_PASSWORD \
    --env 'SSL_CERT_FILE=/opt/openlist/data/database-ca.pem' \
    --entrypoint /bin/sh "$image" -c \
    './openlist admin >/dev/null 2>&1 && ./openlist admin set "$OPENLIST_ADMIN_PASSWORD" >/dev/null 2>&1' \
    >/dev/null 2>&1; then
  echo 'OpenList external MySQL initialization failed' >&2
  exit 1
fi

docker run --detach --rm --name session-openlist \
  --user "$(id -u):$(id -g)" \
  --publish 127.0.0.1:5244:5244 \
  --mount "$mount" \
  --env OPENLIST_ADMIN_PASSWORD \
  --env 'SSL_CERT_FILE=/opt/openlist/data/database-ca.pem' \
  "$image" >/dev/null
ready=false
for _ in $(seq 1 45); do
  if curl --fail --silent --max-time 2 http://127.0.0.1:5244/ >/dev/null; then
    ready=true
    break
  fi
  sleep 2
done
test "$ready" = true
# Ready must mean the configured ephemeral admin can actually log in.
python3 - <<'PY'
import json
import os
import time
import urllib.error
import urllib.request

password = os.environ["OPENLIST_ADMIN_PASSWORD"]
url = "http://127.0.0.1:5244/api/auth/login"
payload = json.dumps({"username": "admin", "password": password}).encode()
for attempt in range(10):
    try:
        request = urllib.request.Request(
            url, data=payload, headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=4) as response:
            result = json.load(response)
        if result.get("code") == 200 and (result.get("data") or {}).get("token"):
            print("OpenList admin login validated")
            break
    except (OSError, ValueError, TypeError):
        pass
    if attempt != 9:
        time.sleep(2)
else:
    raise SystemExit("OpenList admin login verification failed")
PY
