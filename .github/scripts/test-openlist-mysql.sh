#!/usr/bin/env bash
# CI-only: disposable MySQL with verified TLS, no repository secrets.
set -euo pipefail
tmp="$RUNNER_TEMP/openlist-mysql-ci"
mkdir -m 700 -p "$tmp/certs" "$RUNNER_TEMP/openlist-data"
export SESSION_SERVICE_PASSWORD='ci-openlist-isolated-password'
db_password='ci-openlist-isolated-db'
gateway="$(docker network inspect bridge --format '{{(index .IPAM.Config 0).Gateway}}')"
if [[ ! "$gateway" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo 'Docker bridge gateway unavailable' >&2
  exit 1
fi
cleanup() {
  docker rm -f session-openlist sa-openlist-mysql-ci >/dev/null 2>&1 || true
  rm -rf "$RUNNER_TEMP/openlist-data" "$tmp"
  unset OPENLIST_DATABASE_URI OPENLIST_DATABASE_CA OPENLIST_ADMIN_PASSWORD SESSION_SERVICE_PASSWORD
}
trap cleanup EXIT

openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
  -keyout "$tmp/certs/ca-key.pem" -out "$tmp/certs/ca.pem" \
  -subj '/CN=Session Actions Disposable CI Root' >/dev/null 2>&1
openssl req -new -newkey rsa:2048 -nodes \
  -keyout "$tmp/certs/server-key.pem" -out "$tmp/certs/server-csr.pem" \
  -subj '/CN=Session Actions Disposable CI MySQL' >/dev/null 2>&1
printf 'subjectAltName=IP:%s\nextendedKeyUsage=serverAuth\n' "$gateway" > "$tmp/certs/san.ext"
openssl x509 -req -in "$tmp/certs/server-csr.pem" -days 1 \
  -CA "$tmp/certs/ca.pem" -CAkey "$tmp/certs/ca-key.pem" -CAcreateserial \
  -extfile "$tmp/certs/san.ext" -out "$tmp/certs/server.pem" >/dev/null 2>&1
# Disposable test-only credentials, readable by the container's MySQL UID.
# The host directory is bound at /ci/certs; MySQL runs as UID 999 and
# needs directory execute permission to read the public CA and server files.
chmod 755 "$tmp/certs"
chmod 644 "$tmp/certs/ca.pem" "$tmp/certs/server.pem" "$tmp/certs/server-key.pem"

docker run -d --rm --name sa-openlist-mysql-ci \
  --publish "$gateway:3307:3306" \
  --mount "type=bind,source=$tmp/certs,target=/ci/certs,readonly" \
  --env MYSQL_ROOT_PASSWORD=ci-temporary-root \
  --env MYSQL_DATABASE=tenantdb \
  --env MYSQL_USER=openlist \
  --env "MYSQL_PASSWORD=$db_password" \
  mysql:8.4 \
  --ssl-ca=/ci/certs/ca.pem \
  --ssl-cert=/ci/certs/server.pem \
  --ssl-key=/ci/certs/server-key.pem \
  --require-secure-transport=ON >/dev/null
ready=''
for attempt in $(seq 1 30); do
  # MySQL's entrypoint runs a temporary Unix-socket bootstrap server
  # before the final TLS-enabled TCP server; never accept that early socket.
  if docker exec sa-openlist-mysql-ci mysqladmin ping --protocol=tcp \
      -h 127.0.0.1 --ssl-mode=REQUIRED \
      -u root --password=ci-temporary-root --silent >/dev/null 2>&1; then
    ready=yes
    break
  fi
  sleep 2
done
if [[ "$ready" != yes ]]; then
  echo 'Disposable MySQL did not become ready' >&2
  # CI fixture only: contains no production Secrets or remote connection data.
  docker logs --tail 35 sa-openlist-mysql-ci 2>&1 | grep -E 'ERROR|error|Warning|ready|InnoDB|SSL|TLS|Entrypoint' | tail -n 18 || true
  exit 1
fi

export OPENLIST_DATABASE_URI="mysql://openlist:$db_password@$gateway:3307/tenantdb?ssl-mode=REQUIRED"
export OPENLIST_DATABASE_CA
OPENLIST_DATABASE_CA="$(cat "$tmp/certs/ca.pem")"
# Reject an occupied non-OpenList schema before OpenList can create x_ tables.
docker exec sa-openlist-mysql-ci mysql --protocol=socket \
  -u root --password=ci-temporary-root \
  -e 'CREATE TABLE tenantdb.unrelated_ci_guard (id INT PRIMARY KEY)' >/dev/null 2>&1
if bash .github/scripts/start-openlist.sh >"$tmp/guard-stdout" 2>"$tmp/guard-stderr"; then
  echo 'OpenList allowed unrelated existing database tables' >&2
  exit 1
fi
if ! grep -Fq 'OpenList MySQL read-only preflight failed' "$tmp/guard-stderr"; then
  echo 'OpenList failed for a reason other than the schema guard' >&2
  exit 1
fi
unexpected="$(docker exec sa-openlist-mysql-ci mysql -N -s --protocol=socket \
  -u root --password=ci-temporary-root \
  -e "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='tenantdb' AND table_name LIKE 'x_%'")"
if [[ "$unexpected" != 0 ]]; then
  echo 'OpenList created tables despite rejected preflight' >&2
  exit 1
fi
docker exec sa-openlist-mysql-ci mysql --protocol=socket \
  -u root --password=ci-temporary-root \
  -e 'DROP TABLE tenantdb.unrelated_ci_guard' >/dev/null 2>&1
rm -f "$RUNNER_TEMP/openlist-data/config.json" "$RUNNER_TEMP/openlist-data/database-ca.pem"
echo 'Read-only schema collision guard rejected unrelated tables'
# A view named like an OpenList table must never pass the ownership guard.
docker exec sa-openlist-mysql-ci mysql --protocol=socket \
  -u root --password=ci-temporary-root \
  -e 'CREATE VIEW tenantdb.x_users AS SELECT 1 AS id' >/dev/null 2>&1
if bash .github/scripts/start-openlist.sh >"$tmp/view-stdout" 2>"$tmp/view-stderr"; then
  echo 'OpenList allowed a misleading x_users view' >&2
  exit 1
fi
if ! grep -Fq 'OpenList MySQL read-only preflight failed' "$tmp/view-stderr"; then
  echo 'OpenList did not reject the unexpected view during preflight' >&2
  exit 1
fi
docker exec sa-openlist-mysql-ci mysql --protocol=socket \
  -u root --password=ci-temporary-root \
  -e 'DROP VIEW tenantdb.x_users' >/dev/null 2>&1
rm -f "$RUNNER_TEMP/openlist-data/config.json" "$RUNNER_TEMP/openlist-data/database-ca.pem"
echo 'Read-only schema collision guard rejected disguised view'
if ! bash .github/scripts/start-openlist.sh; then
  # This diagnostic uses the CI-only dummy database/password and is never
  # enabled in the production Session workflow.
  echo 'CI-only OpenList bootstrap diagnostics:' >&2
  image='openlistteam/openlist@sha256:c555c6e1c8af2aead38ed12ec761ac077fdf046d19cf033414be8e056aec6b64'
  docker run --rm --user "$(id -u):$(id -g)" \
    --mount "type=bind,source=$RUNNER_TEMP/openlist-data,target=/opt/openlist/data" \
    --env "OPENLIST_ADMIN_PASSWORD=$SESSION_SERVICE_PASSWORD" \
    --env 'SSL_CERT_FILE=/opt/openlist/data/database-ca.pem' \
    --entrypoint /bin/sh "$image" -c './openlist admin' 2>&1 | tail -n 18 || true
  echo 'CI-only MySQL server diagnostics:' >&2
  docker logs --tail 18 sa-openlist-mysql-ci 2>&1 | tail -n 18 || true
  exit 1
fi

tables="$(docker exec sa-openlist-mysql-ci mysql -N -s --protocol=socket \
  -u root --password=ci-temporary-root \
  -e "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='tenantdb' AND table_name LIKE 'x_%'")"
if [[ ! "$tables" =~ ^[0-9]+$ || "$tables" -lt 1 ]]; then
  echo 'OpenList did not initialize isolated MySQL tables' >&2
  exit 1
fi
docker rm -f session-openlist >/dev/null
# Verify that the real OpenList MySQL driver rejects untrusted CA certificates
# and certificates for a different host, without exposing production Secrets.
image='openlistteam/openlist@sha256:c555c6e1c8af2aead38ed12ec761ac077fdf046d19cf033414be8e056aec6b64'
verify_rejected() {
  local label="$1" data_dir="$2" alternate_host="${3:-}"
  local extra=()
  if [[ -n "$alternate_host" ]]; then
    extra=(--add-host "$alternate_host:$gateway")
  fi
  if docker run --rm --user "$(id -u):$(id -g)" \
    --mount "type=bind,source=$data_dir,target=/opt/openlist/data" \
    "${extra[@]}" \
    --env 'SSL_CERT_FILE=/opt/openlist/data/database-ca.pem' \
    --entrypoint /bin/sh "$image" -c './openlist admin >/dev/null 2>&1' \
    >/dev/null 2>&1; then
    echo "OpenList accepted invalid TLS $label" >&2
    exit 1
  fi
}
mkdir -m 700 "$tmp/wrong-ca" "$tmp/wrong-host"
cp -a "$RUNNER_TEMP/openlist-data/." "$tmp/wrong-ca/"
cp -a "$RUNNER_TEMP/openlist-data/." "$tmp/wrong-host/"
openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
  -keyout "$tmp/untrusted-key.pem" -out "$tmp/wrong-ca/database-ca.pem" \
  -subj '/CN=Session Actions Untrusted CI Root' >/dev/null 2>&1
verify_rejected 'CA' "$tmp/wrong-ca"
python3 - "$tmp/wrong-host/config.json" <<'PY'
import json
import sys
from pathlib import Path
path = Path(sys.argv[1])
config = json.loads(path.read_text())
config["database"]["host"] = "wrong-host.invalid"
path.write_text(json.dumps(config))
PY
verify_rejected 'hostname' "$tmp/wrong-host" 'wrong-host.invalid'
echo 'Invalid CA and hostname rejected by the real OpenList runtime'
rm -f "$RUNNER_TEMP/openlist-data/config.json" "$RUNNER_TEMP/openlist-data/database-ca.pem"
bash .github/scripts/start-openlist.sh
second="$(docker exec sa-openlist-mysql-ci mysql -N -s --protocol=socket \
  -u root --password=ci-temporary-root \
  -e "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='tenantdb' AND table_name LIKE 'x_%'")"
if [[ "$second" != "$tables" ]]; then
  echo 'External MySQL tables changed across Session restart' >&2
  exit 1
fi
echo 'Disposable TLS MySQL OpenList startup, admin login, and restart passed'
