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
for attempt in $(seq 1 90); do
  if docker exec sa-openlist-mysql-ci mysqladmin ping -h 127.0.0.1 \
      -u root --password=ci-temporary-root --silent >/dev/null 2>&1; then
    ready=yes
    break
  fi
  sleep 2
done
if [[ "$ready" != yes ]]; then
  echo 'Disposable MySQL did not become ready' >&2
  exit 1
fi

export OPENLIST_DATABASE_URI="mysql://openlist:$db_password@$gateway:3307/tenantdb?ssl-mode=REQUIRED"
export OPENLIST_DATABASE_CA
OPENLIST_DATABASE_CA="$(cat "$tmp/certs/ca.pem")"
bash .github/scripts/start-openlist.sh

tables="$(docker exec sa-openlist-mysql-ci mysql -N -s -h 127.0.0.1 \
  -u root --password=ci-temporary-root \
  -e "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='tenantdb' AND table_name LIKE 'x_%'")"
if [[ ! "$tables" =~ ^[0-9]+$ || "$tables" -lt 1 ]]; then
  echo 'OpenList did not initialize isolated MySQL tables' >&2
  exit 1
fi
docker rm -f session-openlist >/dev/null
rm -f "$RUNNER_TEMP/openlist-data/config.json" "$RUNNER_TEMP/openlist-data/database-ca.pem"
bash .github/scripts/start-openlist.sh
second="$(docker exec sa-openlist-mysql-ci mysql -N -s -h 127.0.0.1 \
  -u root --password=ci-temporary-root \
  -e "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='tenantdb' AND table_name LIKE 'x_%'")"
if [[ "$second" != "$tables" ]]; then
  echo 'External MySQL tables changed across Session restart' >&2
  exit 1
fi
echo 'Disposable TLS MySQL OpenList startup, admin login, and restart passed'
