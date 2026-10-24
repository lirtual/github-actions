#!/usr/bin/env python3
"""Create a temporary OpenList MySQL config from a secret connection URI.

The URI is never passed on the command line or echoed. Only encrypted MySQL
connections are accepted; the Aiven CA is required for server identity verification.
"""
import json
import os
import re
import secrets
import ssl
import sys
from pathlib import Path
from urllib.parse import parse_qsl, unquote, urlsplit


def parse_mysql_uri(raw: str) -> dict:
    if not raw or len(raw) > 8192 or any(ord(c) < 32 or ord(c) == 127 for c in raw):
        raise ValueError("invalid secret")
    u = urlsplit(raw)
    if u.scheme != "mysql" or not u.hostname or u.fragment or u.username is None or u.password is None:
        raise ValueError("invalid MySQL URI")
    if not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?", u.hostname):
        raise ValueError("invalid MySQL host")
    try:
        port = u.port or 3306
        if not 1 <= port <= 65535:
            raise ValueError("invalid port")
        user = unquote(u.username, encoding="utf-8", errors="strict")
        password = unquote(u.password, encoding="utf-8", errors="strict")
        name = unquote(u.path[1:], encoding="utf-8", errors="strict") if u.path.startswith("/") else ""
        query = parse_qsl(u.query, keep_blank_values=True, strict_parsing=True)
    except (ValueError, UnicodeError) as exc:
        raise ValueError("invalid MySQL URI") from None
    # Only support simple account/database values that cannot inject raw Go DSN syntax.
    if (not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", user) or
        not re.fullmatch(r"[A-Za-z0-9_]{1,64}", name) or
        not password or len(password) > 4096 or
        any(ch in password for ch in ("@", "/", "?", "\n", "\r", "\x00"))):
        raise ValueError("invalid MySQL credentials or database name")
    if len(query) != 1 or query[0][0] != "ssl-mode":
        raise ValueError("ssl-mode is required")
    # The source URI's REQUIRED asks only for encryption. Upgrade it to
    # certificate+hostname verification because OPENLIST_DATABASE_CA is supplied.
    # OpenList passes ssl_mode to go-sql-driver/mysql's tls parameter.
    if query[0][1].upper() not in ("REQUIRED", "VERIFY_IDENTITY"):
        raise ValueError("unsupported ssl-mode")
    mode = "true"
    return {
        "type": "mysql", "host": u.hostname, "port": port, "user": user,
        "password": password, "name": name, "db_file": "",
        "table_prefix": "x_", "ssl_mode": mode, "dsn": ""
    }


def validate_ca(ca: str) -> str:
    if not ca or len(ca) > 65536:
        raise ValueError("invalid MySQL CA")
    # Support Aiven certificate-rotation bundles (multiple PEM certificates).
    blocks = re.findall(
        r"-----BEGIN CERTIFICATE-----[\\s\\S]*?-----END CERTIFICATE-----", ca
    )
    if not blocks or "".join(blocks) != "".join(ca.split()):
        # Whitespace between certificates is permitted, other PEM material is not.
        compact = re.sub(r"\\s+", "", ca)
        if not blocks or compact != re.sub(r"\\s+", "", "".join(blocks)):
            raise ValueError("invalid MySQL CA")
    try:
        ssl.create_default_context(cadata="\\n".join(blocks) + "\\n")
    except (ValueError, ssl.SSLError):
        raise ValueError("invalid MySQL CA") from None
    return "\\n".join(blocks) + "\\n"


def main() -> int:
    created = []
    try:
        if len(sys.argv) != 2:
            raise ValueError("invalid arguments")
        temp = Path(os.environ["RUNNER_TEMP"]).resolve(strict=True)
        output = Path(sys.argv[1])
        directory = temp / "openlist-data"
        if (output.name != "config.json" or output.parent.resolve() != directory or
                not directory.is_dir() or directory.is_symlink()):
            raise ValueError("invalid output")
        database = parse_mysql_uri(os.environ.get("OPENLIST_DATABASE_URI", ""))
        ca = validate_ca(os.environ.get("OPENLIST_DATABASE_CA", ""))
        config = {
            "force": True,
            "jwt_secret": secrets.token_hex(32),
            "database": database,
            "scheme": {"address": "0.0.0.0", "http_port": 5244,
                       "https_port": -1, "force_https": False},
            "temp_dir": "/opt/openlist/data/temp",
            "bleve_dir": "/tmp/openlist-bleve",
            "log": {"enable": False}
        }
        ca_path = directory / "database-ca.pem"
        for filename, data in (
            (ca_path, ca),
            (output, json.dumps(config, ensure_ascii=False, separators=(",", ":"))),
        ):
            fd = os.open(str(filename), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            created.append(filename)
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(data)
        return 0
    except (OSError, ValueError, KeyError, IndexError):
        for filename in created:
            try:
                filename.unlink()
            except OSError:
                pass
        print("OpenList database URI/CA configuration is invalid or unavailable", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
