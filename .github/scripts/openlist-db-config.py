#!/usr/bin/env python3
"""Create a temporary OpenList MySQL config from a secret connection URI.

The URI is never passed on the command line or echoed. Only encrypted MySQL
connections are accepted; REQUIRED maps to go-sql-driver/mysql tls=skip-verify.
"""
import json
import os
import re
import secrets
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
    # OpenList v4 internally interpolates ssl_mode as Go MySQL driver tls=<value>.
    # REQUIRED means TLS without certificate verification; VERIFY_IDENTITY
    # verifies the server's certificate and hostname with system trust.
    mode = {"REQUIRED": "skip-verify", "VERIFY_IDENTITY": "true"}.get(query[0][1].upper())
    if not mode:
        raise ValueError("unsupported ssl-mode")
    return {
        "type": "mysql", "host": u.hostname, "port": port, "user": user,
        "password": password, "name": name, "db_file": "",
        "table_prefix": "x_", "ssl_mode": mode, "dsn": ""
    }


def main() -> int:
    try:
        temp = Path(os.environ["RUNNER_TEMP"]).resolve(strict=True)
        output = Path(sys.argv[1])
        if len(sys.argv) != 2 or output.name != "config.json" or output.parent.resolve() != temp / "openlist-data":
            raise ValueError("invalid output")
        database = parse_mysql_uri(os.environ.get("OPENLIST_DATABASE_URI", ""))
        config = {
            "force": True,
            "jwt_secret": secrets.token_hex(32),
            "database": database,
            "scheme": {"address": "0.0.0.0", "http_port": 5244, "https_port": -1, "force_https": False},
            "temp_dir": "/opt/openlist/data/temp",
            "bleve_dir": "/tmp/openlist-bleve",
            "log": {"enable": False}
        }
        fd = os.open(str(output), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(config, handle, ensure_ascii=False, separators=(",", ":"))
        return 0
    except (OSError, ValueError, KeyError, IndexError):
        print("OpenList database URI/configuration is invalid or unavailable", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
