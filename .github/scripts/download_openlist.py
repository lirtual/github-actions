#!/usr/bin/env python3
"""Private loopback-only OpenList mount inventory for Spec #51.

Reads existing admin configuration, never changes persistent users/settings,
and never logs or persists an OpenList login token or mount secrets.
The caller must hold a verified, exclusive Go OpenList admission first.
"""
import json
import urllib.error
import urllib.request
from urllib.parse import urlencode

ORIGIN = "http://127.0.0.1:5244"
MAX_PAGE_BYTES = 1024 * 1024
PAGE_SIZE = 50
MAX_PAGES = 20


class MountReadUnavailable(Exception):
    """Only a constant safe error code is publicly exposed."""


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        return None


def _private_opener():
    # Never allow proxy variables to redirect credential-bearing loopback calls.
    return urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())


def _request_json(opener, path, *, login=None, token=None):
    if not isinstance(path, str) or not path.startswith("/") or "://" in path:
        raise MountReadUnavailable("MOUNT_CONFIG_UNAVAILABLE")
    headers = {"Accept": "application/json"}
    if login is not None:
        headers["Content-Type"] = "application/json"
    if token is not None:
        headers["Authorization"] = token
    data = None if login is None else json.dumps(
        {"username": "admin", "password": login}, separators=(",", ":")
    ).encode("utf-8")
    request = urllib.request.Request(ORIGIN + path, method="POST" if data else "GET",
                                     data=data, headers=headers)
    try:
        with opener.open(request, timeout=8) as response:
            if response.getcode() != 200:
                raise MountReadUnavailable("MOUNT_CONFIG_UNAVAILABLE")
            data = response.read(MAX_PAGE_BYTES + 1)
        if len(data) > MAX_PAGE_BYTES:
            raise MountReadUnavailable("MOUNT_CONFIG_UNAVAILABLE")
        document = json.loads(data)
        if (not isinstance(document, dict) or
                document.get("code") != 200 or "data" not in document):
            raise MountReadUnavailable("MOUNT_CONFIG_UNAVAILABLE")
        return document["data"]
    except (OSError, ValueError, TypeError):
        raise MountReadUnavailable("MOUNT_CONFIG_UNAVAILABLE") from None


def load_mounts(admin_password, opener=None):
    if not isinstance(admin_password, str) or not admin_password or len(admin_password) > 2048:
        raise MountReadUnavailable("MOUNT_CONFIG_UNAVAILABLE")
    if opener is None:
        opener = _private_opener()
    account = _request_json(opener, "/api/auth/login", login=admin_password)
    token = account.get("token") if isinstance(account, dict) else None
    if not isinstance(token, str) or not 8 <= len(token) <= 16384:
        raise MountReadUnavailable("MOUNT_CONFIG_UNAVAILABLE")
    rows = []
    for page in range(1, MAX_PAGES + 1):
        query = urlencode({"page": page, "per_page": PAGE_SIZE})
        section = _request_json(opener, "/api/admin/storage/list?" + query, token=token)
        if not isinstance(section, dict) or not isinstance(section.get("content"), list):
            raise MountReadUnavailable("MOUNT_CONFIG_UNAVAILABLE")
        total = section.get("total")
        if type(total) is not int or total < 0 or total > MAX_PAGE_BYTES:
            raise MountReadUnavailable("MOUNT_CONFIG_UNAVAILABLE")
        part = section["content"]
        if len(part) > PAGE_SIZE or not all(isinstance(item, dict) for item in part):
            raise MountReadUnavailable("MOUNT_CONFIG_UNAVAILABLE")
        rows.extend(part)
        if len(rows) == total:
            names = [row.get("mount_path") for row in rows]
            if not all(isinstance(n, str) for n in names) or len(names) != len(set(names)):
                raise MountReadUnavailable("MOUNT_CONFIG_UNAVAILABLE")
            return rows
        if not part or len(rows) > total:
            raise MountReadUnavailable("MOUNT_CONFIG_UNAVAILABLE")
    raise MountReadUnavailable("MOUNT_CONFIG_UNAVAILABLE")
