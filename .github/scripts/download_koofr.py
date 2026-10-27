#!/usr/bin/env python3
"""Unwired Spec #51 Koofr no-clobber adapter for verified OpenList WebDav mounts.

Official Koofr Go SDK's FilesPutWithOptions uses autorename=false when
NoRename is true and only adds overwrite=true for ForceOverwrite=true.
This adapter deliberately omits overwrite=true, overwriteIgnoreNonexisting,
and never uses OpenList op.Put/WebDAV PUT. NO real server proof yet.
"""
import base64
import hashlib
import http.client
import json
import os
from pathlib import Path
import posixpath
import re
import secrets
import ssl
import stat
import time
import unicodedata
from urllib.parse import quote, urlencode, urlsplit

from download_batch import InvalidBatch, _destination

ORIGIN = "app.koofr.net"
MAX_JSON = 1024 * 1024
MAX_CHUNK = 1024 * 1024
MOUNT_ID = re.compile(r"^[a-zA-Z0-9-]{1,100}$")
ALLOWED_PATH = re.compile(r"^[^\\\x00-\x1f\x7f]+$")


class KoofrUnsupported(Exception):
    pass


class KoofrConflict(Exception):
    pass


class KoofrUnknown(Exception):
    pass


def _safe_parts(path, allow_root=False):
    if path == "/" and allow_root:
        return []
    try:
        _destination(path)
    except (InvalidBatch, TypeError, ValueError):
        raise KoofrUnsupported("NOT_SUPPORTED") from None
    # Koofr documents a 1023-character complete path ceiling and rejects
    # filename codepoints above U+FFFF. Check the documented character limit;
    # do not impose an invented byte limit on valid multibyte filenames.
    if len(path) > 1023:
        raise KoofrUnsupported("NOT_SUPPORTED")
    parts = path.split("/")[1:]
    if any(not ALLOWED_PATH.fullmatch(p) or
           p.strip() != p or p.endswith(".") or
           unicodedata.normalize("NFC", p) != p or
           any(ord(char) > 0xFFFF for char in p) or
           len(p.encode("utf-8")) > 255 or "%" in p
           for p in parts):
        raise KoofrUnsupported("NOT_SUPPORTED")
    return parts


def _addition(mount):
    raw = mount.get("addition")
    try:
        result = json.loads(raw) if isinstance(raw, str) else raw
    except (ValueError, TypeError):
        raise KoofrUnsupported("NOT_SUPPORTED") from None
    if not isinstance(result, dict):
        raise KoofrUnsupported("NOT_SUPPORTED")
    return result


def resolve_mount(storages, destination):
    """Returns credentials privately, never user-visible. Exact longest mount wins."""
    _safe_parts(destination)
    if not isinstance(storages, list) or not storages:
        raise KoofrUnsupported("NOT_SUPPORTED")
    selected = None
    seen_mounts = set()
    destination_key = destination.casefold()
    for mount in storages:
        if not isinstance(mount, dict) or not isinstance(mount.get("mount_path"), str):
            raise KoofrUnsupported("NOT_SUPPORTED")
        mount_path = mount["mount_path"]
        _safe_parts(mount_path, allow_root=True)
        mount_key = mount_path.casefold()
        if mount_key in seen_mounts:
            raise KoofrUnsupported("NOT_SUPPORTED")
        seen_mounts.add(mount_key)
        if (mount_path == "/" or destination_key == mount_key or
                destination_key.startswith(mount_key + "/")):
            # Native Koofr paths may be case-insensitive. An OpenList submount
            # that differs only in case must never fall through to /Koofr.
            if (mount_path != "/" and destination != mount_path and
                    not destination.startswith(mount_path + "/")):
                raise KoofrUnsupported("NOT_SUPPORTED")
            if selected is None or len(mount_path) > len(selected["mount_path"]):
                selected = mount
    if (selected is None or selected.get("mount_path") != "/Koofr" or
            selected.get("driver") != "WebDav" or selected.get("disabled") is not False or
            selected.get("status") != "work"):
        raise KoofrUnsupported("NOT_SUPPORTED")
    remark = selected.get("remark", "")
    if not isinstance(remark, str) or remark.lstrip().lower().startswith("ref:"):
        raise KoofrUnsupported("NOT_SUPPORTED")
    addition = _addition(selected)
    if (addition.get("vendor", "other") != "other" or
            addition.get("tls_insecure_skip_verify") is not False):
        raise KoofrUnsupported("NOT_SUPPORTED")
    address = addition.get("address")
    if not isinstance(address, str) or len(address) > 2048:
        raise KoofrUnsupported("NOT_SUPPORTED")
    try:
        parsed = urlsplit(address)
        port = parsed.port
    except ValueError:
        raise KoofrUnsupported("NOT_SUPPORTED") from None
    if (parsed.scheme != "https" or parsed.hostname != ORIGIN or
            port not in (None, 443) or parsed.username or parsed.password or
            parsed.query or parsed.fragment or "%" in parsed.path):
        raise KoofrUnsupported("NOT_SUPPORTED")
    # Koofr explicitly documents both these WebDAV configurations.
    if parsed.path.rstrip("/") == "/dav/Koofr":
        prefix = []
    elif parsed.path.rstrip("/") == "/dav":
        prefix = ["Koofr"]
    elif parsed.path.startswith("/dav/Koofr/"):
        prefix = parsed.path[len("/dav/Koofr/"):].strip("/").split("/")
    else:
        raise KoofrUnsupported("NOT_SUPPORTED")
    # OpenList WebDav accepts an empty RootPath as the backend root. Treat
    # that documented default exactly like "/", never as an arbitrary path.
    raw_root = addition.get("root_folder_path", "/")
    if raw_root == "":
        raw_root = "/"
    try:
        root_parts = _safe_parts(raw_root, allow_root=True)
    except (TypeError, ValueError):
        raise KoofrUnsupported("NOT_SUPPORTED") from None
    if prefix == ["Koofr"]:
        if not root_parts or root_parts[0] != "Koofr":
            raise KoofrUnsupported("NOT_SUPPORTED")
        root_parts = root_parts[1:]
        prefix = []
    base = prefix + root_parts
    for p in base:
        _safe_parts("/" + p)
    suffix = destination[len("/Koofr"):].lstrip("/")
    dest_parts = _safe_parts("/" + suffix) if suffix else []
    native_parent = "/" + "/".join(base + dest_parts)
    # OpenList's virtual path can be short while its WebDAV root expands to
    # an overlong native Koofr path. Deny the whole stage before any upload.
    _safe_parts(native_parent, allow_root=True)
    user = addition.get("username")
    password = addition.get("password")
    if (not isinstance(user, str) or not user or len(user) > 320 or
            any(ord(x) < 33 or ord(x) == 127 for x in user) or ":" in user or
            not isinstance(password, str) or not password or len(password) > 2048 or
            any(x in password for x in "\r\n")):
        raise KoofrUnsupported("NOT_SUPPORTED")
    return {"parent": native_parent, "username": user,
            "password": password}


def _validated_target(parent, filename):
    """Reject unsafe complete targets before any authenticated Koofr request."""
    _safe_parts(parent, allow_root=True)
    if not isinstance(filename, str) or len(_safe_parts("/" + filename)) != 1:
        raise KoofrUnsupported("NOT_SUPPORTED")
    target = posixpath.join(parent, filename)
    _safe_parts(target)
    return target


def upload_query(parent, filename, mount_id):
    """Construct precisely the official SDK's non-renaming, non-overwrite request."""
    if not isinstance(mount_id, str) or not MOUNT_ID.fullmatch(mount_id):
        raise KoofrUnsupported("NOT_SUPPORTED")
    _validated_target(parent, filename)
    query = urlencode({"path": parent, "filename": filename,
                       "info": "true", "autorename": "false"})
    return "/content/api/v2/mounts/" + quote(mount_id, safe="") + "/files/put?" + query


class KoofrClient:
    """Fixed-origin TLS only; no redirects, proxy, retries or arbitrary endpoints."""

    def __init__(self, username, password, deadline, connection_factory=None):
        if not isinstance(username, str) or not isinstance(password, str):
            raise KoofrUnsupported("NOT_SUPPORTED")
        if not username or not password or "\r" in username + password or "\n" in username + password:
            raise KoofrUnsupported("NOT_SUPPORTED")
        self._basic = "Basic " + base64.b64encode((username + ":" + password).encode()).decode()
        self._deadline = deadline
        self._factory = connection_factory or (
            lambda timeout: http.client.HTTPSConnection(
                ORIGIN, port=443, context=ssl.create_default_context(), timeout=timeout))

    def _connect(self):
        remaining = self._deadline - time.monotonic()
        if remaining <= 1:
            raise KoofrUnknown("REMOTE_UNKNOWN")
        # Each blocking socket operation has a bounded idle timeout even when
        # the approved Task itself has hours remaining. Avoid waiting hours on
        # a stalled send/read, especially after cancellation.
        return self._factory(min(remaining, 30))

    def _request_json(self, path):
        if not path.startswith("/api/v2/mounts"):
            raise KoofrUnsupported("NOT_SUPPORTED")
        conn = self._connect()
        try:
            conn.request("GET", path, headers={"Authorization":self._basic,
                                             "Accept":"application/json"})
            resp = conn.getresponse()
            data = resp.read(MAX_JSON + 1)
            if resp.status != 200 or len(data) > MAX_JSON:
                raise KoofrUnknown("REMOTE_UNKNOWN")
            result = json.loads(data)
            if not isinstance(result, dict):
                raise KoofrUnknown("REMOTE_UNKNOWN")
            return result
        except (OSError, ValueError, TypeError, http.client.HTTPException):
            raise KoofrUnknown("REMOTE_UNKNOWN") from None
        finally:
            conn.close()

    def primary_mount(self):
        payload = self._request_json("/api/v2/mounts")
        mounts = payload.get("mounts")
        if not isinstance(mounts, list) or not 1 <= len(mounts) <= 100:
            raise KoofrUnknown("REMOTE_UNKNOWN")
        primary = [m for m in mounts if isinstance(m, dict) and m.get("isPrimary") is True]
        if len(primary) != 1 or not isinstance(primary[0].get("id"), str) or                 not MOUNT_ID.fullmatch(primary[0]["id"]):
            raise KoofrUnknown("REMOTE_UNKNOWN")
        perms = primary[0].get("permissions")
        if not isinstance(perms, dict) or perms.get("write") is not True:
            raise KoofrUnsupported("NOT_SUPPORTED")
        return primary[0]["id"]

    def assert_directory(self, parent):
        """Read-only native Koofr parent-directory check; no mkdir or overwrite."""
        _safe_parts(parent, allow_root=True)
        mount_id = self.primary_mount()
        path = ("/api/v2/mounts/" + quote(mount_id, safe="") + "/files/info?" +
                urlencode({"path": parent}))
        info = self._request_json(path)
        if info.get("type") != "dir":
            raise KoofrUnsupported("NOT_SUPPORTED")
        return True

    def assert_absent(self, parent, filename):
        """Read-only existence check: 404 only means absent; 200 is conflict.

        This protects existing files in sequential flows, but a GET followed
        by POST is NOT atomic and never satisfies the Koofr Q15 race gate.
        """
        target = _validated_target(parent, filename)
        mount_id = self.primary_mount()
        path = ("/api/v2/mounts/" + quote(mount_id, safe="") + "/files/info?" +
                urlencode({"path": target}))
        conn = self._connect()
        try:
            conn.request("GET", path, headers={"Authorization": self._basic,
                                               "Accept": "application/json"})
            resp = conn.getresponse()
            # Always consume bounded data and close, even for 404.
            if len(resp.read(MAX_JSON + 1)) > MAX_JSON:
                raise KoofrUnknown("REMOTE_UNKNOWN")
            if resp.status == 404:
                return True
            if resp.status == 200:
                raise KoofrConflict("DESTINATION_CONFLICT")
            raise KoofrUnknown("REMOTE_UNKNOWN")
        except (OSError, ValueError, TypeError, http.client.HTTPException):
            raise KoofrUnknown("REMOTE_UNKNOWN") from None
        finally:
            conn.close()

    @staticmethod
    def _matching_md5(metadata, expected):
        if not isinstance(metadata, dict):
            return False
        actual = metadata.get("hash")
        return (isinstance(actual, str) and len(actual) == 32 and
                re.fullmatch(r"[0-9a-fA-F]{32}", actual) is not None and
                actual.lower() == expected)

    def upload_file(self, file, destination_parent, *, expected, cancelled=lambda: False):
        """Require prior digest proof; abandon in-flight writes if cancelled.

        A cancellation AFTER uploading any bytes has an indeterminate remote
        effect, never a provably safe cancellation or a reason to retry.
        """
        src = Path(file)
        try:
            st = src.lstat()
        except OSError:
            raise KoofrUnsupported("NOT_SUPPORTED") from None
        if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
            raise KoofrUnsupported("NOT_SUPPORTED")
        name = src.name
        if (not isinstance(expected, dict) or expected.get("name") != name or
                type(expected.get("size")) is not int or
                expected["size"] != st.st_size or
                not isinstance(expected.get("md5"), str) or
                not re.fullmatch(r"[a-f0-9]{32}", expected["md5"]) or
                not isinstance(expected.get("sha256"), str) or
                not re.fullmatch(r"[a-f0-9]{64}", expected["sha256"])):
            raise KoofrUnsupported("NOT_SUPPORTED")
        # An invalid destination must not trigger even a read-only request
        # with the mount's credentials.
        _validated_target(destination_parent, name)
        mount_id = self.primary_mount()
        path = upload_query(destination_parent, name, mount_id)
        boundary = "spec51" + secrets.token_hex(12)
        prefix = (f"--{boundary}\r\n"
                  'Content-Disposition: form-data; name="file"; filename="dummy"\r\n'
                  "Content-Type: application/octet-stream\r\n\r\n").encode()
        suffix = f"\r\n--{boundary}--\r\n".encode()
        # Length is known; stream bytes instead of buffering arbitrary size.
        length = len(prefix) + st.st_size + len(suffix)
        conn = self._connect()
        actual_md5 = hashlib.md5(usedforsecurity=False)
        actual_sha256 = hashlib.sha256()
        try:
            # Open by no-follow descriptor, then compare inode against lstat.
            fd = os.open(src, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            with os.fdopen(fd, "rb") as inp:
                opened = os.fstat(inp.fileno())
                if (not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1 or
                        (st.st_dev, st.st_ino, st.st_size) !=
                        (opened.st_dev, opened.st_ino, opened.st_size)):
                    raise KoofrUnsupported("NOT_SUPPORTED")
                if cancelled():
                    raise KoofrUnknown("REMOTE_UNKNOWN")
                conn.putrequest("POST", path)
                conn.putheader("Authorization", self._basic)
                conn.putheader("Content-Type", f"multipart/form-data; boundary={boundary}")
                conn.putheader("Content-Length", str(length))
                conn.putheader("Accept", "application/json")
                conn.endheaders()
                conn.send(prefix)
                remaining = st.st_size
                while remaining:
                    if cancelled():
                        raise KoofrUnknown("REMOTE_UNKNOWN")
                    chunk = inp.read(min(MAX_CHUNK, remaining))
                    if not chunk:
                        raise KoofrUnknown("REMOTE_UNKNOWN")
                    actual_md5.update(chunk)
                    actual_sha256.update(chunk)
                    conn.send(chunk)
                    remaining -= len(chunk)
                if inp.read(1):
                    raise KoofrUnknown("REMOTE_UNKNOWN")
                # The bytes actually streamed must exactly match the earlier
                # independent local file census, not merely remote readback.
                if (actual_md5.hexdigest() != expected["md5"] or
                        actual_sha256.hexdigest() != expected["sha256"]):
                    raise KoofrUnknown("REMOTE_UNKNOWN")
                finished = os.fstat(inp.fileno())
                if ((opened.st_dev, opened.st_ino, opened.st_size,
                     opened.st_mtime_ns, opened.st_ctime_ns) !=
                    (finished.st_dev, finished.st_ino, finished.st_size,
                     finished.st_mtime_ns, finished.st_ctime_ns)):
                    raise KoofrUnknown("REMOTE_UNKNOWN")
                if cancelled():
                    raise KoofrUnknown("REMOTE_UNKNOWN")
                conn.send(suffix)
            resp = conn.getresponse()
            data = resp.read(MAX_JSON + 1)
            if resp.status == 409:
                raise KoofrConflict("DESTINATION_CONFLICT")
            if resp.status != 200 or len(data) > MAX_JSON:
                raise KoofrUnknown("REMOTE_UNKNOWN")
            result = json.loads(data)
            if (not isinstance(result, dict) or
                    result.get("name") != name or result.get("size") != st.st_size or
                    result.get("type") != "file"):
                raise KoofrUnknown("REMOTE_UNKNOWN")
        except (OSError, ValueError, TypeError, http.client.HTTPException):
            raise KoofrUnknown("REMOTE_UNKNOWN") from None
        finally:
            conn.close()
        # Fresh provider readback; no remote mutation if mismatch/unknown.
        info_path = ("/api/v2/mounts/" + quote(mount_id, safe="") + "/files/info?" +
                     urlencode({"path": posixpath.join(destination_parent, name)}))
        info = self._request_json(info_path)
        if (info.get("type") != "file" or info.get("name") != name or
                info.get("size") != st.st_size or
                not self._matching_md5(info, actual_md5.hexdigest())):
            raise KoofrUnknown("REMOTE_UNKNOWN")
        # Success response hash, when present, must also agree with readback.
        if "hash" in result and not self._matching_md5(result, actual_md5.hexdigest()):
            raise KoofrUnknown("REMOTE_UNKNOWN")
        try:
            current = src.lstat()
        except OSError:
            raise KoofrUnknown("REMOTE_UNKNOWN") from None
        if ((st.st_dev, st.st_ino, st.st_size,
             st.st_mtime_ns, st.st_ctime_ns) !=
            (current.st_dev, current.st_ino, current.st_size,
             current.st_mtime_ns, current.st_ctime_ns)):
            raise KoofrUnknown("REMOTE_UNKNOWN")
        return {"files":1, "bytes":st.st_size, "remote_observed":"md5_verified"}
