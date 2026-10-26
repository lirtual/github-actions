#!/usr/bin/env python3
"""Fail-closed OneDrive personal Graph uploader for Spec #51.

Requires an ALREADY AUTHENTICATED, server-scoped bearer from a separately
verified trusted transport. Not integrated with download Task or OpenList token
refresh. Never get a credential from batch inputs. Does not implement Go op.Put.
This implementation has only isolated/mock Graph tests, NOT live OneDrive proof.
"""
import json
import os
from pathlib import Path
import posixpath
import stat
import time
import unicodedata
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlsplit
from urllib.request import build_opener, HTTPRedirectHandler, ProxyHandler, Request

from download_batch import InvalidBatch, _destination

# 10 MiB, divisible by Graph's required 320 KiB quantum; below 60 MiB.
CHUNK_BYTES = 10 * 1024 * 1024
GRAPH = "https://graph.microsoft.com/v1.0/me/drive/root:"
ERROR = "ONEDRIVE_UNVERIFIED"


class OneDriveUnsupported(Exception):
    pass


class OneDriveConflict(Exception):
    pass


class OneDriveUnknown(Exception):
    pass


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _new_opener():
    return build_opener(ProxyHandler({}), _NoRedirect())


def _path(value, *, allow_root=False):
    if value == "/" and allow_root:
        return ""
    try:
        _destination(value)
    except InvalidBatch:
        raise OneDriveUnsupported("NOT_SUPPORTED") from None
    parts = value.lstrip("/").split("/")
    if any(unicodedata.normalize("NFC", p) != p or
           p.strip() != p or p.endswith(".") or
           len(p.encode("utf-8")) > 255 or
           not p or "\x00" in p for p in parts):
        raise OneDriveUnsupported("NOT_SUPPORTED")
    return value.lstrip("/")


def _read_addition(storage):
    raw = storage.get("addition")
    try:
        addition = json.loads(raw) if isinstance(raw, str) else raw
    except (ValueError, TypeError):
        raise OneDriveUnsupported("NOT_SUPPORTED") from None
    if not isinstance(addition, dict):
        raise OneDriveUnsupported("NOT_SUPPORTED")
    return addition


def resolve_mount(storages, destination):
    """Find deepest matching mount, including overlays that are unsupported."""
    _path(destination)
    if not isinstance(storages, list) or not storages:
        raise OneDriveUnsupported("NOT_SUPPORTED")
    selected = None
    for mount in storages:
        if not isinstance(mount, dict) or not isinstance(mount.get("mount_path"), str):
            raise OneDriveUnsupported("NOT_SUPPORTED")
        path = mount["mount_path"]
        _path(path, allow_root=True)
        if path == "/" or destination == path or destination.startswith(path + "/"):
            if selected is None or len(path) > len(selected["mount_path"]):
                selected = mount
    if (selected is None or selected.get("driver") != "Onedrive" or
            selected.get("disabled") is not False or
            selected.get("status") != "work"):
        raise OneDriveUnsupported("NOT_SUPPORTED")
    addition = _read_addition(selected)
    # Other OneDrive driver types, national-cloud endpoints, SharePoint,
    # storage references and custom OAuth endpoints have distinct contracts.
    # Stay narrowly within the known personal/global Graph endpoint.
    if addition.get("region") != "global" or addition.get("is_sharepoint") not in (False, None):
        raise OneDriveUnsupported("NOT_SUPPORTED")
    if addition.get("api_url_address") not in (None, "", "https://api.oplist.org/onedrive/renewapi"):
        raise OneDriveUnsupported("NOT_SUPPORTED")
    # Reference mode cannot safely identify the actual backing user.
    remark = selected.get("remark", "")
    if (selected.get("addition_reference") or addition.get("reference") or
            not isinstance(remark, str) or
            remark.lstrip().lower().startswith("ref:")):
        raise OneDriveUnsupported("NOT_SUPPORTED")
    root = _path(addition.get("root_folder_path", "/"), allow_root=True)
    mount_path = selected["mount_path"]
    sub = destination[len(mount_path):].lstrip("/") if mount_path != "/" else destination.lstrip("/")
    target = posixpath.normpath(posixpath.join(root, sub))
    if not target or target == ".":
        raise OneDriveUnsupported("NOT_SUPPORTED")
    return {"prefix": target, "drive": "me"}


def _safe_name(value):
    if (not isinstance(value, str) or value in ("", ".", "..") or
            "/" in value or "\\" in value or ":" in value or
            value[-1:] in (" ", ".") or value.strip() != value or
            unicodedata.normalize("NFC", value) != value or
            len(value.encode("utf-8")) > 255 or
            any(ord(c) < 32 or ord(c) == 127 for c in value)):
        raise OneDriveUnsupported("NOT_SUPPORTED")
    return value


def _uri(relative):
    if not isinstance(relative, str) or not relative:
        raise OneDriveUnsupported("NOT_SUPPORTED")
    return GRAPH + "/" + "/".join(quote(_safe_name(part), safe="") for part in relative.split("/")) + ":"


def _session_url(value):
    if not isinstance(value, str) or len(value) > 8192:
        raise OneDriveUnknown("REMOTE_UNKNOWN")
    try:
        parsed = urlsplit(value)
        if parsed.port not in (None, 443):
            raise OneDriveUnknown("REMOTE_UNKNOWN")
    except ValueError:
        raise OneDriveUnknown("REMOTE_UNKNOWN") from None
    host = parsed.hostname or ""
    # Preauthenticated upload URLs must come from a Microsoft-owned endpoint.
    # No untrusted URL supplied by a batch is ever opened here.
    if (parsed.scheme != "https" or parsed.username or parsed.password or
            not host or parsed.fragment or parsed.path in ("", "/") or
            not (host.endswith(".up.1drv.com") or host.endswith(".sharepoint.com"))):
        raise OneDriveUnknown("REMOTE_UNKNOWN")
    return value


class OneDriveGraphWriter:
    """Caller must inject approved ephemeral Graph access token internally."""

    def __init__(self, access_token, deadline, opener=None):
        if (not isinstance(access_token, str) or not access_token or
                "\n" in access_token or "\r" in access_token):
            raise OneDriveUnsupported("NOT_SUPPORTED")
        self._token = access_token
        self.deadline = deadline
        self._opener = opener if opener is not None else _new_opener()

    def _request(self, method, url, data=None, headers=None, *, graph=False):
        if graph and not url.startswith("https://graph.microsoft.com/v1.0/me/drive/"):
            raise OneDriveUnsupported("NOT_SUPPORTED")
        if not graph:
            _session_url(url)
        timeout = self.deadline - time.monotonic()
        if timeout <= 1:
            raise OneDriveUnknown("REMOTE_UNKNOWN")
        headers = dict(headers or {})
        headers["Accept"] = "application/json"
        if graph:
            headers["Authorization"] = "Bearer " + self._token
        elif "Authorization" in headers:
            raise OneDriveUnsupported("NOT_SUPPORTED")
        req = Request(url, data=data, headers=headers, method=method)
        try:
            with self._opener.open(req, timeout=timeout) as response:
                status = response.getcode()
                raw = response.read(1024 * 1024 + 1)
            if len(raw) > 1024 * 1024:
                raise OneDriveUnknown("REMOTE_UNKNOWN")
            value = json.loads(raw or b"{}")
            if not isinstance(value, dict):
                raise OneDriveUnknown("REMOTE_UNKNOWN")
            return status, value
        except HTTPError as exc:
            # Do not expose Graph diagnostic body, item path or upload URL.
            if exc.code in (409, 412):
                raise OneDriveConflict("DESTINATION_CONFLICT") from None
            raise OneDriveUnknown("REMOTE_UNKNOWN") from None
        except (OSError, ValueError, TypeError):
            raise OneDriveUnknown("REMOTE_UNKNOWN") from None

    def upload_file(self, file, target_prefix):
        """Only a fully downloaded regular local file, never pre-existing objects."""
        source = Path(file)
        name = _safe_name(source.name)
        # No synthetic per-file size ceiling; zero-size commit semantics still
        # need independent validation before enabling this provider.
        try:
            stat_result = source.lstat()
        except OSError:
            raise OneDriveUnsupported("NOT_SUPPORTED") from None
        if (not stat.S_ISREG(stat_result.st_mode) or
                stat_result.st_nlink != 1 or stat_result.st_size <= 0):
            raise OneDriveUnsupported("NOT_SUPPORTED")
        target = posixpath.join(target_prefix, name)
        _path("/" + target)
        # Reject a swapped or unreadable source before even requesting a
        # preauthenticated remote session (not after touching the provider).
        try:
            trial = os.open(source, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            try:
                before = os.fstat(trial)
                if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or
                        (before.st_dev,before.st_ino,before.st_size) !=
                        (stat_result.st_dev,stat_result.st_ino,stat_result.st_size)):
                    raise OneDriveUnsupported("NOT_SUPPORTED")
            finally:
                os.close(trial)
        except OSError:
            raise OneDriveUnsupported("NOT_SUPPORTED") from None
        url = _uri(target)
        _, started = self._request(
            "POST", url + "/createUploadSession",
            json.dumps({"item": {"name": name,
                        "@microsoft.graph.conflictBehavior": "fail"}}).encode("utf-8"),
            {"Content-Type": "application/json"},
            graph=True)
        upload_url = _session_url(started.get("uploadUrl"))
        completed = None
        size = stat_result.st_size
        # Open by descriptor without following a replaced symlink. Validate
        # inode/device against the preflight stat to detect a path swap.
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        try:
            fd = os.open(source, flags)
        except OSError:
            raise OneDriveUnsupported("NOT_SUPPORTED") from None
        with os.fdopen(fd, "rb") as stream:
            opened = os.fstat(stream.fileno())
            if (not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1 or
                    (opened.st_dev, opened.st_ino, opened.st_size) !=
                    (stat_result.st_dev, stat_result.st_ino, stat_result.st_size)):
                raise OneDriveUnsupported("NOT_SUPPORTED")
            offset = 0
            while offset < size:
                chunk = stream.read(min(CHUNK_BYTES, size - offset))
                if not chunk:
                    raise OneDriveUnknown("REMOTE_UNKNOWN")
                final = offset + len(chunk) == size
                status, result = self._request(
                    "PUT", upload_url, chunk,
                    {"Content-Length": str(len(chunk)),
                     "Content-Range": f"bytes {offset}-{offset+len(chunk)-1}/{size}"})
                if final:
                    if status not in (200, 201):
                        raise OneDriveUnknown("REMOTE_UNKNOWN")
                    completed = result
                elif status != 202:
                    raise OneDriveUnknown("REMOTE_UNKNOWN")
                offset += len(chunk)
            if stream.read(1):
                raise OneDriveUnknown("REMOTE_UNKNOWN")
        if (not completed or not isinstance(completed.get("id"), str) or
                not completed["id"] or completed.get("name") != name or
                completed.get("size") != size):
            raise OneDriveUnknown("REMOTE_UNKNOWN")
        # Verify by ID through the Graph service, not a potentially stale
        # OpenList cached mount list. No proof of cryptographic byte identity.
        response_status, observed = self._request(
            "GET", "https://graph.microsoft.com/v1.0/me/drive/items/" +
                   quote(completed["id"], safe=""), graph=True)
        if (response_status != 200 or
                observed.get("id") != completed["id"] or
                observed.get("name") != name or observed.get("size") != size or
                not isinstance(observed.get("file"), dict)):
            raise OneDriveUnknown("REMOTE_UNKNOWN")
        try:
            current = source.lstat()
        except OSError:
            raise OneDriveUnknown("REMOTE_UNKNOWN") from None
        if (current.st_dev,current.st_ino,current.st_size) != (stat_result.st_dev,stat_result.st_ino,size):
            raise OneDriveUnknown("REMOTE_UNKNOWN")
        return {"files": 1, "bytes": size, "remote_observed": "metadata_verified"}
