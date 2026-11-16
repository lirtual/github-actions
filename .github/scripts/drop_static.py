#!/usr/bin/env python3
"""Bounded, no-redirect staging for a reviewed ChatGPT-selected static site.

The caller must obtain the descriptor from an authenticated, attempt-bound
envelope. This module performs no deployment, claim, or logging of URLs.
"""
from __future__ import annotations

import datetime as dt
import io
import json
import pathlib
import sys
import re
import stat
import urllib.parse
import urllib.request
import zipfile

MAX_UPLOAD_BYTES = 10 * 1024 * 1024
MAX_FILE_BYTES = 5 * 1024 * 1024
MAX_UNPACKED_BYTES = 50 * 1024 * 1024
MAX_FILES = 1000
_CHUNK = 64 * 1024
_BLOB_HOST = re.compile(r"^[a-z0-9]{3,24}\.blob\.core\.windows\.net$")
_FILE_ID = re.compile(r"^[^\x00-\x1f\x7f]{1,512}$")


class DropInputError(ValueError):
    """Expose only fixed diagnostic codes; never include signed URLs."""


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        return None


OPENER = urllib.request.build_opener(_NoRedirect())


def _exact_query_value(query, key):
    values = query.get(key, [])
    return values[0] if len(values) == 1 and values[0] else None


def approved_chatgpt_attachment(descriptor, now=None):
    """Return a trusted URL after validating the narrow existing file source."""
    if type(descriptor) is not dict or not set(descriptor).issubset(
        {"file_id", "download_url", "file_name", "mime_type"}
    ):
        raise DropInputError("file_descriptor_invalid")
    file_id, raw_url = descriptor.get("file_id"), descriptor.get("download_url")
    file_name = descriptor.get("file_name")
    if (not isinstance(file_id, str) or not _FILE_ID.fullmatch(file_id)
            or not file_id.strip() or not isinstance(raw_url, str)
            or not 1 <= len(raw_url) <= 4096
            or ("file_name" in descriptor and (
                not isinstance(file_name, str) or not 1 <= len(file_name) <= 255
                or file_name != pathlib.PurePosixPath(file_name).name
                or not file_name.lower().endswith((".html", ".zip"))))):
        raise DropInputError("file_descriptor_invalid")
    if "mime_type" in descriptor and not isinstance(descriptor["mime_type"], str):
        raise DropInputError("file_descriptor_invalid")
    try:
        url = urllib.parse.urlsplit(raw_url)
        host = (url.hostname or "").lower()
        if (url.scheme != "https" or url.username or url.password
                or url.port is not None or url.fragment or not url.path
                or url.path == "/" or not host or raw_url != url.geturl()):
            raise ValueError("invalid url shape")
        if host == "files.oaiusercontent.com":
            return raw_url
        if (not _BLOB_HOST.fullmatch(host) or len(url.path.split("/")) < 3
                or not url.path.split("/")[1] or not url.path.split("/")[2]):
            raise ValueError("invalid host")
        query = urllib.parse.parse_qs(url.query, keep_blank_values=True)
        if not all(_exact_query_value(query, key) for key in ("sig", "se", "sv")):
            raise ValueError("invalid SAS")
        if "sp" in query and _exact_query_value(query, "sp") != "r":
            raise ValueError("invalid SAS permission")
        if "sr" in query and _exact_query_value(query, "sr") not in ("b", "bv", "bs"):
            raise ValueError("invalid SAS resource")
        expiry = _exact_query_value(query, "se")
        expires = dt.datetime.fromisoformat(expiry.replace("Z", "+00:00"))
        current = now or dt.datetime.now(dt.timezone.utc)
        if expires.tzinfo is None or expires <= current:
            raise ValueError("expired SAS")
        return raw_url
    except (ValueError, TypeError):
        raise DropInputError("file_source_unverified") from None


def download_bounded_attachment(url, opener=OPENER):
    """Download at most 10 MiB without redirects or URL-bearing diagnostics."""
    try:
        request = urllib.request.Request(url, method="GET")
        with opener.open(request, timeout=15) as response:
            if response.status != 200:
                raise DropInputError("file_read_unavailable")
            raw_length = response.headers.get("content-length")
            if raw_length is not None and (
                not raw_length.isascii() or not raw_length.isdigit()
                or int(raw_length) > MAX_UPLOAD_BYTES
            ):
                raise DropInputError("file_size_limit")
            result = io.BytesIO()
            while True:
                block = response.read(_CHUNK)
                if not block:
                    break
                if result.tell() + len(block) > MAX_UPLOAD_BYTES:
                    raise DropInputError("file_size_limit")
                result.write(block)
            if result.tell() == 0:
                raise DropInputError("empty_file_not_supported")
            return result.getvalue()
    except DropInputError:
        raise
    except Exception:
        raise DropInputError("file_read_unavailable") from None


def _safe_zip_path(name):
    if (not name or any(ord(char) < 32 or ord(char) == 127 for char in name)
            or "\\" in name or
            name.startswith("/") or ":" in name):
        raise DropInputError("zip_path_invalid")
    path = pathlib.PurePosixPath(name)
    if (path.is_absolute() or ".." in path.parts or "." in name.split("/")
            or any(not part for part in name.rstrip("/").split("/"))):
        raise DropInputError("zip_path_invalid")
    return path


def _stage_zip(archive_bytes, destination):
    try:
        with zipfile.ZipFile(io.BytesIO(archive_bytes)) as archive:
            members = archive.infolist()
            if len(members) > MAX_FILES * 2:
                raise DropInputError("zip_size_limit")
            seen = set()
            total = files = 0
            for member in members:
                path = _safe_zip_path(member.filename)
                key = path.as_posix().casefold()
                if key in seen:
                    raise DropInputError("zip_duplicate_path")
                seen.add(key)
                mode = member.external_attr >> 16
                if (member.flag_bits & 1 or stat.S_ISLNK(mode)
                        or stat.S_IFMT(mode) not in (0, stat.S_IFREG, stat.S_IFDIR)):
                    raise DropInputError("zip_entry_invalid")
                if member.is_dir():
                    continue
                files += 1
                total += member.file_size
                if (files > MAX_FILES or member.file_size > MAX_FILE_BYTES
                        or total > MAX_UNPACKED_BYTES):
                    raise DropInputError("zip_size_limit")
            if files == 0 or not any(m.filename == "index.html" and not m.is_dir() for m in members):
                raise DropInputError("site_entry_missing")
            for member in members:
                target = destination.joinpath(*_safe_zip_path(member.filename).parts)
                if member.is_dir():
                    target.mkdir(parents=True, exist_ok=True)
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                with archive.open(member) as source, target.open("xb") as output:
                    remaining = member.file_size
                    while True:
                        block = source.read(min(_CHUNK, remaining + 1))
                        if not block:
                            break
                        remaining -= len(block)
                        if remaining < 0:
                            raise DropInputError("zip_size_limit")
                        output.write(block)
                    if remaining != 0:
                        raise DropInputError("zip_size_limit")
    except DropInputError:
        raise
    except (zipfile.BadZipFile, EOFError, RuntimeError, OSError, ValueError):
        raise DropInputError("zip_invalid") from None


def stage_static_site(descriptor, destination, opener=OPENER, now=None):
    """Stage a single HTML/ZIP into a new empty directory; no network write."""
    root = pathlib.Path(destination)
    if not root.is_dir() or root.is_symlink() or next(root.iterdir(), None) is not None:
        raise DropInputError("destination_invalid")
    url = approved_chatgpt_attachment(descriptor, now=now)
    data = download_bounded_attachment(url, opener)
    file_name = descriptor.get("file_name")
    if file_name is None:
        # ChatGPT fileParams guarantees file_id and download_url, not a filename.
        # Inspect bounded bytes only; never use the signed URL path or MIME alone.
        if data.startswith(b"PK\x03\x04"):
            file_name = "site.zip"
        else:
            try:
                preview = data.decode("utf-8-sig")
            except UnicodeDecodeError:
                raise DropInputError("file_type_unverified") from None
            if ("\x00" in preview or not re.match(
                r"^\s*<(?:!doctype\s+html\b|!--|[a-z][\w:-]*(?:\s|/?>))",
                preview, re.IGNORECASE,
            )):
                raise DropInputError("file_type_unverified")
            file_name = "index.html"
    if file_name.lower().endswith(".html"):
        if len(data) > MAX_FILE_BYTES:
            raise DropInputError("file_size_limit")
        (root / "index.html").write_bytes(data)
    else:
        _stage_zip(data, root)
    return {"file_count": sum(p.is_file() for p in root.rglob("*"))}


if __name__ == "__main__":
    # Runner passes the short-lived signed descriptor on stdin, never in argv,
    # files, subprocess environments, step outputs, or a diagnostic message.
    try:
        if len(sys.argv) != 2:
            raise DropInputError("stage_arguments_invalid")
        descriptor = json.load(sys.stdin)
        count = stage_static_site(descriptor, sys.argv[1])["file_count"]
        print(f"drop_staged_file_count={count}")
    except DropInputError as error:
        print(f"drop_stage_error={error}", file=sys.stderr)
        sys.exit(1)
    except Exception:
        print("drop_stage_error=internal", file=sys.stderr)
        sys.exit(1)
