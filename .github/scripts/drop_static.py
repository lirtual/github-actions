#!/usr/bin/env python3
"""Bounded, no-redirect staging for a reviewed ChatGPT-selected static site.

The caller must obtain the descriptor from an authenticated, attempt-bound
envelope. This module performs no deployment, claim, or logging of URLs.
"""
from __future__ import annotations

import datetime as dt
import http.client
import io
import ipaddress
import json
import pathlib
import sys
import re
import socket
import stat
import urllib.parse
import urllib.request
import zipfile

MAX_UPLOAD_BYTES = 10 * 1024 * 1024
MAX_FILE_BYTES = 5 * 1024 * 1024
MAX_UNPACKED_BYTES = 50 * 1024 * 1024
MAX_FILES = 1000
_CHUNK = 64 * 1024
_FILE_ID = re.compile(r"^[^\x00-\x1f\x7f]{1,512}$")


class DropInputError(ValueError):
    """Expose only fixed diagnostic codes; never include signed URLs."""


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        return None


def _public_create_connection(address, timeout=socket._GLOBAL_DEFAULT_TIMEOUT,
                              source_address=None):
    """Resolve once and connect to a validated, fixed public address.

    DNS validation followed by a normal hostname connect would allow rebinding.
    Reject a whole DNS answer if any record points to a non-public address.
    """
    hostname, port = address
    answers = socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
    if not answers:
        raise OSError("unresolved destination")
    endpoints = []
    for family, socktype, proto, _, sockaddr in answers:
        ip = ipaddress.ip_address(sockaddr[0])
        if not ip.is_global:
            raise OSError("non-public destination")
        endpoints.append((family, socktype, proto, sockaddr))
    last_error = None
    for family, socktype, proto, sockaddr in endpoints:
        conn = socket.socket(family, socktype, proto)
        try:
            if timeout is not socket._GLOBAL_DEFAULT_TIMEOUT:
                conn.settimeout(timeout)
            if source_address:
                conn.bind(source_address)
            conn.connect(sockaddr)
            return conn
        except OSError as error:
            last_error = error
            conn.close()
    raise OSError("public destination unavailable") from last_error


class _PublicHTTPSConnection(http.client.HTTPSConnection):
    # HTTPConnection.__init__ sets the socket factory, so override the instance.
    # TLS still receives the original hostname for SNI and cert verification.
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._create_connection = _public_create_connection


class _PublicHTTPSHandler(urllib.request.HTTPSHandler):
    def https_open(self, request):
        return self.do_open(_PublicHTTPSConnection, request, context=self._context)


# Never use runner HTTP(S) proxy environment variables; redirects stay disabled.
OPENER = urllib.request.build_opener(
    urllib.request.ProxyHandler({}), _NoRedirect(), _PublicHTTPSHandler()
)


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
        # Do not enumerate file-host providers. Require a canonical DNS name,
        # then enforce public IP addresses at the actual TCP connection.
        dns_label = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
        if len(host) > 253 or all(part.isdigit() for part in host.split('.')) or not re.fullmatch(
                rf"(?:{dns_label}\.)+{dns_label}", host):
            raise ValueError("invalid DNS host")
        # Existing Azure expiry hints remain useful, but a SAS is not mandatory
        # for unrelated public HTTPS hosts.
        if host.endswith(".blob.core.windows.net"):
            query = urllib.parse.parse_qs(url.query, keep_blank_values=True)
            if "se" in query:
                expiry = query["se"]
                if len(expiry) != 1 or not expiry[0]:
                    raise ValueError("invalid expiry")
                expires = dt.datetime.fromisoformat(expiry[0].replace("Z", "+00:00"))
                current = now or dt.datetime.now(dt.timezone.utc)
                if expires.tzinfo is None or expires <= current:
                    raise ValueError("expired URL")
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
