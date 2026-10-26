#!/usr/bin/env python3
"""Fail-closed, side-effect-free preflight for Spec #51's immutable batch input.

This validates caller-controlled syntax only. It does NOT establish egress
isolation, OpenList no-clobber writes, or recursive transfer ownership.
Do not dispatch source downloads on the strength of this check alone.
"""
import ipaddress
import json
import os
import posixpath
import re
import sys
import unicodedata
from urllib.parse import parse_qs, urlsplit

MAX_INPUT_BYTES = 4096
MAX_MINUTES = 330
FIELDS = frozenset({"downloads", "project_purpose", "duration_minutes"})
LINK_FIELDS = frozenset({"url", "destination_path"})
HOST = re.compile(r"^[a-zA-Z0-9.-]{1,253}$")
BTIH = re.compile(r"^(?:[0-9a-fA-F]{40}|[A-Z2-7a-z2-7]{32})$")


class InvalidBatch(ValueError):
    """Only safe constant error codes; never embed untrusted input."""


def _unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise InvalidBatch("duplicate_json_key")
        result[key] = value
    return result


def _safe_text(value, maximum, code):
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise InvalidBatch(code)
    if any(ord(char) < 32 or ord(char) == 127 or 0xD800 <= ord(char) <= 0xDFFF for char in value):
        raise InvalidBatch(code)
    if unicodedata.normalize("NFC", value) != value:
        raise InvalidBatch(code)
    return value


def _public_hostname(hostname):
    if not hostname:
        raise InvalidBatch("source_invalid")
    try:
        ip = ipaddress.ip_address(hostname)
    except ValueError:
        # Full DNS safety is a *runtime* network-boundary requirement.
        if (not HOST.fullmatch(hostname) or ".." in hostname
                or hostname.startswith(("-", ".")) or hostname.endswith(("-", "."))
                or "." not in hostname or hostname.lower().endswith((".local", ".localhost", ".internal", ".invalid", ".test", ".onion", ".home.arpa"))):
            raise InvalidBatch("source_invalid")
    else:
        if not ip.is_global:
            raise InvalidBatch("source_invalid")


def _source(value):
    url = _safe_text(value, 2048, "source_invalid")
    try:
        parsed = urlsplit(url)
        if parsed.scheme in ("http", "https"):
            if parsed.username or parsed.password or parsed.fragment:
                raise InvalidBatch("source_invalid")
            # Signed URLs and tracker passkeys are disallowed in this initial
            # surface; query-free public artifacts remain representable.
            if parsed.query or not parsed.path.startswith("/"):
                raise InvalidBatch("source_invalid")
            _public_hostname(parsed.hostname)
            if parsed.port is not None and parsed.port not in (80, 443):
                raise InvalidBatch("source_invalid")
        elif parsed.scheme == "magnet":
            if parsed.netloc or parsed.fragment or parsed.path:
                raise InvalidBatch("source_invalid")
            params = parse_qs(parsed.query, strict_parsing=True)
            # Reject credential-bearing private tracker parameters. This
            # accepts only a bare public infohash; BT is not runtime-enabled.
            if set(params) - {"xt", "dn"}:
                raise InvalidBatch("source_invalid")
            xt = params.get("xt", [])
            if len(xt) != 1 or not xt[0].startswith("urn:btih:"):
                raise InvalidBatch("source_invalid")
            if not BTIH.fullmatch(xt[0][len("urn:btih:"):]):
                raise InvalidBatch("source_invalid")
        else:
            raise InvalidBatch("source_invalid")
    except (ValueError, UnicodeError) as error:
        if isinstance(error, InvalidBatch):
            raise
        raise InvalidBatch("source_invalid") from None
    return url


def _destination(value):
    dest = _safe_text(value, 1024, "destination_invalid")
    if (not dest.startswith("/") or dest.startswith("//") or dest.endswith("/")
            or "\\" in dest or "?" in dest or "#" in dest or ":" in dest
            or posixpath.normpath(dest) != dest or dest == "/"):
        raise InvalidBatch("destination_invalid")
    parts = dest.split("/")[1:]
    if any(part in ("", ".", "..") for part in parts):
        raise InvalidBatch("destination_invalid")
    return dest


def validate(payload):
    """Return an immutable-shaped in-memory input, never safe to print."""
    if not isinstance(payload, str):
        raise InvalidBatch("batch_invalid")
    try:
        raw = payload.encode("utf-8")
    except UnicodeEncodeError:
        raise InvalidBatch("batch_invalid") from None
    if not raw or len(raw) > MAX_INPUT_BYTES:
        raise InvalidBatch("batch_size_invalid")
    try:
        batch = json.loads(payload, object_pairs_hook=_unique_pairs,
                           parse_constant=lambda _: (_ for _ in ()).throw(
                               InvalidBatch("batch_invalid")))
    except (ValueError, UnicodeError, TypeError):
        raise InvalidBatch("batch_invalid") from None
    if not isinstance(batch, dict) or set(batch) - FIELDS:
        raise InvalidBatch("batch_invalid")
    purpose = _safe_text(batch.get("project_purpose"), 280, "purpose_invalid")
    count = batch.get("duration_minutes", 300)
    if type(count) is not int or not 1 <= count <= MAX_MINUTES:
        raise InvalidBatch("duration_invalid")
    links = batch.get("downloads")
    if not isinstance(links, list) or not links:
        raise InvalidBatch("downloads_invalid")
    approved = []
    paths = []
    for entry in links:
        if not isinstance(entry, dict) or set(entry) != LINK_FIELDS:
            raise InvalidBatch("downloads_invalid")
        source = _source(entry["url"])
        dest = _destination(entry["destination_path"])
        # Source naming and torrent contents are unknown until download.
        # For now demand separate non-nested destination directories.
        if any(dest == old or dest.startswith(old + "/")
               or old.startswith(dest + "/") for old in paths):
            raise InvalidBatch("destination_conflict")
        paths.append(dest)
        approved.append({"url": source, "destination_path": dest})
    return {"downloads": approved, "project_purpose": purpose,
            "duration_minutes": count}


def main():
    try:
        manifest = validate(os.environ.get("BATCH_JSON", ""))
    except InvalidBatch as error:
        # Exception is a literal code; URL, purpose and path remain private.
        print("BATCH_REJECTED:" + str(error), file=sys.stderr)
        return 2
    print("BATCH_SYNTAX_VALID: links=" + str(len(manifest["downloads"])))
    print("RUNTIME_NOT_AUTHORIZED: isolation, ownership and no-clobber unverified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
