#!/usr/bin/env python3
"""Read-only aria2 result verifier for Spec #51; no RPC or download dispatch.

Caller provides authenticated aria2.tellStatus and aria2.getFiles snapshots.
This verifies a known GID's *complete* files match the independent local
manifest. It does NOT prove unknown follow-up tasks are absent or safe egress.
"""
import os
import posixpath
import re

from download_manifest import TreeUnverified, census_tree

GID = re.compile(r"^[0-9a-fA-F]{16}$")


class SourceUnverified(Exception):
    pass


def number(value):
    if not isinstance(value, str) or not value.isascii() or not value.isdecimal() or len(value) > 20:
        raise SourceUnverified("SOURCE_UNVERIFIED")
    return int(value)


def relative_path(root, path):
    if not isinstance(root, str) or not isinstance(path, str):
        raise SourceUnverified("SOURCE_UNVERIFIED")
    if not root.startswith("/") or not path.startswith("/") or posixpath.normpath(path) != path:
        raise SourceUnverified("SOURCE_UNVERIFIED")
    rel = posixpath.relpath(path, root)
    if rel in (".", "..") or rel.startswith("../"):
        raise SourceUnverified("SOURCE_UNVERIFIED")
    return rel


def verify_snapshot(root, gid, status, rows):
    """Return a local manifest iff the known aria2 source finished completely."""
    if not isinstance(gid, str) or not GID.fullmatch(gid):
        raise SourceUnverified("SOURCE_UNVERIFIED")
    if not isinstance(status, dict) or status.get("gid") != gid or status.get("status") != "complete":
        raise SourceUnverified("SOURCE_UNVERIFIED")
    # Chain/task attribution is unverified until explicitly checked by a caller.
    if status.get("followedBy") or status.get("following") or status.get("belongsTo"):
        raise SourceUnverified("SOURCE_UNVERIFIED")
    size = number(status.get("totalLength"))
    if number(status.get("completedLength")) != size:
        raise SourceUnverified("SOURCE_UNVERIFIED")
    if not isinstance(rows, list) or not rows:
        raise SourceUnverified("SOURCE_UNVERIFIED")
    expected, indexes = {}, set()
    for item in rows:
        if not isinstance(item, dict) or item.get("selected") != "true":
            raise SourceUnverified("SOURCE_UNVERIFIED")
        index = number(item.get("index"))
        if index < 1 or index in indexes:
            raise SourceUnverified("SOURCE_UNVERIFIED")
        indexes.add(index)
        if number(item.get("length")) != number(item.get("completedLength")):
            raise SourceUnverified("SOURCE_UNVERIFIED")
        relative = relative_path(root, item.get("path"))
        if relative.casefold() in {x.casefold() for x in expected}:
            raise SourceUnverified("SOURCE_UNVERIFIED")
        expected[relative] = number(item["length"])
    if sum(expected.values()) != size:
        raise SourceUnverified("SOURCE_UNVERIFIED")
    try:
        local = census_tree(root)
    except TreeUnverified:
        raise SourceUnverified("SOURCE_UNVERIFIED") from None
    observed = {entry["relative_path"]: entry["size"] for entry in local["files"]}
    if observed != expected or local["total_bytes"] != size:
        raise SourceUnverified("SOURCE_UNVERIFIED")
    return local
