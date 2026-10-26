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


def verify_queue_closed(known_gids, stats, active, waiting, stopped):
    """Fail if even one aria2 GID is unknown, missing, truncated or nonterminal.

    Inputs are snapshots from the same isolated aria2 instance, which the
    Runner must freeze and query consistently (not yet integrated). Per aria2
    docs numStoppedTotal is not capped by max-download-result; a mismatch
    detects history truncation/purge that would conceal old/child tasks.
    """
    if not isinstance(known_gids, (list, tuple)) or not known_gids:
        raise SourceUnverified("SOURCE_UNVERIFIED")
    if (not all(isinstance(g, str) and GID.fullmatch(g) for g in known_gids)
            or len(known_gids) != len(set(known_gids))):
        raise SourceUnverified("SOURCE_UNVERIFIED")
    if not isinstance(stats, dict) or any(not isinstance(x, list)
                                           for x in (active, waiting, stopped)):
        raise SourceUnverified("SOURCE_UNVERIFIED")
    if number(stats.get("numActive")) != 0 or number(stats.get("numWaiting")) != 0:
        raise SourceUnverified("SOURCE_UNVERIFIED")
    count = number(stats.get("numStoppedTotal"))
    retained = number(stats.get("numStopped"))
    if active or waiting or count != retained or count != len(stopped) or count != len(known_gids):
        raise SourceUnverified("SOURCE_UNVERIFIED")
    observed = []
    for row in stopped:
        if (not isinstance(row, dict) or row.get("status") != "complete" or
                not isinstance(row.get("gid"), str) or not GID.fullmatch(row["gid"]) or
                row.get("followedBy") or row.get("following") or row.get("belongsTo")):
            raise SourceUnverified("SOURCE_UNVERIFIED")
        observed.append(row["gid"])
    if len(set(observed)) != count or set(observed) != set(known_gids):
        raise SourceUnverified("SOURCE_UNVERIFIED")
    return True


def verify_http_source_uris(rows, approved_url):
    """Prove that all recorded source URIs on each downloaded file are approved.

    aria2 1.37 can duplicate the same URI with `used` and `waiting` entries.
    Require at least one `used` and no unknown URI/status; torrent/magnet
    attribution remains unsupported until a separate Q26 release gate.
    """
    from urllib.parse import urlsplit
    if (not isinstance(approved_url, str) or
            urlsplit(approved_url).scheme not in ("http", "https") or
            not isinstance(rows, list) or not rows):
        raise SourceUnverified("SOURCE_UNVERIFIED")
    used = False
    for file in rows:
        if not isinstance(file, dict) or not isinstance(file.get("uris"), list) or not file["uris"]:
            raise SourceUnverified("SOURCE_UNVERIFIED")
        for record in file["uris"]:
            if (not isinstance(record, dict) or record.get("uri") != approved_url or
                    record.get("status") not in ("used", "waiting")):
                raise SourceUnverified("SOURCE_UNVERIFIED")
            used = used or record["status"] == "used"
    if not used:
        raise SourceUnverified("SOURCE_UNVERIFIED")
    return True


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
