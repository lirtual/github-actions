#!/usr/bin/env python3
"""Unwired Spec #51 Koofr upload handoff (no autonomous network activity).

Call only after stage_batch proved ALL sources and destinations. The caller
must separately establish real provider create-only atomicity and authenticated
GitHub/Workflow admission before instantiating a KoofrClient.

Uploads are sequential and never automatically retried or rolled back.
Caller must stop on any unknown remote result. No input paths or credentials
appear in exposed exceptions.
"""
from download_koofr import KoofrConflict, KoofrUnknown, KoofrUnsupported, _safe_parts


class BatchIncomplete(Exception):
    def __init__(self, code, completed):
        self.code = code
        self.completed = completed
        super().__init__(code)


def finish_staged(staged, client, *, cancelled=lambda: False):
    """Pre-validate every parent before uploading the first local file."""
    if not isinstance(staged, list) or not staged:
        raise BatchIncomplete("STAGE_UNVERIFIED", 0)
    parents = set()
    targets = set()
    for entry in staged:
        if not isinstance(entry, dict):
            raise BatchIncomplete("STAGE_UNVERIFIED", 0)
        parent, name = entry.get("destination_parent"), entry.get("name")
        try:
            if not isinstance(parent, str) or not isinstance(name, str):
                raise KoofrUnsupported("NOT_SUPPORTED")
            _safe_parts(parent, allow_root=True)
            if len(_safe_parts("/" + name)) != 1:
                raise KoofrUnsupported("NOT_SUPPORTED")
        except KoofrUnsupported:
            raise BatchIncomplete("STAGE_UNVERIFIED", 0) from None
        key = (parent + "/" + name).casefold()
        if key in targets:
            raise BatchIncomplete("DESTINATION_CONFLICT", 0)
        targets.add(key)
        parents.add(parent)

    try:
        if cancelled():
            raise BatchIncomplete("CANCELLED", 0)
        # Every target must belong to an already-existing directory.
        # No auto-mkdir/merge into unknown remote trees in this version.
        for parent in sorted(parents):
            if cancelled():
                raise BatchIncomplete("CANCELLED", 0)
            client.assert_directory(parent)
        # Do not write even the first file if any target already exists.
        # Existence is read-only; server-side atomic create-only remains a
        # separate mandatory gate (TOCTOU cannot be solved with this GET).
        for entry in staged:
            if cancelled():
                raise BatchIncomplete("CANCELLED", 0)
            client.assert_absent(entry["destination_parent"], entry["name"])
    except KoofrConflict:
        raise BatchIncomplete("DESTINATION_CONFLICT", 0) from None
    except (KoofrUnknown, KoofrUnsupported):
        raise BatchIncomplete("REMOTE_UNVERIFIED", 0) from None

    completed = 0
    total_bytes = 0
    for entry in staged:
        try:
            if cancelled():
                raise BatchIncomplete("CANCELLED", completed)
            result = client.upload_file(entry["file"], entry["destination_parent"],
                                        expected=entry)
            if (not isinstance(result, dict) or
                    result.get("remote_observed") != "md5_verified" or
                    result.get("files") != 1 or
                    result.get("bytes") != entry["size"]):
                raise BatchIncomplete("REMOTE_UNKNOWN", completed)
            completed += 1
            total_bytes += entry["size"]
        except KoofrConflict:
            raise BatchIncomplete("DESTINATION_CONFLICT", completed) from None
        except (KoofrUnknown, KoofrUnsupported):
            raise BatchIncomplete("REMOTE_UNKNOWN", completed) from None
    return {"files": completed, "bytes": total_bytes,
            "remote_observed": "all_verified"}
