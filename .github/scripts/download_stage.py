#!/usr/bin/env python3
"""Spec #51 batch upload plan preflight (UNWIRED / READ-ONLY).

Turns authenticated aria2 snapshots plus a complete local census into an
in-memory Koofr upload plan. It never opens remote connections, dispatches
downloads, calls Koofr or mutates files.

A caller MUST separately prove: fresh isolated aria2 process, consistent
queue snapshots, approved pinned physical GitHub Task, no-clobber provider
semantics, safe network egress and live target parent-directory ownership.
"""
import posixpath
from pathlib import Path

from download_batch import validate, InvalidBatch
from download_koofr import resolve_mount, KoofrUnsupported, _safe_parts
from download_source import verify_queue_closed, verify_snapshot, SourceUnverified


class StageUnverified(Exception):
    """Constant error code only; never leak paths, URLs or credentials."""


def stage_batch(batch_json, snapshots, queue, storages):
    """Return upload intents only if the *whole batch* validates first.

    snapshots: one item per requested download, each:
       gid, root, status (tellStatus), files (getFiles).
    queue: stats (getGlobalStat), active, waiting, stopped.
    """
    try:
        batch = validate(batch_json)
        if (not isinstance(snapshots, list) or
                len(snapshots) != len(batch["downloads"]) or
                not isinstance(queue, dict)):
            raise StageUnverified("STAGE_UNVERIFIED")
        gids = [item.get("gid") if isinstance(item, dict) else None
                for item in snapshots]
        verify_queue_closed(gids, queue.get("stats"), queue.get("active"),
                            queue.get("waiting"), queue.get("stopped"))
        planned, target_keys, root_keys, destination_keys = [], set(), set(), set()
        for request, snapshot in zip(batch["downloads"], snapshots):
            destination_key = request["destination_path"].casefold()
            if any(destination_key == prev or
                   destination_key.startswith(prev + "/") or
                   prev.startswith(destination_key + "/")
                   for prev in destination_keys):
                raise StageUnverified("STAGE_UNVERIFIED")
            destination_keys.add(destination_key)
            root = snapshot.get("root")
            if (not isinstance(root, str) or not root.startswith("/") or
                    posixpath.normpath(root) != root or
                    not Path(root).is_absolute() or
                    root.casefold() in root_keys):
                raise StageUnverified("STAGE_UNVERIFIED")
            root_keys.add(root.casefold())
            census = verify_snapshot(root, snapshot["gid"], snapshot["status"],
                                     snapshot["files"])
            # Mount credentials are NEVER stored in this return value.
            mount = resolve_mount(storages, request["destination_path"])
            base = mount["parent"]
            if not census["files"]:
                raise StageUnverified("STAGE_UNVERIFIED")
            for file in census["files"]:
                relative = file["relative_path"]
                parts = _safe_parts("/" + relative)
                parent = posixpath.join(base, *parts[:-1])
                _safe_parts(parent, allow_root=True)
                # A deeper OpenList mount may shadow an individual file even
                # when the requested destination directory is allowed.
                # Re-resolve its full virtual parent and require the exact
                # same Koofr-native destination path.
                virtual_parent = posixpath.join(request["destination_path"],
                                                *parts[:-1])
                resolved_parent = resolve_mount(storages, virtual_parent)["parent"]
                if resolved_parent != parent:
                    raise StageUnverified("STAGE_UNVERIFIED")
                target = posixpath.join(parent, parts[-1])
                virtual_file = posixpath.join(virtual_parent, parts[-1])
                if resolve_mount(storages, virtual_file)["parent"] != target:
                    raise StageUnverified("STAGE_UNVERIFIED")
                key = target.casefold()
                if key in target_keys:
                    raise StageUnverified("STAGE_UNVERIFIED")
                target_keys.add(key)
                # A downstream uploader MUST independently verify each target
                # parent exists, is a Koofr directory, and has no submount.
                # This stage never creates cloud folders or writes objects.
                planned.append({
                    "file": str(Path(root, relative)),
                    "destination_parent": parent,
                    "name": parts[-1],
                    "size": file["size"],
                    "sha256": file["sha256"],
                    "md5": file["md5"],
                })
        if not planned:
            raise StageUnverified("STAGE_UNVERIFIED")
        return planned
    except (InvalidBatch, KoofrUnsupported, SourceUnverified,
            TypeError, ValueError, KeyError, AttributeError):
        raise StageUnverified("STAGE_UNVERIFIED") from None
