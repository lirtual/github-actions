#!/usr/bin/env python3
"""Spec #51: isolated rclone upload with independent remote readback.

Called after aria2 source closure, restricted egress, verified OIDC Claim
and runtime-pinned binaries.
Unique Task directories reduce accidental collision, not server-atomic writes.
No remote deletion, move, rename, retries of uncertain Task uploads or path logs.
"""
import hashlib
import json
import math
import os
from pathlib import Path
import re
import select
import stat
import subprocess
import time

from download_destination import plan_targets, verify_task_root
from download_manifest import TreeUnverified, census_tree, verify_manifest_file

REMOTE_NAME = re.compile(r"[A-Za-z][A-Za-z0-9_-]{0,63}\Z")


class TransferUnverified(Exception):
    def __init__(self, code, confirmed=0, attempted=0):
        super().__init__(code)
        self.code = code
        self.confirmed = confirmed
        self.attempted = attempted


def _remaining(deadline):
    remaining = deadline - time.monotonic()
    if remaining <= 1:
        raise TransferUnverified("REMOTE_UNKNOWN")
    return remaining


class IsolatedRclone:
    def __init__(self, executable, config, requested_remote, allowed_remote, deadline):
        if (os.name != "posix" or
                not isinstance(executable, str) or not os.path.isabs(executable) or
                not os.path.isfile(executable) or
                not isinstance(config, str) or not os.path.isabs(config) or
                not isinstance(requested_remote, str) or
                REMOTE_NAME.fullmatch(requested_remote) is None or
                requested_remote != allowed_remote or
                not isinstance(deadline, (int, float))):
            raise TransferUnverified("REMOTE_UNAVAILABLE")
        try:
            info = os.lstat(config)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                    or info.st_mode & 0o077):
                raise TransferUnverified("REMOTE_UNAVAILABLE")
        except OSError:
            raise TransferUnverified("REMOTE_UNAVAILABLE") from None
        self.remote = requested_remote
        self.deadline = deadline
        self.prefix = [executable, "--config", config, "--retries", "1",
                       "--low-level-retries", "1", "--log-level", "ERROR",
                       "--stats", "0"]

    def _invoke(self, args, read_json=False):
        try:
            result = subprocess.run(
                self.prefix + args, stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE if read_json else subprocess.DEVNULL,
                stderr=subprocess.DEVNULL, timeout=_remaining(self.deadline),
                check=False)
        except (OSError, subprocess.TimeoutExpired):
            raise TransferUnverified("REMOTE_UNKNOWN") from None
        if result.returncode != 0:
            raise TransferUnverified(
                "REMOTE_UNAVAILABLE" if read_json else "REMOTE_UNKNOWN")
        if not read_json:
            return None
        if len(result.stdout) > 8 * 1024 * 1024:
            raise TransferUnverified("REMOTE_UNAVAILABLE")
        try:
            value = json.loads(result.stdout)
        except (TypeError, ValueError):
            raise TransferUnverified("REMOTE_UNAVAILABLE") from None
        if (not isinstance(value, list) or any(
                not isinstance(item, dict) or
                not isinstance(item.get("Path"), str) or
                not isinstance(item.get("IsDir"), bool) for item in value)):
            raise TransferUnverified("REMOTE_UNAVAILABLE")
        return value

    def create_empty_task_root(self, task_root):
        """Require an existing downloads/ parent, empty new Task root.

        Read + mkdir is not atomic with external writers. Owner accepted
        this residual race; do not represent it as strict no-clobber.
        """
        root = verify_task_root(task_root)
        suffix = root.rsplit("/", 1)[-1]
        listing = self._invoke(
            ["lsjson", self.remote + ":downloads", "--max-depth", "1"], True)
        if any(item["Path"].casefold() == suffix.casefold() for item in listing):
            raise TransferUnverified("DESTINATION_EXISTS")
        self._invoke(["mkdir", self.remote + ":" + root])
        if self._invoke(
                ["lsjson", self.remote + ":" + root, "--max-depth", "1"], True):
            raise TransferUnverified("DESTINATION_EXISTS")

    def upload(self, local_file, remote_path):
        self._invoke(["copyto", str(local_file), self.remote + ":" + remote_path])

    def readback_sha256(self, remote_path):
        """Stream and hash rclone cat; do not buffer whole remote file."""
        try:
            process = subprocess.Popen(
                self.prefix + ["cat", self.remote + ":" + remote_path],
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL)
            checksum = hashlib.sha256()
            size = 0
            try:
                while True:
                    ready, _, _ = select.select(
                        [process.stdout], [], [], _remaining(self.deadline))
                    if not ready:
                        raise TransferUnverified("REMOTE_UNKNOWN")
                    chunk = os.read(process.stdout.fileno(), 1024 * 1024)
                    if not chunk:
                        break
                    checksum.update(chunk)
                    size += len(chunk)
                if process.wait(timeout=_remaining(self.deadline)):
                    raise TransferUnverified("REMOTE_UNVERIFIED")
            finally:
                if process.poll() is None:
                    process.kill()
                process.wait()
                process.stdout.close()
        except (OSError, subprocess.TimeoutExpired):
            raise TransferUnverified("REMOTE_UNKNOWN") from None
        return size, checksum.hexdigest()


def transfer_verified_batch(rclone, batch, source_roots, task_root):
    """Build complete validated plan, create Task root and verify each write.

    Source roots must be exclusive, quiesced aria2 locations whose actual GIDs
    and source URLs were already verified before calling. No remote rollback.
    """
    if (not isinstance(batch, dict) or
            not isinstance(source_roots, (list, tuple)) or
            len(source_roots) != len(batch.get("downloads", []))):
        raise TransferUnverified("SOURCE_UNVERIFIED")
    if batch.get("remote") != rclone.remote:
        raise TransferUnverified("REMOTE_UNAVAILABLE")
    manifests = []
    for root in source_roots:
        if not isinstance(root, (str, Path)) or not os.path.isabs(root):
            raise TransferUnverified("SOURCE_UNVERIFIED")
        try:
            manifests.append(census_tree(root))
        except TreeUnverified:
            raise TransferUnverified("SOURCE_UNVERIFIED") from None
    paths = [[f["relative_path"] for f in m["files"]] for m in manifests]
    try:
        targets = plan_targets(batch, paths, task_root)
    except (ValueError, KeyError, TypeError):
        raise TransferUnverified("DESTINATION_UNVERIFIED") from None
    by_source = [{f["relative_path"]: f for f in m["files"]}
                 for m in manifests]
    rclone.create_empty_task_root(task_root)
    confirmed = attempted = 0
    for target in targets:
        attempted += 1
        index = target["source_index"]
        expected = by_source[index][target["source_file"]]
        file = Path(source_roots[index]) / target["source_file"]
        try:
            # The complete tree was verified once before remote side effects.
            # aria2 has exited and the source mount is read-only. Recheck only
            # this file through no-follow descriptors, retaining its original
            # content fingerprint and rejecting any changed ancestor or inode.
            try:
                verify_manifest_file(source_roots[index], expected)
            except TreeUnverified:
                raise TransferUnverified("SOURCE_UNVERIFIED") from None
            rclone.upload(file, target["remote_target"])
            size, checksum = rclone.readback_sha256(target["remote_target"])
            if size != expected["size"] or checksum != expected["sha256"]:
                raise TransferUnverified("REMOTE_UNVERIFIED")
            confirmed += 1
        except TransferUnverified as error:
            raise TransferUnverified(
                error.code, confirmed, attempted) from None
    return {"confirmed": confirmed, "total": len(targets),
            "task_root": task_root}

def main():
    """Bounded Task entry point: never log URL, token, config or remote paths."""
    import shutil
    import sys
    from download_batch import InvalidBatch, validate
    try:
        batch = validate(os.environ.get("BATCH_JSON", ""))
        deadline = float(os.environ.get("DOWNLOAD_DEADLINE", "nan"))
        remaining = deadline - time.monotonic()
        if not math.isfinite(deadline) or not 0 < remaining <= 19800:
            raise TransferUnverified("TIME_BUDGET_INVALID")
        source_root = Path(os.environ.get("DOWNLOAD_SOURCES_DIR", ""))
        if not source_root.is_absolute() or source_root.is_symlink():
            raise TransferUnverified("SOURCE_UNVERIFIED")
        paths = [source_root / ("source-" + str(i))
                 for i in range(len(batch["downloads"]))]
        client = IsolatedRclone(
            shutil.which("rclone"),
            os.environ.get("DOWNLOAD_RCLONE_CONFIG", ""),
            batch["remote"],
            os.environ.get("DOWNLOAD_REMOTE_NAME", ""),
            deadline)
        result = transfer_verified_batch(
            client, batch, paths, os.environ.get("DOWNLOAD_TASK_ROOT", ""))
        if result["confirmed"] != result["total"]:
            raise TransferUnverified("REMOTE_UNVERIFIED")
        print("REMOTE_READBACK_VERIFIED files=" + str(result["confirmed"]))
        return 0
    except (TransferUnverified, InvalidBatch, OSError, TypeError,
            ValueError, KeyError, OverflowError) as error:
        code = error.code if isinstance(error, TransferUnverified) else "TASK_UNVERIFIED"
        # No paths, URLs, exception strings, OAuth config or token in logs.
        # Record counts even on an unknown or partial remote outcome; never
        # infer success solely from objects already present in the cloud.
        confirmed = error.confirmed if isinstance(error, TransferUnverified) else 0
        attempted = error.attempted if isinstance(error, TransferUnverified) else 0
        print("DOWNLOAD_FAILED_OR_UNKNOWN:" + code +
              " confirmed=" + str(confirmed) +
              " attempted=" + str(attempted), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
