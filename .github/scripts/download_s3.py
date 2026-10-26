#!/usr/bin/env python3
"""Strict create-if-absent adapter for real AWS S3 OpenList mounts (Spec #51).

Not a generic OpenList uploader. It intentionally bypasses op.Put because the
latter can overwrite/delete a pre-existing object. No source downloader,
Workflow dispatch, or runtime egress authorization is provided here.
"""
import hashlib
import json
import math
import os
from pathlib import Path
import posixpath
import re
import stat
import subprocess
import tempfile
import time
from urllib.parse import urlsplit
from urllib import request as http_request

from download_batch import InvalidBatch, _destination

S3_PART_MIN = 5 * 1024 * 1024
S3_PART_DEFAULT = 64 * 1024 * 1024
S3_MAX_PARTS = 10000
S3_MAX_PART_BYTES = 5 * 1024 ** 3
S3_MAX_OBJECT_BYTES = S3_MAX_PARTS * S3_MAX_PART_BYTES  # AWS 50 TB (48.8 TiB)
# PutObject is limited by S3 itself, not a download business size restriction.
S3_SINGLE_PUT_MAX = 5 * 1000 ** 3
BUCKET = re.compile(r"(?=.{3,63}$)[a-z0-9][a-z0-9.-]*[a-z0-9]\Z")
REGION = re.compile(r"[a-z]{2}(?:-gov)?-(?:[a-z]+-)+\d\Z")
ATTEMPT = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$", re.I)
KEY_FIELD = re.compile(r"^[^\x00-\x1f\x7f\\]+$")


class StorageUnsupported(Exception):
    """Configured OpenList target does not have proven no-clobber semantics."""


class StorageConflict(Exception):
    """Atomic conditional write refused a pre-existing/competing object."""


class StorageUnknown(Exception):
    """Upload outcome or final remote integrity cannot be conclusively proved."""


def _clean_virtual(value):
    try:
        return _destination(value)
    except InvalidBatch:
        raise StorageUnsupported("NOT_SUPPORTED") from None


def _safe_root(value):
    if not isinstance(value, str):
        raise StorageUnsupported("NOT_SUPPORTED")
    if value in ("", "/"):
        return ""
    if (not value.startswith("/") or value.startswith("//") or value.endswith("/")
            or posixpath.normpath(value) != value or "\\" in value
            or any(piece in (".", "..", "") for piece in value.split("/")[1:])):
        raise StorageUnsupported("NOT_SUPPORTED")
    return value.lstrip("/")


def _aws_endpoint_allowed(endpoint, region):
    if endpoint in ("", None):
        return True
    if not isinstance(endpoint, str):
        return False
    try:
        split = urlsplit(endpoint)
        port = split.port
    except ValueError:
        return False
    # Custom S3-compatible services are not automatically AWS S3.
    if (split.scheme != "https" or split.username or split.password
            or split.path not in ("", "/") or split.query or split.fragment
            or port not in (None, 443)):
        return False
    return split.hostname in {
        "s3.amazonaws.com",
        "s3." + region + ".amazonaws.com",
        "s3-" + region + ".amazonaws.com",
    }


def resolve_aws_mount(storages, destination):
    """Resolve exact longest OpenList mount, *including* unsupported overlays."""
    _clean_virtual(destination)
    if not isinstance(storages, list) or not storages:
        raise StorageUnsupported("NOT_SUPPORTED")
    selected = None
    for mount in storages:
        if not isinstance(mount, dict):
            raise StorageUnsupported("NOT_SUPPORTED")
        path = mount.get("mount_path")
        if not isinstance(path, str):
            raise StorageUnsupported("NOT_SUPPORTED")
        if path != "/":
            _clean_virtual(path)
        if destination == path or path == "/" or destination.startswith(path + "/"):
            if selected is None or len(path) > len(selected["mount_path"]):
                selected = mount
    if not selected or selected.get("driver") != "S3" or selected.get("disabled") is not False:
        raise StorageUnsupported("NOT_SUPPORTED")
    if selected.get("status", "").lower() != "work":
        raise StorageUnsupported("NOT_SUPPORTED")
    raw = selected.get("addition")
    try:
        addition = json.loads(raw) if isinstance(raw, str) else raw
    except (ValueError, TypeError):
        raise StorageUnsupported("NOT_SUPPORTED") from None
    if not isinstance(addition, dict):
        raise StorageUnsupported("NOT_SUPPORTED")
    bucket, region = addition.get("bucket"), addition.get("region")
    if (not isinstance(bucket, str) or not BUCKET.fullmatch(bucket)
            or ".." in bucket or not isinstance(region, str)
            or not REGION.fullmatch(region)):
        raise StorageUnsupported("NOT_SUPPORTED")
    if not _aws_endpoint_allowed(addition.get("endpoint"), region):
        raise StorageUnsupported("NOT_SUPPORTED")
    access, secret, token = (addition.get("access_key_id"),
                             addition.get("secret_access_key"),
                             addition.get("session_token", ""))
    if not isinstance(access, str) or not access or not isinstance(secret, str) or not secret:
        raise StorageUnsupported("NOT_SUPPORTED")
    if not isinstance(token, str):
        raise StorageUnsupported("NOT_SUPPORTED")
    root = _safe_root(addition.get("root_folder_path", "/"))
    mount_path = selected["mount_path"]
    suffix = destination[len(mount_path):].lstrip("/") if mount_path != "/" else destination.lstrip("/")
    prefix = posixpath.join(root, suffix) if root else suffix
    if not prefix:
        raise StorageUnsupported("NOT_SUPPORTED")
    # Do not copy addition, which may contain unrelated provider secrets.
    return {"bucket": bucket, "region": region, "access": access,
            "secret": secret, "token": token, "prefix": prefix}


def enumerate_regular_files(folder):
    """Close symlink/hardlink/OS path escapes, for fully downloaded local trees."""
    root = Path(folder)
    if root.is_symlink() or not root.is_dir():
        raise StorageUnsupported("NOT_SUPPORTED")
    found = []
    stack = [(root, "")]
    while stack:
        current, relative = stack.pop()
        with os.scandir(current) as entries:
            for item in entries:
                if (not KEY_FIELD.fullmatch(item.name) or item.name in (".", "..")
                        or "/" in item.name or ":" in item.name
                        or item.name.endswith((" ", "."))):
                    raise StorageUnsupported("NOT_SUPPORTED")
                st = item.stat(follow_symlinks=False)
                child = posixpath.join(relative, item.name)
                if stat.S_ISDIR(st.st_mode):
                    if st.st_nlink < 1:
                        raise StorageUnsupported("NOT_SUPPORTED")
                    stack.append((Path(item.path), child))
                elif stat.S_ISREG(st.st_mode) and st.st_nlink == 1:
                    if st.st_size > S3_MAX_OBJECT_BYTES:
                        raise StorageUnsupported("NOT_SUPPORTED")
                    found.append((Path(item.path), child, st.st_size))
                else:
                    raise StorageUnsupported("NOT_SUPPORTED")
    if not found:
        raise StorageUnsupported("NOT_SUPPORTED")
    return sorted(found, key=lambda value: value[1])


def _sha256_file(file):
    digest = hashlib.sha256()
    with open(file, "rb") as stream:
        for part in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(part)
    return digest.hexdigest()


class AwsConditionalWriter:
    """Only static credential AWS S3 API calls; no endpoint or shell arguments."""

    def __init__(self, mount, attempt, timeout_deadline):
        if not ATTEMPT.fullmatch(attempt):
            raise StorageUnsupported("NOT_SUPPORTED")
        self.mount = mount
        self.attempt = attempt.lower()
        self.deadline = timeout_deadline
        self.env = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "HOME": os.environ.get("RUNNER_TEMP", "/tmp"),
            "AWS_ACCESS_KEY_ID": mount["access"],
            "AWS_SECRET_ACCESS_KEY": mount["secret"],
            "AWS_DEFAULT_REGION": mount["region"],
            "AWS_EC2_METADATA_DISABLED": "true",
            "AWS_CONFIG_FILE": "/dev/null",
            "AWS_SHARED_CREDENTIALS_FILE": "/dev/null",
            "AWS_PAGER": "",
            "AWS_MAX_ATTEMPTS": "1",
            "AWS_CLI_AUTO_PROMPT": "off",
        }
        if mount["token"]:
            self.env["AWS_SESSION_TOKEN"] = mount["token"]

    def call(self, operation, *args):
        # An unknown/nonzero result is never silently retried. In particular
        # re-running an ambiguous create can overwrite only if the condition
        # were lost, so every final write always includes If-None-Match.
        remaining = self.deadline - time.monotonic()
        if remaining <= 1:
            raise StorageUnknown("REMOTE_UNKNOWN")
        command = ["aws", "s3api", operation, "--no-cli-pager", *args]
        try:
            result = subprocess.run(command, env=self.env, stdin=subprocess.DEVNULL,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                    timeout=remaining, check=False)
            if result.returncode != 0:
                # AWS CLI reports verified S3 precondition failures with exact
                # API codes. Never echo its raw diagnostics (may include keys).
                diagnostic = (result.stderr or b"")[:8192]
                if re.search(rb"\((?:PreconditionFailed|ConditionalRequestConflict)\)", diagnostic):
                    raise StorageConflict("DESTINATION_CONFLICT")
                raise StorageUnknown("REMOTE_UNKNOWN")
            value = json.loads(result.stdout or b"{}")
            if not isinstance(value, dict):
                raise ValueError()
            return value
        except (OSError, subprocess.TimeoutExpired, ValueError):
            raise StorageUnknown("REMOTE_UNKNOWN") from None

    def _base(self, key):
        return ("--bucket", self.mount["bucket"], "--key", key)

    def upload_file(self, source, key, size):
        if not isinstance(key, str) or not key or not KEY_FIELD.fullmatch(key):
            raise StorageUnsupported("NOT_SUPPORTED")
        content = _sha256_file(source)
        metadata = ("sha256=" + content, "session-action-attempt=" + self.attempt)
        base = self._base(key)
        if size <= S3_SINGLE_PUT_MAX:
            self.call("put-object", *base, "--body", str(source),
                      "--if-none-match", "*", "--metadata", *metadata)
        else:
            self.multipart(source, size, base, metadata)
        # Read-back verification uses the native S3 API, not OpenList cache.
        head = self.call("head-object", *base)
        observed = head.get("Metadata")
        if (head.get("ContentLength") != size
                or not isinstance(observed, dict)
                or observed.get("sha256") != content
                or observed.get("session-action-attempt") != self.attempt):
            raise StorageUnknown("REMOTE_UNKNOWN")
        if _sha256_file(source) != content:
            raise StorageUnknown("REMOTE_UNKNOWN")
        return size

    def multipart(self, source, size, base, metadata):
        # S3's documented physical limits only; no product-level byte cap.
        part_size = max(S3_PART_DEFAULT, math.ceil(size / S3_MAX_PARTS))
        if not S3_PART_MIN <= part_size <= S3_MAX_PART_BYTES:
            raise StorageUnsupported("NOT_SUPPORTED")
        created = self.call("create-multipart-upload", *base, "--metadata", *metadata)
        upload_id = created.get("UploadId")
        if not isinstance(upload_id, str) or not upload_id:
            raise StorageUnknown("REMOTE_UNKNOWN")
        complete = False
        try:
            completed_parts = []
            with open(source, "rb") as stream:
                for number in range(1, math.ceil(size / part_size) + 1):
                    with tempfile.NamedTemporaryFile(
                        dir=os.environ.get("RUNNER_TEMP", "/tmp")
                    ) as scratch:
                        remaining = min(part_size, size - (number - 1) * part_size)
                        while remaining:
                            data = stream.read(min(remaining, 1024 * 1024))
                            if not data:
                                raise StorageUnknown("REMOTE_UNKNOWN")
                            scratch.write(data)
                            remaining -= len(data)
                        scratch.flush()
                        # Still open: automatic unlink even on transport failure.
                        uploaded = self.call(
                            "upload-part", *base, "--upload-id", upload_id,
                            "--part-number", str(number), "--body", scratch.name)
                    etag = uploaded.get("ETag")
                    if not isinstance(etag, str) or not etag:
                        raise StorageUnknown("REMOTE_UNKNOWN")
                    completed_parts.append({"ETag": etag, "PartNumber": number})
            with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8",
                                              dir=os.environ.get("RUNNER_TEMP", "/tmp"),
                                              delete=False) as manifest:
                manifest_path = manifest.name
                json.dump({"Parts": completed_parts}, manifest)
            try:
                self.call("complete-multipart-upload", *base,
                          "--upload-id", upload_id, "--multipart-upload",
                          "file://" + manifest_path, "--if-none-match", "*")
                complete = True
            finally:
                os.unlink(manifest_path)
        finally:
            if not complete:
                try:
                    # Abort only our own UploadId; never DeleteObject or retry
                    # an uncertain final write. Abort cannot undo a completed write.
                    self.call("abort-multipart-upload", *base, "--upload-id", upload_id)
                except StorageUnknown:
                    pass


def upload_tree(storages, destination, folder, attempt, deadline):
    """Upload one already-finalized local source tree; never retry unknown writes."""
    mount = resolve_aws_mount(storages, destination)
    files = enumerate_regular_files(folder)
    writer = AwsConditionalWriter(mount, attempt, deadline)
    total = 0
    for source, rel, size in files:
        key = posixpath.join(mount["prefix"], rel)
        total += writer.upload_file(source, key, size)
    return {"files": len(files), "bytes": total, "remote_observed": "all_verified"}
