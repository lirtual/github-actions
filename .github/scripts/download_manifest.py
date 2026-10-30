#!/usr/bin/env python3
"""Strict read-only local artifact census and focused file verification.

Proves local regular-file closure, but not source GID ownership, network
isolation or independent cloud readback. Never log source file paths.
"""
import hashlib
import os
import stat

from download_batch import InvalidBatch, _destination

READ_BLOCK = 1024 * 1024


class TreeUnverified(Exception):
    """Only fail-closed constant error codes."""


def _safe_component(name):
    try:
        _destination(name)
    except (InvalidBatch, ValueError, TypeError):
        raise TreeUnverified("TREE_UNVERIFIED") from None
    return name


def _fingerprint(st):
    return (st.st_dev, st.st_ino, st.st_mode, st.st_size,
            st.st_nlink, st.st_mtime_ns, st.st_ctime_ns)


def _file_digest(parent_fd, name, before, initial_dev):
    flags = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0)
    fd = os.open(name, flags, dir_fd=parent_fd)
    try:
        opened = os.fstat(fd)
        if (not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1 or
                opened.st_dev != initial_dev or
                _fingerprint(before) != _fingerprint(opened)):
            raise TreeUnverified("TREE_UNVERIFIED")
        sha256 = hashlib.sha256()
        md5 = hashlib.md5(usedforsecurity=False)
        remaining = opened.st_size
        while remaining:
            part = os.read(fd, min(READ_BLOCK, remaining))
            if not part:
                raise TreeUnverified("TREE_UNVERIFIED")
            sha256.update(part)
            md5.update(part)
            remaining -= len(part)
        # Check for growth as well as truncation.
        if os.read(fd, 1):
            raise TreeUnverified("TREE_UNVERIFIED")
        if _fingerprint(opened) != _fingerprint(os.fstat(fd)):
            raise TreeUnverified("TREE_UNVERIFIED")
        if _fingerprint(before) != _fingerprint(
                os.stat(name, dir_fd=parent_fd, follow_symlinks=False)):
            raise TreeUnverified("TREE_UNVERIFIED")
        return {"size": opened.st_size, "sha256": sha256.hexdigest(),
                "md5": md5.hexdigest()}
    finally:
        os.close(fd)


def census_tree(root):
    """Return deterministic local file + directory manifests.

    root must be a real directory (not a symlink); no symlinks/hardlinks,
    aliases, special files, or submounts. File count/bytes are not artificially
    capped: OS disk/inode/time limits are checked by a separate Runner gate.
    """
    if os.name != "posix" or not hasattr(os, "O_NOFOLLOW") or not os.supports_dir_fd:
        raise TreeUnverified("TREE_UNVERIFIED")
    root_fd = None
    try:
        root_fd = os.open(root, os.O_RDONLY | os.O_NOFOLLOW | os.O_DIRECTORY)
        root_stat = os.fstat(root_fd)
        if not stat.S_ISDIR(root_stat.st_mode):
            raise TreeUnverified("TREE_UNVERIFIED")
        files, directories = [], []
        # Explicit DFS stack: avoid recursion-depth failures and bound open FDs
        # to ancestry only; every opened directory is closed on success/error.
        def visit(folder_fd, relative):
            observed = os.fstat(folder_fd)
            with os.scandir(folder_fd) as scanner:
                names = [entry.name for entry in scanner]
            # File-only Task cannot verify or preserve empty subdirectories.
            # Never silently discard these entries from the proof.
            if relative and not names:
                raise TreeUnverified("TREE_UNVERIFIED")
            if len(names) != len(set(names)) or len(names) != len(
                    {name.casefold() for name in names}):
                raise TreeUnverified("TREE_UNVERIFIED")
            for name in sorted(names):
                _safe_component(name)
                before = os.stat(name, dir_fd=folder_fd, follow_symlinks=False)
                if before.st_dev != root_stat.st_dev:
                    raise TreeUnverified("TREE_UNVERIFIED")
                path = relative + "/" + name if relative else name
                if stat.S_ISDIR(before.st_mode):
                    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_DIRECTORY,
                                 dir_fd=folder_fd)
                    try:
                        if _fingerprint(before) != _fingerprint(os.fstat(fd)):
                            raise TreeUnverified("TREE_UNVERIFIED")
                        directories.append(path)
                        visit(fd, path)
                        if _fingerprint(before) != _fingerprint(os.fstat(fd)):
                            raise TreeUnverified("TREE_UNVERIFIED")
                    finally:
                        os.close(fd)
                elif stat.S_ISREG(before.st_mode):
                    attributes = _file_digest(folder_fd, name, before, root_stat.st_dev)
                    files.append({"relative_path": path, **attributes})
                else:
                    raise TreeUnverified("TREE_UNVERIFIED")
            if _fingerprint(observed) != _fingerprint(os.fstat(folder_fd)):
                raise TreeUnverified("TREE_UNVERIFIED")
        visit(root_fd, "")
        if _fingerprint(root_stat) != _fingerprint(os.fstat(root_fd)):
            raise TreeUnverified("TREE_UNVERIFIED")
        if not files:
            raise TreeUnverified("TREE_UNVERIFIED")
        return {"files": sorted(files, key=lambda e:e["relative_path"]),
                "directories": sorted(directories),
                "file_count": len(files),
                "total_bytes": sum(f["size"] for f in files)}
    except (OSError, ValueError, TypeError, RecursionError):
        raise TreeUnverified("TREE_UNVERIFIED") from None
    finally:
        if root_fd is not None:
            os.close(root_fd)


def verify_manifest_file(root, expected):
    """Recheck one manifest entry before upload, without rescanning its siblings.

    The caller has already censused the *whole* quiesced source tree, and the
    uploader has that source mounted read-only. Walk every path component using
    no-follow dirfds, then compare the same strong content fingerprint used by
    census_tree. This is linear in the transferred bytes rather than in each
    source's file_count * total_bytes.
    """
    if (os.name != "posix" or not hasattr(os, "O_NOFOLLOW") or
            not isinstance(expected, dict) or
            set(expected) != {"relative_path", "size", "sha256", "md5"} or
            not isinstance(expected["relative_path"], str)):
        raise TreeUnverified("TREE_UNVERIFIED")
    descriptors = []
    try:
        parts = expected["relative_path"].split("/")
        for part in parts:
            _safe_component(part)
        root_fd = os.open(root, os.O_RDONLY | os.O_NOFOLLOW | os.O_DIRECTORY)
        descriptors.append(root_fd)
        root_stat = os.fstat(root_fd)
        if not stat.S_ISDIR(root_stat.st_mode):
            raise TreeUnverified("TREE_UNVERIFIED")
        current = root_fd
        parents = []
        for part in parts[:-1]:
            before = os.stat(part, dir_fd=current, follow_symlinks=False)
            if not stat.S_ISDIR(before.st_mode) or before.st_dev != root_stat.st_dev:
                raise TreeUnverified("TREE_UNVERIFIED")
            child = os.open(part, os.O_RDONLY | os.O_NOFOLLOW | os.O_DIRECTORY,
                            dir_fd=current)
            descriptors.append(child)
            if _fingerprint(before) != _fingerprint(os.fstat(child)):
                raise TreeUnverified("TREE_UNVERIFIED")
            parents.append((current, part, before, child))
            current = child
        leaf = parts[-1]
        before = os.stat(leaf, dir_fd=current, follow_symlinks=False)
        if before.st_dev != root_stat.st_dev:
            raise TreeUnverified("TREE_UNVERIFIED")
        attributes = _file_digest(current, leaf, before, root_stat.st_dev)
        if {"relative_path": expected["relative_path"], **attributes} != expected:
            raise TreeUnverified("TREE_UNVERIFIED")
        for parent_fd, name, prior, child_fd in reversed(parents):
            if (_fingerprint(prior) != _fingerprint(os.fstat(child_fd)) or
                    _fingerprint(prior) != _fingerprint(os.stat(
                        name, dir_fd=parent_fd, follow_symlinks=False))):
                raise TreeUnverified("TREE_UNVERIFIED")
        if _fingerprint(root_stat) != _fingerprint(os.fstat(root_fd)):
            raise TreeUnverified("TREE_UNVERIFIED")
        return True
    except (OSError, ValueError, TypeError):
        raise TreeUnverified("TREE_UNVERIFIED") from None
    finally:
        for fd in reversed(descriptors):
            os.close(fd)
