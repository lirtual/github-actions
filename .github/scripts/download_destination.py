#!/usr/bin/env python3
"""Pure Spec #51 Task-scoped destination planning (not an uploader).

The physical Runner supplies its own GitHub run ID and attempt. This module
never accepts a caller-provided remote root, does not contact a cloud service,
and does not prove server-side atomic create-only. Cloud root absence, remote
access controls and independent upload/readback remain separate runtime gates.
"""

import os
import re
import secrets
import stat
import sys

from download_batch import InvalidBatch, _destination

RUN = re.compile(r'[1-9][0-9]{0,19}\Z')
TASK_SUFFIX = re.compile(r'run-([1-9][0-9]{0,19})-([1-9][0-9]{0,19})-([a-f0-9]{32})\Z')


class DestinationUnverified(ValueError):
    """A fixed safe failure code without user-supplied paths."""


def _run_number(value):
    if not isinstance(value, str) or RUN.fullmatch(value) is None:
        raise DestinationUnverified('DESTINATION_UNVERIFIED')
    return value


def approved_base_dir(value):
    """An Owner-supplied relative directory, never a Task-provided path.

    Require an explicit setting; do not silently switch to the cloud root or
    change an approved destination when its configuration is missing.
    """
    try:
        return _destination(value)
    except (InvalidBatch, TypeError):
        raise DestinationUnverified('DESTINATION_UNVERIFIED') from None


def new_task_root(physical_run_id, physical_attempt, base_dir):
    """Allocate a unique Task root beneath the fixed, validated Owner base."""
    run = _run_number(physical_run_id)
    attempt = _run_number(physical_attempt)
    base = approved_base_dir(base_dir)
    return f'{base}/run-{run}-{attempt}-{secrets.token_hex(16)}'


def verify_task_root(root, base_dir):
    """Require the complete Task root to remain immediately under the base."""
    base = approved_base_dir(base_dir)
    if (not isinstance(root, str) or
            not root.startswith(base + '/') or
            TASK_SUFFIX.fullmatch(root[len(base) + 1:]) is None):
        raise DestinationUnverified('DESTINATION_UNVERIFIED')
    return root


def plan_targets(batch, files_by_source, task_root, base_dir):
    """Return side-effect-free, whole-batch targets before any cloud write.

    files_by_source includes exact paths under each independent aria2 source
    root, produced by the proven source/manifest closure, not caller input.
    This function guarantees that normal Task destination paths are disjoint;
    no promise of server-atomic no-clobber under a malicious competing writer.
    """
    task_root = verify_task_root(task_root, base_dir)
    if (not isinstance(batch, dict) or
            not isinstance(batch.get('downloads'), list) or
            not isinstance(files_by_source, (list, tuple)) or
            len(files_by_source) != len(batch['downloads']) or
            not files_by_source):
        raise DestinationUnverified('DESTINATION_UNVERIFIED')
    targets = []
    aliases = set()
    for i, (source, files) in enumerate(zip(batch['downloads'], files_by_source)):
        if not isinstance(source, dict) or not isinstance(files, (list, tuple)) or not files:
            raise DestinationUnverified('DESTINATION_UNVERIFIED')
        try:
            directory = _destination(source['destination_dir'])
        except (InvalidBatch, KeyError, TypeError):
            raise DestinationUnverified('DESTINATION_UNVERIFIED') from None
        for relative_file in files:
            try:
                path = _destination(relative_file)
                relative_target = _destination(directory + '/' + path)
            except (InvalidBatch, TypeError):
                raise DestinationUnverified('DESTINATION_UNVERIFIED') from None
            segments = tuple(part.casefold() for part in relative_target.split('/'))
            if (segments in aliases or
                    any(segments[:len(existing)] == existing or
                        existing[:len(segments)] == segments
                        for existing in aliases)):
                raise DestinationUnverified('DESTINATION_UNVERIFIED')
            aliases.add(segments)
            targets.append({'source_index': i,
                            'source_file': path,
                            'relative_target': relative_target,
                            'remote_target': task_root + '/' + relative_target})
    return targets


def main():
    """Allocate one private-to-the-Task namespace after successful Claim.

    This is not an upload or evidence of remote directory absence. Publishing
    one output lets later E2E runtime use exactly the same random namespace.
    """
    try:
        root = new_task_root(os.environ.get('GITHUB_RUN_ID'),
                             os.environ.get('GITHUB_RUN_ATTEMPT'),
                             os.environ.get('DOWNLOAD_REMOTE_BASE_DIR'))
        output = os.environ.get('GITHUB_OUTPUT')
        # This Task is Linux-only. Windows has no O_NOFOLLOW and must fail
        # with a safe diagnostic, rather than weakening the file-open guard.
        if (os.name != 'posix' or not hasattr(os, 'O_NOFOLLOW') or
                not output or not os.path.isabs(output)):
            raise DestinationUnverified('DESTINATION_UNVERIFIED')
        flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW
        fd = os.open(output, flags, 0o600)
        with os.fdopen(fd, 'a', encoding='ascii') as stream:
            if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                raise DestinationUnverified('DESTINATION_UNVERIFIED')
            # The add-mask command takes effect before subsequent step env
            # banners reveal outputs; do not print the private suffix in logs.
            print('::add-mask::' + root, flush=True)
            stream.write('task_root=' + root + '\n')
        print('TASK_ROOT_ALLOCATED')
        return 0
    except (DestinationUnverified, OSError, ValueError):
        print('TASK_ROOT_UNAVAILABLE', file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
