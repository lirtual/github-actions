#!/usr/bin/env python3
"""Spec #51 destination planning: owner-controlled base, direct file targets.

No random Task root. Existing remote files are never intentional targets;
actual provider create-only atomicity is not guaranteed.
"""
from download_batch import InvalidBatch, _destination


class DestinationUnverified(ValueError):
    pass


def approved_base_dir(value):
    """Require an explicit Owner-controlled relative cloud directory."""
    try:
        return _destination(value)
    except (InvalidBatch, TypeError):
        raise DestinationUnverified("DESTINATION_UNVERIFIED") from None


def plan_targets(batch, files_by_source, base_dir):
    """Validate the *whole* batch, including cross-source aliases, before writes."""
    base = approved_base_dir(base_dir)
    if (not isinstance(batch, dict) or
            not isinstance(batch.get("downloads"), list) or
            not isinstance(files_by_source, (list, tuple)) or
            len(files_by_source) != len(batch["downloads"]) or
            not files_by_source):
        raise DestinationUnverified("DESTINATION_UNVERIFIED")
    targets, aliases = [], set()
    for i, (source, files) in enumerate(zip(batch["downloads"], files_by_source)):
        if not isinstance(source, dict) or not isinstance(files, (list, tuple)) or not files:
            raise DestinationUnverified("DESTINATION_UNVERIFIED")
        directory = source.get("destination_dir", "")
        try:
            if directory:
                directory = _destination(directory)
        except (InvalidBatch, TypeError):
            raise DestinationUnverified("DESTINATION_UNVERIFIED") from None
        for relative_file in files:
            try:
                path = _destination(relative_file)
                relative_target = _destination(
                    directory + "/" + path if directory else path)
            except (InvalidBatch, TypeError):
                raise DestinationUnverified("DESTINATION_UNVERIFIED") from None
            segments = tuple(part.casefold() for part in relative_target.split("/"))
            if (segments in aliases or
                    any(segments[:len(existing)] == existing or
                        existing[:len(segments)] == segments for existing in aliases)):
                raise DestinationUnverified("DESTINATION_UNVERIFIED")
            aliases.add(segments)
            targets.append({"source_index": i,
                            "source_file": path,
                            "relative_target": relative_target,
                            "remote_target": base + "/" + relative_target})
    return targets
