#!/usr/bin/env python3
"""Bounded, side-effect-free Spec #51 HTTP(S) batch syntax validator.

Syntax is NOT network authorization, remote qualification, or permission to
perform uploads. The immutable Task must remain disabled until its full gates
(including Task root isolation and real remote readback) are satisfied.
"""
import ipaddress
import json
import os
import posixpath
import re
import sys
import unicodedata
from urllib.parse import unquote, urlsplit

MAX_INPUT_BYTES = 4096
MAX_MINUTES = 330
FIELDS = frozenset({'remote', 'downloads', 'project_purpose', 'duration_minutes'})
LINK_FIELDS = frozenset({'url', 'destination_dir'})
HOST = re.compile(r'^[a-zA-Z0-9.-]{1,253}$')
REMOTE = re.compile(r'^[A-Za-z][A-Za-z0-9_-]{0,63}$')
WINDOWS_RESERVED = re.compile(r'^(?:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\..*)?$', re.I)


class InvalidBatch(ValueError):
    """Safe constant codes only; never include caller-controlled strings."""


def _unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise InvalidBatch('duplicate_json_key')
        result[key] = value
    return result


def _safe_text(value, maximum, code):
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise InvalidBatch(code)
    if (any(ord(c) < 32 or ord(c) == 127 or 0xD800 <= ord(c) <= 0xDFFF
            for c in value) or unicodedata.normalize('NFC', value) != value):
        raise InvalidBatch(code)
    return value


def _public_hostname(hostname):
    if not hostname:
        raise InvalidBatch('source_invalid')
    try:
        ip = ipaddress.ip_address(hostname)
    except ValueError:
        if (not HOST.fullmatch(hostname) or '..' in hostname or
                hostname.startswith(('-', '.')) or hostname.endswith(('-', '.')) or
                '.' not in hostname or hostname.lower().endswith(
                    ('.local', '.localhost', '.internal', '.invalid', '.test',
                     '.onion', '.home.arpa'))):
            raise InvalidBatch('source_invalid')
    else:
        if not ip.is_global:
            raise InvalidBatch('source_invalid')


def _source(value):
    url = _safe_text(value, 2048, 'source_invalid')
    try:
        parsed = urlsplit(url)
        if parsed.scheme not in ('http', 'https'):
            raise InvalidBatch('source_not_supported')
        if parsed.username or parsed.password or parsed.fragment or parsed.query:
            raise InvalidBatch('source_invalid')
        if (not parsed.path.startswith('/') or unquote(parsed.path).lower().endswith('.torrent')
                or parsed.path.startswith('//')):
            raise InvalidBatch('source_not_supported')
        _public_hostname(parsed.hostname)
        if parsed.port is not None and parsed.port not in (80, 443):
            raise InvalidBatch('source_invalid')
    except (ValueError, UnicodeError) as error:
        if isinstance(error, InvalidBatch):
            raise
        raise InvalidBatch('source_invalid') from None
    return url


def _destination(value):
    dest = _safe_text(value, 1024, 'destination_invalid')
    if (dest.startswith('/') or dest.endswith('/') or '\\' in dest or
            any(c in dest for c in ':%?#') or posixpath.normpath(dest) != dest or
            unicodedata.normalize('NFKC', dest) != dest):
        raise InvalidBatch('destination_invalid')
    parts = dest.split('/')
    if any((not part or part in ('.', '..') or part != part.strip() or
            part.endswith('.') or WINDOWS_RESERVED.fullmatch(part)) for part in parts):
        raise InvalidBatch('destination_invalid')
    return dest


def validate(payload):
    """Parse untrusted input. Do not log or serialize the returned URLs."""
    if not isinstance(payload, str):
        raise InvalidBatch('batch_invalid')
    try:
        raw = payload.encode('utf-8')
    except UnicodeEncodeError:
        raise InvalidBatch('batch_invalid') from None
    if not raw or len(raw) > MAX_INPUT_BYTES:
        raise InvalidBatch('batch_size_invalid')
    try:
        batch = json.loads(payload, object_pairs_hook=_unique_pairs,
                           parse_constant=lambda _: (_ for _ in ()).throw(
                               InvalidBatch('batch_invalid')))
    except (ValueError, UnicodeError, TypeError):
        raise InvalidBatch('batch_invalid') from None
    if not isinstance(batch, dict) or set(batch) - FIELDS:
        raise InvalidBatch('batch_invalid')
    remote = _safe_text(batch.get('remote'), 64, 'remote_invalid')
    if not REMOTE.fullmatch(remote):
        raise InvalidBatch('remote_invalid')
    purpose = _safe_text(batch.get('project_purpose'), 280, 'purpose_invalid')
    duration = batch.get('duration_minutes', 300)
    if type(duration) is not int or not 1 <= duration <= MAX_MINUTES:
        raise InvalidBatch('duration_invalid')
    sources = batch.get('downloads')
    if not isinstance(sources, list) or not sources:
        raise InvalidBatch('downloads_invalid')
    approved = []
    dirs = []
    for item in sources:
        if not isinstance(item, dict) or set(item) != LINK_FIELDS:
            raise InvalidBatch('downloads_invalid')
        url = _source(item['url'])
        dest = _destination(item['destination_dir'])
        # Different spelling of the same directory is an alias. Identical
        # directory paths are allowed; actual FILE collisions must be checked
        # after downloads, before the first upload.
        key = dest.casefold()
        if any(key == prior_key and dest != prior_name
               for prior_key, prior_name in dirs):
            raise InvalidBatch('destination_conflict')
        dirs.append((key, dest))
        approved.append({'url': url, 'destination_dir': dest})
    return {'remote': remote, 'downloads': approved,
            'project_purpose': purpose, 'duration_minutes': duration}


def load_batch_json():
    """Read bounded dispatch input without placing URLs in Actions step env logs.

    Tests can continue supplying BATCH_JSON directly. The production workflow
    reads the GitHub-owned event file, not a logged step environment variable.
    """
    if 'BATCH_JSON' in os.environ:
        return os.environ['BATCH_JSON']
    event_path = os.environ.get('GITHUB_EVENT_PATH', '')
    if not event_path or not os.path.isabs(event_path):
        return ''
    try:
        with open(event_path, 'rb') as stream:
            raw = stream.read(1024 * 1024 + 1)
        if len(raw) > 1024 * 1024:
            return ''
        event = json.loads(raw, object_pairs_hook=_unique_pairs)
        value = event.get('inputs', {}).get('batch_json', '')
        return value if isinstance(value, str) else ''
    except (OSError, ValueError, TypeError, AttributeError):
        return ''


def main():
    try:
        batch = validate(load_batch_json())
    except InvalidBatch as error:
        print('BATCH_REJECTED:' + str(error), file=sys.stderr)
        return 2
    print('BATCH_SYNTAX_VALID: links=' + str(len(batch['downloads'])))
    print('RUNTIME_NOT_AUTHORIZED: task root isolation, egress and remote readback unverified')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
