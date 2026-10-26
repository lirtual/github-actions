#!/usr/bin/env python3
"""Read-only, loopback-exclusive aria2 JSON-RPC snapshot for Spec #51.

Only seven fixed read-only query methods are allowed. Does not start/stop/download tasks,
create sockets to public hosts, access Koofr, or print credentials or URL data.

The caller must still prove it owns a fresh isolated aria2 process and has
quiesced all source submissions before trusting any snapshots.
"""
import json
import secrets
import time
import urllib.error
import urllib.request

from download_source import SourceUnverified, verify_queue_closed

URL = "http://127.0.0.1:6800/jsonrpc"
MAX_BYTES = 1024 * 1024
MAX_GIDS = 200
SAFE_METHODS = frozenset((
    "aria2.getGlobalStat", "aria2.tellActive", "aria2.tellWaiting",
    "aria2.tellStopped", "aria2.tellStatus", "aria2.getFiles", "aria2.getUris",
))
DETAIL_KEYS = ("gid", "status", "totalLength", "completedLength",
               "dir", "followedBy", "following", "belongsTo")


class ReadOnlyRPCUnavailable(Exception):
    pass


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        return None


def opener():
    return urllib.request.build_opener(
        urllib.request.ProxyHandler({}), NoRedirect())


class Aria2Reader:
    def __init__(self, secret, deadline, transport=None):
        if (not isinstance(secret, str) or not 16 <= len(secret) <= 256 or
                any(ord(c) < 33 or ord(c) > 126 for c in secret)):
            raise ReadOnlyRPCUnavailable("ARIA2_UNVERIFIED")
        if not isinstance(deadline, (int, float)):
            raise ReadOnlyRPCUnavailable("ARIA2_UNVERIFIED")
        self._auth = "token:" + secret
        self._deadline = deadline
        self._transport = transport or opener()

    def _request(self, method, args):
        if method not in SAFE_METHODS:
            raise ReadOnlyRPCUnavailable("ARIA2_UNVERIFIED")
        remaining = self._deadline - time.monotonic()
        if remaining <= 1:
            raise ReadOnlyRPCUnavailable("ARIA2_UNVERIFIED")
        rid = secrets.token_hex(12)
        body = json.dumps({"jsonrpc":"2.0", "id":rid,
                           "method":method, "params":[self._auth, *args]},
                          separators=(",", ":")).encode("utf-8")
        req = urllib.request.Request(
            URL, method="POST", data=body,
            headers={"Content-Type":"application/json","Accept":"application/json"})
        try:
            with self._transport.open(req, timeout=min(remaining, 10)) as response:
                if response.getcode() != 200:
                    raise ReadOnlyRPCUnavailable("ARIA2_UNVERIFIED")
                raw = response.read(MAX_BYTES + 1)
            if len(raw) > MAX_BYTES:
                raise ReadOnlyRPCUnavailable("ARIA2_UNVERIFIED")
            result = json.loads(raw)
        except (OSError, ValueError, TypeError, urllib.error.URLError):
            raise ReadOnlyRPCUnavailable("ARIA2_UNVERIFIED") from None
        if (not isinstance(result, dict) or
                result.get("jsonrpc") != "2.0" or
                result.get("id") != rid or
                "error" in result or "result" not in result):
            raise ReadOnlyRPCUnavailable("ARIA2_UNVERIFIED")
        return result["result"]

    def read_closed(self, gids):
        """Fetch all exact known result rows, reject queue history truncation.

        Does not independently prove that queue snapshots were taken atomically.
        A caller must be the only producer and must stop all submissions.
        """
        if not isinstance(gids, (list, tuple)) or not 1 <= len(gids) <= MAX_GIDS:
            raise ReadOnlyRPCUnavailable("ARIA2_UNVERIFIED")
        # Force validation first without querying or revealing any GID.
        import re
        if (any(not isinstance(x,str) or not re.fullmatch(r"[a-fA-F0-9]{16}",x)
                for x in gids) or len(set(gids)) != len(gids)):
            raise ReadOnlyRPCUnavailable("ARIA2_UNVERIFIED")
        try:
            stats = self._request("aria2.getGlobalStat", [])
            if not isinstance(stats, dict):
                raise ReadOnlyRPCUnavailable("ARIA2_UNVERIFIED")
            # In an exclusively owned fresh aria2 instance the expected stopped
            # count must exactly equal the known source list.
            from download_source import number
            retained = number(stats.get("numStopped"))
            total = number(stats.get("numStoppedTotal"))
            if (retained != len(gids) or total != len(gids)
                    or number(stats.get("numActive")) != 0
                    or number(stats.get("numWaiting")) != 0):
                raise ReadOnlyRPCUnavailable("ARIA2_UNVERIFIED")
            active = self._request("aria2.tellActive", [list(DETAIL_KEYS)])
            waiting = self._request("aria2.tellWaiting", [0, MAX_GIDS, list(DETAIL_KEYS)])
            stopped = self._request("aria2.tellStopped", [0, MAX_GIDS, list(DETAIL_KEYS)])
            verify_queue_closed(gids, stats, active, waiting, stopped)
            rows = []
            for gid in gids:
                status = self._request("aria2.tellStatus", [gid,list(DETAIL_KEYS)])
                files = self._request("aria2.getFiles", [gid])
                uris = self._request("aria2.getUris", [gid])
                rows.append({"gid":gid, "status":status, "files":files, "uris":uris})
            final_stats = self._request("aria2.getGlobalStat", [])
            if not isinstance(final_stats, dict):
                raise ReadOnlyRPCUnavailable("ARIA2_UNVERIFIED")
            # Transfer speed is inherently time-varying even when the queue is
            # closed. Only identity-bearing counts belong to this comparison.
            for key in ("numActive","numWaiting","numStopped","numStoppedTotal"):
                if number(final_stats.get(key)) != number(stats.get(key)):
                    raise ReadOnlyRPCUnavailable("ARIA2_UNVERIFIED")
            return {"queue":{"stats":stats,"active":active,
                             "waiting":waiting,"stopped":stopped},
                    "sources":rows}
        except (SourceUnverified, TypeError, ValueError):
            raise ReadOnlyRPCUnavailable("ARIA2_UNVERIFIED") from None
