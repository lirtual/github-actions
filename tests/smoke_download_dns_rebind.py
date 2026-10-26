#!/usr/bin/env python3
"""CI-only hostile DNS answer-switch smoke, within existing restricted bridge.

Synthetic public-looking A answer switches to the host gateway's PRIVATE A.
A real aria2 client must not fetch the host-only HTTP fixture after the switch.
This exercises one IPv4 answer-switch path, not every DNS rebinding variant.
No arbitrary URLs, provider secrets, BT traffic or user data.
"""
import json
import os
from pathlib import Path
import re
import secrets
import socket
import struct
import subprocess
import tempfile
import threading
import time
from urllib.request import ProxyHandler, Request, build_opener

gateway = os.environ.get("HOST_GATEWAY", "")
if not re.fullmatch(r"172\.(?:1[6-9]|2[0-9]|3[01])\.\d{1,3}\.\d{1,3}", gateway):
    raise SystemExit("DNS_FIXTURE_UNVERIFIED")

domain = "sa51-rebind.example.com"
hostname = b"".join(bytes((len(label),)) + label.encode() for label in domain.split(".")) + b"\0"
address_public = socket.inet_aton("1.1.1.1")
address_private = socket.inet_aton(gateway)
ready = threading.Event()
stopped = threading.Event()
returned_private = []

def parse_question(message):
    if len(message) < 17:
        return None
    cursor = 12
    names = []
    while True:
        if cursor >= len(message):
            return None
        count = message[cursor]
        cursor += 1
        if count == 0:
            break
        if count & 0xc0 or cursor + count > len(message):
            return None
        names.append(message[cursor:cursor + count].lower())
        cursor += count
    if cursor + 4 > len(message):
        return None
    return b".".join(names).decode("ascii"), struct.unpack("!HH", message[cursor:cursor + 4]), cursor + 4

def dns_loop():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server:
        server.bind(("127.0.0.1", 53))
        server.settimeout(.25)
        while not stopped.is_set():
            try:
                req, peer = server.recvfrom(512)
            except socket.timeout:
                continue
            question = parse_question(req)
            if question is None:
                continue
            name, (kind, klass), end = question
            if name != domain or klass != 1:
                continue
            answer = b""
            if kind == 1:
                private = ready.is_set()
                if private:
                    returned_private.append(True)
                ip = address_private if private else address_public
                answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 0, 4) + ip
            flags = b"\x81\x80"
            counts = struct.pack("!HHHH", 1, 1 if answer else 0, 0, 0)
            server.sendto(req[:2] + flags + counts + req[12:end] + answer, peer)

thread = threading.Thread(target=dns_loop, daemon=True)
thread.start()
client = build_opener(ProxyHandler({}))

def probe():
    ident = secrets.token_bytes(2)
    payload = ident + b"\x01\x00" + struct.pack("!HHHH", 1, 0, 0, 0) + hostname + struct.pack("!HH", 1, 1)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
        udp.settimeout(2)
        udp.sendto(payload, ("127.0.0.1", 53))
        reply, _ = udp.recvfrom(512)
    if reply[:2] != ident or reply[-4:] not in (address_public, address_private):
        raise AssertionError("DNS_PROBE_INVALID")
    return reply[-4:]

def rpc(secret, method, *args):
    ident = secrets.token_hex(8)
    data = json.dumps({"jsonrpc":"2.0", "id":ident, "method":method,
                       "params":["token:"+secret, *args]}).encode()
    request = Request("http://127.0.0.1:6800/jsonrpc", data=data,
                      headers={"Content-Type":"application/json"})
    with client.open(request, timeout=3) as response:
        body = json.loads(response.read(1024 * 1024))
    if body.get("id") != ident or "error" in body:
        raise AssertionError("DNS_ARIA2_RPC_FAILED")
    return body["result"]

try:
    for _ in range(20):
        try:
            if probe() == address_public:
                break
        except (OSError, AssertionError):
            time.sleep(.1)
    else:
        raise AssertionError("DNS_INITIAL_PUBLIC_FAILED")
    ready.set()
    if probe() != address_private:
        raise AssertionError("DNS_ANSWER_SWITCH_FAILED")
    with tempfile.TemporaryDirectory() as scratch:
        secret = secrets.token_hex(24)
        gid = secrets.token_hex(8)
        argv = [
            "aria2c", "--no-conf", "--enable-rpc=true", "--rpc-listen-all=false",
            "--rpc-listen-port=6800", "--rpc-secret=" + secret,
            "--disable-ipv6=true", "--enable-dht=false",
            "--follow-torrent=false", "--follow-metalink=false",
            "--max-tries=1", "--connect-timeout=2", "--timeout=3",
            "--max-concurrent-downloads=1", "--split=1",
            "--file-allocation=none", "--console-log-level=error", "--dir=" + scratch
        ]
        process = subprocess.Popen(argv, stdout=subprocess.DEVNULL,
                                   stderr=subprocess.DEVNULL, env={"PATH": os.environ["PATH"]})
        try:
            for _ in range(60):
                if process.poll() is not None:
                    raise AssertionError("DNS_ARIA2_EXITED")
                try:
                    rpc(secret, "aria2.getGlobalStat")
                    break
                except (OSError, ValueError):
                    time.sleep(.1)
            else:
                raise AssertionError("DNS_ARIA2_NOT_READY")
            submitted = rpc(secret, "aria2.addUri", ["http://" + domain + ":18081/"],
                            {"gid":gid,"dir":scratch,"out":"blocked.txt",
                             "max-tries":"1","connect-timeout":"2","timeout":"3"})
            if submitted != gid:
                raise AssertionError("DNS_GID_MISMATCH")
            for _ in range(70):
                state = rpc(secret, "aria2.tellStatus", gid, ["status"])
                if state["status"] == "error":
                    break
                if state["status"] in ("complete", "removed"):
                    raise AssertionError("DNS_REBOUND_PRIVATE_EGRESS_UNSAFE")
                time.sleep(.1)
            else:
                raise AssertionError("DNS_ARIA2_TERMINAL_MISSING")
            output = Path(scratch) / "blocked.txt"
            if output.exists() and b"PRIVATE_FIXTURE" in output.read_bytes():
                raise AssertionError("DNS_PRIVATE_FIXTURE_LEAKED")
            if not returned_private:
                raise AssertionError("DNS_PRIVATE_ANSWER_NOT_SERVED_TO_CLIENT")
            print("REAL_ARIA2_DNS_ANSWER_SWITCH_PRIVATE_EGRESS_DENIED")
        finally:
            process.terminate()
            try:
                process.wait(timeout=4)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=4)
finally:
    stopped.set()
    thread.join(timeout=3)
