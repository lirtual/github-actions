"""Exercise the real loopback code-server GUI on the stock GitHub Runner.

ChromeDriver and Chrome are supplied by ubuntu-latest; no npm/pip dependency,
external Tunnel, authentication bypass, repository credentials or user files.
"""
import base64
import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
import tempfile
import time
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


def wait_for(fn, timeout=20):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = fn()
        if result:
            return result
        time.sleep(0.25)
    raise RuntimeError("Timed out waiting for code-server terminal behavior")


def main():
    with tempfile.TemporaryDirectory(prefix="code-server-terminal-") as temp:
        marker = Path(temp) / "result"
        value = secrets.token_hex(16)
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        base = f"http://127.0.0.1:{port}"
        driver = subprocess.Popen(["chromedriver", f"--port={port}",
                                   "--allowed-ips=127.0.0.1"],
                                  stdout=subprocess.DEVNULL,
                                  stderr=subprocess.DEVNULL)
        session = None

        def request(method, path, payload=None, timeout=10):
            data = None if payload is None else json.dumps(payload).encode()
            req = Request(base + path, data=data, method=method,
                          headers={"Content-Type": "application/json"})
            try:
                with urlopen(req, timeout=timeout) as response:
                    return json.load(response)["value"]
            except HTTPError as error:
                raise RuntimeError(f"ChromeDriver {path}: {error.read().decode()}") from error

        def ready():
            try:
                return request("GET", "/status").get("ready")
            except (URLError, TimeoutError):
                return False

        try:
            wait_for(ready, 10)
            result = request("POST", "/session", {"capabilities": {
                "alwaysMatch": {"browserName": "chrome",
                                "goog:loggingPrefs": {"performance": "ALL"},
                                "goog:chromeOptions": {"args": [
                                    "--headless=new", "--window-size=1440,900"]}}}},
                             timeout=60)
            session = "/session/" + result["sessionId"]

            def js(script):
                return request("POST", session + "/execute/sync",
                               {"script": script, "args": []})

            def keys(text):
                active = request("GET", session + "/element/active")
                element = active["element-6066-11e4-a52e-4f735466cecf"]
                request("POST", session + "/element/" + element + "/value",
                        {"text": text})

            def command(name):
                keys("\ue031")  # F1 opens the command palette.
                wait_for(lambda: js("return !!document.querySelector('.quick-input-widget input')"))
                keys(name)
                wait_for(lambda: js("return [...document.querySelectorAll('.quick-input-list .monaco-list-row')].some(e => e.innerText.includes(" + json.dumps(name) + "))"))
                keys("\ue007")

            request("POST", session + "/url", {"url": "http://127.0.0.1:8080/"})
            wait_for(lambda: js("return !!document.querySelector('.monaco-workbench')"), 45)
            command("Terminal: Create New Terminal")
            wait_for(lambda: js("return !!document.querySelector('.xterm textarea')"))
            js("document.querySelector('.xterm textarea').focus(); return true")
            # Input must reach the real PTY and shell; a rendered panel or
            # echoed input alone cannot produce this per-run file.
            left, right = value[:16], value[16:]
            # The contiguous value is absent from the typed command, so
            # shell input echo cannot satisfy the output assertion.
            keys(f"printf '%s%s' '{left}' '{right}' > '{marker}'; cat '{marker}'; echo\ue007")
            wait_for(lambda: marker.exists() and marker.read_text() == value)
            # Observe browser-side incoming WebSocket frames, not a second
            # UI shortcut or the Runner's own stdout. The marker is never
            # sent as a contiguous string in the input command.
            tails = {}

            def output_received():
                entries = request("POST", session + "/se/log", {"type": "performance"})
                for entry in entries:
                    event = json.loads(entry["message"])["message"]
                    if event["method"] != "Network.webSocketFrameReceived":
                        continue
                    params = event["params"]
                    frame = params["response"]
                    payload = (base64.b64decode(frame["payloadData"])
                               if frame["opcode"] == 2
                               else frame["payloadData"].encode())
                    channel = params["requestId"]
                    combined = tails.get(channel, b"") + payload
                    if value.encode() in combined:
                        return True
                    tails[channel] = combined[-len(value):]
                return False

            wait_for(output_received)
            print("CODE_SERVER_TERMINAL_COMMAND_AND_OUTPUT_VERIFIED")
        except Exception:
            if session:
                try:
                    print("Workbench:", js("return document.body.innerText.slice(-2500)"))
                except Exception:
                    pass
            log = Path(os.environ["RUNNER_TEMP"]) / "code-server-session.log"
            if log.exists():
                print(log.read_text(errors="replace")[-6000:])
            raise
        finally:
            try:
                if session:
                    request("DELETE", session)
            finally:
                driver.terminate()
                driver.wait(timeout=10)


if __name__ == "__main__":
    main()
