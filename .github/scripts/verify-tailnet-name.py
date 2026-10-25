"""Fail closed if Tailscale allocated a suffixed name instead of the requested MagicDNS name."""
import json
import os
import re
import subprocess


def verify_hostname(status: object, expected: str) -> None:
    if not re.fullmatch(r"[a-z][a-z0-9-]{0,62}", expected) or expected.endswith("-"):
        raise ValueError("invalid requested Tailnet hostname")
    if not isinstance(status, dict) or status.get("BackendState") != "Running":
        raise ValueError("Tailnet is not connected")
    self_node = status.get("Self")
    if not isinstance(self_node, dict):
        raise ValueError("Tailnet node identity missing")
    dns_name = self_node.get("DNSName")
    if not isinstance(dns_name, str) or "." not in dns_name.rstrip("."):
        raise ValueError("Tailnet MagicDNS identity missing")
    actual = dns_name.rstrip(".").split(".", 1)[0].lower()
    if actual != expected:
        raise ValueError("Tailnet allocated another hostname (possible stale device)")


def main() -> None:
    expected = os.environ.get("SESSION_TAILSCALE_HOSTNAME", "")
    try:
        result = subprocess.run(
            ["tailscale", "status", "--json"], capture_output=True,
            text=True, timeout=20, check=True,
        )
        verify_hostname(json.loads(result.stdout), expected)
    except (OSError, ValueError, subprocess.SubprocessError):
        raise SystemExit("Tailnet hostname verification failed; refusing Session Ready") from None
    print("Tailnet hostname confirmed:", expected)


if __name__ == "__main__":
    main()
