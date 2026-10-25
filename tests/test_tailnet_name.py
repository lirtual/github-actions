"""The requested fixed name must never silently become a suffixed Tailscale device."""
import json
import os
from pathlib import Path
import runpy
import subprocess
import unittest
from unittest import mock

VERIFY = runpy.run_path(str(Path(__file__).resolve().parents[1] / ".github/scripts/verify-tailnet-name.py"))
verify_hostname = VERIFY["verify_hostname"]


def status(name):
    return {"BackendState": "Running",
            "Self": {"DNSName": name + ".tailnet.example.ts.net.", "HostName": name}}


class TailnetNameTests(unittest.TestCase):
    def test_fixed_and_temporary_names_are_exact(self):
        for name in ("session-windows", "session-ubuntu", "sa-40198100967-a1"):
            verify_hostname(status(name), name)

    def test_stale_device_suffix_is_never_accepted(self):
        for name in ("session-windows", "session-ubuntu"):
            with self.assertRaisesRegex(ValueError, "another hostname"):
                verify_hostname(status(name + "-1"), name)

    def test_invalid_or_unavailable_magic_dns_fails_closed(self):
        for bad in (
            {"BackendState": "Stopped", "Self": {"DNSName": "session-windows.test."}},
            {"BackendState": "Running", "Self": {"HostName": "session-windows"}},
            {"BackendState": "Running", "Self": {"DNSName": "session-windows"}},
        ):
            with self.assertRaises(ValueError):
                verify_hostname(bad, "session-windows")
        for requested in ("", "Session-Windows", "session-windows-", "../other"):
            with self.assertRaises(ValueError):
                verify_hostname(status("session-windows"), requested)

    def test_cli_rejects_collision_before_ready(self):
        reply = subprocess.CompletedProcess([], 0, stdout=json.dumps(status("session-windows-1")))
        with mock.patch.dict(os.environ, {"SESSION_TAILSCALE_HOSTNAME": "session-windows"}):
            with mock.patch.object(subprocess, "run", return_value=reply):
                with self.assertRaises(SystemExit):
                    VERIFY["main"]()


if __name__ == "__main__":
    unittest.main()
