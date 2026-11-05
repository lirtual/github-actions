"""Offline validation tests for the protected Quick Tunnel email allowlist."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / ".github/scripts/start-tunnel.sh"


class TunnelAllowedMailTests(unittest.TestCase):
    def invoke(self, email, service="chrome"):
        # A local curl stub proves whether validation reached the download step.
        # No network requests, tunnels, credentials or real services are involved.
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            stub_dir = directory / "bin"
            stub_dir.mkdir()
            stub = stub_dir / "curl"
            stub.write_text('#!/bin/sh\nprintf "called" > "$RUNNER_TEMP/curl-called"\nexit 23\n')
            stub.chmod(0o755)
            env = os.environ.copy()
            env.update({
                "PATH": str(stub_dir) + os.pathsep + env.get("PATH", ""),
                "RUNNER_TEMP": tmp,
                "GITHUB_STEP_SUMMARY": str(directory / "summary"),
                "SESSION_SERVICE": service,
            })
            if email is None:
                env.pop("OWNER_EMAIL", None)
            else:
                env["OWNER_EMAIL"] = email
            result = subprocess.run(
                ["bash", str(SCRIPT)], env=env,
                capture_output=True, text=True, timeout=10, check=False,
            )
            return result.returncode, (directory / "curl-called").exists(), result.stderr

    def test_single_and_multiple_explicit_addresses_are_accepted(self):
        for service in ("chrome", "code-server"):
            for addresses in (
                "alice@example.com",
                "alice@example.com,bob@example.org",
                " alice@example.com , bob@example.org ",
            ):
                with self.subTest(service=service, addresses=addresses):
                    status, reached_download, _ = self.invoke(addresses, service)
                    self.assertEqual(status, 23)
                    self.assertTrue(reached_download)

    def test_empty_malformed_and_wildcard_addresses_fail_before_download(self):
        invalid = (
            None, "", " ", ",alice@example.com", "alice@example.com,",
            "alice@example.com,,bob@example.org",
            "alice@example.com, ,bob@example.org",
            "alice@example.com,not-an-email", "*@example.com",
            "alice@example.com,*@example.org",
            "alice@example.com\nbob@example.org",
            "alice@example.com\rbob@example.org",
            "alice@example.com\tbob@example.org",
            "alice@example.com;echo unsafe",
        )
        for service in ("chrome", "code-server"):
            for addresses in invalid:
                with self.subTest(service=service, addresses=addresses):
                    status, reached_download, stderr = self.invoke(addresses, service)
                    self.assertEqual(status, 1)
                    self.assertFalse(reached_download)
                    self.assertIn("OWNER_EMAIL", stderr)

    def test_openlist_keeps_public_tunnel_without_email_gate(self):
        for email in (None, "", "*@example.com"):
            with self.subTest(email=email):
                status, reached_download, _ = self.invoke(email, "openlist")
                self.assertEqual(status, 23)
                self.assertTrue(reached_download)


if __name__ == "__main__":
    unittest.main()
