"""Offline validation tests for the protected Quick Tunnel email allowlist."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / ".github/scripts/start-tunnel.sh"


@unittest.skipUnless(os.name == "posix", "Bash Tunnel shell tests require a POSIX Runner")
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

    def test_single_explicit_mailbox_reaches_download_for_both_services(self):
        for service in ("chrome", "code-server"):
            for address in ("alice@example.com", "alice.smith+tag_2%box@sub-domain.example.co.uk"):
                with self.subTest(service=service, address=address):
                    status, reached_download, _ = self.invoke(address, service)
                    self.assertEqual(status, 23)
                    self.assertTrue(reached_download)

    def test_multiple_mailboxes_are_rejected_before_download(self):
        for service in ("chrome", "code-server"):
            for addresses in ("alice@example.com,bob@example.org",
                              " alice@example.com , bob@example.org "):
                with self.subTest(service=service, addresses=addresses):
                    status, reached_download, stderr = self.invoke(addresses, service)
                    self.assertEqual(status, 1)
                    self.assertFalse(reached_download)
                    self.assertIn("OWNER_EMAIL", stderr)
                    self.assertNotIn(addresses, stderr)

    def test_empty_malformed_and_wildcard_addresses_fail_before_download(self):
        invalid = (
            None, "", " ", " alice@example.com", "alice@example.com ",
            ",alice@example.com", "alice@example.com,",
            "alice@example.com,,bob@example.org",
            "alice@example.com, ,bob@example.org",
            "alice@example.com,not-an-email", "*@example.com",
            "alice@example.com,*@example.org",
            "alice@example.com\nbob@example.org",
            "alice@example.com\rbob@example.org",
            "alice@example.com\tbob@example.org",
            "alice@example.com;echo unsafe",
            ".alice@example.com", "alice.@example.com",
            "alice..smith@example.com", "alice@a..example.com",
            "alice@-example.com", "alice@example-.com",
            "alice@a-.example.com", "alice@.example.com",
            "alice@a.-example.com",
        )
        for service in ("chrome", "code-server"):
            for addresses in invalid:
                with self.subTest(service=service, addresses=addresses):
                    status, reached_download, stderr = self.invoke(addresses, service)
                    self.assertEqual(status, 1)
                    self.assertFalse(reached_download)
                    self.assertIn("OWNER_EMAIL", stderr)
                    if addresses and addresses.strip():
                        self.assertNotIn(addresses, stderr)

    def test_openlist_keeps_public_tunnel_without_email_gate(self):
        for email in (None, "", "*@example.com"):
            with self.subTest(email=email):
                status, reached_download, _ = self.invoke(email, "openlist")
                self.assertEqual(status, 23)
                self.assertTrue(reached_download)


if __name__ == "__main__":
    unittest.main()
