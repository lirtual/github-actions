"""Offline tests for shared GitHub Session protocol (no real secrets or network)."""
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

PATH = Path(__file__).resolve().parents[1] / ".github/scripts/session_action.py"
SPEC = importlib.util.spec_from_file_location("session_action", PATH)
assert SPEC is not None and SPEC.loader is not None
session = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(session)

ATTEMPT = "11111111-1111-4111-8111-111111111111"
DISPATCH = "22222222-2222-4222-8222-222222222222"
AUDIENCE = "workflow-github-action:production"


class SessionProtocolTests(unittest.TestCase):
    def settings(self):
        return {
            "ATTEMPT_ID": ATTEMPT,
            "DISPATCH_ID": DISPATCH,
            "CAPABILITY_ID": "github.action",
            "WORKFLOW_ACTION_CLAIM_URL": "https://example.test/github/action/claim",
            "WORKFLOW_ACTION_OIDC_AUDIENCE": AUDIENCE,
        }

    def test_configuration_checks_strict_server_identity(self):
        with mock.patch.dict(os.environ, self.settings(), clear=True):
            self.assertEqual(session.configuration(),
                             (ATTEMPT, AUDIENCE, "https://example.test/github/action/claim"))
        for name, value in [
            ("CAPABILITY_ID", "github.other"),
            ("ATTEMPT_ID", "not-a-uuid"),
            ("WORKFLOW_ACTION_CLAIM_URL", "http://example.test/github/action/claim"),
            ("WORKFLOW_ACTION_CLAIM_URL", "https://user:pass@example.test/github/action/claim"),
            ("WORKFLOW_ACTION_CLAIM_URL", "https://example.test/github/action/ready"),
            ("WORKFLOW_ACTION_CLAIM_URL", "https://example.test/github/action/claim?a=1"),
            ("WORKFLOW_ACTION_OIDC_AUDIENCE", "untrusted-audience"),
        ]:
            changed = self.settings()
            changed[name] = value
            with mock.patch.dict(os.environ, changed, clear=True):
                with self.subTest(name=name, value=value), self.assertRaises(ValueError):
                    session.configuration()

    def test_hold_rejects_bad_duration_and_does_not_extend_clock(self):
        with tempfile.TemporaryDirectory() as root:
            started = Path(root) / "session-action-start"
            started.write_text("1000", encoding="ascii")
            for duration in ["0", "331", "-3", "1e3", "abc", ""]:
                env = {"RUNNER_TEMP": root, "DURATION_MINUTES": duration}
                with mock.patch.dict(os.environ, env, clear=True):
                    with self.subTest(duration=duration), self.assertRaises(ValueError):
                        session.hold()
            with mock.patch.dict(os.environ, {"RUNNER_TEMP": root, "DURATION_MINUTES": "1"}, clear=True):
                with mock.patch.object(session.time, "time", return_value=1061), mock.patch.object(
                    session.time, "sleep"
                ) as sleep:
                    session.hold()
                    sleep.assert_not_called()

    def test_start_is_once_only_and_creates_local_timestamp(self):
        with tempfile.TemporaryDirectory() as root:
            with mock.patch.dict(os.environ, {"RUNNER_TEMP": root}, clear=True):
                with mock.patch.object(session.time, "time", return_value=1234):
                    session.start()
                self.assertEqual((Path(root) / "session-action-start").read_text(), "1234")
                with self.assertRaises(ValueError):
                    session.start()


if __name__ == "__main__":
    unittest.main()
