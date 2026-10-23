"""Offline tests for shared GitHub Session protocol (no real secrets or network)."""
import importlib.util
import json
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



class _MemoryReply:
    status = 200
    def __init__(self, data):
        import io
        self.stream = io.BytesIO(json.dumps(data).encode("utf-8"))
    def __enter__(self):
        return self
    def __exit__(self, *args):
        return False
    def read(self, size=-1):
        return self.stream.read(size)

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

    def test_signed_claim_and_ready_are_separate_and_do_not_log_tokens(self):
        import io
        from contextlib import redirect_stdout

        issued = {"value": "SIGNED.JWT.DO-NOT-LOG"}
        visited = []

        class Reply:
            status = 200
            def __init__(self, body):
                self.body = io.BytesIO(json.dumps(body).encode("utf-8"))
            def __enter__(self):
                return self
            def __exit__(self, *args):
                return False
            def read(self, size=-1):
                return self.body.read(size)

        def open_request(req, timeout=0):
            self.assertTrue(timeout <= 20)
            visited.append(req)
            if len(visited) % 2:
                self.assertEqual(req.get_header("Authorization"), "Bearer ONLY-GITHUB-SECRET")
                self.assertIn("audience=workflow-github-action%3Aproduction", req.full_url)
                return Reply(issued)
            self.assertEqual(req.get_header("Authorization"), "Bearer " + issued["value"])
            self.assertEqual(json.loads(req.data)["attemptId"], ATTEMPT)
            expected = "claimed" if len(visited) == 2 else "ready"
            return Reply({"result": expected})

        settings = self.settings()
        settings["ACTIONS_ID_TOKEN_REQUEST_URL"] = "https://oidc.actions.example/token"
        settings["ACTIONS_ID_TOKEN_REQUEST_TOKEN"] = "ONLY-GITHUB-SECRET"
        with mock.patch.dict(os.environ, settings, clear=True):
            with mock.patch.object(session.urllib.request, "urlopen", side_effect=open_request):
                out = io.StringIO()
                with redirect_stdout(out):
                    session.assert_status("claim")
                    session.assert_status("ready")
        self.assertTrue(visited[1].full_url.endswith("/github/action/claim"))
        self.assertTrue(visited[3].full_url.endswith("/github/action/ready"))
        self.assertNotIn(issued["value"], out.getvalue())
        self.assertNotIn("ONLY-GITHUB-SECRET", out.getvalue())


    def test_claim_retries_signed_pending_ack_but_does_not_retry_403(self):
        import urllib.error
        settings = self.settings()
        settings["ACTIONS_ID_TOKEN_REQUEST_URL"] = "https://oidc.actions.example/token"
        settings["ACTIONS_ID_TOKEN_REQUEST_TOKEN"] = "SECRET-NEVER-LOG"
        calls = []
        def respond(req, timeout=0):
            if "oidc.actions.example" in req.full_url:
                return _MemoryReply({"value": "fresh.jwt.for.test"})
            calls.append(req.full_url)
            if len(calls) < 3:
                raise urllib.error.HTTPError(req.full_url, 503, "pending", {}, None)
            return _MemoryReply({"result": "claimed"})
        with mock.patch.dict(os.environ, settings, clear=True):
            with mock.patch.object(session.urllib.request, "urlopen", side_effect=respond):
                with mock.patch.object(session.time, "sleep") as sleeper:
                    session.assert_status("claim")
                    self.assertEqual(sleeper.call_count, 2)
        self.assertEqual(len(calls), 3)
        self.assertTrue(all(url.endswith("/github/action/claim") for url in calls))

        denied = []
        def deny(req, timeout=0):
            if "oidc.actions.example" in req.full_url:
                return _MemoryReply({"value": "fresh.jwt.for.test"})
            denied.append(req.full_url)
            raise urllib.error.HTTPError(req.full_url, 403, "forbidden", {}, None)
        with mock.patch.dict(os.environ, settings, clear=True):
            with mock.patch.object(session.urllib.request, "urlopen", side_effect=deny):
                with mock.patch.object(session.time, "sleep") as sleeper:
                    with self.assertRaises(ValueError):
                        session.assert_status("claim")
                    sleeper.assert_not_called()
        self.assertEqual(len(denied), 1)

    def test_ready_retries_only_transient_503_with_fresh_oidc(self):
        import urllib.error
        settings = self.settings()
        settings["ACTIONS_ID_TOKEN_REQUEST_URL"] = "https://oidc.actions.example/token"
        settings["ACTIONS_ID_TOKEN_REQUEST_TOKEN"] = "SECRET-NEVER-LOG"
        attempts = []
        def respond(req, timeout=0):
            if "oidc.actions.example" in req.full_url:
                return _MemoryReply({"value": "fresh.jwt.for.test"})
            attempts.append(req.full_url)
            if len(attempts) < 3:
                raise urllib.error.HTTPError(req.full_url, 503, "temporary", {}, None)
            return _MemoryReply({"result": "ready"})
        with mock.patch.dict(os.environ, settings, clear=True):
            with mock.patch.object(session.urllib.request, "urlopen", side_effect=respond):
                with mock.patch.object(session.time, "sleep") as sleeper:
                    session.assert_status("ready")
        self.assertEqual(len(attempts), 3)
        self.assertEqual(sleeper.call_count, 2)

    def test_ready_accepts_signed_idempotent_replay_after_lost_response(self):
        settings = self.settings()
        settings["ACTIONS_ID_TOKEN_REQUEST_URL"] = "https://oidc.actions.example/token"
        settings["ACTIONS_ID_TOKEN_REQUEST_TOKEN"] = "SECRET-NEVER-LOG"
        calls = []
        def respond(req, timeout=0):
            if "oidc.actions.example" in req.full_url:
                return _MemoryReply({"value": "fresh.jwt.for.test"})
            calls.append(req.full_url)
            return _MemoryReply({"result": "already_ready"})
        with mock.patch.dict(os.environ, settings, clear=True):
            with mock.patch.object(session.urllib.request, "urlopen", side_effect=respond):
                with mock.patch.object(session.time, "sleep") as sleeper:
                    session.assert_status("ready")
                    sleeper.assert_not_called()
                    self.assertEqual(len(calls), 1)

    def test_signed_ready_never_retries_authorization_denial(self):
        import urllib.error
        settings = self.settings()
        settings["ACTIONS_ID_TOKEN_REQUEST_URL"] = "https://oidc.actions.example/token"
        settings["ACTIONS_ID_TOKEN_REQUEST_TOKEN"] = "SECRET-NEVER-LOG"
        calls = []
        def respond(req, timeout=0):
            if "oidc.actions.example" in req.full_url:
                return _MemoryReply({"value": "fresh.jwt.for.test"})
            calls.append(req.full_url)
            raise urllib.error.HTTPError(req.full_url, 403, "forbidden", {}, None)
        with mock.patch.dict(os.environ, settings, clear=True):
            with mock.patch.object(session.urllib.request, "urlopen", side_effect=respond):
                with mock.patch.object(session.time, "sleep") as sleeper:
                    with self.assertRaises(ValueError):
                        session.assert_status("ready")
        self.assertEqual(len(calls), 1)
        sleeper.assert_not_called()

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
