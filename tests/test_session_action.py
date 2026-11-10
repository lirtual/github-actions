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
REAL_DISCOVER_AUDIENCE = session.discover_audience



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
    def setUp(self):
        # Existing protocol tests isolate signed Claim transport from the
        # separate, independently tested public discovery request.
        patcher = mock.patch.object(session, "discover_audience", return_value=AUDIENCE)
        patcher.start()
        self.addCleanup(patcher.stop)

    def settings(self):
        return {
            "ATTEMPT_ID": ATTEMPT,
            "DISPATCH_ID": DISPATCH,
            "CAPABILITY_ID": "github.action",
            "WORKFLOW_ACTION_CLAIM_URL": "https://example.test/github/action/claim",
            "RUNNER_TEMP": tempfile.gettempdir(),
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
        ]:
            changed = self.settings()
            changed[name] = value
            with mock.patch.dict(os.environ, changed, clear=True):
                with self.subTest(name=name, value=value), self.assertRaises(ValueError):
                    session.configuration()

    def test_discovery_uses_claim_origin_and_rejects_invalid_responses(self):
        claim="https://example.test/github/action/claim"
        response=_MemoryReply({"audience":AUDIENCE})
        with mock.patch.object(session.OPENER,"open",return_value=response) as opening:
            self.assertEqual(REAL_DISCOVER_AUDIENCE(claim),AUDIENCE)
            self.assertEqual(opening.call_args.args[0].full_url,
                             "https://example.test/github/action/config")
            self.assertEqual(opening.call_args.kwargs["timeout"],10)
        for response in (_MemoryReply({"audience":"wrong"}),
                         _MemoryReply({"audience":AUDIENCE,"extra":1}),
                         _MemoryReply([AUDIENCE]),
                         _MemoryReply({"audience":"workflow-github-x"+"a"*300})):
            with mock.patch.object(session.OPENER,"open",return_value=response):
                with self.assertRaises(session.SafeProtocolError):
                    REAL_DISCOVER_AUDIENCE(claim)
        for unsafe in ("http://example.test/github/action/claim",
                       "https://evil@example.test/github/action/claim",
                       "https://example.test/github/action/claim?token=x"):
            with mock.patch.object(session.OPENER,"open") as opening:
                with self.assertRaises(session.SafeProtocolError):
                    REAL_DISCOVER_AUDIENCE(unsafe)
                opening.assert_not_called()
        with mock.patch.object(session.OPENER,"open",side_effect=ConnectionResetError("private")):
            with self.assertRaisesRegex(session.SafeProtocolError,"audience_discovery_unavailable"):
                REAL_DISCOVER_AUDIENCE(claim)

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
            with mock.patch.object(session.OPENER, "open", side_effect=open_request):
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
            with mock.patch.object(session.OPENER, "open", side_effect=respond):
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
            with mock.patch.object(session.OPENER, "open", side_effect=deny):
                with mock.patch.object(session.time, "sleep") as sleeper:
                    with self.assertRaises(ValueError):
                        session.assert_status("claim")
                    sleeper.assert_not_called()
        self.assertEqual(len(denied), 1)

    def test_claim_accepts_signed_already_claimed_after_lost_http_ack(self):
        settings = self.settings()
        settings["ACTIONS_ID_TOKEN_REQUEST_URL"] = "https://oidc.actions.example/token"
        settings["ACTIONS_ID_TOKEN_REQUEST_TOKEN"] = "SECRET-NEVER-LOG"
        calls = []
        def respond(req, timeout=0):
            if "oidc.actions.example" in req.full_url:
                return _MemoryReply({"value": "fresh.jwt.for.test"})
            calls.append(req.full_url)
            return _MemoryReply({"result": "already_claimed"})
        with mock.patch.dict(os.environ, settings, clear=True):
            with mock.patch.object(session.OPENER, "open", side_effect=respond):
                with mock.patch.object(session.time, "sleep") as sleeper:
                    session.assert_status("claim")
                    sleeper.assert_not_called()
        self.assertEqual(len(calls), 1)
        self.assertTrue(calls[0].endswith("/github/action/claim"))

    def test_lost_http_200_transport_retries_with_fresh_signed_identity(self):
        import http.client
        import io
        import urllib.error
        from contextlib import redirect_stdout

        settings = self.settings()
        settings["ACTIONS_ID_TOKEN_REQUEST_URL"] = "https://oidc.actions.example/token"
        settings["ACTIONS_ID_TOKEN_REQUEST_TOKEN"] = "SECRET-NEVER-LOG"
        for stage, failure, accepted in [
            ("claim", ConnectionResetError("HTTP 200 reply lost"), "already_claimed"),
            ("ready", http.client.IncompleteRead(b'{"result":', 8), "already_ready"),
            ("claim", _MemoryReply({"result": "already_claimed"}), "already_claimed"),
        ]:
            # The third fixture exercises an ordinary successful response.
            with self.subTest(stage=stage, failure=type(failure).__name__):
                issued = []
                calls = []
                outcomes = [failure, _MemoryReply({"result": accepted})]
                def respond(request, timeout=0):
                    if "oidc.actions.example" in request.full_url:
                        token = "signed-jwt-" + str(len(issued) + 1)
                        issued.append(token)
                        return _MemoryReply({"value": token})
                    calls.append(request.get_header("Authorization"))
                    outcome = outcomes.pop(0)
                    if isinstance(outcome, BaseException):
                        raise outcome
                    return outcome
                with mock.patch.dict(os.environ, settings, clear=True):
                    with mock.patch.object(session.OPENER, "open", side_effect=respond):
                        with mock.patch.object(session.time, "sleep") as sleep:
                            output = io.StringIO()
                            with redirect_stdout(output):
                                session.assert_status(stage)
                            expected = 1 if isinstance(failure, _MemoryReply) else 2
                            self.assertEqual(len(calls), expected)
                            self.assertEqual(sleep.call_count, expected - 1)
                            self.assertEqual(calls, ["Bearer " + token for token in issued])
                            self.assertNotIn("SECRET-NEVER-LOG", output.getvalue())

    def test_signed_protocol_uses_no_redirect_opener(self):
        # The opener must override urllib's default automatic redirect
        # handler, which otherwise may forward Bearer authentication.
        handlers = session.OPENER.handlers
        candidates = [h for h in handlers
                      if isinstance(h, session.urllib.request.HTTPRedirectHandler)]
        self.assertEqual(len(candidates), 1)
        self.assertIsNone(candidates[0].redirect_request(
            object(), None, 302, "Found", {}, "https://untrusted.example/"))

    def test_transport_retry_never_overrides_following_403(self):
        import urllib.error
        settings = self.settings()
        settings["ACTIONS_ID_TOKEN_REQUEST_URL"] = "https://oidc.actions.example/token"
        settings["ACTIONS_ID_TOKEN_REQUEST_TOKEN"] = "SECRET-NEVER-LOG"
        attempts = []
        def respond(request, timeout=0):
            if "oidc.actions.example" in request.full_url:
                return _MemoryReply({"value": "signed.jwt"})
            attempts.append(request.full_url)
            if len(attempts) == 1:
                raise ConnectionResetError("lost initial reply")
            raise urllib.error.HTTPError(request.full_url, 403, "denied", {}, None)
        with mock.patch.dict(os.environ, settings, clear=True):
            with mock.patch.object(session.OPENER, "open", side_effect=respond):
                with mock.patch.object(session.time, "sleep") as sleep:
                    with self.assertRaises(ValueError):
                        session.assert_status("claim")
                    self.assertEqual(sleep.call_count, 1)
        self.assertEqual(len(attempts), 2)

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
            with mock.patch.object(session.OPENER, "open", side_effect=respond):
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
            with mock.patch.object(session.OPENER, "open", side_effect=respond):
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
            with mock.patch.object(session.OPENER, "open", side_effect=respond):
                with mock.patch.object(session.time, "sleep") as sleeper:
                    with self.assertRaises(ValueError):
                        session.assert_status("ready")
        self.assertEqual(len(calls), 1)
        sleeper.assert_not_called()

    def test_claim_failure_diagnostics_expose_only_safe_stage_and_code(self):
        import io
        import urllib.error
        from contextlib import redirect_stderr

        settings = self.settings()
        settings["ACTIONS_ID_TOKEN_REQUEST_URL"] = "https://oidc.actions.example/token?sensitive_url_value=PRIVATE"
        settings["ACTIONS_ID_TOKEN_REQUEST_TOKEN"] = "SECRET-NEVER-LOG"
        tests = (
            ("oidc_401", "oidc_request_http_401"),
            ("claim_403", "claim_request_http_403"),
            ("oidc_network_error", "oidc_request_ConnectionResetError"),
        )
        for kind, expected in tests:
            with self.subTest(kind=kind):
                requested = []
                def respond(req, timeout=0):
                    requested.append(req.full_url)
                    if "oidc.actions.example" in req.full_url:
                        if kind == "oidc_401":
                            raise urllib.error.HTTPError(req.full_url, 401, "SECRET-NEVER-LOG", {}, None)
                        if kind == "oidc_network_error":
                            raise ConnectionResetError("SECRET-NEVER-LOG " + req.full_url)
                        return _MemoryReply({"value": "SIGNED.JWT.PRIVATE"})
                    raise urllib.error.HTTPError(req.full_url, 403, "SIGNED.JWT.PRIVATE", {}, None)

                output = io.StringIO()
                with mock.patch.dict(os.environ, settings, clear=True):
                    with mock.patch.object(session.OPENER, "open", side_effect=respond):
                        with mock.patch.object(session.sys, "argv", ["session_action.py", "claim"]):
                            with redirect_stderr(output), self.assertRaises(SystemExit) as exit_status:
                                session.main()
                self.assertEqual(exit_status.exception.code, 1)
                self.assertIn(expected, output.getvalue())
                self.assertNotIn("SECRET-NEVER-LOG", output.getvalue())
                self.assertNotIn("SIGNED.JWT.PRIVATE", output.getvalue())
                self.assertNotIn("oidc.actions.example", output.getvalue())
                self.assertNotIn("https://", output.getvalue())
                self.assertEqual(len(requested), 2 if kind == "claim_403" else 1)

    def test_start_rejects_invalid_repo_duration_before_claim_or_service(self):
        import time
        with tempfile.TemporaryDirectory() as root:
            (Path(root) / "session-action-start").write_text(str(int(time.time())), encoding="ascii")
            for duration in ("0", "301", "-2", "1.5", "five", "", " 300", "00301"):
                with self.subTest(duration=duration), mock.patch.dict(
                    os.environ, {"RUNNER_TEMP": root, "DURATION_MINUTES": duration}, clear=True
                ), self.assertRaises(ValueError):
                    session.start()
            for duration in ("1", "299", "300"):
                with self.subTest(duration=duration), mock.patch.dict(
                    os.environ, {"RUNNER_TEMP": root, "DURATION_MINUTES": duration}, clear=True
                ):
                    session.start()

    def test_hold_rejects_bad_duration_and_does_not_extend_clock(self):
        with tempfile.TemporaryDirectory() as root:
            started = Path(root) / "session-action-start"
            started.write_text("1000", encoding="ascii")
            for duration in ["0", "301", "-3", "1e3", "abc", ""]:
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

    def test_start_requires_first_step_timestamp_and_cannot_extend_it(self):
        with tempfile.TemporaryDirectory() as root:
            marker = Path(root) / "session-action-start"
            with mock.patch.dict(os.environ, {"RUNNER_TEMP": root, "DURATION_MINUTES": "300"}, clear=True):
                with mock.patch.object(session.time, "time", return_value=1234):
                    with self.assertRaises(ValueError):
                        session.start()  # No marker means checkout/setup cannot extend lifetime.
                    marker.write_text("1200", encoding="ascii")
                    session.start()
                    session.start()  # Retry validates, never resets the timestamp.
                    self.assertEqual(marker.read_text(), "1200")
                    with mock.patch.object(session.time, "time", return_value=1200 + 300 * 60 + 1):
                        with mock.patch.dict(os.environ, {"DURATION_MINUTES": "300"}, clear=False):
                            with mock.patch.object(session.time, "sleep") as sleeper:
                                session.hold()
                                sleeper.assert_not_called()
                marker.write_text(str(1234 + 361 * 60), encoding="ascii")
                with mock.patch.object(session.time, "time", return_value=1234):
                    with self.assertRaises(ValueError):
                        session.start()


    def test_signed_ready_freezes_physical_runner_duration_only_for_tailnet_sessions(self):
        with tempfile.TemporaryDirectory() as path:
            for workflow in ("ubuntu", "windows"):
                env = self.settings()
                env.update({"RUNNER_TEMP": path, "GITHUB_REPOSITORY": "lirtual/github-actions",
                            "GITHUB_WORKFLOW": workflow, "DURATION_MINUTES": "7"})
                with mock.patch.dict(os.environ, env, clear=True):
                    self.assertEqual(session.signed_status_payload(ATTEMPT, "ready"),
                                     {"attemptId": ATTEMPT, "durationMinutes": 7})
                    self.assertEqual(session.signed_status_payload(ATTEMPT, "claim"),
                                     {"attemptId": ATTEMPT})
                    os.environ["DURATION_MINUTES"] = "301"
                    with self.assertRaises(ValueError):
                        session.signed_status_payload(ATTEMPT, "ready")
            env = self.settings()
            env.update({"RUNNER_TEMP": path, "GITHUB_REPOSITORY": "lirtual/github-actions",
                        "GITHUB_WORKFLOW": "chrome", "DURATION_MINUTES": "8"})
            with mock.patch.dict(os.environ, env, clear=True):
                self.assertEqual(session.signed_status_payload(ATTEMPT, "ready"),
                                 {"attemptId": ATTEMPT})

    def test_signed_ready_attaches_only_the_verified_temporary_web_url(self):
        with tempfile.TemporaryDirectory() as path:
            settings = self.settings()
            settings["RUNNER_TEMP"] = path
            locator = Path(path) / "session-tunnel-url"
            with mock.patch.dict(os.environ, settings, clear=True):
                self.assertEqual(session.signed_status_payload(ATTEMPT, "claim"),
                                 {"attemptId": ATTEMPT})
                self.assertEqual(session.signed_status_payload(ATTEMPT, "ready"),
                                 {"attemptId": ATTEMPT})
                url = "https://example-temp-session.trycloudflare.com"
                locator.write_text(url + "\n", encoding="ascii")
                self.assertEqual(session.signed_status_payload(ATTEMPT, "ready"),
                                 {"attemptId": ATTEMPT, "sessionUrl": url})
                self.assertEqual(session.signed_status_payload(ATTEMPT, "claim"),
                                 {"attemptId": ATTEMPT})
                for invalid in ["http://example.trycloudflare.com",
                                "https://example.trycloudflare.com.evil.org",
                                "https://example.trycloudflare.com/?token=bad",
                                "https://127.0.0.1/"]:
                    locator.write_text(invalid, encoding="ascii")
                    with self.subTest(value=invalid), self.assertRaises(ValueError):
                        session.signed_status_payload(ATTEMPT, "ready")
                locator.unlink()
                locator.symlink_to(Path(path) / "missing-file")
                with self.assertRaises(ValueError):
                    session.signed_status_payload(ATTEMPT, "ready")



class SessionRuntimeDataTests(unittest.TestCase):
    def settings(self, root):
        return {
            "ATTEMPT_ID": ATTEMPT,
            "DISPATCH_ID": DISPATCH,
            "CAPABILITY_ID": "github.action",
            "WORKFLOW_ACTION_CLAIM_URL": "https://example.test/github/action/claim",
            "RUNNER_TEMP": root,
            "ACTIONS_ID_TOKEN_REQUEST_URL": "https://oidc.example.test/token",
            "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "SECRET-JWT-ISSUE",
        }

if __name__ == "__main__":
    unittest.main()
