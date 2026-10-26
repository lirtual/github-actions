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

    def test_windows_hold_refreshes_uu_without_exposing_output_or_extending_lifetime(self):
        import types
        with tempfile.TemporaryDirectory() as root:
            (Path(root) / "session-action-start").write_text("1000", encoding="ascii")
            credential = Path(root) / "session-actions" / "uu-remote.json"
            credential.parent.mkdir()
            credential.write_text("{}", encoding="utf-8")
            clock = {"wall": 1000.0, "mono": 0.0}
            def sleep(seconds):
                clock["wall"] += seconds
                clock["mono"] += seconds
            fake_os = types.SimpleNamespace(name="nt", getenv=os.getenv, environ=os.environ)
            env = {"RUNNER_TEMP": root, "LOCALAPPDATA": root, "DURATION_MINUTES": "1"}
            with mock.patch.dict(os.environ, env, clear=True):
                with mock.patch.object(session, "os", fake_os), mock.patch.object(
                    session.time, "time", side_effect=lambda: clock["wall"]
                ), mock.patch.object(
                    session.time, "monotonic", side_effect=lambda: clock["mono"]
                ), mock.patch.object(
                    session.time, "sleep", side_effect=sleep
                ), mock.patch.object(session.subprocess, "run") as runner:
                    session.hold()
            self.assertEqual(runner.call_count, 1)
            args, kwargs = runner.call_args
            self.assertEqual(args[0][-1], "-Refresh")
            self.assertEqual(kwargs["stdout"], session.subprocess.DEVNULL)
            self.assertEqual(kwargs["stderr"], session.subprocess.DEVNULL)
            self.assertFalse(kwargs["check"])
            self.assertLessEqual(kwargs["timeout"], 15)
            self.assertEqual(clock["wall"], 1060.0)

    def test_start_requires_first_step_timestamp_and_cannot_extend_it(self):
        with tempfile.TemporaryDirectory() as root:
            marker = Path(root) / "session-action-start"
            with mock.patch.dict(os.environ, {"RUNNER_TEMP": root}, clear=True):
                with mock.patch.object(session.time, "time", return_value=1234):
                    with self.assertRaises(ValueError):
                        session.start()  # No marker means checkout/setup cannot extend lifetime.
                    marker.write_text("1200", encoding="ascii")
                    session.start()
                    session.start()  # Retry validates, never resets the timestamp.
                    self.assertEqual(marker.read_text(), "1200")
                    with mock.patch.object(session.time, "time", return_value=1200 + 330 * 60 + 1):
                        with mock.patch.dict(os.environ, {"DURATION_MINUTES": "330"}, clear=False):
                            with mock.patch.object(session.time, "sleep") as sleeper:
                                session.hold()
                                sleeper.assert_not_called()
                marker.write_text(str(1234 + 361 * 60), encoding="ascii")
                with mock.patch.object(session.time, "time", return_value=1234):
                    with self.assertRaises(ValueError):
                        session.start()


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
            "WORKFLOW_ACTION_OIDC_AUDIENCE": AUDIENCE,
            "RUNNER_TEMP": root,
            "ACTIONS_ID_TOKEN_REQUEST_URL": "https://oidc.example.test/token",
            "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "SECRET-JWT-ISSUE",
        }

    def test_observation_is_strict_and_capture_failure_never_reuses_old_code(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "uu-remote.json"
            good = {"status": "ready", "device_id": "123456789",
                    "verification_code": "AB12CD34"}
            path.write_text(json.dumps(good), encoding="utf-8")
            self.assertEqual(session.observed_uu(path), ("ready", {
                "device_id": "123456789", "verification_code": "AB12CD34"}))
            invite = "https://uuyc.163.com/invite/" + "a4" * 16
            path.write_text(json.dumps({**good, "share_url": invite}), encoding="utf-8")
            self.assertEqual(session.observed_uu(path), ("ready", {
                "device_id": "123456789", "verification_code": "AB12CD34",
                "share_url": invite}))
            for malformed in [
                "https://uuyc.163.com.evil.com/invite/" + "a4" * 16,
                "http://uuyc.163.com/invite/" + "a4" * 16,
                invite + "?redirect=evil",
                invite + "#fragment",
                "https://uuyc.163.com/invite/" + "x" * 32,
            ]:
                path.write_text(json.dumps({**good, "share_url": malformed}), encoding="utf-8")
                self.assertEqual(session.observed_uu(path), ("ready", {
                    "device_id": "123456789", "verification_code": "AB12CD34"}))
            path.write_text(json.dumps(good), encoding="utf-8")
            self.assertEqual(session.observed_uu(path, False), ("unavailable", None))
            for bad in [
                {"status": "ready", "device_id": "123456789",
                 "verification_code": "12345678"},
                {"status": "ready", "device_id": "123456789",
                 "verification_code": "AB12CD34", "leak": True},
                {"status": "unavailable", "reason": "code_unstable"},
                {"status": "ready", "device_id": "1",
                 "verification_code": "AB12CD34"},
            ]:
                path.write_text(json.dumps(bad), encoding="utf-8")
                self.assertEqual(session.observed_uu(path), ("unavailable", None))
            path.unlink()
            path.symlink_to(Path(root) / "missing")
            self.assertEqual(session.observed_uu(path), ("unavailable", None))

    def test_signed_ready_observation_includes_optional_invite_without_logging(self):
        import io
        from contextlib import redirect_stdout
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "uu-remote.json"
            invite = "https://uuyc.163.com/invite/" + "1b" * 16
            path.write_text(json.dumps({
                "status": "ready", "device_id": "123456789",
                "verification_code": "AB12CD34", "share_url": invite
            }), encoding="utf-8")
            submitted = []
            def request_open(req, timeout=0):
                if "oidc.example.test" in req.full_url:
                    return _MemoryReply({"value": "PRIVATE-SIGNED-JWT"})
                submitted.append(json.loads(req.data))
                return _MemoryReply({"result": "recorded"})
            with mock.patch.dict(os.environ, self.settings(root), clear=True):
                with mock.patch.object(session.OPENER, "open", side_effect=request_open):
                    output = io.StringIO()
                    with redirect_stdout(output):
                        session.report_uu_observation(path)
            self.assertEqual(submitted[0]["value"]["share_url"], invite)
            self.assertNotIn(invite, output.getvalue())
            self.assertNotIn("AB12CD34", output.getvalue())

    def test_sequence_is_durable_scoped_to_attempt_and_advances_on_same_ui_value(self):
        with tempfile.TemporaryDirectory() as root:
            with mock.patch.dict(os.environ, {"RUNNER_TEMP": root}, clear=True):
                self.assertEqual(session.next_uu_sequence(ATTEMPT), 1)
                self.assertEqual(session.next_uu_sequence(ATTEMPT), 2)
                self.assertEqual(session.next_uu_sequence(DISPATCH), 1)
                self.assertEqual(session.next_uu_sequence(DISPATCH), 2)
                self.assertEqual(session.next_uu_sequence(ATTEMPT), 1)
                file = Path(root) / "session-uu-sequence.json"
                self.assertEqual(json.loads(file.read_text())["key"], "uu.credentials")
                if os.name != "nt":
                    self.assertEqual(file.stat().st_mode & 0o777, 0o600)
                file.unlink()
                file.symlink_to(Path(root) / "missing")
                with self.assertRaises(ValueError):
                    session.next_uu_sequence(ATTEMPT)

    def test_signed_report_reuses_same_sequence_on_lost_response_without_logging(self):
        import io
        from contextlib import redirect_stdout
        import urllib.error
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "uu-remote.json"
            path.write_text(json.dumps({"status": "ready", "device_id": "123456789",
                                        "verification_code": "AB12CD34"}))
            submitted = []
            def request_open(req, timeout=0):
                if "oidc.example.test" in req.full_url:
                    return _MemoryReply({"value": "PRIVATE-SIGNED-JWT"})
                submitted.append((req.full_url, json.loads(req.data),
                                  req.get_header("Authorization")))
                if len(submitted) == 1:
                    raise urllib.error.HTTPError(req.full_url, 503, "PRIVATE-BODY", {}, None)
                return _MemoryReply({"result": "already_recorded"
                                     if len(submitted) == 2 else "recorded"})
            with mock.patch.dict(os.environ, self.settings(root), clear=True):
                with mock.patch.object(session.OPENER, "open", side_effect=request_open):
                    out = io.StringIO()
                    with redirect_stdout(out):
                        session.report_uu_observation(path)
                        session.report_uu_observation(path)
                        session.report_uu_observation(path, refreshed=False)
            self.assertEqual([r[1]["sequence"] for r in submitted], [1, 1, 2, 3])
            self.assertTrue(all(r[0].endswith("/github/action/session-data") for r in submitted))
            self.assertEqual(submitted[0][1], submitted[1][1])
            self.assertEqual(submitted[2][1]["status"], "ready")
            self.assertEqual(submitted[3][1]["status"], "unavailable")
            self.assertNotIn("value", submitted[3][1])
            self.assertTrue(all(r[2] == "Bearer PRIVATE-SIGNED-JWT" for r in submitted))
            self.assertNotIn("AB12CD34", out.getvalue())
            self.assertNotIn("PRIVATE-SIGNED-JWT", out.getvalue())
            self.assertNotIn("PRIVATE-BODY", out.getvalue())

    def test_signed_report_distinguishes_exhausted_503_from_transport(self):
        import urllib.error
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "uu-remote.json"
            settings = self.settings(root)
            calls = []
            def unavailable(request, timeout=0):
                if "oidc.example.test" in request.full_url:
                    return _MemoryReply({"value": "PRIVATE-SIGNED-JWT"})
                calls.append(request.data)
                raise urllib.error.HTTPError(request.full_url, 503,
                                             "PRIVATE-BODY", {}, None)
            with mock.patch.dict(os.environ, settings, clear=True):
                with mock.patch.object(session.OPENER, "open", side_effect=unavailable):
                    with self.assertRaisesRegex(session.SafeProtocolError,
                                                "^session_data_http_503$"):
                        session.report_uu_observation(path)
            self.assertEqual(len(calls), 2)
            self.assertEqual(calls[0], calls[1])
            def network_failure(request, timeout=0):
                if "oidc.example.test" in request.full_url:
                    return _MemoryReply({"value": "PRIVATE-SIGNED-JWT"})
                raise ConnectionResetError("PRIVATE-TRANSPORT-MESSAGE")
            with mock.patch.dict(os.environ, settings, clear=True):
                with mock.patch.object(session.OPENER, "open", side_effect=network_failure):
                    with self.assertRaisesRegex(session.SafeProtocolError,
                                                "^session_data_unavailable$"):
                        session.report_uu_observation(path)

    def test_windows_refresh_reports_failure_as_unavailable_without_stopping_hold(self):
        import types
        with tempfile.TemporaryDirectory() as root:
            (Path(root) / "session-action-start").write_text("1000")
            location = Path(root) / "session-actions" / "uu-remote.json"
            location.parent.mkdir()
            location.write_text('{"status":"ready","device_id":"123456789","verification_code":"AB12CD34"}')
            clock = {"wall": 1000., "mono": 0.}
            def sleep(seconds):
                clock["wall"] += seconds
                clock["mono"] += seconds
            captured = []
            fake_os = types.SimpleNamespace(name="nt", getenv=os.getenv, environ=os.environ)
            env = {"RUNNER_TEMP": root, "LOCALAPPDATA": root, "DURATION_MINUTES": "1"}
            with mock.patch.dict(os.environ, env, clear=True), mock.patch.object(
                session, "os", fake_os
            ), mock.patch.object(
                session.time, "time", side_effect=lambda: clock["wall"]
            ), mock.patch.object(
                session.time, "monotonic", side_effect=lambda: clock["mono"]
            ), mock.patch.object(
                session.time, "sleep", side_effect=sleep
            ), mock.patch.object(
                session.subprocess, "run", return_value=types.SimpleNamespace(returncode=1)
            ), mock.patch.object(
                session, "report_uu_observation",
                side_effect=lambda path, refreshed=True: captured.append(refreshed)
            ):
                session.hold()
            self.assertEqual(captured, [True, False])
            self.assertEqual(clock["wall"], 1060.)


if __name__ == "__main__":
    unittest.main()
