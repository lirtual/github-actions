"""Regression checks for immutable Session execution. Actionlint validates YAML separately."""
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ("linux", "windows", "chrome", "code-server", "openlist")

class SessionWorkflowInvariants(unittest.TestCase):
    def test_every_session_checks_out_exact_run_sha(self):
        for name in WORKFLOWS:
            with self.subTest(workflow=name):
                yml = (ROOT / ".github/workflows" / (name + ".yml")).read_text()
                self.assertIn("ref: ${{ github.sha }}", yml)
                self.assertIn("persist-credentials: false", yml)
                self.assertIn("hostname: sa-${{ github.run_id }}-a${{ github.run_attempt }}", yml)
                self.assertIn("timeout-minutes: 330", yml)
                self.assertIn("oauth-client-id: ${{ vars.TS_OAUTH_CLIENT_ID }}", yml)
                self.assertIn("audience: ${{ vars.TS_AUDIENCE }}", yml)
                self.assertNotIn("secrets.TS_OAUTH_CLIENT_ID", yml)
                self.assertNotIn("secrets.TS_AUDIENCE", yml)

                self.assertIn("WORKFLOW_ACTION_TYPE: session", yml)
                self.assertIn("session_action.py claim", yml)
                self.assertIn("session_action.py ready", yml)
                self.assertIn("session_action.py hold", yml)
                self.assertEqual(len(re.findall(r"(?m)^  session:$", yml)), 1)

    def test_external_packages_are_immutable(self):
        code = (ROOT / ".github/scripts/start-code-server.sh").read_text()
        self.assertIn("864c5d01c808ade57e4d12c708717be7a187219fded60428f263b9e2da9f6b48", code)
        self.assertIn("sha256sum -c -", code)
        image = (ROOT / ".github/scripts/start-openlist.sh").read_text()
        self.assertIn("openlistteam/openlist@sha256:c555c6e1c8af2aead38ed12ec761ac077fdf046d19cf033414be8e056aec6b64", image)
        self.assertNotIn("openlistteam/openlist:v4.2.6", image)


    def test_task_signed_claim_transport_recovery_and_403_denial(self):
        # Execute the actual embedded Task script, not a copy of its logic.
        import contextlib
        import http.client
        import io
        import json
        import os
        import textwrap
        import urllib.error
        from unittest import mock

        source = (ROOT / ".github/workflows/verify-action.yml").read_text()
        code = textwrap.dedent(source.split("python3 - <<'PY'\n", 1)[1]
                               .split("\n          PY", 1)[0])
        environment = {
            "ATTEMPT_ID": "11111111-1111-4111-8111-111111111111",
            "DISPATCH_ID": "22222222-2222-4222-8222-222222222222",
            "CAPABILITY_ID": "github.action",
            "CLAIM_URL": "https://claim.example/github/action/claim",
            "OIDC_AUDIENCE": "workflow-github-action:production",
            "ACTIONS_ID_TOKEN_REQUEST_URL": "https://oidc.example/token",
            "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "DO-NOT-PRINT-THIS-SECRET",
        }

        class Reply:
            status = 200
            def __init__(self, value):
                self.data = io.BytesIO(json.dumps(value).encode())
            def __enter__(self):
                return self
            def __exit__(self, *args):
                return False
            def read(self, size=-1):
                return self.data.read(size)

        for statuses, expected_calls, should_succeed in [
            ([503, "already_claimed"], 2, True),
            ([503, "claimed"], 2, True),
            ([ConnectionResetError("lost HTTP 200"), "already_claimed"], 2, True),
            ([http.client.IncompleteRead(b'{"result":', 9), "already_claimed"], 2, True),
            ([ConnectionResetError("lost HTTP 200"), 403], 2, False),
            ([403], 1, False),
        ]:
            with self.subTest(statuses=statuses):
                responses = list(statuses)
                observed_tokens = []
                claim_tokens = []

                def respond(request, timeout=0):
                    if request.full_url.startswith("https://oidc.example/"):
                        token = "jwt-" + str(len(observed_tokens) + 1)
                        observed_tokens.append(token)
                        return Reply({"value": token})
                    claim_tokens.append(request.get_header("Authorization"))
                    result = responses.pop(0)
                    if isinstance(result, BaseException):
                        raise result
                    if isinstance(result, int):
                        raise urllib.error.HTTPError(request.full_url, result,
                                                     "temporary or denied", {}, None)
                    return Reply({"result": result})

                stdout = io.StringIO()
                with mock.patch.dict(os.environ, environment, clear=True):
                    with mock.patch("urllib.request.urlopen", side_effect=respond):
                        with mock.patch("time.sleep") as sleep:
                            with contextlib.redirect_stdout(stdout):
                                if should_succeed:
                                    exec(compile(code, "Task Claim", "exec"), {})
                                else:
                                    with self.assertRaises(SystemExit):
                                        exec(compile(code, "Task Claim", "exec"), {})
                            self.assertEqual(sleep.call_count, 1 if expected_calls == 2 else 0)
                self.assertEqual(len(observed_tokens), expected_calls)
                self.assertEqual(claim_tokens,
                                 ["Bearer " + value for value in observed_tokens])
                self.assertNotIn(environment["ACTIONS_ID_TOKEN_REQUEST_TOKEN"],
                                 stdout.getvalue())


if __name__ == "__main__":
    unittest.main()
