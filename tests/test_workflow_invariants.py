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

    def test_session_claim_precedes_tailnet_and_protected_resources(self):
        """A manual GitHub dispatch can run without a D1 Attempt; it must not
        reach Tailnet enrollment, SSH, service credentials or Ready."""
        pinned_tailnet = (
            "uses: tailscale/github-action@"
            "99a8333667fff04fdd6cffb46dfd409f8329a7bf"
        )
        for name in WORKFLOWS:
            with self.subTest(workflow=name):
                text = (ROOT / ".github/workflows" / (name + ".yml")).read_text()
                claim = text.index("session_action.py claim")
                join = text.index(pinned_tailnet)
                ready = text.index("session_action.py ready")
                hold = text.index("session_action.py hold")
                self.assertTrue(claim < join < ready < hold)
                self.assertIn("id-token: write", text[:claim])
                self.assertIn("WORKFLOW_ACTION_TYPE: session", text[:claim])
                self.assertNotIn("tailscale set", text[:join])
                self.assertNotIn("${{ secrets.", text[:claim])
                self.assertNotIn("TS_OAUTH_CLIENT_ID", text[:claim])
                self.assertNotIn("TS_AUDIENCE", text[:claim])
                self.assertIn("if: always()", text[hold:])
                if name == "openlist":
                    self.assertIn("secrets.OPENLIST_ADMIN_PASSWORD",
                                  text[join:ready])
                if name == "windows":
                    self.assertIn("vars.SESSION_SSH_PUBLIC_KEY",
                                  text[join:ready])

    def test_windows_ssh_does_not_shadow_powershell_home(self):
        # Real windows-latest failed because PowerShell treats $Home and $HOME
        # as the same read-only automatic variable; source parsing misses it.
        text = (ROOT / ".github/scripts/windows-ssh.ps1").read_text()
        self.assertNotRegex(text, r"(?im)^\s*\$home\s*=")
        self.assertIn("$UserHome = Join-Path", text)
        self.assertIn("Join-Path $UserHome '.ssh'", text)

    def test_windows_ssh_keeps_administrators_for_key_acl_setup(self):
        # The runner must still be able to set authorized_keys permissions
        # after disabling inheritance on the parent .ssh directory.
        text = (ROOT / ".github/scripts/windows-ssh.ps1").read_text()
        self.assertIn("'*S-1-5-32-544:(OI)(CI)F'", text)
        self.assertIn("'*S-1-5-32-544:F'", text)
        self.assertIn("'*S-1-5-18:F'", text)

    def test_windows_tailnet_firewall_rule_has_required_display_name(self):
        text = (ROOT / ".github/scripts/windows-ssh.ps1").read_text()
        self.assertIn("New-NetFirewallRule -Name 'SessionActionsTailscaleSSH' -DisplayName", text)
        self.assertIn("-RemoteAddress '100.64.0.0/10' -InterfaceAlias", text)

    def test_windows_sshd_uses_absolute_authorized_keys_path(self):
        # Newly created Windows local accounts might not have a user profile
        # yet, so the default relative .ssh/authorized_keys can miss the key.
        text = (ROOT / ".github/scripts/windows-ssh.ps1").read_text()
        self.assertIn("('AuthorizedKeysFile \"' + $Keys + '\"')", text)
        self.assertIn("'AllowUsers sessionuser'", text)

    def test_windows_authorized_keys_owned_by_session_user(self):
        # Windows OpenSSH checks the owner as well as strict file ACLs.
        text = (ROOT / ".github/scripts/windows-ssh.ps1").read_text()
        self.assertIn("icacls.exe $Keys '/setowner' $Username", text)
        self.assertIn("icacls.exe $Directory '/setowner' $Username", text)
        self.assertIn("throw 'SSH key owner update failed'", text)

    def test_windows_sshd_is_reloaded_with_key_only_policy(self):
        text = (ROOT / ".github/scripts/windows-ssh.ps1").read_text()
        config = text.index("& $Sshd -t")
        effective = text.index("& $Sshd -T -C")
        stop = text.index("Stop-Service sshd -ErrorAction Stop")
        start = text.index("Start-Service sshd -ErrorAction Stop")
        self.assertLess(config, effective)
        self.assertLess(effective, stop)
        self.assertLess(stop, start)
        self.assertIn("passwordauthentication no", text)
        self.assertIn("pubkeyauthentication yes", text)

    def test_windows_sshd_emits_only_safe_effective_policy_diagnostics(self):
        text = (ROOT / ".github/scripts/windows-ssh.ps1").read_text()
        self.assertIn("OpenSSH effective auth: ", text)
        self.assertIn("passwordauthentication|pubkeyauthentication", text)
        self.assertLess(text.index("OpenSSH effective auth: "),
                        text.index("OpenSSH effective authentication policy is not key-only"))
        self.assertNotIn("LogLevel DEBUG3", text)

    def test_task_cannot_execute_before_a_signed_claim(self):
        text = (ROOT / ".github/workflows/verify-action.yml").read_text()
        self.assertIn("id-token: write", text)
        claim = text.index("Claim approved physical Run before any task work")
        execute = text.index("Execute bounded verification Task")
        self.assertLess(claim, execute)
        self.assertNotIn("${{ secrets.", text[:execute])
        self.assertNotIn("actions/checkout", text[:execute])

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
            ([302], 1, False),
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
                stderr = io.StringIO()
                with mock.patch.dict(os.environ, environment, clear=True):
                    with mock.patch("urllib.request.build_opener") as build_opener:
                        build_opener.return_value.open.side_effect = respond
                        with mock.patch("time.sleep") as sleep:
                            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                                if should_succeed:
                                    exec(compile(code, "Task Claim", "exec"), {})
                                else:
                                    with self.assertRaises(SystemExit) as captured:
                                        exec(compile(code, "Task Claim", "exec"), {})
                            self.assertEqual(sleep.call_count, 1 if expected_calls == 2 else 0)
                self.assertEqual(len(observed_tokens), expected_calls)
                self.assertEqual(claim_tokens,
                                 ["Bearer " + value for value in observed_tokens])
                self.assertNotIn(environment["ACTIONS_ID_TOKEN_REQUEST_TOKEN"],
                                 stdout.getvalue() + stderr.getvalue())
                self.assertNotIn("jwt-", stderr.getvalue())
                if not should_succeed:
                    self.assertIn("GitHub Action Claim claim_request HTTP",
                                  str(captured.exception.code))
                    self.assertNotIn(environment["ACTIONS_ID_TOKEN_REQUEST_TOKEN"],
                                     str(captured.exception.code))

        # A failed GitHub token mint is distinguished from a worker Claim 403.
        # The exception message may contain a token-bearing URL: never echo it.
        stderr = io.StringIO()
        claim_calls = []
        def oidc_denied(request, timeout=0):
            if "oidc.example" not in request.full_url:
                claim_calls.append(request.full_url)
            raise urllib.error.HTTPError(request.full_url, 401,
                                         "sensitive URL and bearer must not print",
                                         {}, None)
        with mock.patch.dict(os.environ, environment, clear=True):
            with mock.patch("urllib.request.build_opener") as build_opener:
                build_opener.return_value.open.side_effect = oidc_denied
                with contextlib.redirect_stderr(stderr):
                    with self.assertRaises(SystemExit) as captured_oidc:
                        exec(compile(code, "Task Claim OIDC rejection", "exec"), {})
        self.assertEqual(claim_calls, [])
        self.assertIn("GitHub Action Claim oidc_request HTTP 401",
                      str(captured_oidc.exception.code))
        self.assertNotIn("oidc.example", str(captured_oidc.exception.code))
        self.assertNotIn("DO-NOT-PRINT-THIS-SECRET", str(captured_oidc.exception.code))


if __name__ == "__main__":
    unittest.main()
