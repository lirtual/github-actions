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
                self.assertIn("timeout-minutes: 360", yml)
                self.assertIn("Capture job lifetime before checkout", yml)
                self.assertLess(yml.index("Capture job lifetime before checkout"),
                                yml.index("Checkout pinned dispatched revision"))
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
                if name in ("linux", "windows"):
                    self.assertIn("secrets.SESSION_SSH_PASSWORD",
                                  text[join:ready])
                    self.assertNotIn("SESSION_SSH_PUBLIC_KEY", text)
                    self.assertNotIn("SESSION_SSH_PASSWORD", text)
                    self.assertNotIn("Remove-LocalUser", text)
                    self.assertEqual(text.count("secrets.SESSION_SSH_PASSWORD"), 1)

    def test_ubuntu_uses_existing_runner_user_and_real_password_ssh(self):
        workflow = (ROOT / ".github/workflows/linux.yml").read_text()
        script = (ROOT / ".github/scripts/linux-ssh.sh").read_text()
        self.assertIn('account="$(id -un)"', script)
        self.assertIn('printf \'%s:%s\\n\' "$account" "$SESSION_SSH_PASSWORD" | sudo chpasswd', script)
        self.assertIn('sudo tailscale set --ssh=false', script)
        self.assertNotIn('sudo tailscale set --ssh\n', workflow)
        self.assertNotIn('useradd', script)
        self.assertNotIn('adduser', script)
        self.assertNotIn('New-LocalUser', script)
        self.assertIn('PasswordAuthentication yes', script)
        self.assertIn('PubkeyAuthentication no', script)
        self.assertIn('AuthenticationMethods password', script)
        self.assertIn('ListenAddress $tailnet_ip', script)
        self.assertIn('sudo /usr/sbin/sshd -t', script)
        self.assertIn('sudo systemctl restart ssh', script)
        self.assertIn('sudo systemctl stop ssh', workflow)
        self.assertIn('SESSION_SSH_PASSWORD: ${{ secrets.SESSION_SSH_PASSWORD }}', workflow)
        self.assertNotIn('16 characters', script)
        self.assertNotIn('Length -lt 16', script)

    def test_windows_ssh_uses_default_runner_account_not_a_new_user(self):
        text = (ROOT / ".github/scripts/windows-ssh.ps1").read_text()
        self.assertIn("$Username = [Environment]::UserName", text)
        self.assertIn("Get-LocalUser -Name $Username", text)
        self.assertIn("$Account.SID.Value -ne $Identity.User.Value", text)
        self.assertIn("[Security.Principal.WindowsBuiltInRole]::Administrator", text)
        self.assertIn("Set-LocalUser -Name $Username -Password $SecurePassword", text)
        self.assertNotIn("New-LocalUser", text)
        self.assertNotIn("Remove-LocalUser", text)
        self.assertNotIn("sessionuser", text)

    def test_windows_password_is_secret_and_fails_closed(self):
        text = (ROOT / ".github/scripts/windows-ssh.ps1").read_text()
        workflow = (ROOT / ".github/workflows/windows.yml").read_text()
        self.assertIn("$env:SESSION_SSH_PASSWORD", text)
        self.assertIn("[string]::IsNullOrEmpty($Password)", text)
        self.assertNotIn("$Password.Length -lt 16", text)
        self.assertIn("$env:SESSION_SSH_PASSWORD = $null", text)
        self.assertIn("secrets.SESSION_SSH_PASSWORD", workflow)
        self.assertNotIn("vars.SESSION_SSH_PASSWORD", workflow)
        self.assertNotIn("SESSION_SSH_PUBLIC_KEY", workflow + text)
        self.assertNotIn("Write-Output $Password", text)
        self.assertNotIn("Write-Host $Password", text)
        self.assertNotIn("LogLevel DEBUG3", text)
        self.assertNotIn("SyslogFacility LOCAL0", text)

    def test_windows_tailnet_firewall_and_listener_are_scoped(self):
        text = (ROOT / ".github/scripts/windows-ssh.ps1").read_text()
        self.assertIn("New-NetFirewallRule -Name 'SessionActionsTailscaleSSH' -DisplayName", text)
        self.assertIn("-LocalAddress $TailnetAddress -RemoteAddress '100.64.0.0/10' -InterfaceAlias", text)
        self.assertIn("('ListenAddress ' + $TailnetAddress)", text)
        self.assertIn("Get-NetTCPConnection -State Listen -LocalPort 22 -LocalAddress $TailnetAddress", text)
        self.assertIn("Disable-NetFirewallRule", text)

    def test_windows_sshd_reloads_password_only_policy(self):
        text = (ROOT / ".github/scripts/windows-ssh.ps1").read_text()
        config = text.index("& $Sshd -t")
        effective = text.index("$EffectiveConfig = & $Sshd -T")
        stop = text.index("Stop-Service sshd -ErrorAction Stop")
        start = text.index("Start-Service sshd -ErrorAction Stop")
        self.assertLess(config, effective)
        self.assertLess(effective, stop)
        self.assertLess(stop, start)
        self.assertIn("'PasswordAuthentication yes'", text)
        self.assertIn("'PubkeyAuthentication no'", text)
        self.assertIn("'AuthenticationMethods password'", text)
        self.assertIn("('AllowUsers ' + $Username.ToLowerInvariant())", text)
        self.assertIn("('listenaddress ' + $TailnetAddress + ':22')", text)
        self.assertNotIn("AuthorizedKeysFile", text)
        self.assertNotIn("'AllowUsers sessionuser'", text)

    def test_openlist_ready_requires_admin_authentication(self):
        # The real Ubuntu service smoke runs this script with an isolated,
        # non-production password; Ready cannot rely on homepage HTTP 200.
        startup = (ROOT / ".github/scripts/start-openlist.sh").read_text()
        self.assertIn('OPENLIST_ADMIN_PASSWORD', startup)
        self.assertIn('/api/auth/login', startup)
        self.assertIn('result.get("code") == 200', startup)
        self.assertIn('get("token")', startup)
        self.assertIn('OpenList admin login verification failed', startup)
        self.assertNotIn('print(password)', startup)
        self.assertNotIn('print(result)', startup)
        self.assertNotIn('print(payload)', startup)

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
