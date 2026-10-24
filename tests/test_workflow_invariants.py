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
                if name in ("chrome", "code-server", "openlist"):
                    self.assertIn("secrets.SESSION_SERVICE_PASSWORD", text[join:ready])
                    self.assertIn("start-tunnel.sh", text[join:ready])
                    self.assertIn("actions/upload-artifact@", text[join:ready])
                    self.assertNotIn("sudo tailscale set --ssh\\n", text[join:ready])
                    self.assertNotIn("secrets.OPENLIST_ADMIN_PASSWORD", text)
                    self.assertLess(text.index("start-tunnel.sh"), ready)
                if name in ("linux", "windows"):
                    self.assertIn("secrets.SESSION_SYSTEM_PASSWORD",
                                  text[join:ready])
                    self.assertNotIn("SESSION_SSH_PUBLIC_KEY", text)
                    self.assertNotIn("WINDOWS_ADMIN_PASSWORD", text)
                    self.assertNotIn("Remove-LocalUser", text)
                    self.assertEqual(text.count("secrets.SESSION_SYSTEM_PASSWORD"), 1)
                if name == "openlist":
                    self.assertIn("secrets.OPENLIST_DATABASE_URI", text[join:ready])
                    self.assertIn("openlist-db-config.py", (ROOT / ".github/scripts/start-openlist.sh").read_text())
                    self.assertNotIn("secrets.OPENLIST_DATABASE }}", text)
                if name == "windows":
                    self.assertNotIn("SESSION_RDP_PASSWORD", text)
                    self.assertIn("windows-rdp.ps1", text[join:ready])
                    self.assertIn("SessionActionsTailscaleRDP", text[hold:])

    def test_services_use_native_auth_before_cloudflare_tunnel(self):
        chrome = (ROOT / ".github/scripts/start-chrome.sh").read_text()
        code = (ROOT / ".github/scripts/start-code-server.sh").read_text()
        openlist = (ROOT / ".github/scripts/start-openlist.sh").read_text()
        tunnel = (ROOT / ".github/scripts/start-tunnel.sh").read_text()
        self.assertIn("lscr.io/linuxserver/chrome@sha256:49a019a04b8d38422609d3c586636293417f61886704d516b7d5233cb4bd0b12", chrome)
        self.assertIn("CUSTOM_USER=admin", chrome)
        self.assertIn("FILE__PASSWORD=", chrome)
        self.assertIn('if [[ "$status" == 401 ]]', chrome)
        self.assertNotIn("remote-debugging-port", chrome)
        self.assertIn("--auth password", code)
        self.assertNotIn("--auth none", code)
        self.assertIn('PASSWORD="$SESSION_SERVICE_PASSWORD"', code)
        self.assertIn('OPENLIST_ADMIN_PASSWORD="$SESSION_SERVICE_PASSWORD"', openlist)
        self.assertIn('/api/auth/login', openlist)
        self.assertIn("2026.8.2", tunnel)
        self.assertIn("fcfb02b575a52ca1af2e3267af4e1517bcdeb30ac48c834c69abaed3c0576ad2", tunnel)
        self.assertIn("trycloudflare", tunnel)
        self.assertIn("session-tunnel-url", tunnel)
        self.assertIn("GITHUB_STEP_SUMMARY", tunnel)
        self.assertIn("Cloudflare Tunnel exited before Ready", tunnel)
        self.assertNotIn('secrets.SESSION_SERVICE_PASSWORD', tunnel)

    def test_windows_rdp_uses_existing_account_and_private_firewall(self):
        rdp = (ROOT / ".github/scripts/windows-rdp.ps1").read_text()
        self.assertNotIn("Set-LocalUser", rdp)
        self.assertNotIn("SESSION_RDP_PASSWORD", rdp)
        self.assertIn("SESSION_SYSTEM_PASSWORD", rdp)
        self.assertIn("Get-LocalUser -Name ([Environment]::UserName)", rdp)
        self.assertNotIn("New-LocalUser", rdp)
        self.assertIn("UserAuthentication -Value 1", rdp)
        self.assertIn("fDenyTSConnections -Value 0", rdp)
        self.assertIn("-LocalPort 3389 -LocalAddress $TailnetAddress", rdp)
        self.assertIn("Start-Service TermService", rdp)
        windows = (ROOT / ".github/workflows/windows.yml").read_text()
        self.assertNotIn("secrets.SESSION_RDP_PASSWORD", windows)
        self.assertIn("Remove-NetFirewallRule -Name SessionActionsTailscaleRDP", windows)
        self.assertIn("fDenyTSConnections -Value 1", windows)

    def test_ubuntu_uses_existing_runner_user_and_real_password_ssh(self):
        workflow = (ROOT / ".github/workflows/linux.yml").read_text()
        script = (ROOT / ".github/scripts/linux-ssh.sh").read_text()
        self.assertIn('account="$(id -un)"', script)
        self.assertIn('printf \'%s:%s\\n\' "$account" "$SESSION_SYSTEM_PASSWORD" | sudo chpasswd', script)
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
        self.assertIn('SESSION_SYSTEM_PASSWORD: ${{ secrets.SESSION_SYSTEM_PASSWORD }}', workflow)
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
        self.assertIn("$env:SESSION_SYSTEM_PASSWORD", text)
        self.assertIn("[string]::IsNullOrEmpty($Password)", text)
        self.assertNotIn("$Password.Length -lt 16", text)
        self.assertIn("$env:SESSION_SYSTEM_PASSWORD = $null", text)
        self.assertIn("secrets.SESSION_SYSTEM_PASSWORD", workflow)
        self.assertNotIn("vars.SESSION_SYSTEM_PASSWORD", workflow)
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

    def test_openlist_mysql_uri_modes_and_validation(self):
        import runpy
        parser = runpy.run_path(str(ROOT / ".github/scripts/openlist-db-config.py"))
        parse = parser["parse_mysql_uri"]
        base = "mysql://appuser:p%5Fass@db.example.invalid:18691/tenantdb?ssl-mode=REQUIRED"
        config = parse(base)
        self.assertEqual(config["type"], "mysql")
        self.assertEqual(config["host"], "db.example.invalid")
        self.assertEqual(config["port"], 18691)
        self.assertEqual(config["name"], "tenantdb")
        self.assertEqual(config["password"], "p_ass")
        self.assertEqual(config["table_prefix"], "x_")
        self.assertEqual(config["ssl_mode"], "skip-verify")
        verified = parse(base.replace("REQUIRED", "VERIFY_IDENTITY"))
        self.assertEqual(verified["ssl_mode"], "true")
        for invalid in [
            base.replace("REQUIRED", "DISABLED"),
            base.replace("REQUIRED", "PREFERRED"),
            base.replace("?ssl-mode=REQUIRED", ""),
            base + "&extra=1",
            base.replace("mysql://", "postgres://"),
            base.replace("/tenantdb?", "/?"),
            base.replace("appuser", "user@injected"),
            base.replace("p%5Fass", ""),
            base.replace("db.example.invalid", "bad host"),
        ]:
            with self.subTest(uri=invalid):
                with self.assertRaises(ValueError):
                    parse(invalid)

    def test_openlist_mysql_uri_config_is_private_and_has_no_sqlite_fallback(self):
        import json
        import os
        import stat
        import subprocess
        import tempfile
        with tempfile.TemporaryDirectory() as temp:
            target = Path(temp) / "openlist-data"
            target.mkdir()
            config_path = target / "config.json"
            env = dict(os.environ)
            env["RUNNER_TEMP"] = temp
            env["OPENLIST_DATABASE_URI"] = "mysql://openlist:s3cret@mysql.example.invalid:18691/testdb?ssl-mode=REQUIRED"
            script = ROOT / ".github/scripts/openlist-db-config.py"
            result = subprocess.run(
                ["python", str(script), str(config_path)],
                env=env, text=True, capture_output=True, timeout=10,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertNotIn("s3cret", result.stdout + result.stderr)
            self.assertEqual(stat.S_IMODE(config_path.stat().st_mode), 0o600)
            data = json.loads(config_path.read_text())
            self.assertEqual(data["database"]["name"], "testdb")
            self.assertEqual(data["database"]["ssl_mode"], "skip-verify")
            self.assertEqual(data["database"]["password"], "s3cret")
            self.assertNotEqual(data["jwt_secret"], "")
            result = subprocess.run(
                ["python", str(script), str(config_path)],
                env=env, text=True, capture_output=True, timeout=10,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertNotIn("s3cret", result.stdout + result.stderr)
        start = (ROOT / ".github/scripts/start-openlist.sh").read_text()
        self.assertIn("OPENLIST_DATABASE_URI", start)
        self.assertIn("openlist-db-config.py", start)
        self.assertIn("openlist admin set", start)
        self.assertIn("external MySQL initialization failed", start)
        self.assertNotIn("sqlite3", start)
        workflow = (ROOT / ".github/workflows/openlist.yml").read_text()
        self.assertIn("OPENLIST_DATABASE_URI: ${{ secrets.OPENLIST_DATABASE_URI }}", workflow)
        self.assertIn('rm -f "$RUNNER_TEMP/openlist-data/config.json"', workflow)

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
