"""Regression checks for immutable Session execution. Actionlint validates YAML separately."""
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ("ubuntu", "windows", "chrome", "code-server", "openlist")

class SessionWorkflowInvariants(unittest.TestCase):
    def test_public_session_action_names_are_lowercase_and_match_paths(self):
        self.assertFalse((ROOT / ".github/workflows/linux.yml").exists())
        self.assertFalse((ROOT / ".github/scripts/linux-ssh.sh").exists())
        for name in WORKFLOWS:
            with self.subTest(workflow=name):
                text = (ROOT / ".github/workflows" / (name + ".yml")).read_text()
                self.assertEqual(text.splitlines()[0], "name: " + name)

    def test_every_session_checks_out_exact_run_sha(self):
        for name in WORKFLOWS:
            with self.subTest(workflow=name):
                yml = (ROOT / ".github/workflows" / (name + ".yml")).read_text()
                self.assertIn("ref: ${{ github.sha }}", yml)
                self.assertIn("persist-credentials: false", yml)
                if name in ("ubuntu", "windows"):
                    self.assertIn("hostname: ${{ env.SESSION_TAILSCALE_HOSTNAME }}", yml)
                    self.assertIn("session_mode:", yml)
                    self.assertIn("type: choice", yml)
                    self.assertIn("- temporary", yml)
                    self.assertIn("- fixed", yml)
                    self.assertIn("default: fixed", yml)
                    self.assertIn(f"runs-on: {name}-latest", yml)
                    self.assertIn("verify-tailnet-name.py", yml)
                    self.assertIn("SESSION_TAILSCALE_HOSTNAME:", yml)
                else:
                    self.assertNotIn("tailscale/github-action@", yml)
                self.assertIn("timeout-minutes: 360", yml)
                self.assertIn("Capture job lifetime before checkout", yml)
                self.assertLess(yml.index("Capture job lifetime before checkout"),
                                yml.index("Checkout pinned dispatched revision"))
                if name in ("ubuntu", "windows"):
                    self.assertIn("oauth-client-id: ${{ vars.TS_OAUTH_CLIENT_ID }}", yml)
                    self.assertIn("audience: ${{ vars.TS_AUDIENCE }}", yml)
                self.assertNotIn("secrets.TS_OAUTH_CLIENT_ID", yml)
                self.assertNotIn("secrets.TS_AUDIENCE", yml)

                self.assertIn("WORKFLOW_ACTION_TYPE: session", yml)
                self.assertIn("session_action.py claim", yml)
                self.assertIn("session_action.py ready", yml)
                self.assertIn("session_action.py hold", yml)
                self.assertEqual(len(re.findall(r"(?m)^  session:$", yml)), 1)

    def test_duration_mode_opt_in_and_hard_bounded_default(self):
        for name in WORKFLOWS:
            with self.subTest(name=name):
                yml = (ROOT / ".github/workflows" / (name + ".yml")).read_text()
                self.assertIn("      duration_mode:", yml)
                self.assertIn("          - repository", yml)
                self.assertIn("        default: explicit", yml)
                self.assertIn("        default: 300", yml)
                self.assertIn("vars.SESSION_DURATION_MINUTES || '300'", yml)
                self.assertIn("inputs.duration_mode == 'repository'", yml)
                self.assertIn("timeout-minutes: 360", yml)

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
                join = text.index(pinned_tailnet) if name in ("ubuntu", "windows") else text.index("Start loopback-only" if name in ("chrome", "code-server") else "Start password-protected")
                ready = text.index("session_action.py ready")
                hold = text.index("session_action.py hold")
                self.assertTrue(claim < join < ready < hold)
                if name in ("ubuntu", "windows"):
                    verify = text.index("verify-tailnet-name.py")
                    self.assertTrue(join < verify < ready)
                    self.assertIn("hostname: ${{ env.SESSION_TAILSCALE_HOSTNAME }}", text)
                self.assertIn("id-token: write", text[:claim])
                self.assertIn("WORKFLOW_ACTION_TYPE: session", text[:claim])
                self.assertNotIn("tailscale set", text[:join])
                if name not in ("ubuntu", "windows"):
                    self.assertNotIn(pinned_tailnet, text)
                    self.assertNotIn("sudo tailscale set", text)
                self.assertNotIn("${{ secrets.", text[:claim])
                self.assertNotIn("TS_OAUTH_CLIENT_ID", text[:claim])
                self.assertNotIn("TS_AUDIENCE", text[:claim])
                self.assertIn("if: always()", text[hold:])
                if name in ("chrome", "code-server", "openlist"):
                    if name == "openlist":
                        self.assertIn("secrets.SESSION_SERVICE_PASSWORD", text[join:ready])
                    else:
                        self.assertNotIn("SESSION_SERVICE_PASSWORD", text)
                        self.assertNotIn("${{ secrets.", text[join:ready])
                    self.assertIn("start-tunnel.sh", text[join:ready])
                    if name == "openlist":
                        self.assertNotIn("vars.SESSION_TUNNEL_ALLOWED_EMAIL", text[join:ready])
                    else:
                        self.assertIn("vars.SESSION_TUNNEL_ALLOWED_EMAIL", text[join:ready])
                    self.assertIn("actions/upload-artifact@", text[join:ready])
                    self.assertNotIn("sudo tailscale set --ssh\\n", text[join:ready])
                    self.assertNotIn("secrets.OPENLIST_ADMIN_PASSWORD", text)
                    self.assertLess(text.index("start-tunnel.sh"), ready)
                if name in ("ubuntu", "windows"):
                    self.assertIn("secrets.SESSION_SYSTEM_PASSWORD",
                                  text[join:ready])
                    self.assertNotIn("SESSION_SSH_PUBLIC_KEY", text)
                    self.assertNotIn("WINDOWS_ADMIN_PASSWORD", text)
                    self.assertNotIn("Remove-LocalUser", text)
                    self.assertEqual(text.count("secrets.SESSION_SYSTEM_PASSWORD"), 1)
                if name == "openlist":
                    self.assertIn("secrets.OPENLIST_DATABASE_URI", text[join:ready])
                    self.assertIn("secrets.OPENLIST_DATABASE_CA", text[join:ready])
                    self.assertIn("openlist-db-config.py", (ROOT / ".github/scripts/start-openlist.sh").read_text())
                    self.assertNotIn("secrets.OPENLIST_DATABASE }}", text)
                if name == "windows":
                    self.assertNotIn("SESSION_RDP_PASSWORD", text)
                    self.assertIn("windows-rdp.ps1", text[join:ready])
                    self.assertIn("SessionActionsTailscaleRDP", text[hold:])

    def test_windows_hides_tailscale_onboarding_before_install(self):
        windows = (ROOT / ".github/workflows/windows.yml").read_text()
        claim = windows.index("session_action.py claim")
        policy = windows.index("Suppress Tailscale first-run onboarding")
        tailnet = windows.index("uses: tailscale/github-action@")
        rdp = windows.index("windows-rdp.ps1")
        self.assertTrue(claim < policy < tailnet < rdp)
        self.assertIn(r"HKLM:\SOFTWARE\Policies\Tailscale", windows)
        self.assertIn("New-ItemProperty -Path $Policy -Name OnboardingFlow -PropertyType String -Value hide -Force", windows)
        self.assertNotIn("Stop-Service Tailscale", windows)
        self.assertNotIn("Stop-Process -Name tailscaled", windows)

    def test_windows_hides_only_pre_job_terminal_before_ready(self):
        workflow = (ROOT / ".github/workflows/windows.yml").read_text()
        claim = workflow.index("session_action.py claim")
        hide = workflow.index("Hide pre-existing Windows Terminal window")
        ready = workflow.index("session_action.py ready")
        self.assertTrue(claim < hide < ready)
        snippet = workflow[hide:ready]
        self.assertIn("session-action-start", snippet)
        self.assertIn("Get-Process -Name WindowsTerminal", snippet)
        self.assertIn("$_.SessionId -eq $SessionId", snippet)
        self.assertIn("$_.StartTime.ToUniversalTime() -lt $StartedAt", snippet)
        self.assertIn("[SessionWindow]::ShowWindow($_.MainWindowHandle, 0)", snippet)
        self.assertIn("[SessionWindow]::IsWindowVisible($_.MainWindowHandle)", snippet)
        self.assertNotIn("Stop-Process", snippet)
        self.assertNotIn("taskkill", snippet)

    def test_web_service_tunnels_keep_otp_only_for_chrome_and_code_server(self):
        chrome = (ROOT / ".github/scripts/start-chrome.sh").read_text()
        code = (ROOT / ".github/scripts/start-code-server.sh").read_text()
        openlist = (ROOT / ".github/scripts/start-openlist.sh").read_text()
        tunnel = (ROOT / ".github/scripts/start-tunnel.sh").read_text()
        self.assertIn("lscr.io/linuxserver/chrome@sha256:49a019a04b8d38422609d3c586636293417f61886704d516b7d5233cb4bd0b12", chrome)
        self.assertNotIn("CUSTOM_USER=", chrome)
        self.assertNotIn("FILE__PASSWORD=", chrome)
        self.assertNotIn("session-service-password", chrome)
        self.assertIn('if [[ "$status" == 200 ]]', chrome)
        self.assertNotIn("remote-debugging-port", chrome)
        self.assertIn("--auth none", code)
        self.assertNotIn("--auth password", code)
        self.assertNotIn("SESSION_SERVICE_PASSWORD", code)
        self.assertIn('if [[ "$status" == 200 ]]', code)
        self.assertIn('OPENLIST_ADMIN_PASSWORD="$SESSION_SERVICE_PASSWORD"', openlist)
        self.assertIn('/api/auth/login', openlist)
        self.assertIn("2026.10.3", tunnel)
        self.assertIn("053b80b0a23031a038fdbf3c073f59f82b8f1f152aa67971d7383ffafc0dbab0", tunnel)
        self.assertIn("trycloudflare", tunnel)
        self.assertIn("session-tunnel-url", tunnel)
        self.assertIn("GITHUB_STEP_SUMMARY", tunnel)
        self.assertIn("Cloudflare Tunnel exited before Ready", tunnel)
        self.assertIn('SESSION_TUNNEL_ALLOWED_EMAIL must be one explicit email address', tunnel)
        self.assertIn('SESSION_TUNNEL_ALLOWED_EMAIL', tunnel)
        self.assertIn("--allowed-mail", tunnel)
        self.assertIn('"$binary" tunnel --help', tunnel)
        self.assertIn('if [[ ! "$allowed_mail" =~', tunnel)
        self.assertIn('tunnel --no-autoupdate --url "http://127.0.0.1:$port" >', tunnel)

        self.assertIn('if [[ "$service" != openlist ]]', tunnel)
        self.assertIn('if [[ "$service" == openlist ]]', tunnel)
        self.assertIn('"$candidate/api/public/settings"', tunnel)
        self.assertIn('r.get("code")==200', tunnel)
        self.assertIn('login.trycloudflare.com/authorize', tunnel)
        self.assertIn("email one-time PIN is the only access gate", tunnel)
        self.assertIn("OpenList handles user login and guest permissions", tunnel)
        self.assertNotIn("Complete the email one-time PIN gate", tunnel)
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

    def test_windows_rdp_disconnect_returns_only_runner_session_to_console(self):
        rdp = (ROOT / ".github/scripts/windows-rdp.ps1").read_text()
        handoff = (ROOT / ".github/scripts/windows-rdp-handoff.ps1").read_text()
        workflow = (ROOT / ".github/workflows/windows.yml").read_text()
        self.assertIn("'windows-rdp-handoff.ps1') -Install", rdp)
        self.assertIn("RUNNER_ENVIRONMENT: ${{ runner.environment }}", workflow)
        self.assertIn("SessionActionsRdpConsoleHandoff", workflow)
        self.assertIn("Unregister-ScheduledTask", workflow)
        self.assertIn("$env:RUNNER_ENVIRONMENT -ne 'github-hosted'", handoff)
        self.assertIn("<StateChange>RemoteDisconnect</StateChange>", handoff)
        self.assertIn("<LogonType>InteractiveToken</LogonType>", handoff)
        self.assertIn("<RunLevel>HighestAvailable</RunLevel>", handoff)
        self.assertIn("MultipleInstancesPolicy>IgnoreNew", handoff)
        self.assertIn("quser.exe", handoff)
        self.assertIn("CandidateIds.Count -ne 1", handoff)
        self.assertIn("'/dest:console'", handoff)
        self.assertNotIn("LockWorkStation", handoff)
        self.assertNotIn("Set-ItemProperty", handoff)
        self.assertNotIn("$env:SESSIONNAME", handoff)

    def test_uu_share_invite_is_optional_and_not_automatically_disclosed(self):
        script = (ROOT / ".github/scripts/windows-uu.ps1").read_text(encoding="utf-8")
        hold = (ROOT / ".github/scripts/session_action.py").read_text()
        ci = (ROOT / ".github/workflows/ci.yml").read_text()
        self.assertIn("复制并分享", script)
        self.assertIn("GetCurrentPattern(", script)
        self.assertIn("[System.Windows.Automation.InvokePattern]::Pattern", script)
        self.assertIn("$ClipboardPrimed", script)
        self.assertIn("$AllButtons.Count -eq 2", script)
        self.assertIn("$CodeBox.Right", script)
        self.assertIn("$DistanceY -le 45", script)
        self.assertIn("$Adjacent.Count -eq 1", script)
        self.assertIn("$Marker = 'uu-share-'", script)
        self.assertIn("Set-Clipboard -Value $Marker", script)
        self.assertIn("$Current -cne $Marker", script)
        self.assertIn("if (-not $Refresh", script)
        self.assertIn("if ($Refresh", script)
        self.assertIn("if ($ShareUrl) { $Payload.share_url = $ShareUrl }", script)
        self.assertIn("UU_SHARE_URL.fullmatch", hold)
        self.assertIn("UU_LITE_SHARE_URL_UNAVAILABLE=true", ci)
        self.assertNotIn("Write-Output $ShareUrl", script)
        self.assertNotIn("Write-Host $ShareUrl", script)

    def test_ubuntu_uses_existing_runner_user_and_real_password_ssh(self):
        workflow = (ROOT / ".github/workflows/ubuntu.yml").read_text()
        script = (ROOT / ".github/scripts/ubuntu-ssh.sh").read_text()
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
        self.assertIn('sudo ss -H -ltn', script)
        self.assertIn('"$ssh_listeners" != "$tailnet_ip:22"', script)
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
        self.assertIn("$Password.Length -lt 8", text)
        self.assertIn("MinimumPasswordLength = 8", text)
        self.assertIn("PasswordComplexity = 0", text)
        self.assertIn("$env:RUNNER_ENVIRONMENT -ne 'github-hosted'", text)
        self.assertIn("runner.environment", workflow)
        self.assertIn("if ($LASTEXITCODE -ne 0)", text)
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
        self.assertIn("Get-NetTCPConnection -State Listen -LocalPort 22", text)
        self.assertIn("$Listeners.Count -ne 1", text)
        self.assertIn("$Listeners[0].LocalAddress -ne $TailnetAddress", text)
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
        self.assertEqual(config["ssl_mode"], "true")
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

    def test_aiven_ca_pem_bundle_validation(self):
        import runpy
        module = runpy.run_path(str(ROOT / ".github/scripts/openlist-db-config.py"))
        validate_ca = module["validate_ca"]
        ca = (ROOT / "tests/fixtures/test-ca.pem").read_text()
        self.assertEqual(validate_ca(ca), ca)
        self.assertEqual(validate_ca(ca + ca), ca + ca)
        for invalid in ("", "not a PEM certificate", ca + "\\nsecret", ca.replace("CERTIFICATE", "PRIVATE KEY")):
            with self.subTest(invalid=invalid[:30]):
                with self.assertRaises(ValueError):
                    validate_ca(invalid)

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
            ca = (ROOT / "tests/fixtures/test-ca.pem").read_text()
            env["OPENLIST_DATABASE_CA"] = ca
            script = ROOT / ".github/scripts/openlist-db-config.py"
            result = subprocess.run(
                ["python", str(script), str(config_path)],
                env=env, text=True, capture_output=True, timeout=10,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertNotIn("s3cret", result.stdout + result.stderr)
            if os.name != "nt":
                self.assertEqual(stat.S_IMODE(config_path.stat().st_mode), 0o600)
            data = json.loads(config_path.read_text())
            self.assertEqual(data["database"]["name"], "testdb")
            self.assertEqual(data["database"]["ssl_mode"], "true")
            self.assertEqual(data["database"]["password"], "s3cret")
            self.assertEqual(data["database"]["ssl_mode"], "true")
            pem_path = target / "database-ca.pem"
            self.assertEqual(pem_path.read_text(), ca)
            if os.name != "nt":
                self.assertEqual(stat.S_IMODE(pem_path.stat().st_mode), 0o600)
            self.assertNotEqual(data["jwt_secret"], "")
            result = subprocess.run(
                ["python", str(script), str(config_path)],
                env=env, text=True, capture_output=True, timeout=10,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertNotIn("s3cret", result.stdout + result.stderr)
            # A missing/invalid CA must fail without creating any secret files.
            config_path.unlink()
            pem_path.unlink()
            env["OPENLIST_DATABASE_CA"] = "not a PEM certificate"
            rejected = subprocess.run(
                ["python", str(script), str(config_path)],
                env=env, text=True, capture_output=True, timeout=10,
            )
            self.assertNotEqual(rejected.returncode, 0)
            self.assertNotIn("s3cret", rejected.stdout + rejected.stderr)
            self.assertFalse(config_path.exists())
            self.assertFalse(pem_path.exists())
        start = (ROOT / ".github/scripts/start-openlist.sh").read_text()
        self.assertIn("OPENLIST_DATABASE_URI", start)
        self.assertIn("openlist-db-config.py", start)
        self.assertIn("openlist admin set", start)
        self.assertIn("SSL_CERT_FILE=/opt/openlist/data/database-ca.pem", start)
        self.assertIn("unset OPENLIST_DATABASE_URI OPENLIST_DATABASE_CA", start)
        self.assertIn("external MySQL initialization failed", start)
        self.assertNotIn("sqlite3", start)
        workflow = (ROOT / ".github/workflows/openlist.yml").read_text()
        self.assertIn("OPENLIST_DATABASE_URI: ${{ secrets.OPENLIST_DATABASE_URI }}", workflow)
        self.assertIn("OPENLIST_DATABASE_CA: ${{ secrets.OPENLIST_DATABASE_CA }}", workflow)
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
        # The upstream admin set command bootstraps the DB itself; avoid a redundant
        # full OpenList initialization while preserving login verification.
        self.assertEqual(startup.count('./openlist admin set'), 1)
        self.assertNotIn('./openlist admin >/dev/null', startup)
        self.assertIn('OpenList total local startup:', startup)
        self.assertIn('OpenList config and MySQL preflight:', startup)
        self.assertIn('OpenList pinned image acquisition:', startup)
        self.assertIn('docker image inspect "$image"', startup)
        self.assertIn('docker pull --quiet "$image"', startup)
        self.assertIn('OpenList admin CLI initialization:', startup)
        self.assertIn('OpenList service and admin login:', startup)
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
