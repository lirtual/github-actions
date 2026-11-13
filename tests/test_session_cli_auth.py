"""Spec #93: supported terminal boundary checks using synthetic credentials."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / ".github/scripts/session-cli-ubuntu.sh"


class WorkflowContract(unittest.TestCase):
    def test_only_interactive_sessions_receive_auth_after_signed_claim(self):
        for name in ("ubuntu", "windows"):
            with self.subTest(workflow=name):
                workflow = (ROOT / ".github/workflows" / f"{name}.yml").read_text()
                claim = workflow.index("session_action.py claim")
                auth = workflow.index("secrets.GH_TOKEN")
                cf = workflow.index("secrets.CLOUDFLARE_API_TOKEN")
                ready = workflow.index("session_action.py ready")
                ssh_setup = workflow.index("Configure Ubuntu Runner password SSH" if name == "ubuntu" else "Configure Tailnet-only password SSH")
                self.assertLess(claim, min(auth, cf))
                self.assertLess(max(auth, cf), ssh_setup)
                self.assertLess(ssh_setup, ready)
                self.assertNotIn("secrets.GH_TOKEN", workflow[:claim])
                self.assertNotIn("secrets.CLOUDFLARE_API_TOKEN", workflow[:claim])
                self.assertIn("persist-credentials: false", workflow)
                self.assertIn("if: always()", workflow[ready:])
        for name in ("chrome", "code-server", "openlist", "download", "ci", "verify-action"):
            with self.subTest(unrelated=name):
                workflow = (ROOT / ".github/workflows" / f"{name}.yml").read_text()
                self.assertNotIn("secrets.GH_TOKEN", workflow)
                self.assertNotIn("secrets.CLOUDFLARE_API_TOKEN", workflow)

    def test_windows_ssh_and_rdp_use_powershell_profile_loader(self):
        script = (ROOT / ".github/scripts/session-cli-windows.ps1").read_text()
        self.assertIn("DefaultShell", script)
        self.assertIn("CurrentUserAllHosts", script)
        self.assertIn("if ($env:GITHUB_ACTIONS -ne 'true')", script)
        self.assertIn("GH_TOKEN", script)
        self.assertIn("CLOUDFLARE_API_TOKEN", script)
        self.assertNotIn("gh auth login", script)
        self.assertNotIn("credential.helper store", script)


@unittest.skipUnless(os.name == "posix", "Bash login boundary runs on Ubuntu")
class UbuntuLoginShell(unittest.TestCase):
    def clean_env(self):
        env = dict(os.environ)
        # The test runner may itself be a live RCA child. Never let its
        # actual credentials or Bash loader enter synthetic fixture shells.
        for key in ("SESSION_ACTION_RCA", "BASH_ENV", "GH_TOKEN", "GITHUB_TOKEN",
                    "CLOUDFLARE_API_TOKEN", "CLOUDFLARE_ACCOUNT_ID"):
            env.pop(key, None)
        return env

    def setup_home(self, home):
        (home / ".bashrc").write_text("# existing user profile\n")
        fakebin = home / "bin"
        fakebin.mkdir()
        gh = fakebin / "gh"
        actual = shutil.which("gh")
        if actual:
            gh.symlink_to(actual)
        else:
            gh.write_text("#!/bin/sh\nexit 0\n")
            gh.chmod(0o755)
        return fakebin, bool(actual)

    def run_shell(self, env, command):
        return subprocess.run(["bash", "--noprofile", "-ic", command],
                              env=env, text=True, capture_output=True)

    def test_activation_fresh_shell_git_identity_and_cleanup(self):
        with tempfile.TemporaryDirectory() as temp:
            home = Path(temp)
            fakebin, real_gh = self.setup_home(home)
            path = str(fakebin) + ":" + os.environ["PATH"]
            env = dict(self.clean_env(), HOME=temp, PATH=path, GH_TOKEN="synthetic-gh-token",
                       CLOUDFLARE_API_TOKEN="synthetic-cf-token",
                       CLOUDFLARE_ACCOUNT_ID="synthetic-account", GIT_USER_NAME="Spec User",
                       GIT_USER_EMAIL="spec@example.invalid")
            subprocess.run(["bash", str(SCRIPT), "activate"], check=True, env=env, capture_output=True)
            fresh = dict(self.clean_env(), HOME=temp, PATH=path, GITHUB_ACTIONS="false")
            for key in ("GH_TOKEN", "CLOUDFLARE_API_TOKEN", "CLOUDFLARE_ACCOUNT_ID"):
                fresh.pop(key, None)
            result = self.run_shell(
                fresh, 'test "$GH_TOKEN" = synthetic-gh-token && '
                       'test "$CLOUDFLARE_API_TOKEN" = synthetic-cf-token && '
                       'test "$CLOUDFLARE_ACCOUNT_ID" = synthetic-account && '
                       'test "$(git config --global user.name)" = "Spec User" && '
                       'test "$(git config --global user.email)" = spec@example.invalid && '
                       'test "$(git config --global user.useConfigOnly)" = true')
            self.assertEqual(result.returncode, 0, result.stderr)
            actions = self.run_shell(dict(fresh, GITHUB_ACTIONS="true"),
                                     'test -z "$GH_TOKEN" && test -z "$CLOUDFLARE_API_TOKEN"')
            self.assertEqual(actions.returncode, 0, actions.stderr)
            # The RCA child inherits GITHUB_ACTIONS=true but is explicitly
            # admitted after signed Claim; both Bash invocation forms work.
            rca = dict(fresh, GITHUB_ACTIONS="true", SESSION_ACTION_RCA="1")
            interactive = self.run_shell(
                rca, 'test "$GH_TOKEN" = synthetic-gh-token && '
                     'test "$CLOUDFLARE_API_TOKEN" = synthetic-cf-token')
            self.assertEqual(interactive.returncode, 0, interactive.stderr)
            loader = home / ".config/session-actions/rca-env.bash"
            self.assertEqual(loader.stat().st_mode & 0o777, 0o600)
            shell = home / ".config/session-actions/rca-shell"
            self.assertEqual(shell.stat().st_mode & 0o777, 0o700)
            # Real first-level commands source the controlled loader
            # explicitly, not merely a nested Bash startup hook.
            first_env = dict(fresh, GITHUB_ACTIONS="true",
                             GITHUB_REPOSITORY="autoactions/github-actions",
                             SESSION_ACTION_RCA="1", BASH_ENV=str(loader))
            first = subprocess.run(
                [str(shell), "-c",
                 'test "$GH_TOKEN" = synthetic-gh-token && '
                 'test "$CLOUDFLARE_API_TOKEN" = synthetic-cf-token'],
                env=first_env, text=True, capture_output=True)
            self.assertEqual(first.returncode, 0, first.stderr)
            unreviewed = subprocess.run(
                [str(shell), "-c",
                 'test -z "$GH_TOKEN" && test -z "$CLOUDFLARE_API_TOKEN"'],
                env=dict(first_env, GITHUB_REPOSITORY="unreviewed/repo"),
                text=True, capture_output=True)
            self.assertEqual(unreviewed.returncode, 0, unreviewed.stderr)
            malformed = subprocess.run([str(shell), "--unreviewed"],
                                       env=first_env, text=True, capture_output=True)
            self.assertEqual(malformed.returncode, 125)
            noninteractive = subprocess.run(
                ["bash", "--noprofile", "--norc", "-c",
                 'test "$GH_TOKEN" = synthetic-gh-token && '
                 'test "$CLOUDFLARE_API_TOKEN" = synthetic-cf-token'],
                env=dict(rca, BASH_ENV=str(loader)), capture_output=True, text=True)
            self.assertEqual(noninteractive.returncode, 0, noninteractive.stderr)
            inactive = subprocess.run(
                ["bash", "--noprofile", "--norc", "-c",
                 'test -z "$GH_TOKEN" && test -z "$CLOUDFLARE_API_TOKEN"'],
                env=dict(fresh, GITHUB_ACTIONS="true", BASH_ENV=str(loader)),
                capture_output=True, text=True)
            self.assertEqual(inactive.returncode, 0, inactive.stderr)
            stored = home / ".config/session-actions/credentials.bash"
            self.assertEqual(stored.stat().st_mode & 0o777, 0o600)
            self.assertEqual(stored.parent.stat().st_mode & 0o777, 0o700)
            gitconfig = (home / ".gitconfig").read_text()
            self.assertNotIn("synthetic-gh-token", gitconfig)
            self.assertNotIn("synthetic-cf-token", gitconfig)
            if real_gh:
                self.assertIn("gh auth git-credential", gitconfig)

            repo = home / "example-repo"
            repo.mkdir()
            subprocess.run(["git", "-C", str(repo), "init", "-q"], check=True, env=fresh)
            subprocess.run(["git", "-C", str(repo), "config", "user.name", "Local Author"], check=True, env=fresh)
            subprocess.run(["git", "-C", str(repo), "config", "user.email", "local@example.invalid"], check=True, env=fresh)
            subprocess.run(["git", "-C", str(repo), "commit", "-q", "--allow-empty", "-m", "sample"],
                           check=True, env=fresh)
            author = subprocess.check_output(["git", "-C", str(repo), "show", "-s", "--format=%an|%ae|%cn|%ce"],
                                             env=fresh, text=True).strip()
            self.assertEqual(author, "Local Author|local@example.invalid|Local Author|local@example.invalid")
            subprocess.run(["bash", str(SCRIPT), "cleanup"], check=True, env=env, capture_output=True)
            self.assertFalse(stored.exists())
            self.assertFalse(loader.exists())
            self.assertFalse(shell.exists())
            self.assertNotIn("session-actions", (home / ".bashrc").read_text())

    def test_missing_credentials_never_fall_back_to_inferred_git_identity(self):
        with tempfile.TemporaryDirectory() as temp:
            home = Path(temp)
            fakebin, _ = self.setup_home(home)
            env = dict(self.clean_env(), HOME=temp, PATH=str(fakebin) + ":" + os.environ["PATH"])
            for key in ("GH_TOKEN", "GITHUB_TOKEN", "CLOUDFLARE_API_TOKEN",
                        "CLOUDFLARE_ACCOUNT_ID", "GIT_USER_NAME", "GIT_USER_EMAIL",
                        "GIT_AUTHOR_NAME", "GIT_AUTHOR_EMAIL",
                        "GIT_COMMITTER_NAME", "GIT_COMMITTER_EMAIL"):
                env.pop(key, None)
            subprocess.run(["bash", str(SCRIPT), "activate"], check=True, env=env, capture_output=True)
            result = subprocess.run(["git", "config", "--global", "--get", "user.useConfigOnly"],
                                    env=env, capture_output=True, text=True)
            self.assertEqual(result.stdout.strip(), "true")
            self.assertFalse((home / ".config/session-actions/credentials.bash").exists())
            self.assertNotIn("credential", (home / ".gitconfig").read_text())
            repo = home / "identity-not-set"
            repo.mkdir()
            subprocess.run(["git", "-C", str(repo), "init", "-q"], check=True, env=env)
            commit = subprocess.run(["git", "-C", str(repo), "commit", "-q", "--allow-empty", "-m", "must fail"],
                                    env=env, capture_output=True)
            self.assertNotEqual(commit.returncode, 0)
            subprocess.run(["bash", str(SCRIPT), "cleanup"], check=True, env=env, capture_output=True)


if __name__ == "__main__":
    unittest.main()
