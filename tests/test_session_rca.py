"""Offline contract tests of the optional, immutable Session RCA bootstrap."""
import hashlib
import importlib.util
import io
import json
import os
import sys
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest import mock
import zipfile

SCRIPT = Path(__file__).resolve().parents[1] / '.github/scripts/session_rca.py'
if str(SCRIPT.parent) not in sys.path:
    sys.path.insert(0, str(SCRIPT.parent))
spec = importlib.util.spec_from_file_location('session_rca', SCRIPT)
assert spec and spec.loader
rca = importlib.util.module_from_spec(spec)
spec.loader.exec_module(rca)

TAG = 'v0.1.40'


def bundle(windows=False, version=TAG, extra=()):
    target = 'windows-x64' if windows else 'linux-x64-glibc'
    name = 'session-rca-windows.js' if windows else 'session-rca-main.js'
    files = {
        'bundle.json': json.dumps({'name': 'remote-control-agent', 'version': version,
            'target': target, 'device_protocol': 2, 'upgrade_profile': 'paired-full-v1'}).encode(),
        'bin/node.exe' if windows else 'bin/node': b'synthetic-node-not-executed',
        f'apps/remote-control-agent/src/{name}': b'// synthetic entry not executed\n',
    }
    output = io.BytesIO()
    if windows:
        with zipfile.ZipFile(output, 'w') as z:
            for path, content in [*files.items(), *extra]:
                z.writestr(path, content)
    else:
        with tarfile.open(fileobj=output, mode='w:gz') as tf:
            for path, content in [*files.items(), *extra]:
                entry = tarfile.TarInfo(path)
                entry.size = len(content)
                tf.addfile(entry, io.BytesIO(content))
    return output.getvalue()


class Download:
    def __init__(self, data):
        self.stream = io.BytesIO(data)
    def __enter__(self):
        return self
    def __exit__(self, *args):
        return False
    def geturl(self):
        return 'https://objects.githubusercontent.com/synthetic-release'
    def read(self, n):
        return self.stream.read(n)


def settings(root, data):
    return {'GITHUB_ACTIONS': 'true', 'RUNNER_ENVIRONMENT': 'github-hosted',
        'GITHUB_WORKFLOW': 'ubuntu', 'GITHUB_REPOSITORY': 'autoactions/github-actions',
        'ATTEMPT_ID': '11111111-1111-4111-8111-111111111111',
        'WORKFLOW_ACTION_CLAIM_URL': 'https://workflow.lirtual.dpdns.org/github/action/claim',
        'ACTIONS_ID_TOKEN_REQUEST_URL': 'https://oidc.example.net/',
        'ACTIONS_ID_TOKEN_REQUEST_TOKEN': 'synthetic-only', 'RUNNER_TEMP': root}


class SessionRcaBootstrapTests(unittest.TestCase):
    def invoke(self, payload, env_override=None, windows=False, select_override=None):
        with tempfile.TemporaryDirectory() as root:
            env = settings(root, payload)
            if windows:
                env['GITHUB_WORKFLOW'] = 'windows'
            env.update(env_override or {})
            calls = []
            def launch(argv, **kwargs):
                calls.append((argv, kwargs))
                return type('Child', (), {'pid': 1234, 'wait': lambda self, timeout: 0})()
            with mock.patch.object(rca, 'discover_audience', return_value='workflow-github-abcde') as discover, \
                    mock.patch.object(rca.sys, 'platform', 'win32' if windows else 'linux'):
                self.audience_discovery = discover
                with mock.patch.object(rca.subprocess, 'CREATE_NEW_PROCESS_GROUP', 512, create=True):
                    outcome = None
                    try:
                        outcome = rca.start(
                            env, opener=lambda *_args, **_kwargs: Download(payload),
                            launch=launch, select_release=select_override or
                            (lambda target, extension, opener: (
                                TAG, hashlib.sha256(payload).hexdigest(),
                                f"https://github.com/{rca.REPOSITORY}/releases/download/"
                                f"{TAG}/remote-control-agent-{TAG}-{target}.{extension}")))
                    except rca.BootstrapError:
                        outcome = 'denied'
            return outcome, calls

    def test_invalid_job_environment_never_downloads_or_launches(self):
        with mock.patch.object(rca.urllib.request, 'urlopen', side_effect=AssertionError('downloaded')):
            with self.assertRaises(rca.BootstrapError):
                rca.start({})

    def test_release_comes_from_current_mcp_workers_repo(self):
        self.assertEqual(rca.REPOSITORY, 'lirtual/mcp-workers')

    def test_untrusted_source_repository_cannot_register_session_agent(self):
        result, calls = self.invoke(bundle(), {'GITHUB_REPOSITORY': 'lirtual/github-actions'})
        self.assertEqual(result, 'denied')
        self.assertEqual(calls, [])

    def test_missing_ambient_oidc_audience_is_discovered_for_both_runners(self):
        for windows in (False, True):
            with self.subTest(windows=windows):
                result, calls = self.invoke(bundle(windows=windows), windows=windows)
                self.assertTrue(result)
                self.assertEqual(len(calls), 1)
                self.assertEqual(calls[0][1]['env']['WORKFLOW_ACTION_OIDC_AUDIENCE'],
                                 'workflow-github-abcde')
                self.audience_discovery.assert_called_once_with(
                    'https://workflow.lirtual.dpdns.org/github/action/claim')

    def test_missing_claim_audience_discovery_denies_before_release_download(self):
        for windows in (False, True):
            with self.subTest(windows=windows), tempfile.TemporaryDirectory() as root:
                env = settings(root, bundle(windows=windows))
                env['GITHUB_WORKFLOW'] = 'windows' if windows else 'ubuntu'
                env.pop('WORKFLOW_ACTION_CLAIM_URL')
                with mock.patch.object(rca.sys, 'platform', 'win32' if windows else 'linux'):
                    with mock.patch.object(rca.urllib.request, 'urlopen',
                                           side_effect=AssertionError('unexpected download')):
                        with self.assertRaises(ValueError):
                            rca.start(env)

    def test_stale_ambient_oidc_audience_is_not_trusted(self):
        result, calls = self.invoke(bundle(),
            {'WORKFLOW_ACTION_OIDC_AUDIENCE': 'workflow-github-wrong'})
        self.assertTrue(result)
        self.assertEqual(calls[0][1]['env']['WORKFLOW_ACTION_OIDC_AUDIENCE'],
                         'workflow-github-abcde')

    def test_linux_matching_pin_launches_job_private_reviewed_entrypoint(self):
        result, calls = self.invoke(bundle())
        self.assertTrue(result)
        self.assertEqual(len(calls), 1)
        argv, opts = calls[0]
        self.assertTrue(argv[0].replace('\\', '/').endswith('/bin/node'))
        self.assertTrue(argv[1].replace('\\', '/').endswith('/apps/remote-control-agent/src/session-rca-main.js'))
        self.assertTrue(opts['start_new_session'])
        self.assertEqual(opts['env']['GITHUB_REPOSITORY'], 'autoactions/github-actions')
        self.assertEqual(opts['env']['SESSION_ACTION_RCA'], '1')
        self.assertTrue(opts['env']['BASH_ENV'].replace('\\', '/').endswith('/.config/session-actions/rca-env.bash'))
        self.assertTrue(opts['env']['PATH'].split(os.pathsep)[0].replace('\\', '/').endswith('/.local/bin'))
        self.assertTrue(opts['env']['PATH'].split(os.pathsep)[1].replace('\\', '/').endswith('/.local/session-actions/npm/bin'))

    def test_windows_matching_pin_launches_approved_windows_entrypoint(self):
        result, calls = self.invoke(bundle(windows=True), windows=True)
        self.assertTrue(result)
        self.assertEqual(len(calls), 1)
        self.assertTrue(calls[0][0][1].endswith('session-rca-windows.js'))
        self.assertFalse(calls[0][1]['start_new_session'])
        self.assertNotIn('SESSION_ACTION_RCA', calls[0][1]['env'])
        self.assertNotIn('BASH_ENV', calls[0][1]['env'])
        self.assertIs(calls[0][1]['stderr'], rca.subprocess.DEVNULL)
        self.assertIs(calls[0][1]['stdout'], rca.subprocess.DEVNULL)

    def test_windows_registration_nonzero_exit_fails_without_error_output(self):
        from contextlib import redirect_stdout
        for code in (1, 17):
            class Child:
                def wait(self, timeout):
                    self.timeout = timeout
                    return code
            output = io.StringIO()
            with redirect_stdout(output):
                with self.assertRaises(rca.BootstrapError):
                    rca.confirm_windows_registration(Child())
            self.assertEqual(output.getvalue(), '')

    def test_windows_registration_timeout_kills_and_reaps_oidc_parent(self):
        class Child:
            killed = False
            reaped = False
            def wait(self, timeout):
                if not self.killed:
                    raise rca.subprocess.TimeoutExpired('synthetic', timeout)
                self.reaped = True
                return -9
            def kill(self):
                self.killed = True
        process = Child()
        with self.assertRaises(rca.BootstrapError):
            rca.confirm_windows_registration(process, timeout=1)
        self.assertTrue(process.killed)
        self.assertTrue(process.reaped)

    def test_windows_registration_zero_exit_does_not_claim_wss_online(self):
        from contextlib import redirect_stdout
        output = io.StringIO()
        class Child:
            def wait(self, timeout):
                self.timeout = timeout
                return 0
        with redirect_stdout(output):
            rca.confirm_windows_registration(Child())
        self.assertIn('registration exited successfully', output.getvalue())
        self.assertIn('WSS online is not yet confirmed', output.getvalue())

    def test_windows_transport_probe_emits_only_allowlisted_status(self):
        class Result:
            def __init__(self, value, code=0):
                self.returncode = code
                self.stdout = value
        def check(result, expected):
            calls = []
            def run(argv, **opts):
                calls.append((argv, opts))
                return result
            value = rca.observe_windows_transport(
                1234, r"C:\\Runner\\private\\node.exe", run=run, delay=lambda _: None)
            self.assertEqual(value, expected)
            self.assertEqual(len(calls), 1)
            argv, opts = calls[0]
            self.assertIn("ParentProcessId = 1234", argv[-1])
            self.assertIn("--session-transport", argv[-1])
            self.assertIn(r'(?:^|\s)', argv[-1])
            self.assertIn("node.exe", argv[-1])
            self.assertIs(opts['stderr'], rca.subprocess.DEVNULL)
            self.assertLessEqual(opts['timeout'], 10)
        check(Result(b"alive\n"), "alive")
        check(Result(b"exited\n"), "exited")
        check(Result(b"UNTRUSTED_SECRET_CONTENT"), "unknown")
        check(Result(b"alive\n", code=1), "unknown")

    def test_windows_transport_probe_timeout_is_unknown(self):
        def hang(*args, **kwargs):
            raise rca.subprocess.TimeoutExpired("synthetic", 1)
        self.assertEqual(rca.observe_windows_transport(
            1234, r"C:\\Runner\\node.exe", run=hang, delay=lambda _: None), "unknown")
        self.assertEqual(rca.observe_windows_transport(
            0, r"C:\\Runner\\node.exe", run=hang, delay=lambda _: None), "unknown")

    @unittest.skipUnless(sys.platform == 'win32' and os.environ.get('GITHUB_ACTIONS') == 'true',
                         'Native Windows CI only')
    def test_native_windows_transport_probe_against_synthetic_process(self):
        # Synthetic child has no credentials, network, Session identity or real RCA.
        import subprocess as sp
        import sys
        import time
        child = sp.Popen([sys.executable, '-c', 'import time; time.sleep(20)',
                          '--session-transport'], stdout=sp.DEVNULL,
                         stderr=sp.DEVNULL)
        try:
            self.assertEqual(rca.observe_windows_transport(
                os.getpid(), sys.executable, delay=lambda _: time.sleep(1)), 'alive')
        finally:
            child.kill()
            child.wait(timeout=5)
        self.assertEqual(rca.observe_windows_transport(
            os.getpid(), sys.executable, delay=lambda _: None), 'exited')

    def test_child_stage_reader_only_reports_allowlisted_values(self):
        with tempfile.TemporaryDirectory() as root:
            stage = Path(root) / "session-rca" / "transport-stage"
            stage.parent.mkdir()
            self.assertEqual(rca.observe_windows_child_stage(root,delay=lambda _:None),"unknown")
            for value in ("pending","entered","store_ready","pem_ready","challenge_start","wss_error","connected"):
                stage.write_bytes((value+"\n").encode())
                self.assertEqual(rca.observe_windows_child_stage(root,delay=lambda _:None),value)
            for raw in (b"OIDC_TOKEN_SECRET\n",b"challenge_ok\nMORE_SECRET",
                        b"wss_open\r\n",b"A"*65,b"\xff\n"):
                stage.write_bytes(raw)
                self.assertEqual(rca.observe_windows_child_stage(root,delay=lambda _:None),"unknown")

    def test_child_stage_reader_handles_late_identity_progress(self):
        with tempfile.TemporaryDirectory() as root:
            marker = Path(root) / "session-rca" / "transport-stage"
            marker.parent.mkdir()
            marker.write_bytes(b"entered\n")
            intervals = []
            def delay(seconds):
                intervals.append(seconds)
                if len(intervals) == 2:
                    marker.write_bytes(b"identity_ready\n")
            self.assertEqual(rca.observe_windows_child_stage(root, delay=delay),
                             "identity_ready")
            self.assertEqual(intervals, [12, 8])

    def test_child_stage_reader_returns_early_stage_after_bounded_window(self):
        with tempfile.TemporaryDirectory() as root:
            marker = Path(root) / "session-rca" / "transport-stage"
            marker.parent.mkdir()
            marker.write_bytes(b"pem_ready\n")
            intervals = []
            self.assertEqual(rca.observe_windows_child_stage(
                root, delay=lambda seconds: intervals.append(seconds)), "pem_ready")
            self.assertEqual(intervals, [12, 8, 8])

    def test_child_stage_reader_rejects_linked_files(self):
        with tempfile.TemporaryDirectory() as root:
            path=Path(root)/"session-rca"
            path.mkdir()
            outside=Path(root)/"outside"
            outside.write_text("connected\n")
            marker=path/"transport-stage"
            marker.symlink_to(outside)
            self.assertEqual(rca.observe_windows_child_stage(root,delay=lambda _:None),"unknown")

    def test_release_lookup_failure_denied_before_download(self):
        def unavailable(*_args):
            raise rca.BootstrapError("synthetic metadata unavailable")
        result, calls = self.invoke(bundle(), select_override=unavailable)
        self.assertEqual(result, 'denied')
        self.assertFalse(calls)

    def test_asset_source_and_sha_are_immutable(self):
        payload = bundle()
        with tempfile.TemporaryDirectory() as root:
            env = settings(root, payload)
            urls = []
            def opener(req, timeout):
                urls.append((req.full_url, timeout))
                return Download(payload)
            with mock.patch.object(rca.sys, 'platform', 'linux'), \
                    mock.patch.object(rca, 'discover_audience', return_value='workflow-github-abcde'):
                self.assertTrue(rca.start(env, opener=opener,
                    launch=lambda *_a, **_kw: type('Child', (), {'pid': 1234})(),
                    select_release=lambda target, ext, _opener: (
                        TAG, hashlib.sha256(payload).hexdigest(),
                        f"https://github.com/{rca.REPOSITORY}/releases/download/"
                        f"{TAG}/remote-control-agent-{TAG}-{target}.{ext}")))
            self.assertEqual(urls, [(
                'https://github.com/lirtual/mcp-workers/releases/download/v0.1.40/'
                'remote-control-agent-v0.1.40-linux-x64-glibc.tar.gz', 20)])

    def test_symlink_member_refused(self):
        import stat
        out = io.BytesIO()
        with zipfile.ZipFile(out, 'w') as z:
            item = zipfile.ZipInfo('linked-secret')
            item.create_system = 3
            item.external_attr = (stat.S_IFLNK | 0o777) << 16
            z.writestr(item, '../private')
        result, calls = self.invoke(out.getvalue(), windows=True)
        self.assertEqual(result, 'denied')
        self.assertFalse(calls)

    def test_changed_manifest_cannot_launch(self):
        result, calls = self.invoke(bundle(version='v0.1.41'))
        self.assertEqual(result, 'denied')
        self.assertFalse(calls)

    def test_wrong_sha_cannot_launch(self):
        result, calls = self.invoke(bundle(), select_override=lambda target, ext, _opener: (
            TAG, '0' * 64, f"https://github.com/{rca.REPOSITORY}/releases/download/"
            f"{TAG}/remote-control-agent-{TAG}-{target}.{ext}"))
        self.assertEqual(result, 'denied')
        self.assertFalse(calls)

    def test_unreviewed_runner_cannot_launch(self):
        result, calls = self.invoke(bundle(), {'RUNNER_ENVIRONMENT': 'self-hosted'})
        self.assertEqual(result, 'denied')
        self.assertFalse(calls)

    def test_duplicate_archive_member_rejected(self):
        result, calls = self.invoke(bundle(extra=[('bundle.json', b'{}')]))
        self.assertEqual(result, 'denied')
        self.assertFalse(calls)

    def test_traversal_archive_member_rejected(self):
        result, calls = self.invoke(bundle(extra=[('../external', b'bad')]))
        self.assertEqual(result, 'denied')
        self.assertFalse(calls)

    def test_windows_traversal_rejected(self):
        result, calls = self.invoke(bundle(windows=True, extra=[('../external', b'bad')]), windows=True)
        self.assertEqual(result, 'denied')
        self.assertFalse(calls)



class LatestReleaseSelectionTests(unittest.TestCase):
    def release(self, tag=TAG, *, immutable=True, draft=False, digest=None,
                windows=False, uploaded=True):
        target = 'windows-x64' if windows else 'linux-x64-glibc'
        ext = 'zip' if windows else 'tar.gz'
        name = f'remote-control-agent-{tag}-{target}.{ext}'
        return {'tag_name': tag, 'draft': draft, 'prerelease': True,
                'immutable': immutable, 'assets': [{
                    'name': name, 'state': 'uploaded' if uploaded else 'new',
                    'size': 1234,
                    'digest': 'sha256:' + (digest or 'a' * 64),
                    'browser_download_url':
                        f'https://github.com/{rca.REPOSITORY}/releases/download/{tag}/{name}',
                }]}

    def lookup(self, releases, *, redirect=False, windows=False):
        requested = []
        def opener(req, timeout):
            requested.append((req.full_url, timeout))
            data = json.dumps(releases).encode()
            response = Download(data)
            response.geturl = lambda: (
                'https://evil.invalid/' if redirect else req.full_url)
            return response
        target, ext = ('windows-x64', 'zip') if windows else ('linux-x64-glibc', 'tar.gz')
        return rca.resolve_latest_release(target, ext, opener=opener), requested

    def test_highest_complete_semver_not_latest_api_order(self):
        result, urls = self.lookup([self.release('v0.1.49'),
                                    self.release('v0.1.51'),
                                    self.release('v0.1.50-rc.3'),
                                    self.release('v0.1.52', draft=True)])
        self.assertEqual('v0.1.51', result[0])
        self.assertEqual('a' * 64, result[1])
        self.assertTrue(result[2].endswith('v0.1.51-linux-x64-glibc.tar.gz'))
        self.assertEqual(1, len(urls))
        self.assertIn('per_page=100&page=1', urls[0][0])
        self.assertLessEqual(urls[0][1], 8)

    def test_windows_target_uses_matching_asset(self):
        result, _ = self.lookup([self.release(windows=True)], windows=True)
        self.assertTrue(result[2].endswith('v0.1.40-windows-x64.zip'))

    def test_no_downgrade_if_highest_release_is_mutable_or_missing_asset(self):
        for latest in (self.release('v0.1.52', immutable=False),
                       self.release('v0.1.52', uploaded=False),
                       self.release('v0.1.52', digest='bad'),
                       {'tag_name': 'v0.1.52', 'draft': False,
                        'immutable': True, 'assets': []}):
            with self.subTest(latest=latest), self.assertRaises(rca.BootstrapError):
                self.lookup([self.release('v0.1.51'), latest])

    def test_draft_rc_and_empty_listing_are_denied(self):
        with self.assertRaises(rca.BootstrapError):
            self.lookup([self.release('v0.1.52-rc.1'),
                         self.release('v0.1.53', draft=True)])
        with self.assertRaises(rca.BootstrapError):
            self.lookup([])

    def test_api_redirect_is_rejected(self):
        with self.assertRaises(rca.BootstrapError):
            self.lookup([self.release()], redirect=True)

    def test_pagination_limit_fails_closed(self):
        releases = [self.release() for _ in range(rca.RELEASE_PAGE_SIZE)]
        with self.assertRaisesRegex(rca.BootstrapError, 'pagination incomplete'):
            self.lookup(releases)

    def test_tampered_download_url_denied(self):
        release = self.release()
        release['assets'][0]['browser_download_url'] = 'https://evil.invalid/asset'
        with self.assertRaises(rca.BootstrapError):
            self.lookup([release])

if __name__ == '__main__':
    unittest.main()
