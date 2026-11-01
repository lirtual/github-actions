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
    return {'SESSION_RCA_RELEASE_TAG': TAG,
        'SESSION_RCA_RELEASE_SHA256': hashlib.sha256(data).hexdigest(),
        'GITHUB_ACTIONS': 'true', 'RUNNER_ENVIRONMENT': 'github-hosted',
        'GITHUB_WORKFLOW': 'ubuntu', 'GITHUB_REPOSITORY': 'lirtual/github-actions',
        'ATTEMPT_ID': '11111111-1111-4111-8111-111111111111',
        'WORKFLOW_ACTION_OIDC_AUDIENCE': 'workflow-github-abcde',
        'ACTIONS_ID_TOKEN_REQUEST_URL': 'https://oidc.example.net/',
        'ACTIONS_ID_TOKEN_REQUEST_TOKEN': 'synthetic-only', 'RUNNER_TEMP': root}


class SessionRcaBootstrapTests(unittest.TestCase):
    def invoke(self, payload, env_override=None, windows=False):
        with tempfile.TemporaryDirectory() as root:
            env = settings(root, payload)
            if windows:
                env['GITHUB_WORKFLOW'] = 'windows'
            env.update(env_override or {})
            calls = []
            def launch(argv, **kwargs):
                calls.append((argv, kwargs))
                return type('Child', (), {'pid': 1234, 'wait': lambda self, timeout: 0})()
            with mock.patch.object(rca.sys, 'platform', 'win32' if windows else 'linux'):
                with mock.patch.object(rca.subprocess, 'CREATE_NEW_PROCESS_GROUP', 512, create=True):
                    outcome = None
                    try:
                        outcome = rca.start(env, opener=lambda *_args, **_kwargs: Download(payload), launch=launch)
                    except rca.BootstrapError:
                        outcome = 'denied'
            return outcome, calls

    def test_default_disabled_never_downloads_or_launches(self):
        with mock.patch.object(rca.urllib.request, 'urlopen', side_effect=AssertionError('downloaded')):
            self.assertFalse(rca.start({}))

    def test_linux_matching_pin_launches_job_private_reviewed_entrypoint(self):
        result, calls = self.invoke(bundle())
        self.assertTrue(result)
        self.assertEqual(len(calls), 1)
        argv, opts = calls[0]
        self.assertTrue(argv[0].replace('\\', '/').endswith('/bin/node'))
        self.assertTrue(argv[1].replace('\\', '/').endswith('/apps/remote-control-agent/src/session-rca-main.js'))
        self.assertTrue(opts['start_new_session'])
        self.assertEqual(opts['env']['GITHUB_REPOSITORY'], 'lirtual/github-actions')

    def test_windows_matching_pin_launches_approved_windows_entrypoint(self):
        result, calls = self.invoke(bundle(windows=True), windows=True)
        self.assertTrue(result)
        self.assertEqual(len(calls), 1)
        self.assertTrue(calls[0][0][1].endswith('session-rca-windows.js'))
        self.assertFalse(calls[0][1]['start_new_session'])
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

    def test_partial_pin_denied_before_download(self):
        result, calls = self.invoke(bundle(), {'SESSION_RCA_RELEASE_TAG': ''})
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
            with mock.patch.object(rca.sys, 'platform', 'linux'):
                self.assertTrue(rca.start(env, opener=opener,
                    launch=lambda *_a, **_kw: type('Child', (), {'pid': 1234})()))
            self.assertEqual(urls, [(
                'https://github.com/lirtual/remote-control-agent/releases/download/v0.1.40/'
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
        result, calls = self.invoke(bundle(), {'SESSION_RCA_RELEASE_SHA256': '0' * 64})
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


if __name__ == '__main__':
    unittest.main()
