"""Spec #51: public batch syntax, not authorization or runtime safety."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch
import tempfile

FILE = Path(__file__).resolve().parents[1] / '.github/scripts/download_batch.py'
spec = importlib.util.spec_from_file_location('download_batch', FILE)
download = importlib.util.module_from_spec(spec)
spec.loader.exec_module(download)


def sample(**changes):
    batch = {
        'remote': 'approved-remote',
        'downloads': [
            {'url': 'https://example.org/release.tar.gz', 'destination_dir': 'build/artifacts'},
            {'url': 'https://example.net/release.zip', 'destination_dir': 'build/fixtures'},
        ],
        'project_purpose': 'Testing artifacts for this repository',
        'duration_minutes': 300,
    }
    batch.update(changes)
    return json.dumps(batch)


class DownloadBatchTests(unittest.TestCase):
    def test_event_file_avoids_logging_raw_batch_env(self):
        expected = sample()
        with tempfile.TemporaryDirectory() as tmp:
            event = Path(tmp) / "event.json"
            event.write_text(json.dumps({"inputs": {"batch_json": expected}}))
            with patch.dict(os.environ, {"GITHUB_EVENT_PATH": str(event)}, clear=True):
                self.assertEqual(expected, download.load_batch_json())
                self.assertEqual(2, len(download.validate(download.load_batch_json())["downloads"]))
            event.write_text(json.dumps({"inputs": {"batch_json": "x" * 5000}}))
            with patch.dict(os.environ, {"GITHUB_EVENT_PATH": str(event)}, clear=True):
                with self.assertRaises(download.InvalidBatch):
                    download.validate(download.load_batch_json())
            event.write_text(json.dumps({"inputs": {}}))
            with patch.dict(os.environ, {"GITHUB_EVENT_PATH": str(event)}, clear=True):
                self.assertEqual("", download.load_batch_json())

    def test_one_fixed_remote_many_sources_and_default_duration(self):
        manifest = download.validate(sample())
        self.assertEqual('approved-remote', manifest['remote'])
        self.assertEqual(2, len(manifest['downloads']))
        self.assertEqual('build/artifacts', manifest['downloads'][0]['destination_dir'])
        self.assertEqual(300, manifest['duration_minutes'])
        batch = json.loads(sample())
        del batch['duration_minutes']
        self.assertEqual(300, download.validate(json.dumps(batch))['duration_minutes'])

    def test_url_only_defaults_to_direct_owner_root(self):
        approved = download.validate(sample(downloads=[
            {'url': 'https://example.org/Clash.Verge-2.5.8-1.aarch64.rpm'}]))
        self.assertEqual('', approved['downloads'][0]['destination_dir'])
        self.assertNotIn('destination_path', approved['downloads'][0])

    def test_reject_second_or_dynamic_remote_and_legacy_openlist(self):
        for remote in ('', 'Koofr:/folder', '/Koofr', '../drive', 'foo/bar', 'a.b',
                       'remote name', '_hidden', 'http://host', 'x'*65):
            with self.subTest(remote=remote), self.assertRaises(download.InvalidBatch):
                download.validate(sample(remote=remote))
        for legacy in (
            {'url': 'https://example.org/a', 'destination_path': '/Koofr/file'},
            {'url': 'https://example.org/a', 'destination_dir': '/Koofr/folder'},
            {'url': 'https://example.org/a', 'destination_dir': 'Koofr:folder'},
            {'url': 'https://example.org/a', 'destination_dir': 'ok', 'remote': 'other'},
        ):
            with self.subTest(legacy=legacy), self.assertRaises(download.InvalidBatch):
                download.validate(sample(downloads=[legacy]))
        with self.assertRaises(download.InvalidBatch):
            download.validate(sample(remotes=['approved-remote', 'second']))

    def test_reject_non_http_sources_including_torrent_and_magnet(self):
        for url in ('magnet:?xt=urn:btih:' + 'a'*40, 'ftp://example.org/a',
                    'https://example.org/file.torrent', 'https://example.org/A.TORRENT',
                    'https://example.org/file%2Etorrent',
                    'file:///etc/passwd'):
            with self.subTest(url=url), self.assertRaises(download.InvalidBatch):
                download.validate(sample(downloads=[{'url': url, 'destination_dir': 'safe'}]))

    def test_reject_private_signed_and_embedded_credentials(self):
        for url in ('http://127.0.0.1/a', 'https://[::1]/a',
                    'http://169.254.169.254/latest', 'https://10.2.3.4/a',
                    'https://a.local/a', 'https://user:pass@example.org/a',
                    'https://example.org/a?token=1', 'https://example.org/a#secret',
                    'https://example.org:8080/a', 'http://example.org/a\nINJECTED'):
            with self.subTest(url=url), self.assertRaises(download.InvalidBatch):
                download.validate(sample(downloads=[{'url': url, 'destination_dir': 'safe'}]))

    def test_reject_unsafe_relative_directories_and_aliases(self):
        for dest in ('', '/', '/build', 'build/', './build', 'build/./test',
                     'build/../test', 'build//test', 'a\\b', 'a:b', 'a?b',
                     'a#b', 'a%20', 'trail.', ' a ', 'a/COM1', 'a/../b'):
            with self.subTest(dest=dest), self.assertRaises(download.InvalidBatch):
                download.validate(sample(downloads=[{'url': 'https://example.org/a',
                                                     'destination_dir': dest}]))
        for dest in ('BUILD/artifacts', 'build/ARTIFACTS'):
            with self.subTest(dest=dest), self.assertRaises(download.InvalidBatch):
                download.validate(sample(downloads=[
                    {'url': 'https://example.org/a', 'destination_dir': 'build/artifacts'},
                    {'url': 'https://example.net/b', 'destination_dir': dest},
                ]))

    def test_same_or_nested_directory_is_not_a_file_collision_yet(self):
        # Actual final file paths can only be checked after aria2 finishes.
        for directory in ('build/artifacts', 'build', 'build/artifacts/nested'):
            approved = download.validate(sample(downloads=[
                {'url': 'https://example.org/a', 'destination_dir': 'build/artifacts'},
                {'url': 'https://example.net/b', 'destination_dir': directory},
            ]))
            self.assertEqual(2, len(approved['downloads']))

    def test_reject_malformed_bounded_and_duplicate_keys(self):
        for raw in ('', '{}', '[]', '{"downloads":[]}',
                    sample(duration_minutes=True), sample(duration_minutes=331),
                    sample(duration_minutes=0), sample(project_purpose='x'*5000),
                    sample(project_purpose='\ud800'),
                    sample().replace('"remote":', '"remote":"duplicate","remote":')):
            with self.subTest(raw=repr(raw)[:40]), self.assertRaises(download.InvalidBatch):
                download.validate(raw)

    def test_reject_unknown_fields_and_never_log_source(self):
        with self.assertRaises(download.InvalidBatch):
            download.validate(sample(command='arbitrary'))
        secret = 'private-source-secret'
        env = {**os.environ, 'BATCH_JSON': sample(downloads=[
            {'url': 'https://example.org/file?sig=' + secret, 'destination_dir': 'safe'}])}
        proc = subprocess.run([sys.executable, str(FILE)], capture_output=True,
                              text=True, env=env, check=False)
        self.assertEqual(2, proc.returncode)
        self.assertNotIn(secret, proc.stdout + proc.stderr)
        proc = subprocess.run([sys.executable, str(FILE)], capture_output=True,
                              text=True, env={**os.environ, 'BATCH_JSON': sample()})
        self.assertEqual(0, proc.returncode)
        self.assertIn('RUNTIME_NOT_AUTHORIZED', proc.stdout)
        self.assertNotIn('approved-remote', proc.stdout)
        self.assertNotIn('https://', proc.stdout)


if __name__ == '__main__':
    unittest.main()
