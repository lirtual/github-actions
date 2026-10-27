"""Spec #51: parser tests are not network/download security acceptance."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest

FILE = Path(__file__).resolve().parents[1] / ".github/scripts/download_batch.py"
spec = importlib.util.spec_from_file_location("download_batch", FILE)
download = importlib.util.module_from_spec(spec)
spec.loader.exec_module(download)

def sample(**changes):
    value = {
        "downloads": [
            {"url": "https://example.org/release.tar.gz",
             "destination_path": "/build/artifacts"},
            {"url": "https://example.net/release.torrent",
             "destination_path": "/build/test-fixtures"},
        ],
        "project_purpose": "Fixtures for testing this repository",
        "duration_minutes": 300,
    }
    value.update(changes)
    return json.dumps(value)

class DownloadBatchTests(unittest.TestCase):
    def test_multi_source_and_deadline(self):
        accepted = download.validate(sample())
        self.assertEqual(2, len(accepted["downloads"]))
        self.assertEqual(300, accepted["duration_minutes"])

    def test_default_deadline(self):
        payload = json.loads(sample())
        payload.pop("duration_minutes")
        self.assertEqual(300, download.validate(json.dumps(payload))["duration_minutes"])

    def test_rejects_out_of_range_deadlines_and_bool(self):
        for value in (0, 331, True, 1.2, "300", -1):
            with self.subTest(value=value), self.assertRaises(download.InvalidBatch):
                download.validate(sample(duration_minutes=value))

    def test_rejects_empty_and_malformed(self):
        for value in ('', '{}', '[]', '{"downloads":[]}', '{"downloads":',
                      '{"downloads":0,"project_purpose":"a"}'):
            with self.subTest(value=value), self.assertRaises(download.InvalidBatch):
                download.validate(value)

    def test_rejects_duplicate_json_keys(self):
        value = sample()
        with self.assertRaises(download.InvalidBatch):
            download.validate(value.replace('"project_purpose":',
                                            '"project_purpose":"oops","project_purpose":'))

    def test_invalid_unicode_fails_closed(self):
        with self.assertRaises(download.InvalidBatch):
            download.validate("\ud800")
        with self.assertRaises(download.InvalidBatch):
            download.validate(sample(project_purpose="\ud800"))

    def test_rejects_large_manifest(self):
        with self.assertRaises(download.InvalidBatch):
            download.validate(sample(project_purpose="x" * 5000))

    def test_rejects_private_sources_credentials_and_unverified_queries(self):
        bad = [
            "http://127.0.0.1/a", "https://[::1]/a", "http://169.254.169.254/latest",
            "https://10.1.2.3/a", "http://localhost/a", "https://a.local/a",
            "https://alice:secret@example.org/a", "https://example.org/a?sig=abc",
            "https://example.org/a#secret", "file:///etc/passwd",
            "ftp://example.org/a", "https://example.org:8080/a",
            "http://example.org/a\nInjected: foo",
        ]
        for url in bad:
            with self.subTest(url=url), self.assertRaises(download.InvalidBatch):
                download.validate(sample(downloads=[{"url": url,
                                                     "destination_path": "/drive/artifact"}]))

    def test_public_infohash_format_not_runtime_bt_authorization(self):
        magnet = "magnet:?xt=urn:btih:" + "a" * 40
        accepted = download.validate(sample(downloads=[
            {"url": magnet, "destination_path": "/drive/artifact"}]))
        self.assertEqual(magnet, accepted["downloads"][0]["url"])
        for bad in (magnet + "&tr=http%3A%2F%2F127.0.0.1",
                    "magnet:?xt=urn:btih:invalid"):
            with self.assertRaises(download.InvalidBatch):
                download.validate(sample(downloads=[
                    {"url": bad, "destination_path": "/drive/artifact"}]))

    def test_destination_path_escape_and_ambiguity(self):
        for path in ("/", "//drive/root", "/drive/../root", "/drive/./root",
                     "/drive//root", "/drive/root/", "relative/path",
                     "/drive\\root", "/drive/root?token=x"):
            with self.subTest(path=path), self.assertRaises(download.InvalidBatch):
                download.validate(sample(downloads=[
                    {"url": "https://example.org/a", "destination_path": path}]))

    def test_destination_conflicts_are_rejected(self):
        for path in ("/build/artifacts", "/build", "/build/artifacts/a"):
            with self.subTest(path=path), self.assertRaises(download.InvalidBatch):
                download.validate(sample(downloads=[
                    {"url": "https://example.org/a", "destination_path": "/build/artifacts"},
                    {"url": "https://example.net/b", "destination_path": path}]))

    def test_reject_casefold_aliases_before_admitting_a_batch(self):
        for path in ("/build/ARTIFACTS", "/BUILD/artifacts",
                     "/build/ARTIFACTS/nested", "/BUILD"):
            with self.subTest(path=path), self.assertRaises(download.InvalidBatch):
                download.validate(sample(downloads=[
                    {"url": "https://example.org/a",
                     "destination_path": "/build/artifacts"},
                    {"url": "https://example.net/b",
                     "destination_path": path}]))
        accepted=download.validate(sample(downloads=[
            {"url": "https://example.org/a",
             "destination_path": "/build/artifacts"},
            {"url": "https://example.net/b",
             "destination_path": "/build/artifacts-extra"}]))
        self.assertEqual(2,len(accepted["downloads"]))

    def test_entry_extra_properties_are_rejected(self):
        with self.assertRaises(download.InvalidBatch):
            download.validate(sample(downloads=[
                {"url": "https://example.org/a", "destination_path": "/drive/a",
                 "command": "echo not allowed"}]))

    def test_cli_redacts_untrusted_data(self):
        secret = "private-user-data"
        payload = sample(downloads=[
            {"url": "https://example.org/a?sig=" + secret,
             "destination_path": "/drive/secret"}])
        env = {**os.environ, "BATCH_JSON": payload}
        result = subprocess.run([sys.executable, str(FILE)], capture_output=True,
                                text=True, env=env, check=False)
        self.assertEqual(2, result.returncode)
        self.assertNotIn(secret, result.stdout + result.stderr)
        self.assertNotIn("/drive/secret", result.stdout + result.stderr)

    def test_valid_cli_reports_only_counts_and_unverified_gates(self):
        result = subprocess.run([sys.executable, str(FILE)], capture_output=True,
                                text=True, env={**os.environ, "BATCH_JSON": sample()})
        self.assertEqual(0, result.returncode)
        self.assertIn("RUNTIME_NOT_AUTHORIZED", result.stdout)
        self.assertNotIn("https://", result.stdout)
        self.assertNotIn("/build/", result.stdout)

if __name__ == "__main__":
    unittest.main()
