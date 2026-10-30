"""Spec #51 isolated receiver: fail closed before launching aria2."""
import json
import os
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

SCRIPTS = Path(__file__).resolve().parents[1] / ".github/scripts"
sys.path.insert(0, str(SCRIPTS))
from download_receive import DownloadUnverified, receive

BATCH = json.dumps({
    "remote": "fixed",
    "downloads": [
        {"url": "https://example.org/public.zip",
         "destination_dir": "release"},
    ],
    "project_purpose": "repository build artifacts",
})


class ReceiverTests(unittest.TestCase):
    def test_rejects_empty_and_invalid_batch_without_process(self):
        with tempfile.TemporaryDirectory() as tmp:
            for batch in ("{}", "[]", "", BATCH.replace(
                    "https://example.org/public.zip", "http://127.0.0.1/private")):
                with self.subTest(batch=batch[:24]):
                    with patch("download_receive.subprocess.Popen") as started:
                        with self.assertRaises(DownloadUnverified):
                            receive(batch, tmp, time.monotonic() + 10)
                        started.assert_not_called()

    def test_rejects_nonempty_work_dir_without_erasing_any_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            existing = Path(tmp) / "keep"
            existing.write_bytes(b"preserve")
            with patch("download_receive.subprocess.Popen") as started:
                with self.assertRaises(DownloadUnverified):
                    receive(BATCH, tmp, time.monotonic() + 10)
                started.assert_not_called()
            self.assertEqual(b"preserve", existing.read_bytes())

    def test_rejects_relative_work_dir(self):
        with patch("download_receive.subprocess.Popen") as started:
            with self.assertRaises(DownloadUnverified):
                receive(BATCH, "relative/dir", time.monotonic() + 10)
            started.assert_not_called()

    def test_secret_urls_are_not_echoed_on_cli_rejection(self):
        import subprocess
        sensitive = BATCH.replace(
            "https://example.org/public.zip", "https://example.org/a?secret=PRIVATE_SENTINEL")
        with tempfile.TemporaryDirectory() as tmp:
            env = {**os.environ, "BATCH_JSON": sensitive,
                   "DOWNLOAD_WORKSPACE": tmp}
            result = subprocess.run(
                [sys.executable, str(SCRIPTS / "download_receive.py")],
                env=env, text=True, capture_output=True, timeout=10)
            self.assertEqual(2, result.returncode)
            self.assertNotIn("PRIVATE_SENTINEL", result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
