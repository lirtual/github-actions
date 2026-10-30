"""Spec #51 isolated receiver: fail closed before launching aria2."""
import hashlib
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import time
import unittest
from contextlib import redirect_stdout
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
    def test_verified_source_audit_binds_gid_and_url_without_leaking_url(self):
        import download_receive
        source = "https://example.org/unpublished/release.zip"
        out = io.StringIO()
        with redirect_stdout(out):
            download_receive._emit_source_audit(
                1, "0123456789abcdef", source, {"file_count": 2, "total_bytes": 42})
        value = out.getvalue()
        self.assertIn("DOWNLOAD_SOURCE_VERIFIED source_index=1", value)
        self.assertIn("gid=0123456789abcdef", value)
        self.assertIn("url_sha256=" + hashlib.sha256(source.encode()).hexdigest(), value)
        self.assertIn("status=complete files=2 bytes=42", value)
        self.assertNotIn("unpublished", value)
        self.assertNotIn("https://", value)

    def test_entrypoint_reuses_absolute_deadline_and_rejects_expiry(self):
        import download_receive
        deadline = time.monotonic() + 55
        with patch.dict(os.environ, {"BATCH_JSON": BATCH,
                                      "DOWNLOAD_WORKSPACE": "/work",
                                      "DOWNLOAD_DEADLINE": str(deadline)}):
            with patch("download_receive.receive",
                       return_value={"sources": 1, "files": 1}) as called:
                self.assertEqual(0, download_receive.main())
                self.assertEqual(deadline, called.call_args.args[2])
            with patch.dict(os.environ, {"DOWNLOAD_DEADLINE": str(time.monotonic() - 1)}):
                with patch("download_receive.receive") as called:
                    self.assertEqual(2, download_receive.main())
                    called.assert_not_called()

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
