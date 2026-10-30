"""Spec #51 draft: actual rclone local-backend, safe-scratch transfer tests.

No cloud credentials, network, existing user files or storage side effects.
"""
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import time
import unittest

SCRIPTS = Path(__file__).resolve().parents[1] / ".github/scripts"
sys.path.insert(0, str(SCRIPTS))
from download_batch import validate
from download_destination import new_task_root
from download_upload import IsolatedRclone, TransferUnverified, transfer_verified_batch

BATCH = json.dumps({
    "remote": "local-test", "project_purpose": "test repo public fixtures",
    "downloads": [
        {"url": "https://example.org/a", "destination_dir": "releases/first"},
        {"url": "https://example.net/b", "destination_dir": "releases/second"},
    ],
})


@unittest.skipUnless(os.name == "posix" and shutil.which("rclone"),
                     "actual rclone local-backend requires POSIX + installed rclone")
class LocalRcloneIntegration(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="sa51-local-")
        self.addCleanup(self.tmp.cleanup)
        self.original = os.getcwd()
        os.chdir(self.tmp.name)
        self.addCleanup(os.chdir, self.original)
        self.path = Path(self.tmp.name)
        self.cfg = self.path / "rclone.conf"
        self.cfg.write_text("[local-test]\ntype = local\n")
        self.cfg.chmod(0o600)
        (self.path / "downloads").mkdir(mode=0o700)
        self.roots = [self.path / "source-a", self.path / "source-b"]
        for root in self.roots:
            root.mkdir()
        (self.roots[0] / "same.zip").write_bytes(b"first" * 1000)
        (self.roots[1] / "same.zip").write_bytes(b"second" * 1000)
        self.batch = validate(BATCH)
        self.root = new_task_root("1001", "1")

    def backend(self):
        return IsolatedRclone(
            shutil.which("rclone"), str(self.cfg), "local-test",
            "local-test", time.monotonic() + 90)

    def test_two_sources_same_filename_are_isolated_and_read_back(self):
        result = transfer_verified_batch(
            self.backend(), self.batch, self.roots, self.root)
        self.assertEqual((2, 2), (result["confirmed"], result["total"]))
        self.assertEqual(self.root, result["task_root"])
        for index, part in enumerate(("first", "second")):
            uploaded = (self.path / self.root / "releases" /
                        part / "same.zip")
            self.assertEqual((self.roots[index] / "same.zip").read_bytes(),
                             uploaded.read_bytes())

    def test_existing_task_root_fails_without_touching_existing_bytes(self):
        existing = self.path / self.root
        existing.mkdir()
        protected = existing / "same.zip"
        protected.write_bytes(b"do-not-touch")
        with self.assertRaises(TransferUnverified) as caught:
            transfer_verified_batch(self.backend(), self.batch,
                                    self.roots, self.root)
        self.assertEqual("DESTINATION_EXISTS", caught.exception.code)
        self.assertEqual(b"do-not-touch", protected.read_bytes())

    def test_missing_base_directory_must_not_be_implicitly_created(self):
        (self.path / "downloads").rmdir()
        with self.assertRaises(TransferUnverified):
            transfer_verified_batch(self.backend(), self.batch,
                                    self.roots, self.root)
        self.assertFalse((self.path / self.root).exists())

    def test_user_supplied_remote_cannot_differ_from_approved(self):
        with self.assertRaises(TransferUnverified) as caught:
            IsolatedRclone(shutil.which("rclone"), str(self.cfg),
                           "other", "local-test", time.monotonic() + 90)
        self.assertEqual("REMOTE_UNAVAILABLE", caught.exception.code)

    def test_batch_remote_must_match_exact_approved_remote(self):
        self.batch["remote"] = "another"
        with self.assertRaises(TransferUnverified) as caught:
            transfer_verified_batch(self.backend(), self.batch,
                                    self.roots, self.root)
        self.assertEqual("REMOTE_UNAVAILABLE", caught.exception.code)
        self.assertFalse((self.path / self.root).exists())

    def test_config_must_be_private_regular_file(self):
        self.cfg.chmod(0o644)
        with self.assertRaises(TransferUnverified):
            self.backend()

    def test_alias_collision_rejected_without_creating_remote_directory(self):
        self.batch["downloads"][1]["destination_dir"] = "releases/first"
        with self.assertRaises(TransferUnverified) as caught:
            transfer_verified_batch(self.backend(), self.batch,
                                    self.roots, self.root)
        self.assertEqual("DESTINATION_UNVERIFIED", caught.exception.code)
        self.assertFalse((self.path / self.root).exists())

    def test_partial_failure_preserves_confirmed_bytes(self):
        instance = self.backend()
        original_upload = instance.upload
        count = [0]

        def fail_second(file, destination):
            count[0] += 1
            if count[0] == 2:
                raise TransferUnverified("REMOTE_UNKNOWN")
            original_upload(file, destination)

        instance.upload = fail_second
        with self.assertRaises(TransferUnverified) as caught:
            transfer_verified_batch(instance, self.batch, self.roots, self.root)
        self.assertEqual((1, 2), (caught.exception.confirmed,
                                  caught.exception.attempted))
        self.assertEqual("REMOTE_UNKNOWN", caught.exception.code)
        self.assertTrue((self.path / self.root /
                         "releases/first/same.zip").exists())

    def test_remote_content_mismatch_does_not_claim_success(self):
        instance = self.backend()
        instance.readback_sha256 = lambda _path: (999, "0" * 64)
        with self.assertRaises(TransferUnverified) as caught:
            transfer_verified_batch(instance, self.batch, self.roots, self.root)
        self.assertEqual("REMOTE_UNVERIFIED", caught.exception.code)
        self.assertEqual(0, caught.exception.confirmed)
        self.assertEqual(1, caught.exception.attempted)


if __name__ == "__main__":
    unittest.main()
