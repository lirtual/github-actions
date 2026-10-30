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
from unittest.mock import patch
from contextlib import redirect_stderr, redirect_stdout
import io

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
        self.base_dir = "downloads"
        self.root = new_task_root("1001", "1", self.base_dir)

    def backend(self):
        return IsolatedRclone(
            shutil.which("rclone"), str(self.cfg), "local-test",
            "local-test", time.monotonic() + 90)

    def test_two_sources_same_filename_are_isolated_and_read_back(self):
        result = transfer_verified_batch(
            self.backend(), self.batch, self.roots, self.root, self.base_dir)
        self.assertEqual((2, 2), (result["confirmed"], result["total"]))
        self.assertEqual(self.root, result["task_root"])
        for index, part in enumerate(("first", "second")):
            uploaded = (self.path / self.root / "releases" /
                        part / "same.zip")
            self.assertEqual((self.roots[index] / "same.zip").read_bytes(),
                             uploaded.read_bytes())

    def test_existing_custom_base_supports_real_rclone_readback(self):
        self.base_dir = "Projects/Artifacts"
        (self.path / self.base_dir).mkdir(parents=True)
        self.root = new_task_root("1001", "1", self.base_dir)
        result = transfer_verified_batch(
            self.backend(), self.batch, self.roots, self.root, self.base_dir)
        self.assertEqual((2, 2), (result["confirmed"], result["total"]))
        self.assertTrue((self.path / self.root /
                         "releases/first/same.zip").is_file())
        self.assertFalse((self.path / "downloads" / self.root).exists())

    def test_missing_custom_base_cannot_be_created_implicitly(self):
        self.base_dir = "Projects/Missing"
        (self.path / "Projects").mkdir()
        self.root = new_task_root("1001", "1", self.base_dir)
        with self.assertRaises(TransferUnverified) as caught:
            transfer_verified_batch(self.backend(), self.batch,
                                    self.roots, self.root, self.base_dir)
        self.assertIn(caught.exception.code,
                      ("DESTINATION_UNVERIFIED", "REMOTE_UNAVAILABLE"))
        self.assertFalse((self.path / self.base_dir).exists())

    def test_base_name_case_alias_is_not_accepted(self):
        self.base_dir = "Projects/Artifacts"
        (self.path / "Projects" / "artifacts").mkdir(parents=True)
        self.root = new_task_root("1001", "1", self.base_dir)
        with self.assertRaises(TransferUnverified) as caught:
            transfer_verified_batch(self.backend(), self.batch,
                                    self.roots, self.root, self.base_dir)
        self.assertEqual("DESTINATION_UNVERIFIED", caught.exception.code)

    def test_existing_task_root_fails_without_touching_existing_bytes(self):
        existing = self.path / self.root
        existing.mkdir()
        protected = existing / "same.zip"
        protected.write_bytes(b"do-not-touch")
        with self.assertRaises(TransferUnverified) as caught:
            transfer_verified_batch(self.backend(), self.batch,
                                    self.roots, self.root, self.base_dir)
        self.assertEqual("DESTINATION_EXISTS", caught.exception.code)
        self.assertEqual(b"do-not-touch", protected.read_bytes())

    def test_missing_base_directory_must_not_be_implicitly_created(self):
        (self.path / "downloads").rmdir()
        with self.assertRaises(TransferUnverified):
            transfer_verified_batch(self.backend(), self.batch,
                                    self.roots, self.root, self.base_dir)
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
                                    self.roots, self.root, self.base_dir)
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
                                    self.roots, self.root, self.base_dir)
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
            transfer_verified_batch(instance, self.batch, self.roots, self.root, self.base_dir)
        self.assertEqual((1, 2), (caught.exception.confirmed,
                                  caught.exception.attempted))
        self.assertEqual("REMOTE_UNKNOWN", caught.exception.code)
        self.assertTrue((self.path / self.root /
                         "releases/first/same.zip").exists())

    def test_verified_file_audit_is_hash_bound_and_path_redacted(self):
        captured = io.StringIO()
        with redirect_stdout(captured):
            result = transfer_verified_batch(
                self.backend(), self.batch, self.roots, self.root, self.base_dir)
        self.assertEqual(2, result["confirmed"])
        rows = [row for row in captured.getvalue().splitlines()
                if row.startswith("DOWNLOAD_FILE_VERIFIED ")]
        self.assertEqual(2, len(rows))
        for index, row in enumerate(rows):
            self.assertIn("source_index=" + str(index), row)
            self.assertIn("target_sha256=", row)
            self.assertIn("sha256=", row)
            self.assertIn("size=", row)
            self.assertNotIn(self.root, row)
            self.assertNotIn("same.zip", row)
            self.assertNotIn("releases/", row)
            self.assertNotIn("https://", row)

    def test_remote_content_mismatch_does_not_claim_success(self):
        instance = self.backend()
        instance.readback_sha256 = lambda _path: (999, "0" * 64)
        with self.assertRaises(TransferUnverified) as caught:
            transfer_verified_batch(instance, self.batch, self.roots, self.root, self.base_dir)
        self.assertEqual("REMOTE_UNVERIFIED", caught.exception.code)
        self.assertEqual(0, caught.exception.confirmed)
        self.assertEqual(1, caught.exception.attempted)


class UploadFailureSummaryTests(unittest.TestCase):
    def test_unknown_second_write_preserves_confirmed_and_attempted_counts(self):
        import download_upload
        env = {"BATCH_JSON": BATCH,
               "DOWNLOAD_SOURCES_DIR": str(Path.cwd()),
               "DOWNLOAD_TASK_ROOT": "downloads/run-1001-1-" + "f"*32,
               "DOWNLOAD_REMOTE_NAME": "local-test",
               "DOWNLOAD_REMOTE_BASE_DIR": "downloads",
               "DOWNLOAD_RCLONE_CONFIG": str(Path.cwd() / "spec51-test-config"),
               "DOWNLOAD_DEADLINE": str(time.monotonic() + 45)}
        log = io.StringIO()
        with patch.dict(os.environ, env):
            with patch("download_upload.IsolatedRclone") as client:
                client.return_value.remote = "local-test"
                with patch("download_upload.transfer_verified_batch",
                           side_effect=TransferUnverified("REMOTE_UNKNOWN", confirmed=1,
                                                         attempted=2)):
                    with redirect_stderr(log):
                        self.assertEqual(2, download_upload.main())
        self.assertIn("REMOTE_UNKNOWN confirmed=1 attempted=2", log.getvalue())
        self.assertNotIn("https://", log.getvalue())


@unittest.skipUnless(os.name == "posix" and hasattr(os, "O_NOFOLLOW"),
                     "focused source verifier requires POSIX no-follow descriptors")
class FocusedFileVerificationTests(unittest.TestCase):
    class MemoryRclone:
        remote = "local-test"

        def __init__(self):
            self.uploaded = {}
            self.before_upload = None
            self.before_root = None

        def create_empty_task_root(self, task_root, base_dir):
            if self.before_root is not None:
                self.before_root()

        def upload(self, path, remote_path):
            if self.before_upload is not None:
                self.before_upload(path, remote_path)
            self.uploaded[remote_path] = Path(path).read_bytes()

        def readback_sha256(self, remote_path):
            content = self.uploaded[remote_path]
            return len(content), hashlib.sha256(content).hexdigest()

    def test_many_files_census_once_and_rehash_each_file_once(self):
        import download_manifest
        import download_upload
        with tempfile.TemporaryDirectory(prefix="sa51-focused-") as tmp:
            root = Path(tmp) / "source-0"
            (root / "nested").mkdir(parents=True)
            for i in range(48):
                (root / "nested" / f"file-{i:02}.dat").write_bytes(
                    bytes([i]) * 4096)
            batch = validate(json.dumps({
                "remote": "local-test", "project_purpose": "repository release",
                "downloads": [{"url": "https://example.org/source",
                               "destination_dir": "artifacts"}]}))
            client = self.MemoryRclone()
            with patch("download_upload.census_tree",
                       wraps=download_manifest.census_tree) as scans:
                with patch("download_manifest._file_digest",
                           wraps=download_manifest._file_digest) as digests:
                    result = transfer_verified_batch(
                        client, batch, [root], new_task_root("1001", "1", "downloads"), "downloads")
            self.assertEqual((48, 48),
                             (result["confirmed"], result["total"]))
            self.assertEqual(48, len(client.uploaded))
            self.assertEqual(1, scans.call_count)
            # One whole-tree census + one focused recheck per file. Previous
            # implementation rehashed 48 files for EACH of the 48 uploads.
            self.assertEqual(96, digests.call_count)

    def test_modified_content_after_full_census_rejects_upload(self):
        with tempfile.TemporaryDirectory(prefix="sa51-focused-") as tmp:
            root = Path(tmp) / "source-0"
            root.mkdir()
            file = root / "artifact.bin"
            file.write_bytes(b"original")
            batch = validate(json.dumps({
                "remote": "local-test", "project_purpose": "repository release",
                "downloads": [{"url": "https://example.org/file",
                               "destination_dir": "build"}]}))
            client = self.MemoryRclone()
            client.before_root = lambda: file.write_bytes(b"modified")
            with self.assertRaises(TransferUnverified) as caught:
                transfer_verified_batch(client, batch, [root],
                                        new_task_root("1002", "1", "downloads"), "downloads")
            self.assertEqual("SOURCE_UNVERIFIED", caught.exception.code)
            self.assertEqual((0, 1), (caught.exception.confirmed,
                                     caught.exception.attempted))
            self.assertFalse(client.uploaded)

    def test_replaced_ancestor_symlink_and_hardlink_fail_closed(self):
        with tempfile.TemporaryDirectory(prefix="sa51-focused-") as tmp:
            base = Path(tmp)
            root = base / "source-0"
            folder = root / "nested"
            folder.mkdir(parents=True)
            file = folder / "artifact.bin"
            file.write_bytes(b"original")
            batch = validate(json.dumps({
                "remote": "local-test", "project_purpose": "repository release",
                "downloads": [{"url": "https://example.org/file",
                               "destination_dir": "build"}]}))
            for mode in ("symlink", "hardlink"):
                client = self.MemoryRclone()
                def change_tree():
                    if mode == "symlink":
                        relocated = root / "relocated"
                        folder.rename(relocated)
                        folder.symlink_to(relocated, target_is_directory=True)
                    else:
                        os.link(file, base / "second-hardlink")
                client.before_root = change_tree
                with self.subTest(mode=mode), self.assertRaises(TransferUnverified) as caught:
                    transfer_verified_batch(client, batch, [root],
                                            new_task_root("1003", "1", "downloads"), "downloads")
                self.assertEqual("SOURCE_UNVERIFIED", caught.exception.code)
                self.assertFalse(client.uploaded)
                if mode == "symlink":
                    folder.unlink()
                    (root / "relocated").rename(folder)
                else:
                    (base / "second-hardlink").unlink()

    def test_late_file_change_preserves_confirmed_count(self):
        with tempfile.TemporaryDirectory(prefix="sa51-focused-") as tmp:
            root = Path(tmp) / "source-0"
            root.mkdir()
            (root / "a.txt").write_bytes(b"first")
            later = root / "b.txt"
            later.write_bytes(b"second")
            batch = validate(json.dumps({
                "remote": "local-test", "project_purpose": "repository release",
                "downloads": [{"url": "https://example.org/source",
                               "destination_dir": "build"}]}))
            client = self.MemoryRclone()
            def after_first(path, remote_path):
                if Path(path).name == "a.txt":
                    later.write_bytes(b"tamper")
            client.before_upload = after_first
            with self.assertRaises(TransferUnverified) as caught:
                transfer_verified_batch(client, batch, [root],
                                        new_task_root("1004", "1", "downloads"), "downloads")
            self.assertEqual("SOURCE_UNVERIFIED", caught.exception.code)
            self.assertEqual((1, 2), (caught.exception.confirmed,
                                     caught.exception.attempted))
            self.assertEqual(1, len(client.uploaded))


if __name__ == "__main__":
    unittest.main()
