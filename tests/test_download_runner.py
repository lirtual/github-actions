"""Spec #51 candidate runtime contract; guarded live Workflow remains disabled.

This is a static policy check, not proof of real hosted cloud E2E.
"""
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = (ROOT / ".github/scripts/download-runner.sh").read_text()
WORKFLOW = (ROOT / ".github/workflows/download.yml").read_text()


class DownloadRunnerContractTests(unittest.TestCase):
    def test_candidate_not_yet_enabled_in_physical_github_task(self):
        self.assertIn("Block unverified download and cloud writes", WORKFLOW)
        self.assertIn("DOWNLOAD_UNAVAILABLE:", WORKFLOW)
        self.assertNotIn("download-runner.sh", WORKFLOW)

    def test_claim_precedes_credential_access_when_later_wired(self):
        self.assertLess(WORKFLOW.find("session_action.py claim"),
                        WORKFLOW.find("download_batch.py"))
        self.assertLess(WORKFLOW.find("download_batch.py"),
                        WORKFLOW.find("download_destination.py"))
        self.assertNotIn("${{ secrets.", WORKFLOW)

    def test_runtime_download_container_never_receives_rclone_secret(self):
        self.assertEqual(2, SCRIPT.count("docker run --rm --network"))
        downloader = SCRIPT.split("docker run --rm --network")[1]
        uploader = SCRIPT.split("docker run --rm --network")[2]
        self.assertNotIn("--volume \"$config:", downloader)
        self.assertNotIn("DOWNLOAD_RCLONE_CONFIG=", downloader)
        self.assertIn("--volume \"$config:", uploader)
        self.assertIn("--env DOWNLOAD_RCLONE_CONFIG=", uploader)
        for section in (downloader, uploader):
            self.assertIn("--cap-drop ALL", section)
            self.assertIn("--security-opt no-new-privileges:true", section)
            self.assertIn("--read-only", section)
            self.assertIn("--dns 1.1.1.1", section)
            self.assertNotIn("--network host", section)
            self.assertNotIn("/var/run/docker.sock", section)
        self.assertIn(":ro", downloader)

    def test_network_and_credential_cleanup_strict(self):
        self.assertIn("download-network.sh\" setup", SCRIPT)
        self.assertIn("download-network.sh\" cleanup", SCRIPT)
        self.assertIn("trap cleanup EXIT", SCRIPT)
        self.assertLess(SCRIPT.index("trap cleanup EXIT"),
                        SCRIPT.index('base64 --decode > "$config"'))
        self.assertIn("unset DOWNLOAD_RCLONE_CONFIG_B64", SCRIPT)
        self.assertIn("rm -rf -- \"$task_dir\"", SCRIPT)
        self.assertRegex(SCRIPT, r"python:3\.12-alpine@sha256:[0-9a-f]{64}")

    def test_remote_root_and_input_are_not_shell_interpreted(self):
        self.assertIn("DOWNLOAD_TASK_ROOT", SCRIPT)
        self.assertIn("GITHUB_RUN_ID", SCRIPT)
        self.assertIn("GITHUB_RUN_ATTEMPT", SCRIPT)
        self.assertNotIn('eval ', SCRIPT)
        self.assertNotIn('source "$BATCH_JSON"', SCRIPT)
        self.assertIn("download_batch.py", SCRIPT)


if __name__ == "__main__":
    unittest.main()
