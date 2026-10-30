"""Spec #51 runtime contract; formal production admission remains disabled.

This is a static policy check, not proof of real hosted cloud E2E.
"""
from pathlib import Path
import os
import re
import subprocess
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = (ROOT / ".github/scripts/download-runner.sh").read_text()
WORKFLOW = (ROOT / ".github/workflows/download.yml").read_text()


class DownloadRunnerContractTests(unittest.TestCase):
    def test_candidate_wired_to_unpublished_physical_task(self):
        self.assertIn("    environment: download", WORKFLOW)
        self.assertIn("download-runner.sh", WORKFLOW)
        self.assertIn("session_action.py claim", WORKFLOW)
        self.assertNotIn("Block unverified download and cloud writes", WORKFLOW)

    def test_claim_precedes_credential_access_when_later_wired(self):
        self.assertLess(WORKFLOW.find("session_action.py claim"),
                        WORKFLOW.find("download_batch.py"))
        self.assertLess(WORKFLOW.find("download_batch.py"),
                        WORKFLOW.find("download_destination.py"))
        self.assertNotIn("${{ secrets.", WORKFLOW.split("      - name: Execute verified isolated aria2 to rclone Task")[0])

    def test_runtime_download_container_never_receives_rclone_secret(self):
        self.assertEqual(2, SCRIPT.count('docker run --rm --network "$network"'))
        downloader = SCRIPT.split('docker run --rm --network "$network"')[1]
        uploader = SCRIPT.split('docker run --rm --network "$network"')[2]
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
        self.assertIn('aria2=1.37.0-r2', SCRIPT)
        self.assertIn('rclone=1.74.1-r3', SCRIPT)
        self.assertIn('sha256sum -c -s', SCRIPT)
        self.assertIn('DOWNLOAD_DEADLINE', SCRIPT)
        self.assertNotIn('DOWNLOAD_SECONDS', SCRIPT)
        self.assertIn('os.statvfs', SCRIPT)

    def test_setup_and_payload_share_one_enforced_deadline(self):
        self.assertIn("for binary in docker python3 base64 sha256sum sudo timeout;", SCRIPT)
        for command in ("docker build", "docker run --rm --network none",
                        'bash "$repo/.github/scripts/download-network.sh" setup'):
            self.assertIn("run_before_deadline " + command, SCRIPT)
        self.assertEqual(2, SCRIPT.count(
            'run_before_deadline docker run --rm --network "$network"'))
    @unittest.skipUnless(os.name == "posix", "Bash/GNU timeout runtime requires POSIX")
    def test_setup_deadline_runtime_timeout(self):
        helper = re.search(r"(?ms)^run_before_deadline\(\) \{\n.*?^\}", SCRIPT)
        self.assertIsNotNone(helper)

        def invoke(command, budget):
            env = {**os.environ, "DOWNLOAD_DEADLINE":
                   str(time.monotonic() + budget)}
            return subprocess.run(["bash", "-c", helper.group(0) + "\n" + command],
                                  capture_output=True, text=True, env=env,
                                  timeout=5)

        self.assertEqual(0, invoke("run_before_deadline true", 3).returncode)
        limited = invoke("run_before_deadline sleep 2", 0.3)
        self.assertEqual(124, limited.returncode)
        expired = invoke("run_before_deadline true", -2)
        self.assertEqual(124, expired.returncode)

    def test_remote_root_and_input_are_not_shell_interpreted(self):
        self.assertIn("DOWNLOAD_TASK_ROOT", SCRIPT)
        self.assertIn("DOWNLOAD_REMOTE_BASE_DIR", SCRIPT)
        self.assertIn("verify_task_root", SCRIPT)
        self.assertIn("GITHUB_RUN_ID", SCRIPT)
        self.assertIn("GITHUB_RUN_ATTEMPT", SCRIPT)
        self.assertNotIn('eval ', SCRIPT)
        self.assertNotIn('source "$BATCH_JSON"', SCRIPT)
        self.assertIn("download_batch.py", SCRIPT)


if __name__ == "__main__":
    unittest.main()
