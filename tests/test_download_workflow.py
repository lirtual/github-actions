"""Spec #51: physical GitHub Task Claim/order and credential isolation guards.

CI static checks do not replace the separate controlled cloud E2E.
"""
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
YAML = (ROOT / ".github/workflows/download.yml").read_text()


def commands(step):
    match = re.search(r"(?m)^        run: \|\n((?:^          .*\n?)+)", step)
    if match is None or step[match.end():].strip():
        raise AssertionError("Unexpected YAML or shell commands")
    return "\n".join(s[10:] for s in match.group(1).splitlines())


class DownloadWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.sections = re.split(r"(?m)^      - name: ", YAML)
        self.assertEqual(6, len(self.sections), "Task step ordering/number changed")
        self.checkout, self.claim, self.validate, self.namespace, self.execute = self.sections[1:]

    def test_contract_exactly_one_bounded_task(self):
        self.assertTrue(YAML.startswith("name: download\n"))
        self.assertEqual(["name", "on", "env", "permissions", "jobs"],
                         re.findall(r"(?m)^([a-z][a-z_-]*):", YAML))
        self.assertEqual(1, YAML.count("workflow_dispatch:"))
        for field in ("attempt_id", "dispatch_id", "capability_id", "batch_json"):
            self.assertEqual(1, YAML.count("      " + field + ":\n"))
        self.assertEqual(1, YAML.count("    runs-on: ubuntu-latest"))
        self.assertIn("    environment: download\n", YAML)
        self.assertIn("    timeout-minutes: 330\n", YAML)
        self.assertIn("WORKFLOW_ACTION_TYPE: task", YAML)
        self.assertIn("id-token: write", YAML)
        self.assertIn("contents: read", YAML)
        self.assertIn("persist-credentials: false", YAML)
        self.assertIn("ref: ${{ github.sha }}", YAML)
        self.assertNotIn("continue-on-error:", YAML)
        self.assertNotIn("    if:", YAML)

    def test_ordered_oidc_claim_then_validation_and_secret_step(self):
        self.assertTrue(self.checkout.startswith("Checkout pinned dispatched revision\n"))
        self.assertTrue(self.claim.startswith("Claim approved physical GitHub Task before any privileged action\n"))
        self.assertTrue(self.validate.startswith("Validate approved public-source batch before any side effects\n"))
        self.assertTrue(self.namespace.startswith("Allocate server-owned Task destination namespace\n"))
        self.assertTrue(self.execute.startswith("Execute verified isolated aria2 to rclone Task\n"))
        self.assertEqual(1, YAML.count("        uses:"))
        self.assertEqual(4, YAML.count("        run: |"))
        self.assertEqual("set -euo pipefail\npython3 .github/scripts/session_action.py claim",
                         commands(self.claim))
        self.assertEqual("set -euo pipefail\npython3 .github/scripts/download_batch.py",
                         commands(self.validate))
        self.assertEqual("set -euo pipefail\npython3 .github/scripts/download_destination.py",
                         commands(self.namespace))
        self.assertEqual("set -euo pipefail\nbash .github/scripts/download-runner.sh",
                         commands(self.execute))
        self.assertIn("id: task_destination", self.namespace)

    def test_cloud_credentials_referenced_only_in_final_step(self):
        beginning = "".join(self.sections[:-1])
        self.assertNotIn("${{ secrets.", beginning)
        self.assertNotIn("DOWNLOAD_REMOTE_NAME:", beginning)
        self.assertIn("DOWNLOAD_REMOTE_BASE_DIR: ${{ vars.DOWNLOAD_REMOTE_BASE_DIR }}",
                      self.namespace)
        self.assertIn("DOWNLOAD_RCLONE_CONFIG_B64: ${{ secrets.DOWNLOAD_RCLONE_CONFIG_B64 }}",
                      self.execute)
        self.assertIn("DOWNLOAD_REMOTE_NAME: ${{ vars.DOWNLOAD_REMOTE_NAME }}",
                      self.execute)
        self.assertIn("DOWNLOAD_REMOTE_BASE_DIR: ${{ vars.DOWNLOAD_REMOTE_BASE_DIR }}",
                      self.execute)
        self.assertNotIn("BATCH_JSON: ${{ inputs.batch_json }}", YAML)
        self.assertIn("python3 .github/scripts/download_batch.py", self.validate)
        self.assertIn("download-runner.sh", self.execute)
        self.assertIn("DOWNLOAD_TASK_ROOT: ${{ steps.task_destination.outputs.task_root }}",
                      self.execute)
        self.assertIn("ATTEMPT_ID: ${{ inputs.attempt_id }}", self.execute)
        self.assertIn("WORKFLOW_ACTION_CLAIM_URL: ${{ vars.WORKFLOW_ACTION_CLAIM_URL }}",
                      self.claim)
        self.assertIn("WORKFLOW_ACTION_OIDC_AUDIENCE: ${{ vars.WORKFLOW_ACTION_OIDC_AUDIENCE }}",
                      self.claim)

    def test_privileged_steps_cannot_skip_claim(self):
        for section in self.sections[2:]:
            self.assertNotRegex(section, r"(?m)^        (?:if|continue-on-error|uses|environment):")
            self.assertIn("        shell: bash", section)
        self.assertNotIn("session_action.py ready", YAML)
        self.assertNotIn("rclone copy", YAML)
        self.assertNotIn("aria2c ", YAML)

    def test_direct_upload_in_validation_is_rejected(self):
        unsafe = self.validate.replace(
            "          python3 .github/scripts/download_batch.py",
            "          python3 .github/scripts/download_batch.py\n"
            "          rclone copy /tmp/source unapproved:target")
        with self.assertRaises(AssertionError):
            self.assertEqual(
                "set -euo pipefail\npython3 .github/scripts/download_batch.py",
                commands(unsafe))


if __name__ == "__main__":
    unittest.main()
