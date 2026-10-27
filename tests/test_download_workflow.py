"""Fail-closed Spec #51 draft workflow guard.

A regression check, not a substitute for reviewer approval.
"""
import re
import unittest
from pathlib import Path

YAML = (Path(__file__).resolve().parents[1] /
        ".github/workflows/download.yml").read_text(encoding="utf-8")


def commands(step):
    match = re.search(r"(?m)^        run: \|\n((?:^          .*\n?)+)", step)
    if match is None or step[match.end():].strip():
        raise AssertionError("Unexpected YAML or shell commands")
    return "\n".join(s[10:] for s in match.group(1).splitlines())


class DownloadWorkflowTests(unittest.TestCase):
    def test_job_contract_remains_exactly_one_bounded_task(self):
        self.assertTrue(YAML.startswith("name: download\n"))
        self.assertEqual(["name", "on", "env", "permissions", "jobs"],
                         re.findall(r"(?m)^([a-z][a-z_-]*):", YAML))
        self.assertEqual(1, YAML.count("workflow_dispatch:"))
        for field in ("attempt_id", "dispatch_id", "capability_id", "batch_json"):
            self.assertEqual(1, YAML.count("      " + field + ":\n"))
        self.assertEqual(1, YAML.count("    runs-on: ubuntu-latest"))
        self.assertIn("timeout-minutes: 330", YAML)
        self.assertIn("WORKFLOW_ACTION_TYPE: task", YAML)
        self.assertIn("id-token: write", YAML)
        self.assertIn("contents: read", YAML)
        self.assertIn("persist-credentials: false", YAML)
        self.assertIn("ref: ${{ github.sha }}", YAML)
        self.assertNotIn("${{ secrets.", YAML)
        self.assertNotIn("session_action.py ready", YAML)

    def test_exact_steps_prevent_premature_download_or_upload(self):
        steps = re.split(r"(?m)^      - name: ", YAML)
        self.assertEqual(5, len(steps), "unexpected Task step added")
        checkout, claim, validate, deny = steps[1:]
        self.assertTrue(checkout.startswith("Checkout pinned dispatched revision\n"))
        self.assertTrue(claim.startswith("Claim approved physical GitHub Task before any privileged action\n"))
        self.assertTrue(validate.startswith("Validate approved public-source batch before any side effects\n"))
        self.assertTrue(deny.startswith("Block unverified download and cloud writes\n"))
        self.assertEqual(1, YAML.count("        uses:"))
        self.assertEqual(3, YAML.count("        run: |"))
        self.assertIn("uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683", checkout)
        self.assertEqual("set -euo pipefail\npython3 .github/scripts/session_action.py claim",
                         commands(claim))
        self.assertEqual("set -euo pipefail\npython3 .github/scripts/download_batch.py",
                         commands(validate))
        self.assertEqual(
            "echo 'DOWNLOAD_UNAVAILABLE: real Koofr no-clobber, isolated downloader, "
            "and complete transfer E2E not yet proven' >&2\nexit 1",
            commands(deny))
        self.assertIn("WORKFLOW_ACTION_CLAIM_URL: ${{ vars.WORKFLOW_ACTION_CLAIM_URL }}", claim)
        self.assertIn("WORKFLOW_ACTION_OIDC_AUDIENCE: ${{ vars.WORKFLOW_ACTION_OIDC_AUDIENCE }}", claim)
        self.assertIn("BATCH_JSON: ${{ inputs.batch_json }}", validate)
        for step in (claim, validate, deny):
            self.assertNotIn("        uses:", step)
            self.assertIn("        shell: bash", step)

    def assert_denial_cannot_be_skipped(self, workflow):
        # A four-step script can still falsely succeed if the mandatory final
        # exit 1 is conditional or marked continue-on-error.
        self.assertNotRegex(
            workflow,
            r"(?m)^\\s*(?:if|continue-on-error|environment|strategy|container|services|defaults):",
        )

    def test_failure_step_is_unconditional_and_cannot_be_ignored(self):
        self.assert_denial_cannot_be_skipped(YAML)
        original = "      - name: Block unverified download and cloud writes\\n"
        self.assertEqual(1, YAML.count(original))
        for injected in ("        if: false\\n",
                         "        continue-on-error: true\\n"):
            with self.subTest(injected=injected), self.assertRaises(AssertionError):
                self.assert_denial_cannot_be_skipped(
                    YAML.replace(original, original + injected))

    def test_premature_inserted_upload_is_rejected_by_exact_command_guard(self):
        _prefix, _checkout, _claim, validate, _deny = re.split(
            r"(?m)^      - name: ", YAML)
        unsafe = validate.replace(
            "          python3 .github/scripts/download_batch.py",
            "          python3 .github/scripts/download_batch.py\n"
            "          python3 .github/scripts/download_finish.py")
        self.assertNotEqual(
            "set -euo pipefail\npython3 .github/scripts/download_batch.py",
            commands(unsafe))


if __name__ == "__main__":
    unittest.main()
