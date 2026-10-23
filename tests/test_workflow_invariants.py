"""Regression checks for immutable Session execution. Actionlint validates YAML separately."""
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ("linux", "windows", "chrome", "code-server", "openlist")

class SessionWorkflowInvariants(unittest.TestCase):
    def test_every_session_checks_out_exact_run_sha(self):
        for name in WORKFLOWS:
            with self.subTest(workflow=name):
                yml = (ROOT / ".github/workflows" / (name + ".yml")).read_text()
                self.assertIn("ref: ${{ github.sha }}", yml)
                self.assertIn("persist-credentials: false", yml)
                self.assertIn("hostname: sa-${{ github.run_id }}-a${{ github.run_attempt }}", yml)
                self.assertIn("timeout-minutes: 330", yml)
                self.assertIn("oauth-client-id: ${{ vars.TS_OAUTH_CLIENT_ID }}", yml)
                self.assertIn("audience: ${{ vars.TS_AUDIENCE }}", yml)
                self.assertNotIn("secrets.TS_OAUTH_CLIENT_ID", yml)
                self.assertNotIn("secrets.TS_AUDIENCE", yml)

                self.assertIn("WORKFLOW_ACTION_TYPE: session", yml)
                self.assertIn("session_action.py claim", yml)
                self.assertIn("session_action.py ready", yml)
                self.assertIn("session_action.py hold", yml)
                self.assertEqual(len(re.findall(r"(?m)^  session:$", yml)), 1)

    def test_external_packages_are_immutable(self):
        code = (ROOT / ".github/scripts/start-code-server.sh").read_text()
        self.assertIn("864c5d01c808ade57e4d12c708717be7a187219fded60428f263b9e2da9f6b48", code)
        self.assertIn("sha256sum -c -", code)
        image = (ROOT / ".github/scripts/start-openlist.sh").read_text()
        self.assertIn("openlistteam/openlist@sha256:c555c6e1c8af2aead38ed12ec761ac077fdf046d19cf033414be8e056aec6b64", image)
        self.assertNotIn("openlistteam/openlist:v4.2.6", image)

if __name__ == "__main__":
    unittest.main()
