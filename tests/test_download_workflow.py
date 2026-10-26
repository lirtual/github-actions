"""Guard against unsafe activation of the draft download workflow."""
from pathlib import Path
import unittest

BASE = Path(__file__).resolve().parents[1]
FILE = BASE / ".github/workflows/download.yml"


class DownloadWorkflowTests(unittest.TestCase):
    def test_claim_then_validate_then_deny(self):
        yml = FILE.read_text()
        self.assertTrue(yml.startswith("name: download\n"))
        self.assertIn("WORKFLOW_ACTION_TYPE: task", yml)
        self.assertIn("timeout-minutes: 330", yml)
        self.assertIn("runs-on: ubuntu-latest", yml)
        self.assertIn("id-token: write", yml)
        self.assertIn("persist-credentials: false", yml)
        self.assertIn("ref: ${{ github.sha }}", yml)
        a = yml.index("session_action.py claim")
        b = yml.index("download_batch.py")
        c = yml.index("DOWNLOAD_UNAVAILABLE:")
        self.assertLess(a, b)
        self.assertLess(b, c)
        self.assertIn("exit 1", yml[c:])
        self.assertIn("inputs.batch_json", yml)
        self.assertNotIn("session_action.py ready", yml)


if __name__ == "__main__":
    unittest.main()
