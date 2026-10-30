"""Test disposable network cleanup ordering without changing host firewall."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / ".github/scripts/download-network.sh"
MOCK = '''#!/usr/bin/env python3
import os
from pathlib import Path
import sys
root = Path(os.environ["MOCK_STATE_DIR"])
name = Path(sys.argv[0]).name
args = sys.argv[1:]
with (root / "calls").open("a") as f:
    f.write(name + " " + " ".join(args) + "\\n")
if name == "sudo":
    sys.exit(1 if "-C" in args or "-S" in args else 0)
if args[0] == "ps":
    if (root / "attached").exists():
        print("abcdef012345")
    sys.exit(0)
if args[:2] == ["rm", "-f"]:
    if os.environ.get("MOCK_FAIL_REMOVE") == "1":
        sys.exit(1)
    (root / "attached").unlink(missing_ok=True)
    sys.exit(0)
if args[:2] == ["network", "rm"]:
    if (root / "attached").exists() or os.environ.get("MOCK_FAIL_NETWORK_RM") == "1":
        sys.exit(1)
    if (root / "network").exists():
        (root / "network").unlink()
        sys.exit(0)
    sys.exit(1)
if args[:2] == ["network", "ls"]:
    if (root / "network").exists():
        print("sa51-11111111")
    sys.exit(0)
if args[:2] == ["network", "inspect"]:
    sys.exit(0 if (root / "network").exists() else 1)
sys.exit(2)
'''


@unittest.skipUnless(os.name == "posix", "Linux network cleanup only")
class DownloadNetworkCleanupTests(unittest.TestCase):
    def execute(self, *, network=True, attached=False, fail_remove=False,
                fail_network_rm=False):
        with tempfile.TemporaryDirectory(prefix="sa51-cleanup-") as path:
            root = Path(path)
            if network:
                (root / "network").touch()
            if attached:
                (root / "attached").touch()
            for executable in ("docker", "sudo"):
                fake = root / executable
                fake.write_text(MOCK)
                fake.chmod(0o755)
            env = dict(os.environ, PATH=path + os.pathsep + os.environ["PATH"],
                       MOCK_STATE_DIR=path,
                       ATTEMPT_ID="11111111-1111-4111-8111-111111111111",
                       MOCK_FAIL_REMOVE="1" if fail_remove else "0",
                       MOCK_FAIL_NETWORK_RM="1" if fail_network_rm else "0")
            run = subprocess.run(["bash", str(SCRIPT), "cleanup"],
                                 env=env, capture_output=True, text=True,
                                 timeout=10)
            calls = (root / "calls").read_text().splitlines()
            return run, calls, (root / "network").exists(), (root / "attached").exists()

    def test_orphan_container_removed_before_network_and_firewall(self):
        result, calls, network, attached = self.execute(attached=True)
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertFalse(network)
        self.assertFalse(attached)
        stop = next(i for i, line in enumerate(calls) if line.startswith("docker rm -f "))
        drop_net = next(i for i, line in enumerate(calls) if line.startswith("docker network rm "))
        drop_rules = next(i for i, line in enumerate(calls) if line.startswith("sudo -n iptables -D "))
        self.assertLess(stop, drop_net)
        self.assertLess(drop_net, drop_rules)

    def test_failed_container_stop_must_keep_firewall(self):
        result, calls, network, attached = self.execute(attached=True, fail_remove=True)
        self.assertNotEqual(0, result.returncode)
        self.assertTrue(network)
        self.assertTrue(attached)
        self.assertFalse(any(line.startswith("sudo -n iptables -D ") for line in calls))

    def test_failed_network_remove_must_keep_firewall(self):
        result, calls, network, attached = self.execute(fail_network_rm=True)
        self.assertNotEqual(0, result.returncode)
        self.assertTrue(network)
        self.assertFalse(attached)
        self.assertFalse(any(line.startswith("sudo -n iptables -D ") for line in calls))

    def test_missing_network_allows_idempotent_cleanup(self):
        result, calls, network, attached = self.execute(network=False)
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertFalse(network)
        self.assertFalse(attached)
        self.assertTrue(any(line.startswith("sudo -n iptables -D ") for line in calls))


if __name__ == "__main__":
    unittest.main()
