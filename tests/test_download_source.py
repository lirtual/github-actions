"""Read-only aria2 result checks: exact GIDs, every file, no hidden children."""
import importlib.util
import os
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1] / ".github/scripts"
sys.path.insert(0, str(ROOT))
spec = importlib.util.spec_from_file_location("download_source", ROOT/"download_source.py")
s = importlib.util.module_from_spec(spec)
spec.loader.exec_module(s)
GID = "0123456789abcdef"


def rows(root):
    return [
        {"index":"1","path":str(root/"readme.txt"),
         "length":"5","completedLength":"5","selected":"true"},
        {"index":"2","path":str(root/"sub"/"binary.bin"),
         "length":"3","completedLength":"3","selected":"true"},
    ]


def status(**changes):
    result = {"gid":GID,"status":"complete","totalLength":"8","completedLength":"8"}
    result.update(changes)
    return result


@unittest.skipUnless(os.name == "posix" and hasattr(os, "O_NOFOLLOW"),
                     "source tree census requires POSIX no-follow descriptors")
class SourceSnapshotTests(unittest.TestCase):
    def setup_files(self, root):
        (root/"sub").mkdir()
        (root/"readme.txt").write_bytes(b"hello")
        (root/"sub"/"binary.bin").write_bytes(b"\x00\x01\x02")

    def test_complete_two_files_match_local_sha256_manifest(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            self.setup_files(root)
            manifest=s.verify_snapshot(str(root),GID,status(),rows(root))
        self.assertEqual(2,manifest["file_count"])
        self.assertEqual(8,manifest["total_bytes"])
        self.assertEqual(["readme.txt","sub/binary.bin"],
                         [i["relative_path"] for i in manifest["files"]])

    def test_reject_incomplete_failed_and_followed_by(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            self.setup_files(root)
            for variant in (
                status(status="active"),status(status="error"),
                status(completedLength="7"),status(totalLength="9"),
                status(followedBy=["1234567890abcdef"]),
                status(following="1234567890abcdef"),
                status(belongsTo="1234567890abcdef"),
                status(gid="not-this-source"),
            ):
                with self.subTest(variant=variant), self.assertRaises(s.SourceUnverified):
                    s.verify_snapshot(str(root),GID,variant,rows(root))

    def test_reject_missing_extra_and_partial_files(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            self.setup_files(root)
            original=rows(root)
            for variant in (
                original[:1], original+[original[0]],
                [{**original[0],"selected":"false"},original[1]],
                [{**original[0],"completedLength":"4"},original[1]],
                [{**original[0],"path":str(root.parent/"escape.txt")},original[1]],
                [{**original[0],"index":"2"},original[1]],
                [{**original[0],"length":"03"},original[1]],
            ):
                with self.subTest(variant=variant), self.assertRaises(s.SourceUnverified):
                    s.verify_snapshot(str(root),GID,status(),variant)
            (root/"untracked.tmp").write_bytes(b"extra")
            with self.assertRaises(s.SourceUnverified):
                s.verify_snapshot(str(root),GID,status(),original)

    def test_reject_path_traversal_and_nontext_numbers(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            self.setup_files(root)
            for name in (str(root)+"/../other", "../../outside", str(root)+"/sub/../readme.txt"):
                variant=rows(root)
                variant[0]["path"]=name
                with self.subTest(name=name),self.assertRaises(s.SourceUnverified):
                    s.verify_snapshot(str(root),GID,status(),variant)
            for numeric in (8,True,-1,"-1","3.1",None):
                with self.subTest(value=numeric),self.assertRaises(s.SourceUnverified):
                    s.verify_snapshot(str(root),GID,status(totalLength=numeric),rows(root))

    def test_closed_queue_requires_exact_gid_set_without_hidden_results(self):
        first,second=GID,"fedcba9876543210"
        ok={"numActive":"0", "numWaiting":"0", "numStopped":"2",
            "numStoppedTotal":"2"}
        completed=[{"gid":first,"status":"complete"},
                   {"gid":second,"status":"complete"}]
        self.assertTrue(s.verify_queue_closed([first,second],ok,[],[],completed))
        bad_cases=[
            (ok,[],[],completed[:1]),
            ({**ok,"numStoppedTotal":"3"},[],[],completed),
            ({**ok,"numStopped":"1"},[],[],completed),
            ({**ok,"numActive":"1"},[completed[0]],[],completed),
            ({**ok,"numWaiting":"1"},[],[completed[0]],completed),
            (ok,[],[],[completed[0],completed[0]]),
            (ok,[],[],[completed[0],{"gid":second,"status":"error"}]),
            (ok,[],[],[completed[0],{"gid":second,"status":"complete",
                                  "followedBy":["aaaaaaaaaaaaaaaa"]}]),
        ]
        for stats,active,waiting,stopped in bad_cases:
            with self.subTest(stats=stats,stopped=stopped),self.assertRaises(s.SourceUnverified):
                s.verify_queue_closed([first,second],stats,active,waiting,stopped)
        with self.assertRaises(s.SourceUnverified):
            s.verify_queue_closed([first,first],ok,[],[],completed)

    def test_every_aria2_file_needs_its_own_used_approved_uri(self):
        approved = "https://example.org/build.tar.gz"
        used = [{"uri": approved, "status": "used"}]
        waiting = [{"uri": approved, "status": "waiting"}]
        self.assertTrue(s.verify_http_source_uris(
            [{"uris": used}, {"uris": used + waiting}], approved))
        # Global "some URI was used" is insufficient: a second file with
        # only waiting URIs has no independent source provenance.
        for records in (
            [{"uris": used}, {"uris": waiting}],
            [{"uris": waiting}, {"uris": used}],
            [{"uris": used}, {"uris": waiting + waiting}],
        ):
            with self.subTest(records=records), self.assertRaises(s.SourceUnverified):
                s.verify_http_source_uris(records, approved)

    def test_reject_unverified_symlinks(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d,"root")
            root.mkdir()
            self.setup_files(root)
            (root/"sneaky").symlink_to(root/"readme.txt")
            with self.assertRaises(s.SourceUnverified):
                s.verify_snapshot(str(root),GID,status(),rows(root))

if __name__=="__main__":
    unittest.main()
