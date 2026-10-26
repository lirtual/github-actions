"""No network and no Koofr writes: prove manifest closes the *local* file tree."""
import hashlib
import importlib.util
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

SRC = Path(__file__).resolve().parents[1] / ".github/scripts"
sys.path.insert(0, str(SRC))
spec = importlib.util.spec_from_file_location("download_manifest", SRC/"download_manifest.py")
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


@unittest.skipUnless(os.name == "posix" and hasattr(os, "O_NOFOLLOW"),
                     "POSIX dir_fd/no-follow needed")
class ManifestTests(unittest.TestCase):
    def test_nested_unicode_multifile_and_empty_file(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d, "accepted-source")
            (root/"sub"/"nested").mkdir(parents=True)
            (root/"sub"/"empty.txt").write_bytes(b"")
            (root/"sub"/"nested"/"file.bin").write_bytes(b"payload")
            (root/"你好.md").write_bytes(b"readme")
            result=m.census_tree(root)
        self.assertEqual(3,result["file_count"])
        self.assertEqual(len(b"payload")+len(b"readme"),result["total_bytes"])
        self.assertEqual(["sub","sub/nested"],result["directories"])
        self.assertEqual(["sub/empty.txt","sub/nested/file.bin","你好.md"],
                         [f["relative_path"] for f in result["files"]])
        self.assertEqual(hashlib.sha256(b"payload").hexdigest(),
                         result["files"][1]["sha256"])
        self.assertEqual(hashlib.md5(b"payload",usedforsecurity=False).hexdigest(),
                         result["files"][1]["md5"])

    def test_reject_empty_manifest_including_empty_subfolder(self):
        with tempfile.TemporaryDirectory() as d:
            Path(d,"just-directory").mkdir()
            with self.assertRaises(m.TreeUnverified):
                m.census_tree(d)

    def test_reject_empty_subdirectory_even_if_other_files_exist(self):
        with tempfile.TemporaryDirectory() as d:
            Path(d,"real-file").write_bytes(b"content")
            Path(d,"empty-dir").mkdir()
            with self.assertRaises(m.TreeUnverified):
                m.census_tree(d)

    def test_reject_root_mutation_during_walk(self):
        with tempfile.TemporaryDirectory() as d:
            Path(d,"item.bin").write_bytes(b"content")
            original=m._file_digest
            def mutate(parent_fd,name,before,dev):
                result=original(parent_fd,name,before,dev)
                Path(d,"appeared-late").write_bytes(b"unexpected")
                return result
            with mock.patch.object(m,"_file_digest",side_effect=mutate):
                with self.assertRaises(m.TreeUnverified):
                    m.census_tree(d)

    def test_reject_symlink_of_file_or_directory(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d,"root")
            root.mkdir()
            other=Path(d,"sensitive")
            other.write_bytes(b"DO-NOT-READ")
            (root/"link.bin").symlink_to(other)
            with self.assertRaises(m.TreeUnverified):
                m.census_tree(root)
            (root/"link.bin").unlink()
            (root/"symlink-folder").symlink_to(Path(d), target_is_directory=True)
            with self.assertRaises(m.TreeUnverified):
                m.census_tree(root)
            with self.assertRaises(m.TreeUnverified):
                m.census_tree(root/"symlink-folder")

    def test_reject_hardlinks(self):
        with tempfile.TemporaryDirectory() as d:
            original=Path(d,"original.txt")
            original.write_bytes(b"content")
            os.link(original,Path(d,"hardlink.txt"))
            with self.assertRaises(m.TreeUnverified):
                m.census_tree(d)

    def test_reject_casefold_collisions_and_unsafe_names(self):
        with tempfile.TemporaryDirectory() as d:
            Path(d,"Foo").write_bytes(b"alpha")
            Path(d,"foo").write_bytes(b"beta")
            with self.assertRaises(m.TreeUnverified):
                m.census_tree(d)
        for unsafe in ("percent%20", "name:", "trail.", " a ", "back\\slash"):
            with self.subTest(unsafe=unsafe),tempfile.TemporaryDirectory() as d:
                Path(d,unsafe).write_bytes(b"file")
                with self.assertRaises(m.TreeUnverified):
                    m.census_tree(d)

    def test_fifo_is_rejected_without_opening(self):
        with tempfile.TemporaryDirectory() as d:
            os.mkfifo(Path(d,"input.fifo"))
            with self.assertRaises(m.TreeUnverified):
                m.census_tree(d)

    def test_file_modified_in_place_during_read_fails(self):
        with tempfile.TemporaryDirectory() as d:
            file=Path(d,"item.bin")
            file.write_bytes(b"contents")
            real_read=m.os.read
            touched=[False]
            def modify(fd,n):
                part=real_read(fd,n)
                if part and not touched[0]:
                    touched[0]=True
                    with file.open("r+b") as stream:
                        stream.write(b"changed!")
                return part
            with mock.patch.object(m.os,"read",side_effect=modify):
                with self.assertRaises(m.TreeUnverified):
                    m.census_tree(d)

    def test_no_external_file_open_when_unsafe(self):
        with tempfile.TemporaryDirectory() as d:
            out=Path(d,"outside")
            out.write_bytes(b"private")
            base=Path(d,"root")
            base.mkdir()
            (base/"outside").symlink_to(out)
            with self.assertRaises(m.TreeUnverified):
                m.census_tree(base)

    def test_unreadable_root_fails_closed(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(m.TreeUnverified):
                m.census_tree(str(Path(d,"notfound")))

if __name__=="__main__":
    unittest.main()
