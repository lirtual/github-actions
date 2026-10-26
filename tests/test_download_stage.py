"""Synthetic-only, no network or remote writes, full-batch Koofr stage tests."""
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1] / ".github/scripts"
sys.path.insert(0, str(ROOT))
import download_stage as stage


def mount():
    return {"mount_path": "/Koofr", "driver": "WebDav",
            "disabled": False, "status": "work",
            "addition": json.dumps({
                "address":"https://app.koofr.net/dav/Koofr",
                "username":"test@example.org", "password":"synthetic-app-password",
                "root_folder_path":"/", "vendor":"other",
                "tls_insecure_skip_verify":False})}


def batch(destinations):
    return json.dumps({
        "downloads":[{"url":f"https://example.org/release-{i}.bin",
                      "destination_path": dest} for i,dest in enumerate(destinations)],
        "project_purpose":"software test artifacts for the associated repo",
        "duration_minutes":300}, separators=(",",":"))


def snapshots(roots):
    result=[]
    for i,root in enumerate(roots):
        gid=f"{i+1:016x}"
        entries=[]
        size=0
        for index,file in enumerate(sorted(root.rglob("*"))):
            if file.is_file() and not file.is_symlink():
                length=file.stat().st_size
                entries.append({"index":str(index+1),"path":str(file),
                                "selected":"true","length":str(length),
                                "completedLength":str(length)})
                size+=length
        result.append({"gid":gid,"root":str(root),
                       "status":{"gid":gid,"status":"complete",
                                 "totalLength":str(size),
                                 "completedLength":str(size)},
                       "files":entries})
    return result


def queue(inputs):
    gids=[item["gid"] for item in inputs]
    return {
        "stats":{"numActive":"0", "numWaiting":"0",
                 "numStopped":str(len(gids)),
                 "numStoppedTotal":str(len(gids))},
        "active":[], "waiting":[],
        "stopped":[{"gid":gid,"status":"complete"} for gid in gids]}


@unittest.skipUnless(sys.platform.startswith("linux"), "Linux/POSIX isolated artifact test")
class StageTests(unittest.TestCase):
    def fixtures(self):
        temp=tempfile.TemporaryDirectory()
        base=Path(temp.name)
        roots=[base/"src0",base/"src1"]
        for root in roots:root.mkdir()
        (roots[0]/"binary.bin").write_bytes(b"first package")
        (roots[1]/"binary.bin").write_bytes(b"second release")
        return temp,roots

    def test_readonly_aria2_reader_snapshots_bind_to_private_roots(self):
        tmp,roots=self.fixtures()
        with tmp:
            sources=snapshots(roots)
            for item in sources:
                item["status"]["dir"] = item["root"]
            recorded={"sources":[{"gid":s["gid"],"status":s["status"],"files":s["files"]}
                                 for s in sources],"queue":queue(sources)}
            class Reader:
                def __init__(self, data): self.data=data
                def read_closed(self,gids):
                    assert gids==[s["gid"] for s in sources]
                    return self.data
            assigned=[{"gid":s["gid"],"root":s["root"],
                       "url":f"https://example.org/release-{i}.bin"}
                      for i,s in enumerate(sources)]
            intents=stage.stage_from_reader(batch(["/Koofr/build-a","/Koofr/build-b"]),
                                             assigned,[mount()],Reader(recorded))
            self.assertEqual(2,len(intents))
            self.assertEqual(["/build-a","/build-b"],
                             [item["destination_parent"] for item in intents])
            assigned[1]["url"]="https://example.org/different-source.bin"
            with self.assertRaises(stage.StageUnverified):
                stage.stage_from_reader(batch(["/Koofr/build-a","/Koofr/build-b"]),
                                       assigned,[mount()],Reader(recorded))
            assigned[1]["url"]="https://example.org/release-1.bin"
            recorded["sources"][1]["status"]["dir"]="/tmp/another-download"
            with self.assertRaises(stage.StageUnverified):
                stage.stage_from_reader(batch(["/Koofr/build-a","/Koofr/build-b"]),
                                       assigned,[mount()],Reader(recorded))
            recorded["sources"][1]["status"]["dir"]=assigned[1]["root"]
            recorded["sources"][1]["gid"]="eeeeeeeeeeeeeeee"
            with self.assertRaises(stage.StageUnverified):
                stage.stage_from_reader(batch(["/Koofr/build-a","/Koofr/build-b"]),
                                       assigned,[mount()],Reader(recorded))

    def test_two_completed_links_produce_two_distinct_intents(self):
        tmp,roots=self.fixtures()
        with tmp:
            inputs=snapshots(roots)
            intents=stage.stage_batch(batch(["/Koofr/release/A","/Koofr/release/B"]),
                                      inputs,queue(inputs),[mount()])
        self.assertEqual(2,len(intents))
        self.assertEqual(["/release/A","/release/B"],
                         [entry["destination_parent"] for entry in intents])
        self.assertEqual(["binary.bin","binary.bin"],
                         [entry["name"] for entry in intents])
        self.assertTrue(all(len(entry["sha256"])==64 for entry in intents))
        self.assertTrue(all("password" not in repr(entry) for entry in intents))

    def test_reject_entire_batch_when_one_source_incomplete(self):
        tmp,roots=self.fixtures()
        with tmp:
            inputs=snapshots(roots)
            inputs[1]["status"]["status"]="active"
            with self.assertRaises(stage.StageUnverified):
                stage.stage_batch(batch(["/Koofr/a","/Koofr/b"]),
                                  inputs,queue(inputs),[mount()])

    def test_reject_untracked_aria2_task_and_corrupted_file(self):
        tmp,roots=self.fixtures()
        with tmp:
            inputs=snapshots(roots)
            metadata=queue(inputs)
            metadata["stats"]["numStoppedTotal"]="3"
            with self.assertRaises(stage.StageUnverified):
                stage.stage_batch(batch(["/Koofr/a","/Koofr/b"]),
                                  inputs,metadata,[mount()])
            (roots[0]/"extra.txt").write_text("extra")
            with self.assertRaises(stage.StageUnverified):
                stage.stage_batch(batch(["/Koofr/a","/Koofr/b"]),
                                  inputs,queue(inputs),[mount()])

    def test_reject_casefold_destination_conflict_before_upload(self):
        tmp,roots=self.fixtures()
        with tmp:
            inputs=snapshots(roots)
            with self.assertRaises(stage.StageUnverified):
                stage.stage_batch(batch(["/Koofr/RELEASE","/Koofr/release"]),
                                  inputs,queue(inputs),[mount()])

    def test_reject_casefold_parent_alias_even_when_filenames_differ(self):
        tmp,roots=self.fixtures()
        with tmp:
            (roots[1]/"binary.bin").rename(roots[1]/"distinct.bin")
            inputs=snapshots(roots)
            with self.assertRaises(stage.StageUnverified):
                stage.stage_batch(batch(["/Koofr/Same", "/Koofr/same"]),
                                  inputs,queue(inputs),[mount()])

    def test_reject_casefold_nested_destination_alias(self):
        tmp,roots=self.fixtures()
        with tmp:
            inputs=snapshots(roots)
            with self.assertRaises(stage.StageUnverified):
                stage.stage_batch(batch(["/Koofr/Top", "/Koofr/top/nested"]),
                                  inputs,queue(inputs),[mount()])

    def test_reject_nested_storage_overlay(self):
        tmp,roots=self.fixtures()
        with tmp:
            inputs=snapshots(roots)
            overlay={"mount_path":"/Koofr/release/A","driver":"S3",
                     "disabled":False,"status":"work","addition":"{}"}
            with self.assertRaises(stage.StageUnverified):
                stage.stage_batch(batch(["/Koofr/release/A","/Koofr/release/B"]),
                                  inputs,queue(inputs),[mount(),overlay])

    def test_reject_overlay_on_nested_output_directory(self):
        tmp,roots=self.fixtures()
        with tmp:
            (roots[0]/"nested").mkdir()
            (roots[0]/"nested"/"data.txt").write_bytes(b"data")
            inputs=snapshots(roots)
            overlay={"mount_path":"/Koofr/build/nested", "driver":"S3",
                     "disabled":False,"status":"work","addition":"{}"}
            with self.assertRaises(stage.StageUnverified):
                stage.stage_batch(batch(["/Koofr/build","/Koofr/release"]),
                                  inputs,queue(inputs),[mount(),overlay])

    def test_reject_overlay_on_exact_output_filename(self):
        tmp,roots=self.fixtures()
        with tmp:
            inputs=snapshots(roots)
            overlay={"mount_path":"/Koofr/build/binary.bin", "driver":"S3",
                     "disabled":False,"status":"work","addition":"{}"}
            with self.assertRaises(stage.StageUnverified):
                stage.stage_batch(batch(["/Koofr/build","/Koofr/release"]),
                                  inputs,queue(inputs),[mount(),overlay])

    def test_reject_missing_second_source_and_reused_local_root(self):
        tmp,roots=self.fixtures()
        with tmp:
            inputs=snapshots(roots)
            with self.assertRaises(stage.StageUnverified):
                stage.stage_batch(batch(["/Koofr/a","/Koofr/b"]),
                                  inputs[:1],queue(inputs),[mount()])
            inputs[1]["root"]=inputs[0]["root"]
            with self.assertRaises(stage.StageUnverified):
                stage.stage_batch(batch(["/Koofr/a","/Koofr/b"]),
                                  inputs,queue(inputs),[mount()])

    def test_multifile_nested_paths_preserved_not_dropped(self):
        tmp,roots=self.fixtures()
        with tmp:
            (roots[0]/"nested").mkdir()
            (roots[0]/"nested"/"readme.txt").write_bytes(b"documentation")
            inputs=snapshots(roots)
            intents=stage.stage_batch(batch(["/Koofr/d1","/Koofr/d2"]),
                                      inputs,queue(inputs),[mount()])
        self.assertEqual(3,len(intents))
        self.assertIn("/d1/nested",[e["destination_parent"] for e in intents])
        self.assertEqual(2,len([e for e in intents if e["destination_parent"].startswith("/d1")]))

if __name__ == "__main__":
    unittest.main()
