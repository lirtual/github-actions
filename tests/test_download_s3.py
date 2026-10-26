"""Spec #51 strict S3 adapter: isolated tests, no AWS or remote storage writes."""
import importlib.util
import json
import os
import sys
from pathlib import Path
import tempfile
import time
import unittest
from unittest import mock

SCRIPT = Path(__file__).resolve().parents[1] / ".github/scripts/download_s3.py"
sys.path.insert(0, str(SCRIPT.parent))
spec = importlib.util.spec_from_file_location("download_s3", SCRIPT)
s3 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(s3)

ATTEMPT = "11111111-1111-4111-8111-111111111111"

def mount(**changes):
    raw = {"bucket": "repo-artifacts-dev", "region": "us-east-1",
           "endpoint": "https://s3.us-east-1.amazonaws.com",
           "root_folder_path": "/release", "access_key_id": "example-key",
           "secret_access_key": "private-secret", "session_token": ""}
    raw.update(changes)
    return {"mount_path": "/drive", "driver": "S3", "status": "work",
            "disabled": False, "addition": json.dumps(raw)}

class ResolveTests(unittest.TestCase):
    def test_maps_openlist_virtual_path_through_existing_root_prefix(self):
        result = s3.resolve_aws_mount([mount()], "/drive/builds")
        self.assertEqual("release/builds", result["prefix"])
        self.assertEqual("repo-artifacts-dev", result["bucket"])

    def test_s3_2026_physical_object_limit_is_not_old_five_tib(self):
        self.assertEqual(10000 * 5 * 1024**3, s3.S3_MAX_OBJECT_BYTES)

    def test_2026_regions(self):
        for region in ("us-east-1", "ap-southeast-2", "us-gov-west-1"):
            with self.subTest(region=region):
                selected = s3.resolve_aws_mount([mount(region=region, endpoint="")], "/drive/artifacts")
                self.assertEqual(region, selected["region"])

    def test_longest_mount_wins_even_if_unsupported(self):
        overlay = {"mount_path": "/drive/private", "driver": "WebDav",
                   "disabled": False, "status": "work", "addition": "{}"}
        with self.assertRaises(s3.StorageUnsupported):
            s3.resolve_aws_mount([mount(), overlay], "/drive/private/a")

    def test_rejects_non_aws_s3_endpoints(self):
        for endpoint in ("http://s3.us-east-1.amazonaws.com",
                         "https://s3.us-east-1.amazonaws.com.evil.org",
                         "https://my.bucket.com", "https://127.0.0.1:443",
                         "https://s3.us-east-1.amazonaws.com:444"):
            with self.subTest(endpoint=endpoint), self.assertRaises(s3.StorageUnsupported):
                s3.resolve_aws_mount([mount(endpoint=endpoint)], "/drive/artifacts")

    def test_rejects_custom_and_invalid_mounts(self):
        cases = [
            mount(region="openlist"), mount(root_folder_path="/safe/../escape"),
            mount(bucket="invalid_bucket"), mount(access_key_id=""),
            {**mount(), "disabled": True},
            {**mount(), "driver": "Doge"},
            {**mount(), "status": "error"},
        ]
        for case in cases:
            with self.subTest(case=case.get("status")), self.assertRaises(s3.StorageUnsupported):
                s3.resolve_aws_mount([case], "/drive/builds")

    def test_destination_traversal_and_root_not_allowed(self):
        for path in ("/drive/../private", "/other/path", "/"):
            with self.subTest(path=path), self.assertRaises(s3.StorageUnsupported):
                s3.resolve_aws_mount([mount()], path)

    def test_only_approved_mount_selected(self):
        a = mount()
        b = {**mount(), "mount_path": "/other"}
        self.assertEqual("release", s3.resolve_aws_mount([a,b], "/drive/a")["prefix"].split("/")[0])


class FileTreeTests(unittest.TestCase):
    def test_sorted_regular_files(self):
        with tempfile.TemporaryDirectory() as root:
            Path(root,"nested").mkdir()
            Path(root,"b.txt").write_bytes(b"2")
            Path(root,"nested","a.txt").write_bytes(b"1")
            self.assertEqual(["b.txt","nested/a.txt"],
                             [x[1] for x in s3.enumerate_regular_files(root)])

    def test_symlink_is_refused_even_inside_tree(self):
        with tempfile.TemporaryDirectory() as root:
            Path(root,"safe").write_bytes(b"one")
            Path(root,"link").symlink_to("safe")
            with self.assertRaises(s3.StorageUnsupported):
                s3.enumerate_regular_files(root)

    def test_hardlink_is_refused(self):
        with tempfile.TemporaryDirectory() as root:
            Path(root,"a").write_bytes(b"one")
            os.link(Path(root,"a"),Path(root,"b"))
            with self.assertRaises(s3.StorageUnsupported):
                s3.enumerate_regular_files(root)

    def test_empty_tree_and_unsafe_names_refused(self):
        with tempfile.TemporaryDirectory() as root:
            with self.assertRaises(s3.StorageUnsupported):
                s3.enumerate_regular_files(root)
            Path(root,"bad:name").write_bytes(b"one")
            with self.assertRaises(s3.StorageUnsupported):
                s3.enumerate_regular_files(root)


class FakeS3:
    """Stateful AWS CLI facade enforcing if-none-match under a competing writer."""
    def __init__(self):
        self.objects = {}
        self.calls = []
        self.uploads = {}
        self.fail_finalize = False

    def __call__(self, cmd, **options):
        self.calls.append(cmd)
        assert cmd[0:3] == ["aws","s3api",cmd[2]]
        assert options["stderr"] == mock.ANY or options["stderr"] is not None
        assert "--endpoint-url" not in cmd
        assert "private-secret" not in " ".join(cmd)
        assert options["env"]["AWS_SECRET_ACCESS_KEY"] == "private-secret"
        args = cmd[3:]
        def get(name, default=None):
            return args[args.index(name)+1] if name in args else default
        operation = cmd[2]
        key = get("--key")
        bucket = get("--bucket")
        assert bucket == "repo-artifacts-dev"
        pair = (bucket,key)
        def success(data):
            return mock.Mock(returncode=0, stdout=json.dumps(data).encode(), stderr=b"")
        def fail():
            return mock.Mock(returncode=1, stdout=b"", stderr=b"An error occurred (PreconditionFailed) when calling the PutObject operation")
        if operation == "put-object":
            assert get("--if-none-match") == "*"
            if pair in self.objects: return fail()
            metadata = dict(x.split("=", 1) for x in args[args.index("--metadata")+1:])
            body = Path(get("--body")).read_bytes()
            self.objects[pair] = {"ContentLength":len(body),
                                  "Metadata":metadata,"Content":body}
            return success({"ETag":"test"})
        if operation == "head-object":
            return success({k:v for k,v in self.objects[pair].items() if k!="Content"})
        if operation == "create-multipart-upload":
            self.uploads["one"]={"parts":{}}
            self.uploads["one"]["metadata"] = dict(
                x.split("=",1) for x in args[args.index("--metadata")+1:])
            return success({"UploadId":"one"})
        if operation == "upload-part":
            part=int(get("--part-number"))
            self.uploads["one"]["parts"][part] = Path(get("--body")).read_bytes()
            return success({"ETag":'"part-'+str(part)+'"'})
        if operation == "complete-multipart-upload":
            assert get("--if-none-match") == "*"
            if self.fail_finalize or pair in self.objects: return fail()
            parts=self.uploads["one"]["parts"]
            body=b"".join(parts[k] for k in sorted(parts))
            self.objects[pair] = {"ContentLength":len(body),
                                  "Metadata":self.uploads["one"]["metadata"],
                                  "Content":body}
            return success({"ETag":"mp"})
        if operation == "abort-multipart-upload":
            self.uploads.pop("one",None)
            return success({})
        raise AssertionError(operation)


class UploadTests(unittest.TestCase):
    def writer(self):
        return s3.AwsConditionalWriter(
            s3.resolve_aws_mount([mount()],"/drive/builds"),
            ATTEMPT,time.monotonic()+60)

    def test_conditional_create_success_and_collision_leaves_old_bytes(self):
        fake=FakeS3()
        with tempfile.TemporaryDirectory() as root, mock.patch.object(s3.subprocess,"run",fake):
            file=Path(root,"hello.txt")
            file.write_bytes(b"artifact-one")
            writer=self.writer()
            self.assertEqual(len(b"artifact-one"),
                             writer.upload_file(file,"release/builds/hello.txt",file.stat().st_size))
            file.write_bytes(b"artifact-two")
            with self.assertRaises(s3.StorageConflict):
                writer.upload_file(file,"release/builds/hello.txt",file.stat().st_size)
            self.assertEqual(b"artifact-one",
                             fake.objects[("repo-artifacts-dev","release/builds/hello.txt")]["Content"])
            self.assertTrue(all("--if-none-match" in c for c in fake.calls if c[2]=="put-object"))

    def test_large_file_multipart_still_conditional_on_final_commit(self):
        fake=FakeS3()
        with tempfile.TemporaryDirectory() as root, mock.patch.object(s3.subprocess,"run",fake), \
                mock.patch.object(s3,"S3_SINGLE_PUT_MAX", 3), \
                mock.patch.object(s3,"S3_PART_DEFAULT", 5), \
                mock.patch.object(s3,"S3_PART_MIN", 1), \
                mock.patch.dict(os.environ,{"RUNNER_TEMP":root}):
            file=Path(root,"payload.bin")
            file.write_bytes(b"123456789abcdef")
            writer=self.writer()
            writer.upload_file(file,"release/builds/payload.bin",file.stat().st_size)
            ops=[c[2] for c in fake.calls]
            self.assertEqual(["create-multipart-upload","upload-part",
                              "upload-part","upload-part",
                              "complete-multipart-upload","head-object"],ops)
            self.assertIn("--if-none-match",fake.calls[-2])
            self.assertEqual(file.read_bytes(),fake.objects[("repo-artifacts-dev","release/builds/payload.bin")]["Content"])

    def test_multipart_conflict_never_deletes_existing_object(self):
        fake=FakeS3()
        fake.fail_finalize=True
        with tempfile.TemporaryDirectory() as root, mock.patch.object(s3.subprocess,"run",fake), \
                mock.patch.object(s3,"S3_SINGLE_PUT_MAX",3), \
                mock.patch.object(s3,"S3_PART_DEFAULT",5), \
                mock.patch.object(s3,"S3_PART_MIN",1), \
                mock.patch.dict(os.environ,{"RUNNER_TEMP":root}):
            file=Path(root,"x")
            file.write_bytes(b"abcdefghijk")
            writer=self.writer()
            with self.assertRaises(s3.StorageConflict):
                writer.upload_file(file,"release/builds/x",file.stat().st_size)
            self.assertEqual("abort-multipart-upload",fake.calls[-1][2])
            self.assertFalse(any(call[2] == "delete-object" for call in fake.calls))

    def test_server_attempt_must_be_a_real_uuid(self):
        for candidate in ("-" * 36, "arbitrary-text", "0" * 36):
            with self.subTest(candidate=candidate), self.assertRaises(s3.StorageUnsupported):
                s3.AwsConditionalWriter(s3.resolve_aws_mount([mount()],"/drive/builds"),
                                        candidate,time.monotonic()+30)

    def test_integrity_mismatch_fails_closed(self):
        fake=FakeS3()
        with tempfile.TemporaryDirectory() as root, mock.patch.object(s3.subprocess,"run",fake):
            file=Path(root,"p")
            file.write_bytes(b"abcd")
            writer=self.writer()
            original=writer.call
            def corrupt(op,*args):
                response=original(op,*args)
                if op == "head-object":
                    response["ContentLength"] = -1
                return response
            writer.call=corrupt
            with self.assertRaises(s3.StorageUnknown):
                writer.upload_file(file,"release/builds/p",4)

if __name__ == "__main__":
    unittest.main()
