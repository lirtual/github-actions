"""OneDrive Graph atomic no-overwrite transport: purely synthetic, NO live credentials."""
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest import mock
from urllib.error import HTTPError

SCRIPT = Path(__file__).resolve().parents[1] / ".github/scripts/download_onedrive.py"
sys.path.insert(0, str(SCRIPT.parent))
spec = importlib.util.spec_from_file_location("download_onedrive", SCRIPT)
onedrive = importlib.util.module_from_spec(spec)
spec.loader.exec_module(onedrive)


def mount(**changes):
    addition = {"root_folder_path": "/build", "region": "global",
                "is_sharepoint": False, "use_online_api": False}
    addition.update(changes)
    return {"mount_path": "/onedrive", "driver": "Onedrive",
            "disabled": False, "status": "work", "addition": json.dumps(addition)}


class FakeResponse:
    def __init__(self, status, result):
        self.status = status
        self.body = json.dumps(result).encode()

    def __enter__(self): return self
    def __exit__(self, *_): return False
    def getcode(self): return self.status
    def read(self, n): return self.body[:n]


UPLOAD = "https://sn123.up.1drv.com/up/session-one?private=opaque"


class FakeGraph:
    def __init__(self, *, existing=False, final_conflict=False, wrong_host=False,
                 wrong_metadata=False):
        self.calls = []
        self.existing = existing
        self.final_conflict = final_conflict
        self.wrong_host = wrong_host
        self.wrong_metadata = wrong_metadata
        self.data = bytearray()
        self.target = "payload.bin"

    def open(self, request, timeout):
        self.calls.append(request)
        assert timeout > 0
        assert request.full_url.startswith("https://")
        method = request.get_method()
        if "createUploadSession" in request.full_url:
            assert method == "POST"
            assert request.get_header("Authorization") == "Bearer private-graph-token"
            options = json.loads(request.data)
            assert options == {"item": {"name": self.target,
                              "@microsoft.graph.conflictBehavior": "fail"}}
            assert request.get_header("Content-type") == "application/json"
            if self.existing:
                raise HTTPError(request.full_url,409,"private error",{},io.BytesIO(b"secret"))
            return FakeResponse(200,{"uploadUrl":
               ("https://attacker.example/upload/something" if self.wrong_host else UPLOAD)})
        if request.full_url == UPLOAD:
            assert method == "PUT"
            assert request.get_header("Authorization") is None
            assert request.get_header("Content-range")
            if self.final_conflict:
                raise HTTPError(request.full_url,409,"private error",{},io.BytesIO(b"secret"))
            self.data.extend(request.data)
            _, position = request.get_header("Content-range").split(" ")
            r,total = position.split("/")
            _begin,_end = r.split("-")
            if len(self.data) < int(total):
                return FakeResponse(202,{"nextExpectedRanges":[f"{len(self.data)}-"]})
            return FakeResponse(201,{"id":"stable-id","name":self.target,
                                    "size":len(self.data)})
        if "/items/stable-id" in request.full_url:
            assert method == "GET"
            assert request.get_header("Authorization") == "Bearer private-graph-token"
            return FakeResponse(200,{"id":"stable-id","name":self.target,
                                     "size":len(self.data) + (1 if self.wrong_metadata else 0),
                                     "file":{}})
        raise AssertionError("unexpected URL")


class ResolveTests(unittest.TestCase):
    def test_virtual_mount_resolves_root_and_child(self):
        m = mount()
        self.assertEqual("build",onedrive.resolve_mount([m],"/onedrive")["prefix"])
        self.assertEqual("build/artifacts",onedrive.resolve_mount([m],"/onedrive/artifacts")["prefix"])

    def test_unsupported_variant_or_nested_overlay_fails_closed(self):
        for variant in ("OnedriveAPP","OnedriveSharelink","S3","WebDav"):
            with self.subTest(variant=variant):
                with self.assertRaises(onedrive.OneDriveUnsupported):
                    onedrive.resolve_mount([{**mount(),"driver":variant}],"/onedrive/artifacts")
        overlay = {**mount(),"mount_path":"/onedrive/restricted","driver":"WebDav"}
        with self.assertRaises(onedrive.OneDriveUnsupported):
            onedrive.resolve_mount([mount(),overlay],"/onedrive/restricted/folder")

    def test_reference_mount_rejected_without_guessing_backing_identity(self):
        with self.assertRaises(onedrive.OneDriveUnsupported):
            onedrive.resolve_mount([{**mount(), "remark": "ref:/another-drive\nclone"}],
                                   "/onedrive/artifacts")

    def test_session_client_disables_credential_proxy_and_redirect(self):
        from urllib.request import ProxyHandler
        opener=onedrive._new_opener()
        self.assertTrue(all(not handler.proxies for handler in opener.handlers
                            if isinstance(handler,ProxyHandler)))
        self.assertIsNone(onedrive._NoRedirect().redirect_request(
            None,None,302,None,None,"https://untrusted.example/upload"))

    def test_region_sharepoint_root_and_bad_status(self):
        for m in (mount(region="cn"),mount(is_sharepoint=True),
                  mount(root_folder_path="/abc/../def"),
                  {**mount(),"status":"error"},
                  {**mount(),"disabled":True}):
            with self.subTest(m=m.get("status")), self.assertRaises(onedrive.OneDriveUnsupported):
                onedrive.resolve_mount([m],"/onedrive/artifacts")

    def test_url_has_encoded_exact_path(self):
        self.assertEqual(onedrive._uri("build/hello world.txt"),
            "https://graph.microsoft.com/v1.0/me/drive/root:/build/hello%20world.txt:")

    def test_upload_url_must_be_microsoft_https_not_user_redirect(self):
        for value in ("http://sn123.up.1drv.com/up/ok","https://evil.test/up",
                      "https://sn123.up.1drv.com.attacker.test/up",
                      "https://attacker@sn123.up.1drv.com/up",
                      "https://sn123.up.1drv.com:9443/up"):
            with self.subTest(value=value), self.assertRaises(onedrive.OneDriveUnknown):
                onedrive._session_url(value)


class UploadTests(unittest.TestCase):
    def writer(self, fake):
        return onedrive.OneDriveGraphWriter(
            "private-graph-token",time.monotonic()+15,opener=fake)

    def test_upload_creates_fail_session_and_verifies_by_id(self):
        fake = FakeGraph()
        with tempfile.TemporaryDirectory() as root:
            file = Path(root,"payload.bin")
            file.write_bytes(b"sample-file-content")
            result = self.writer(fake).upload_file(file,"build/artifacts")
            self.assertEqual({"files":1,"bytes":19,"remote_observed":"metadata_verified"},result)
            self.assertEqual(b"sample-file-content",bytes(fake.data))
            self.assertEqual(3,len(fake.calls))
            self.assertNotIn("private-graph-token",str(result))

    def test_existing_conflict_has_no_upload_attempt(self):
        fake = FakeGraph(existing=True)
        with tempfile.TemporaryDirectory() as root:
            file=Path(root,"payload.bin")
            file.write_bytes(b"original-untouched")
            with self.assertRaises(onedrive.OneDriveConflict):
                self.writer(fake).upload_file(file,"build")
            self.assertEqual(1,len(fake.calls))

    def test_conflict_on_final_chunk_does_not_retry_or_rename(self):
        fake = FakeGraph(final_conflict=True)
        with tempfile.TemporaryDirectory() as root:
            file=Path(root,"payload.bin")
            file.write_bytes(b"hello")
            with self.assertRaises(onedrive.OneDriveConflict):
                self.writer(fake).upload_file(file,"build")
            self.assertEqual(["POST","PUT"],[x.get_method() for x in fake.calls])

    def test_upload_url_misroute_fails_before_put(self):
        fake = FakeGraph(wrong_host=True)
        with tempfile.TemporaryDirectory() as root:
            file=Path(root,"payload.bin")
            file.write_bytes(b"hello")
            with self.assertRaises(onedrive.OneDriveUnknown):
                self.writer(fake).upload_file(file,"build")
            self.assertEqual(1,len(fake.calls))

    def test_bad_final_metadata_fails_closed(self):
        fake = FakeGraph(wrong_metadata=True)
        with tempfile.TemporaryDirectory() as root:
            file=Path(root,"payload.bin")
            file.write_bytes(b"hello")
            with self.assertRaises(onedrive.OneDriveUnknown):
                self.writer(fake).upload_file(file,"build")

    def test_multipart_is_sequential_and_multiple_of_320k(self):
        fake=FakeGraph()
        with tempfile.TemporaryDirectory() as root, mock.patch.object(onedrive,"CHUNK_BYTES",327680):
            file=Path(root,"payload.bin")
            file.write_bytes(b"x"*(327680+50))
            result=self.writer(fake).upload_file(file,"build")
            self.assertEqual(327730,result["bytes"])
            self.assertEqual(["POST","PUT","PUT","GET"],[x.get_method() for x in fake.calls])
            self.assertEqual("bytes 0-327679/327730",fake.calls[1].get_header("Content-range"))
            self.assertEqual("bytes 327680-327729/327730",fake.calls[2].get_header("Content-range"))

    def test_zero_byte_not_accepted(self):
        with tempfile.TemporaryDirectory() as root:
            file=Path(root,"payload.bin")
            file.write_bytes(b"")
            with self.assertRaises(onedrive.OneDriveUnsupported):
                self.writer(FakeGraph()).upload_file(file,"build")

    @unittest.skipUnless(os.name=="posix", "symlink creation requires POSIX semantics")
    def test_symlink_not_accepted(self):
        with tempfile.TemporaryDirectory() as root:
            file=Path(root,"payload.bin")
            file.write_bytes(b"secret")
            link=Path(root,"link")
            link.symlink_to(file)
            with self.assertRaises(onedrive.OneDriveUnsupported):
                self.writer(FakeGraph()).upload_file(link,"build")

if __name__ == "__main__":
    unittest.main()
