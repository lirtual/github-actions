"""Synthetic-only tests for Koofr Q15 no-clobber; no provider traffic."""
import importlib.util
import io
import hashlib
import json
import os
from pathlib import Path
from urllib.parse import parse_qs, urlsplit
import sys
import threading
import tempfile
import time
import unittest
from unittest import mock

SRC = Path(__file__).resolve().parents[1] / ".github/scripts/download_koofr.py"
sys.path.insert(0, str(SRC.parent))
spec = importlib.util.spec_from_file_location("download_koofr", SRC)
k = importlib.util.module_from_spec(spec)
spec.loader.exec_module(k)


def mount(address="https://app.koofr.net/dav/Koofr", **kwargs):
    add = {"address":address, "username":"test@example.com", "password":"very private",
           "root_folder_path":"/", "vendor":"other",
           "tls_insecure_skip_verify":False}
    add.update(kwargs)
    return {"mount_path":"/Koofr", "driver":"WebDav", "disabled":False,
            "status":"work", "addition":json.dumps(add)}


class MockResp:
    def __init__(self, status, data):
        self.status=status
        self._body=io.BytesIO(json.dumps(data).encode())
    def read(self, amount): return self._body.read(amount)


class MockConnection:
    def __init__(self, options):
        self.options=options
        self.history=[]
        self.pending=[]
        self.sends=[]
        self.closed=False
        self._path=None

    def request(self, method, path, headers):
        self.history.append((method,path,headers))
        self._path=path

    def putrequest(self, method, path):
        self.history.append((method,path,{}))
        self._path=path

    def putheader(self, key, value): self.history[-1][2][key]=value
    def endheaders(self): pass
    def send(self, body):
        self.sends.append(body)
        hook = self.options.get("on_send")
        if callable(hook):
            hook(body)
    def getresponse(self):
        if self.options.get("failure") and self._path.startswith("/content/"):
            return MockResp(self.options["failure"], {})
        if self._path == "/api/v2/mounts":
            return MockResp(200,{"mounts":[{"id":"primary-id", "isPrimary":True,
                                        "permissions":{"write":True}}]})
        if self._path.startswith("/content/"):
            parts=parse_qs(urlsplit(self._path).query)
            assert parts["autorename"] == ["false"]
            assert parts["info"] == ["true"]
            assert "overwrite" not in parts
            assert "overwriteIgnoreNonexisting" not in parts
            body=b"".join(self.sends)
            assert b"very private" not in body
            assert b"payload contents" in body
            size=self.options.get("size",16)
            digest=hashlib.md5(b"payload contents",usedforsecurity=False).hexdigest()
            return MockResp(200,{"name":self.options.get("name","payload.txt"),
                                 "type":"file","size":size,
                                 "hash":self.options.get("upload_hash",digest)})
        if self._path.startswith("/api/v2/mounts/primary-id/files/info?"):
            target=parse_qs(urlsplit(self._path).query).get("path",[])
            if target == ["/build"]:
                return MockResp(200,{"type":"dir","name":"build"})
            if target == ["/build/payload.txt"] and "existence" in self.options:
                return MockResp(self.options["existence"], {})
            digest=hashlib.md5(b"payload contents",usedforsecurity=False).hexdigest()
            info={"name":"payload.txt","type":"file",
                  "size":self.options.get("size",16)}
            if not self.options.get("missing_hash"):
                info["hash"]=self.options.get("remote_hash",digest)
            return MockResp(200,info)
        raise AssertionError("Unexpected path "+self._path)

    def close(self):self.closed=True


class Connections:
    def __init__(self, **options):
        self.options=options
        self.connections=[]
    def __call__(self, timeout):
        assert timeout > 0
        c=MockConnection(self.options)
        self.connections.append(c)
        return c


class MountTests(unittest.TestCase):
    def test_exact_webdav_mount_maps_without_secret_echo(self):
        result=k.resolve_mount([mount()],"/Koofr/Downloads/build")
        self.assertEqual("/Downloads/build",result["parent"])
        self.assertEqual("very private",result["password"])

    def test_native_webdav_root_and_subfolder_forms(self):
        self.assertEqual("/hello/Folder",
            k.resolve_mount([mount(root_folder_path="/hello")],"/Koofr/Folder")["parent"])
        self.assertEqual("/base/Folder",
            k.resolve_mount([mount(address="https://app.koofr.net/dav/Koofr/base")],
                            "/Koofr/Folder")["parent"])
        self.assertEqual("/base/Folder",
            k.resolve_mount([mount(address="https://app.koofr.net/dav",
                                   root_folder_path="/Koofr/base")],
                            "/Koofr/Folder")["parent"])

    def test_empty_openlist_root_path_maps_to_backend_root_only(self):
        # OpenList WebDav accepts an unset/empty root_folder_path as "/".
        # Do not interpret /dav alone as the writable primary mount.
        self.assertEqual(
            "/Downloads/build",
            k.resolve_mount([mount(root_folder_path="")],
                            "/Koofr/Downloads/build")["parent"])
        self.assertEqual(
            "/subfolder/build",
            k.resolve_mount([mount(address="https://app.koofr.net/dav/Koofr/subfolder",
                                   root_folder_path="")],
                            "/Koofr/build")["parent"])
        with self.assertRaises(k.KoofrUnsupported):
            k.resolve_mount([mount(address="https://app.koofr.net/dav",
                                   root_folder_path="")], "/Koofr/build")

    def test_other_webdav_url_or_driver_fails_closed(self):
        for m in [
            mount(address="https://evil.test/dav/Koofr"),
            mount(address="http://app.koofr.net/dav/Koofr"),
            mount(address="https://app.koofr.net@evil.test/dav/Koofr"),
            mount(address="https://app.koofr.net/dav"),
            mount(address="https://app.koofr.net/dav/ConnectedDropbox"),
            mount(address="https://app.koofr.net/dav/Koofr", tls_insecure_skip_verify=True),
            mount(address="https://app.koofr.net/dav/Koofr", vendor="sharepoint"),
            {**mount(), "driver":"Onedrive"},
            {**mount(), "status":"error"},
            {**mount(), "disabled":True},
            {**mount(), "remark":"ref:/elsewhere"},
            {**mount(), "mount_path":"/koofr"},
        ]:
            with self.subTest(item=m.get("mount_path")),self.assertRaises(k.KoofrUnsupported):
                k.resolve_mount([m],"/Koofr/downloads")

    def test_nested_other_driver_cannot_bypass(self):
        overlay={**mount(), "mount_path":"/Koofr/secret", "driver":"S3"}
        with self.assertRaises(k.KoofrUnsupported):
            k.resolve_mount([mount(),overlay],"/Koofr/secret/whatever")

    def test_case_alias_of_nested_mount_never_falls_through_to_koofr(self):
        overlay={**mount(), "mount_path":"/Koofr/Secret", "driver":"S3"}
        for destination in ("/Koofr/secret/file.bin",
                            "/Koofr/SECRET",
                            "/Koofr/SeCrEt/file.bin"):
            with self.subTest(destination=destination), self.assertRaises(k.KoofrUnsupported):
                k.resolve_mount([mount(),overlay], destination)
        # An unrelated branch must continue to resolve normally.
        self.assertEqual("/Public/file.bin",
                         k.resolve_mount([mount(),overlay],
                                         "/Koofr/Public/file.bin")["parent"])

    def test_duplicate_and_case_aliased_mount_paths_are_rejected(self):
        for extra in (mount(), {**mount(), "mount_path":"/koofr"}):
            with self.subTest(path=extra["mount_path"]), self.assertRaises(k.KoofrUnsupported):
                k.resolve_mount([mount(),extra],"/Koofr/Downloads/file.bin")

    def test_reject_koofr_unsupported_astral_filename_before_upload(self):
        # Official Koofr restrictions exclude filename codepoints above U+FFFF.
        # Ordinary BMP Unicode names remain valid.
        self.assertEqual(["报告.txt"], k._safe_parts("/报告.txt"))
        for filename in ("package😀.zip", "music𝄞.wav"):
            with self.subTest(name=filename), self.assertRaises(k.KoofrUnsupported):
                k.upload_query("/build", filename, "primary-id")
            with self.subTest(name=filename), self.assertRaises(k.KoofrUnsupported):
                k.resolve_mount([mount()], "/Koofr/" + filename)

    def test_full_koofr_path_ceiling_including_expanded_webdav_root(self):
        short = "/" + "/".join(["a" * 254] * 4)
        self.assertEqual(1020, len(short))
        self.assertEqual(4, len(k._safe_parts(short)))
        excessive = "/" + "/".join(["a" * 255] * 4)
        self.assertEqual(1024, len(excessive))
        with self.assertRaises(k.KoofrUnsupported):
            k._safe_parts(excessive)
        # A short *virtual* path may expand to a path above the Koofr limit
        # when OpenList's root_folder_path is applied.
        long_root = "/" + "/".join(["a" * 240] * 4)
        self.assertEqual(964, len(long_root))
        self.assertEqual(1015, len(
            k.resolve_mount([mount(root_folder_path=long_root)],
                            "/Koofr/" + "b" * 50)["parent"]))
        with self.assertRaises(k.KoofrUnsupported):
            k.resolve_mount([mount(root_folder_path=long_root)],
                            "/Koofr/" + "b" * 60)
        # A direct uploader may bypass the staging helper: the query builder
        # must still reject an overlong complete native target.
        self.assertIn("autorename=false",
                      k.upload_query(long_root, "b" * 50, "primary-id"))
        with self.assertRaises(k.KoofrUnsupported):
            k.upload_query(long_root, "b" * 60, "primary-id")

    def test_query_no_overwrite_or_rename_even_if_filename_unicode(self):
        url=k.upload_query("/build","你好.txt","primary-id")
        qs=parse_qs(urlsplit(url).query)
        self.assertEqual(qs["autorename"],["false"])
        self.assertEqual(qs["filename"],["你好.txt"])
        self.assertNotIn("overwrite",qs)
        self.assertNotIn("overwriteIgnoreNonexisting",qs)

    def test_path_traversal_and_names_reject(self):
        for dest in ("/Koofr/../whatever","/Koofr/foo%2Fbar",
                     "/Koofr/one/","/Koofr/ a ", "/Koofr/name."):
            with self.subTest(dest=dest),self.assertRaises(k.KoofrUnsupported):
                k.resolve_mount([mount()],dest)
        for name in ("../h", "hello:world", "name%2Ffoo", "a/b"):
            with self.subTest(name=name),self.assertRaises(k.KoofrUnsupported):
                k.upload_query("/build",name,"primary-id")


def proof(path):
    body=Path(path).read_bytes()
    return {"name":Path(path).name, "size":len(body),
            "md5":hashlib.md5(body,usedforsecurity=False).hexdigest(),
            "sha256":hashlib.sha256(body).hexdigest()}


class APIContractTests(unittest.TestCase):
    def _client(self, connections):
        return k.KoofrClient("test@example.com","very private",
                             time.monotonic()+10,connection_factory=connections)

    def test_native_parent_directory_requires_existing_dir(self):
        conn=Connections()
        self.assertTrue(self._client(conn).assert_directory("/build"))
        self.assertEqual(2,len(conn.connections))
        with self.assertRaises(k.KoofrUnsupported):
            self._client(Connections()).assert_directory("/other")

    def test_read_only_absence_must_be_explicit_404(self):
        for status in (200, 401, 403, 404, 409, 500):
            conn=Connections(existence=status)
            client=self._client(conn)
            with self.subTest(status=status):
                if status == 404:
                    self.assertTrue(client.assert_absent("/build", "payload.txt"))
                elif status == 200:
                    with self.assertRaises(k.KoofrConflict):
                        client.assert_absent("/build", "payload.txt")
                else:
                    with self.assertRaises(k.KoofrUnknown):
                        client.assert_absent("/build", "payload.txt")
            self.assertEqual("GET",conn.connections[-1].history[0][0])
            self.assertTrue(all(x.closed for x in conn.connections))

    def test_regular_file_success_and_provider_readback(self):
        conn=Connections(size=16)
        with tempfile.TemporaryDirectory() as d:
            path=Path(d,"payload.txt")
            path.write_bytes(b"payload contents")
            result=self._client(conn).upload_file(path,"/build",expected=proof(path))
        self.assertEqual({"files":1,"bytes":16,"remote_observed":"md5_verified"},result)
        self.assertEqual(3,len(conn.connections))
        upload=conn.connections[1]
        self.assertEqual("POST",upload.history[0][0])
        self.assertEqual("Basic ",upload.history[0][2]["Authorization"][:6])
        self.assertEqual(16,len(b"payload contents"))
        self.assertTrue(all(c.closed for c in conn.connections))
        self.assertNotIn("private",str(result))

    def test_connection_timeout_is_bounded_independently_of_task_deadline(self):
        observed = []
        def factory(timeout):
            observed.append(timeout)
            return MockConnection({})
        client = k.KoofrClient("test@example.com", "pass",
                               time.monotonic()+330*60, connection_factory=factory)
        conn = client._connect()
        conn.close()
        self.assertEqual(1,len(observed))
        self.assertGreater(observed[0],0)
        self.assertLessEqual(observed[0],30)

    def test_midstream_cancel_is_indeterminate_and_does_not_finish_post(self):
        cancelled = [False]
        def flag_on_first_data_chunk(chunk):
            if chunk == b"payl":
                cancelled[0] = True
        conn=Connections(on_send=flag_on_first_data_chunk)
        with tempfile.TemporaryDirectory() as d:
            path=Path(d,"payload.txt")
            path.write_bytes(b"payload contents")
            with mock.patch.object(k,"MAX_CHUNK",4):
                with self.assertRaises(k.KoofrUnknown):
                    self._client(conn).upload_file(path,"/build",expected=proof(path),
                                                   cancelled=lambda:cancelled[0])
        self.assertTrue(cancelled[0])
        self.assertEqual(2,len(conn.connections))
        sent=conn.connections[1].sends
        self.assertIn(b"payl",sent)
        self.assertFalse(any(b"--spec51" in part and part.startswith(b"\r\n--")
                             for part in sent))
        self.assertTrue(all(c.closed for c in conn.connections))

    def test_409_conflict_never_auto_rename_or_retry(self):
        conn=Connections(failure=409)
        with tempfile.TemporaryDirectory() as d:
            path=Path(d,"payload.txt")
            path.write_bytes(b"payload contents")
            with self.assertRaises(k.KoofrConflict):
                self._client(conn).upload_file(path,"/build",expected=proof(path))
        self.assertEqual(2,len(conn.connections))
        self.assertEqual(1,len(conn.connections[1].history))

    def test_ambiguous_status_not_success(self):
        for failure in (400,401,403,412,500):
            conn=Connections(failure=failure)
            with tempfile.TemporaryDirectory() as d:
                path=Path(d,"payload.txt")
                path.write_bytes(b"payload contents")
                with self.subTest(failure=failure),self.assertRaises(k.KoofrUnknown):
                    self._client(conn).upload_file(path,"/build",expected=proof(path))

    def test_requires_prior_sha256_md5_attestation(self):
        with tempfile.TemporaryDirectory() as d:
            path=Path(d,"payload.txt")
            path.write_bytes(b"payload contents")
            conn=Connections(size=16)
            with self.assertRaises(k.KoofrUnsupported):
                self._client(conn).upload_file(path,"/build",expected=None)
            with self.assertRaises(k.KoofrUnsupported):
                self._client(conn).upload_file(path,"/build",expected={**proof(path),"size":15})
            self.assertEqual(0,len(conn.connections))
            with self.assertRaises(k.KoofrUnknown):
                self._client(conn).upload_file(path,"/build",
                                               expected={**proof(path),"sha256":"0"*64})

    def test_remote_same_size_corruption_is_never_success(self):
        for kwargs in ({"remote_hash": "a"*32}, {"upload_hash":"b"*32},
                       {"missing_hash":True}):
            conn=Connections(**kwargs)
            with tempfile.TemporaryDirectory() as d:
                path=Path(d,"payload.txt")
                path.write_bytes(b"payload contents")
                with self.subTest(kwargs=kwargs),self.assertRaises(k.KoofrUnknown):
                    self._client(conn).upload_file(path,"/build",expected=proof(path))

    def test_filename_changed_is_not_success(self):
        conn=Connections(name="payload (1).txt",size=16)
        with tempfile.TemporaryDirectory() as d:
            path=Path(d,"payload.txt")
            path.write_bytes(b"payload contents")
            with self.assertRaises(k.KoofrUnknown):
                self._client(conn).upload_file(path,"/build",expected=proof(path))

    def test_simulated_parallel_same_name_only_one_wins(self):
        # Transport contract test, NOT proof that Koofr's real server is atomic.
        lock=threading.Lock()
        gate=threading.Barrier(2,timeout=5)
        remote={}

        class SharedConnection(MockConnection):
            def getresponse(self):
                if self._path.startswith("/content/"):
                    # Both requests reach the same logical server concurrently.
                    gate.wait()
                    body=b"".join(self.sends)
                    with lock:
                        if "payload.txt" in remote:
                            return MockResp(409,{})
                        if b"source first" in body:
                            value=b"source first"
                        elif b"source second" in body:
                            value=b"source second"
                        else:
                            raise AssertionError("unexpected upload")
                        remote["payload.txt"]=value
                        return MockResp(200,{"name":"payload.txt","type":"file",
                            "size":len(value),
                            "hash":hashlib.md5(value,usedforsecurity=False).hexdigest()})
                if self._path.startswith("/api/v2/mounts/primary-id/files/info?"):
                    with lock:
                        value=remote["payload.txt"]
                    return MockResp(200,{"name":"payload.txt","type":"file",
                        "size":len(value),
                        "hash":hashlib.md5(value,usedforsecurity=False).hexdigest()})
                return super().getresponse()

        outcomes=[]
        with tempfile.TemporaryDirectory() as d:
            sources=[]
            for index,data in enumerate((b"source first",b"source second")):
                folder=Path(d,str(index))
                folder.mkdir()
                path=folder/"payload.txt"
                path.write_bytes(data)
                sources.append(path)
            def run(src):
                try:
                    factory=lambda _: SharedConnection({})
                    result=self._client(factory).upload_file(src,"/build",expected=proof(src))
                    outcomes.append(result["remote_observed"])
                except k.KoofrConflict:
                    outcomes.append("DESTINATION_CONFLICT")
            threads=[threading.Thread(target=run,args=(p,)) for p in sources]
            for t in threads:t.start()
            for t in threads:t.join(timeout=8)
            self.assertTrue(all(not t.is_alive() for t in threads))
        self.assertCountEqual(outcomes,["md5_verified","DESTINATION_CONFLICT"])
        self.assertIn(remote["payload.txt"],(b"source first",b"source second"))

    @unittest.skipUnless(os.name=="posix","requires POSIX symlink")
    def test_symlink_blocked_before_request(self):
        conn=Connections()
        with tempfile.TemporaryDirectory() as d:
            path=Path(d,"payload.txt")
            path.write_bytes(b"payload contents")
            link=Path(d,"fake.txt")
            link.symlink_to(path)
            with self.assertRaises(k.KoofrUnsupported):
                self._client(conn).upload_file(link,"/build",expected=proof(path))
        self.assertEqual(0,len(conn.connections))
if __name__=="__main__": unittest.main()
