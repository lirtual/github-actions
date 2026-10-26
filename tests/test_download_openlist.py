"""No live OpenList server/credentials required: request/response contract tests."""
import importlib.util
import json
from pathlib import Path
import sys
import unittest
from urllib.error import HTTPError

SCRIPT = Path(__file__).resolve().parents[1] / ".github/scripts/download_openlist.py"
spec = importlib.util.spec_from_file_location("download_openlist", SCRIPT)
openlist = importlib.util.module_from_spec(spec)
spec.loader.exec_module(openlist)


class Response:
    def __init__(self, value, status=200):
        self.payload = value if isinstance(value, bytes) else json.dumps(value).encode()
        self.status = status

    def __enter__(self): return self
    def __exit__(self, *args): return False
    def read(self, maximum): return self.payload[:maximum]
    def getcode(self): return self.status


class FakeOpener:
    def __init__(self, mounts, *, login=True, wrong_data=False):
        self.mounts = mounts
        self.login = login
        self.wrong_data = wrong_data
        self.calls = []

    def open(self, request, timeout):
        self.calls.append(request)
        assert timeout == 8
        assert request.full_url.startswith(openlist.ORIGIN + "/")
        if request.full_url.endswith("/api/auth/login"):
            assert request.get_method() == "POST"
            assert request.get_header("Authorization") is None
            payload = json.loads(request.data)
            assert payload == {"username":"admin","password":"private-admin-pass"}
            return Response({"code":200,"data":{"token":"private-session-token"}}) if self.login else Response(
                {"code":401,"message":"login failed","data":None})
        if request.full_url.startswith(openlist.ORIGIN + "/api/admin/storage/list?"):
            assert request.get_method() == "GET"
            assert request.get_header("Authorization") == "private-session-token"
            from urllib.parse import parse_qs, urlparse
            query = parse_qs(urlparse(request.full_url).query)
            page = int(query["page"][0])
            per = int(query["per_page"][0])
            subset = self.mounts[(page-1)*per:page*per]
            if self.wrong_data:
                return Response({"code":500,"data":{"content":subset,"total":len(self.mounts)}})
            return Response({"code":200,"data":{"content":subset,"total":len(self.mounts)}})
        raise AssertionError("unexpected URL")


class OpenListMountTests(unittest.TestCase):
    def test_reads_multiple_pages_without_mutation(self):
        mounts = [{"mount_path":f"/repo/{i}","driver":"S3","addition":"{}"} for i in range(57)]
        opener = FakeOpener(mounts)
        self.assertEqual(mounts,openlist.load_mounts("private-admin-pass", opener))
        self.assertEqual(3,len(opener.calls))
        self.assertTrue(all(req.get_method() == "GET" for req in opener.calls[1:]))

    def test_empty_mount_collection(self):
        opener = FakeOpener([])
        self.assertEqual([],openlist.load_mounts("private-admin-pass",opener))
        self.assertEqual(2,len(opener.calls))

    def test_login_is_not_optional(self):
        with self.assertRaisesRegex(openlist.MountReadUnavailable,"MOUNT_CONFIG_UNAVAILABLE"):
            openlist.load_mounts("private-admin-pass",FakeOpener([],login=False))

    def test_non_200_api_response_is_rejected(self):
        with self.assertRaises(openlist.MountReadUnavailable):
            openlist.load_mounts("private-admin-pass",FakeOpener([{"mount_path":"/a"}],wrong_data=True))

    def test_duplicate_mounts_rejected(self):
        mounts = [{"mount_path":"/x"},{"mount_path":"/x"}]
        with self.assertRaises(openlist.MountReadUnavailable):
            openlist.load_mounts("private-admin-pass", FakeOpener(mounts))

    def test_wrong_and_missing_admin_password(self):
        for value in ("", None, "x"*2049):
            with self.subTest(value=str(value)[:6]), self.assertRaises(openlist.MountReadUnavailable):
                openlist.load_mounts(value, FakeOpener([]))

    def test_fake_or_secret_bearing_response_is_never_accepted(self):
        class Broken:
            def open(self, *args, **kwargs):
                return Response(b"{" + b"x" * (openlist.MAX_PAGE_BYTES + 1) + b"}")
        with self.assertRaises(openlist.MountReadUnavailable):
            openlist.load_mounts("private-admin-pass",Broken())

    def test_loopback_proxy_and_redirect_are_disabled(self):
        opener = openlist._private_opener()
        from urllib.request import ProxyHandler
        proxies = [handler.proxies for handler in opener.handlers
                   if isinstance(handler,ProxyHandler)]
        self.assertTrue(all(not configured for configured in proxies))
        redirect = openlist.NoRedirect()
        self.assertIsNone(redirect.redirect_request(None,None,302,None,None,
                                                       "https://example.org/"))

    def test_http_errors_are_sanitized(self):
        class Denied:
            def open(self,*args,**kwargs):
                raise HTTPError("http://127.0.0.1:5244/api/auth/login",302,
                                "private-token-in-upstream-error",{},None)
        with self.assertRaises(openlist.MountReadUnavailable) as caught:
            openlist.load_mounts("private-admin-pass",Denied())
        self.assertNotIn("private-token",str(caught.exception))

if __name__ == "__main__":
    unittest.main()
