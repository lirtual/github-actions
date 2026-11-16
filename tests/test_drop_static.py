"""Spec #87: local-only safety tests; never provision a temporary account."""
import datetime as dt
import importlib.util
import io
import pathlib
import stat
import tempfile
import unittest
from unittest import mock
import zipfile

SCRIPT = pathlib.Path(__file__).resolve().parents[1] / ".github/scripts/drop_static.py"
spec = importlib.util.spec_from_file_location("drop_static", SCRIPT)
drop = importlib.util.module_from_spec(spec)
spec.loader.exec_module(drop)

NOW = dt.datetime(2026, 11, 15, tzinfo=dt.timezone.utc)
SOURCE = "https://files.oaiusercontent.com/test/fixture?sig=not-logged"


def descriptor(name="index.html", url=SOURCE):
    return {"file_id": "fixture-1", "file_name": name, "download_url": url}


class FakeResponse(io.BytesIO):
    status = 200

    def __init__(self, body, headers=None):
        super().__init__(body)
        self.headers = headers or {}


class FakeOpener:
    def __init__(self, body, headers=None):
        self.body = body
        self.headers = headers
        self.requests = []

    def open(self, request, timeout):
        self.requests.append((request, timeout))
        return FakeResponse(self.body, self.headers)


def make_zip(items):
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w") as archive:
        for name, content in items:
            archive.writestr(name, content)
    return out.getvalue()


class DropStaticTests(unittest.TestCase):
    def stage(self, name, data):
        with tempfile.TemporaryDirectory() as temp:
            output = pathlib.Path(temp)
            opener = FakeOpener(data)
            receipt = drop.stage_static_site(descriptor(name), output, opener=opener, now=NOW)
            files = {p.relative_to(output).as_posix(): p.read_bytes()
                     for p in output.rglob("*") if p.is_file()}
            self.assertEqual(len(opener.requests), 1)
            self.assertEqual(opener.requests[0][0].full_url, SOURCE)
            self.assertEqual(opener.requests[0][1], 15)
            self.assertEqual(receipt["file_count"], len(files))
            return files

    def reject_zip(self, data, code):
        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaises(drop.DropInputError) as caught:
                drop.stage_static_site(
                    descriptor("site.zip"), temp, opener=FakeOpener(data), now=NOW)
            self.assertEqual(str(caught.exception), code)
            self.assertNotIn("sig=", str(caught.exception))

    def test_html_is_root_entry(self):
        self.assertEqual(self.stage("demo.html", b"<h1>Test</h1>"),
                         {"index.html": b"<h1>Test</h1>"})

    def test_zip_preserves_nested_static_assets(self):
        archive = make_zip([
            ("index.html", "<h1>Root</h1>"),
            ("assets/style.css", "body { color: teal }"),
        ])
        self.assertEqual(set(self.stage("site.zip", archive)),
                         {"index.html", "assets/style.css"})

    def test_without_filename_stages_html_or_zip_from_verified_content(self):
        cases = (
            (b"<!doctype html><html><body>Safe</body></html>",
             {"index.html": b"<!doctype html><html><body>Safe</body></html>"}),
            (make_zip([("index.html", b"Root"), ("assets/app.js", b"safe")]),
             {"index.html": b"Root", "assets/app.js": b"safe"}),
        )
        for data, expected in cases:
            with self.subTest(data=data[:16]), tempfile.TemporaryDirectory() as temp:
                file = descriptor()
                file.pop("file_name")
                self.assertEqual(drop.approved_chatgpt_attachment(file, NOW), SOURCE)
                receipt = drop.stage_static_site(
                    file, temp, opener=FakeOpener(data), now=NOW)
                files = {p.relative_to(temp).as_posix(): p.read_bytes()
                         for p in pathlib.Path(temp).rglob("*") if p.is_file()}
                self.assertEqual(files, expected)
                self.assertEqual(receipt["file_count"], len(expected))

    def test_without_filename_rejects_unrecognized_content(self):
        for data in (b"plain text", b"\x00\x01binary", b"<html invalid\x00"):
            with self.subTest(data=data), tempfile.TemporaryDirectory() as temp:
                file = descriptor()
                file.pop("file_name")
                with self.assertRaises(drop.DropInputError) as caught:
                    drop.stage_static_site(file, temp, opener=FakeOpener(data), now=NOW)
                self.assertEqual(str(caught.exception), "file_type_unverified")

    def test_public_https_hosts_are_not_enumerated(self):
        self.assertEqual(drop.approved_chatgpt_attachment(descriptor(), NOW), SOURCE)
        for url in ("https://files.oaiusercontent.com.evil.example/fixture",
                    "https://cdn.example.com/fixture?token=opaque",
                    "https://bucket.s3.amazonaws.com/file.html",
                    "https://oaisdmntpr1.blob.core.windows.net/c/blob"):
            with self.subTest(url=url):
                self.assertEqual(drop.approved_chatgpt_attachment(descriptor(url=url), NOW), url)
        for url in ("http://files.oaiusercontent.com/fixture",
                    "https://localhost/fixture", "https://127.0.0.1/fixture",
                    "https://files.oaiusercontent.com:8443/fixture",
                    "https://user:secret@public.example/fixture",
                    "https://files.oaiusercontent.com/fixture#fragment"):
            with self.subTest(url=url), self.assertRaises(drop.DropInputError):
                drop.approved_chatgpt_attachment(descriptor(url=url), NOW)

    def test_optional_azure_expiry_is_checked_without_requiring_sas(self):
        base = "https://oaisdmntpr1.blob.core.windows.net/c/blob"
        valid = base + "?sig=opaque&sv=2026-01-01&se=2030-01-01T00%3A00%3A00Z&sp=r&sr=b"
        self.assertEqual(drop.approved_chatgpt_attachment(descriptor(url=valid), NOW), valid)
        self.assertEqual(drop.approved_chatgpt_attachment(descriptor(url=base), NOW), base)
        for bad in (valid.replace("2030", "2020"), base + "?se=invalid",
                    base + "?se=2030-01-01T00%3A00%3A00Z&se=2030-01-01"):
            with self.subTest(bad=bad), self.assertRaises(drop.DropInputError):
                drop.approved_chatgpt_attachment(descriptor(url=bad), NOW)

    def test_non_public_dns_never_creates_a_socket(self):
        public = (drop.socket.AF_INET, drop.socket.SOCK_STREAM, 6, "",
                  ("93.184.215.14", 443))
        for address in ("127.0.0.1", "10.1.1.1", "169.254.169.254",
                        "172.16.1.1", "192.168.0.2", "100.64.0.1",
                        "0.0.0.0", "192.0.2.1"):
            private = (drop.socket.AF_INET, drop.socket.SOCK_STREAM, 6, "",
                       (address, 443))
            for answers in ([private], [public, private]):
                with self.subTest(address=address, mixed=len(answers) == 2), \
                     mock.patch.object(drop.socket, "getaddrinfo", return_value=answers), \
                     mock.patch.object(drop.socket, "socket") as socket_ctor:
                    with self.assertRaises(OSError):
                        drop._public_create_connection(("download.example", 443), 15)
                    socket_ctor.assert_not_called()

    def test_public_ip_connect_is_pinned_without_second_dns_resolution(self):
        endpoint = (drop.socket.AF_INET, drop.socket.SOCK_STREAM, 6, "",
                    ("93.184.215.14", 443))
        with mock.patch.object(drop.socket, "getaddrinfo", return_value=[endpoint]) as dns, \
             mock.patch.object(drop.socket, "socket") as socket_ctor:
            sock = socket_ctor.return_value
            result = drop._public_create_connection(("download.example", 443), 15)
            self.assertIs(result, sock)
            dns.assert_called_once_with("download.example", 443,
                                        type=drop.socket.SOCK_STREAM)
            socket_ctor.assert_called_once_with(drop.socket.AF_INET,
                                                drop.socket.SOCK_STREAM, 6)
            sock.connect.assert_called_once_with(("93.184.215.14", 443))
            sock.settimeout.assert_called_once_with(15)

    def test_tls_uses_original_hostname_and_no_proxy(self):
        context = mock.MagicMock()
        connection = drop._PublicHTTPSConnection("download.example", 443,
                                                  context=context)
        with mock.patch.object(connection, "_create_connection",
                               return_value=mock.MagicMock()) as dial:
            connection.connect()
        dial.assert_called_once_with(("download.example", 443),
                                     mock.ANY, mock.ANY)
        context.wrap_socket.assert_called_once_with(
            dial.return_value, server_hostname="download.example")
        self.assertTrue(any(isinstance(h, drop._PublicHTTPSHandler)
                            for h in drop.OPENER.handlers))
        self.assertFalse(any(isinstance(h, drop.urllib.request.ProxyHandler)
                             and h.proxies for h in drop.OPENER.handlers))

    def test_rejects_untrusted_filename_and_extra_fields(self):
        for name in ("../../site.zip", "example.txt", "folder/index.html", ""):
            with self.subTest(name=name), self.assertRaises(drop.DropInputError):
                drop.approved_chatgpt_attachment(descriptor(name), NOW)
        extra = dict(descriptor(), callback_url="https://evil.example/")
        with self.assertRaises(drop.DropInputError):
            drop.approved_chatgpt_attachment(extra, NOW)
        with self.assertRaises(drop.DropInputError):
            drop.approved_chatgpt_attachment(dict(descriptor(), file_name=None), NOW)

    def test_rejects_oversize_html(self):
        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaises(drop.DropInputError) as caught:
                drop.stage_static_site(descriptor(), temp,
                    opener=FakeOpener(b"a" * (drop.MAX_FILE_BYTES + 1)), now=NOW)
            self.assertEqual(str(caught.exception), "file_size_limit")

    def test_rejects_declared_oversize_attachment(self):
        with self.assertRaises(drop.DropInputError) as caught:
            drop.download_bounded_attachment(SOURCE, FakeOpener(
                b"safe", {"content-length": str(drop.MAX_UPLOAD_BYTES + 1)}))
        self.assertEqual(str(caught.exception), "file_size_limit")

    def test_rejects_zip_traversal(self):
        self.reject_zip(make_zip([
            ("index.html", "safe"), ("../escape.txt", "bad")]), "zip_path_invalid")

    def test_rejects_zip_backslash(self):
        self.reject_zip(make_zip([
            ("index.html", "safe"), ("..\\escape.txt", "bad")]), "zip_path_invalid")

    def test_rejects_zip_symlink(self):
        file = zipfile.ZipInfo("assets/link")
        file.create_system = 3
        file.external_attr = (stat.S_IFLNK | 0o777) << 16
        self.reject_zip(make_zip([
            ("index.html", "safe"), (file, "../outside")]), "zip_entry_invalid")

    def test_rejects_duplicate_and_case_collisions(self):
        self.reject_zip(make_zip([
            ("index.html", "safe"), ("INDEX.HTML", "bad")]), "zip_duplicate_path")

    def test_rejects_zip_missing_entry(self):
        self.reject_zip(make_zip([("elsewhere.html", "no entry")]),
                        "site_entry_missing")

    def test_rejects_archive_bombs(self):
        self.reject_zip(make_zip([
            ("index.html", "safe"),
            ("big.dat", "a" * (drop.MAX_FILE_BYTES + 1))]), "zip_size_limit")

    def test_rejects_existing_destination(self):
        with tempfile.TemporaryDirectory() as temp:
            pathlib.Path(temp, "existing").write_text("preserve")
            with self.assertRaises(drop.DropInputError) as caught:
                drop.stage_static_site(descriptor(), temp, opener=FakeOpener(b"safe"), now=NOW)
            self.assertEqual(str(caught.exception), "destination_invalid")
            self.assertEqual(pathlib.Path(temp, "existing").read_text(), "preserve")

    def test_entry_is_exact_lowercase_root_file(self):
        self.reject_zip(make_zip([("INDEX.HTML", "not index.html")]),
                        "site_entry_missing")

    def test_rejects_excessive_directory_entries(self):
        entries = [(f"assets/d{i}/", "") for i in range(drop.MAX_FILES * 2 + 1)]
        self.reject_zip(make_zip(entries), "zip_size_limit")

    def test_rejects_control_characters_in_zip_path(self):
        self.reject_zip(make_zip([
            ("index.html", "safe"), ("assets/strange\x01.txt", "bad")]),
            "zip_path_invalid")

    def test_no_automatic_redirect(self):
        self.assertIsNone(drop._NoRedirect().redirect_request(
            None, None, 302, "redirect", {}, "https://evil.example/"))


if __name__ == "__main__":
    unittest.main()
