import io
import json
import pathlib
import sys
import time
import unittest
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / ".github" / "scripts"))
import drop_result


class FakeStdin:
    def __init__(self, data):
        self.buffer = io.BytesIO(data)


class HttpResponse:
    status = 200

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False

    def read(self, size):
        return b'{"result":"recorded"}'


class DropResultTests(unittest.TestCase):
    def setUp(self):
        self.attempt = "11111111-2222-4333-8444-555555555555"
        self.result = {
            "drop_claim_v": 1,
            "preview_url": "https://temporary-preview.workers.dev",
            "expires_at": int(time.time() * 1000) + 1200000,
            "sealed_claim": "X" * 500,
        }

    def test_signed_result_is_private_and_once_only(self):
        seen = []

        def open_once(request, timeout):
            seen.append(request)
            self.assertEqual(request.get_method(), "POST")
            self.assertEqual(request.full_url, "https://workflow.example/github/action/result")
            self.assertEqual(json.loads(request.data), {
                "attemptId": self.attempt, "result": self.result
            })
            self.assertNotIn(b"claimToken", request.data)
            self.assertNotIn(b"claim-preview", request.data)
            return HttpResponse()

        with mock.patch.object(drop_result, "configuration", return_value=(
            self.attempt, "workflow-github-action",
            "https://workflow.example/github/action/claim"
        )), mock.patch.object(drop_result, "github_token", return_value="signed-jwt"), (
            mock.patch.object(drop_result, "OPENER")
        ) as opener, mock.patch.object(drop_result.sys, "stdin", FakeStdin(
            json.dumps(self.result).encode()
        )):
            opener.open.side_effect = open_once
            drop_result.deliver_sealed_result()
        self.assertEqual(len(seen), 1)

    def test_unknown_result_is_not_retried(self):
        with mock.patch.object(drop_result, "configuration", return_value=(
            self.attempt, "workflow-github-action",
            "https://workflow.example/github/action/claim"
        )), mock.patch.object(drop_result, "github_token", return_value="jwt"), (
            mock.patch.object(drop_result, "OPENER")
        ) as opener, mock.patch.object(drop_result.sys, "stdin", FakeStdin(
            json.dumps(self.result).encode()
        )):
            opener.open.side_effect = TimeoutError("do not leak")
            with self.assertRaises(drop_result.SafeProtocolError):
                drop_result.deliver_sealed_result()
            self.assertEqual(opener.open.call_count, 1)


if __name__ == "__main__":
    unittest.main()
