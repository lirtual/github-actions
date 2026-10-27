"""Synthetic-only Koofr upload handoff tests; never access the network."""
import importlib.util
from pathlib import Path
import sys
import unittest

SCRIPTS = Path(__file__).resolve().parents[1] / ".github/scripts"
sys.path.insert(0, str(SCRIPTS))
spec = importlib.util.spec_from_file_location("download_finish", SCRIPTS/"download_finish.py")
f = importlib.util.module_from_spec(spec)
spec.loader.exec_module(f)

from download_koofr import KoofrConflict, KoofrUnknown, KoofrUnsupported


def entry(name, parent="/release"):
    return {"file":"/tmp/" + name, "destination_parent":parent,
            "name":name, "size":13, "sha256":"a"*64,"md5":"b"*32}


class FakeClient:
    def __init__(self, missing=None, fail_index=None, fail_kind=None, existing=None, unknown=None):
        self.missing=missing
        self.fail_index=fail_index
        self.fail_kind=fail_kind
        self.existing=existing
        self.unknown=unknown
        self.simulate_midstream_cancel=False
        self.parents=[]
        self.absence_checks=[]
        self.uploads=[]

    def assert_absent(self, parent, name):
        self.absence_checks.append((parent, name))
        if (parent, name) == self.existing:
            raise KoofrConflict("DESTINATION_CONFLICT")
        if (parent, name) == self.unknown:
            raise KoofrUnknown("REMOTE_UNKNOWN")
        return True

    def assert_directory(self, parent):
        self.parents.append(parent)
        if parent==self.missing:
            raise KoofrUnsupported("NOT_SUPPORTED")
        return True

    def upload_file(self, file, parent, *, expected, cancelled=lambda: False):
        self.uploads.append((file,parent,expected))
        if self.simulate_midstream_cancel and cancelled():
            raise KoofrUnknown("REMOTE_UNKNOWN")
        if self.fail_index == len(self.uploads):
            if self.fail_kind=="conflict":
                raise KoofrConflict("DESTINATION_CONFLICT")
            raise KoofrUnknown("REMOTE_UNKNOWN")
        return {"files":1,"bytes":expected["size"],"remote_observed":"md5_verified"}


class UploadHandoffTests(unittest.TestCase):
    def test_two_distinct_files_both_confirmed(self):
        client=FakeClient()
        result=f.finish_staged([entry("one.bin"),entry("two.bin")],client)
        self.assertEqual({"files":2,"bytes":26,"remote_observed":"all_verified"},result)
        self.assertEqual(["/release"],client.parents)
        self.assertEqual(2,len(client.uploads))
        self.assertEqual("a"*64,client.uploads[0][2]["sha256"])

    def test_all_parents_checked_before_first_upload(self):
        client=FakeClient(missing="/z")
        with self.assertRaises(f.BatchIncomplete) as observed:
            f.finish_staged([entry("one",parent="/a"),entry("two",parent="/z")],client)
        self.assertEqual("REMOTE_UNVERIFIED",observed.exception.code)
        self.assertEqual(0,observed.exception.completed)
        self.assertEqual([],client.uploads)
        self.assertEqual(["/a","/z"],client.parents)

    def test_existing_target_denies_whole_batch_without_any_upload(self):
        client=FakeClient(existing=("/release", "two.bin"))
        with self.assertRaises(f.BatchIncomplete) as observed:
            f.finish_staged([entry("one.bin"),entry("two.bin")],client)
        self.assertEqual("DESTINATION_CONFLICT",observed.exception.code)
        self.assertEqual(0,observed.exception.completed)
        self.assertEqual([],client.uploads)
        self.assertEqual([("/release", "one.bin"),("/release", "two.bin")],
                         client.absence_checks)

    def test_unknown_file_existence_is_not_an_absence(self):
        client=FakeClient(unknown=("/release", "one"))
        with self.assertRaises(f.BatchIncomplete) as observed:
            f.finish_staged([entry("one"),entry("two")],client)
        self.assertEqual("REMOTE_UNVERIFIED",observed.exception.code)
        self.assertEqual([],client.uploads)

    def test_partial_409_is_never_retried_or_rolled_back(self):
        client=FakeClient(fail_index=2,fail_kind="conflict")
        with self.assertRaises(f.BatchIncomplete) as observed:
            f.finish_staged([entry("one"),entry("two"),entry("three")],client)
        self.assertEqual("DESTINATION_CONFLICT",observed.exception.code)
        self.assertEqual(1,observed.exception.completed)
        self.assertEqual(2,len(client.uploads))

    def test_unknown_remote_effect_does_not_retry(self):
        client=FakeClient(fail_index=1)
        with self.assertRaises(f.BatchIncomplete) as observed:
            f.finish_staged([entry("one"),entry("two")],client)
        self.assertEqual("REMOTE_UNKNOWN",observed.exception.code)
        self.assertEqual(0,observed.exception.completed)
        self.assertEqual(1,len(client.uploads))

    def test_cancel_before_any_network_request(self):
        client=FakeClient()
        with self.assertRaises(f.BatchIncomplete) as observed:
            f.finish_staged([entry("one")],client,cancelled=lambda:True)
        self.assertEqual("CANCELLED",observed.exception.code)
        self.assertEqual([],client.parents)
        self.assertEqual([],client.uploads)

    def test_cancel_after_one_success(self):
        client=FakeClient()
        with self.assertRaises(f.BatchIncomplete) as observed:
            f.finish_staged([entry("one"),entry("two")],client,
                            cancelled=lambda:len(client.uploads)>0)
        self.assertEqual("CANCELLED",observed.exception.code)
        self.assertEqual(1,observed.exception.completed)
        self.assertEqual(1,len(client.uploads))

    def test_cancel_signaled_during_upload_must_be_remote_unknown(self):
        client=FakeClient()
        client.simulate_midstream_cancel=True
        with self.assertRaises(f.BatchIncomplete) as caught:
            f.finish_staged([entry("one")],client,
                            cancelled=lambda:len(client.uploads)>0)
        self.assertEqual("REMOTE_UNKNOWN",caught.exception.code)
        self.assertEqual(0,caught.exception.completed)
        self.assertEqual(1,len(client.uploads))

    def test_overlong_native_target_denied_before_first_remote_request(self):
        parent="/" + "/".join(["a" * 240] * 4)
        self.assertEqual(964, len(parent))
        client=FakeClient()
        with self.assertRaises(f.BatchIncomplete) as caught:
            f.finish_staged([entry("ok.bin", parent="/release"),
                             entry("b" * 60, parent=parent)], client)
        self.assertEqual("STAGE_UNVERIFIED", caught.exception.code)
        self.assertEqual(0, caught.exception.completed)
        self.assertEqual([], client.parents)
        self.assertEqual([], client.absence_checks)
        self.assertEqual([], client.uploads)

    def test_invalid_or_duplicate_plan_denied_before_provider(self):
        invalid=([[entry("dup"),entry("DUP")],
                 [entry("one"),{"name":"bad"}],
                 [],[entry("bad/name")]])
        for plan in invalid:
            client=FakeClient()
            with self.subTest(plan=plan),self.assertRaises(f.BatchIncomplete):
                f.finish_staged(plan,client)
            self.assertEqual([],client.parents)
            self.assertEqual([],client.uploads)

if __name__=="__main__":
    unittest.main()
