"""Synthetic aria2 JSON-RPC read-only query contract, no daemon or downloads."""
import importlib.util
import io
import json
from pathlib import Path
import sys
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]/".github/scripts"
sys.path.insert(0, str(ROOT))
spec = importlib.util.spec_from_file_location("download_aria2_readonly", ROOT/"download_aria2_readonly.py")
rpc = importlib.util.module_from_spec(spec)
spec.loader.exec_module(rpc)

GID="0123456789abcdef"
TOKEN="synthetic-test-secret"


class Response:
    def __init__(self, document):
        self.raw=io.BytesIO(json.dumps(document).encode())
    def getcode(self): return 200
    def read(self, size): return self.raw.read(size)
    def __enter__(self):return self
    def __exit__(self,*_):return None


class Transport:
    def __init__(self,*,unknown=False,changed=False,empty=False,velocity=False):
        self.calls=[]
        self.unknown=unknown
        self.changed=changed
        self.empty=empty
        self.velocity=velocity
    def open(self,request,timeout):
        assert request.full_url == "http://127.0.0.1:6800/jsonrpc"
        assert request.get_method()=="POST"
        assert 0 < timeout <= 10
        body=json.loads(request.data)
        self.calls.append(body)
        assert body["params"][0]=="token:"+TOKEN
        method=body["method"]
        if method=="aria2.getGlobalStat":
            value={"numActive":"0","numWaiting":"0","numStopped":"1","numStoppedTotal":"1"}
            if self.velocity:
                value["downloadSpeed"]=("0" if len([x for x in self.calls
                                                     if x["method"]==method])>1
                                        else "243")
            if self.changed and len([x for x in self.calls if x["method"]==method])>1:
                value["numActive"]="1"
        elif method in ("aria2.tellActive","aria2.tellWaiting"):
            value=[]
        elif method=="aria2.tellStopped":
            if self.empty:
                value=[]
            else:
                value=[{"gid":"ffffffffffffffff" if self.unknown else GID,"status":"complete"}]
        elif method=="aria2.tellStatus":
            value={"gid":GID,"status":"complete","totalLength":"3","completedLength":"3"}
        elif method=="aria2.getFiles":
            value=[{"index":"1","path":"/tmp/file.bin","selected":"true","length":"3",
                    "completedLength":"3"}]
        else:
            raise AssertionError(method)
        return Response({"jsonrpc":"2.0","id":body["id"],"result":value})


class Aria2ReadOnlyTests(unittest.TestCase):
    def client(self,transport):
        return rpc.Aria2Reader(TOKEN,time.monotonic()+20,transport=transport)

    def test_complete_snapshot_reads_exact_readonly_methods(self):
        fixture=Transport()
        result=self.client(fixture).read_closed([GID])
        self.assertEqual(GID,result["sources"][0]["gid"])
        self.assertEqual(3,int(result["sources"][0]["status"]["totalLength"]))
        self.assertEqual(["aria2.getGlobalStat","aria2.tellActive",
                          "aria2.tellWaiting","aria2.tellStopped",
                          "aria2.tellStatus","aria2.getFiles",
                          "aria2.getGlobalStat"],
                         [v["method"] for v in fixture.calls])
        self.assertNotIn("synthetic-test-secret",repr(result))
        self.assertTrue(all(v["method"].startswith("aria2.tell") or
                            v["method"] in ("aria2.getGlobalStat","aria2.getFiles")
                            for v in fixture.calls))

    def test_dynamic_speed_does_not_change_closed_task_identity(self):
        fixture=Transport(velocity=True)
        observed=self.client(fixture).read_closed([GID])
        self.assertEqual(GID,observed["sources"][0]["gid"])
        self.assertEqual(7,len(fixture.calls))

    def test_unknown_stopped_gid_denied(self):
        fixture=Transport(unknown=True)
        with self.assertRaises(rpc.ReadOnlyRPCUnavailable):
            self.client(fixture).read_closed([GID])
        self.assertEqual(4,len(fixture.calls))

    def test_truncated_task_history_denied(self):
        fixture=Transport(empty=True)
        with self.assertRaises(rpc.ReadOnlyRPCUnavailable):
            self.client(fixture).read_closed([GID])
        self.assertEqual(4,len(fixture.calls))

    def test_queue_change_during_snapshot_denied(self):
        fixture=Transport(changed=True)
        with self.assertRaises(rpc.ReadOnlyRPCUnavailable):
            self.client(fixture).read_closed([GID])
        self.assertEqual(7,len(fixture.calls))

    def test_invalid_gid_denied_without_rpc_call(self):
        fixture=Transport()
        for ids in ([],[GID,GID],["not-a-gid"],[123],list(range(201))):
            with self.subTest(ids=str(ids)[:25]),self.assertRaises(rpc.ReadOnlyRPCUnavailable):
                self.client(fixture).read_closed(ids)
        self.assertEqual([],fixture.calls)

    def test_invalid_secret_and_deadline_denied(self):
        with self.assertRaises(rpc.ReadOnlyRPCUnavailable):
            rpc.Aria2Reader("weak",time.monotonic()+30,transport=Transport())
        fixture=Transport()
        with self.assertRaises(rpc.ReadOnlyRPCUnavailable):
            rpc.Aria2Reader(TOKEN,time.monotonic()-1,transport=fixture).read_closed([GID])
        self.assertEqual([],fixture.calls)

    def test_arbitrary_rpc_method_not_supported(self):
        fixture=Transport()
        with self.assertRaises(rpc.ReadOnlyRPCUnavailable):
            self.client(fixture)._request("aria2.addUri",[["https://example.org/"]])
        self.assertEqual([],fixture.calls)


if __name__=="__main__":
    unittest.main()
