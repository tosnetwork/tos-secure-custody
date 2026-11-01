from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from tos_custody.canonical import canonical, loads
from tos_custody.errors import CustodyError
from tos_custody.proofs import ProofVerifier
from test_batch_state import TARGET, CODE, NOW, BUSINESS

ANCHOR = {**TARGET, "kind": "key_block", "seqno": 1}


class ProofTests(unittest.TestCase):
    def test_large_public_boc_does_not_bypass_metadata_validation(self):
        from tos_custody.proofs import _verdict, MAX_VERDICT
        raw = json.dumps({"status": "verified", "account": {"state_boc": "A"*200000}}).encode()
        self.assertEqual(_verdict(raw)["account"], {})
        with self.assertRaises(CustodyError):
            _verdict(b" " * (MAX_VERDICT+1))
        with self.assertRaises(CustodyError):
            _verdict(b'{"status":"verified","status":"refused"}')

    def setUp(self):
        self.verifier = ProofVerifier(executable=sys.executable,
                                      executable_sha256=sha256(Path(sys.executable).read_bytes()).hexdigest(), anchor=ANCHOR)
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.native_state = Path(self.tmp.name) / "native-state.json"
        self.native_state.write_text("{}")

    def result(self, command, *, stdout, **kwargs):
        request_raw = Path(command[command.index("--request")+1]).read_bytes()
        request = loads(request_raw)
        result = {"status": "verified", "interface": "tos-proof-verify/1", "mode": request["mode"],
                  "anchor": ANCHOR, "target": {**TARGET, "gen_utime": NOW},
                  "request_sha256": sha256(request_raw).hexdigest(),
                  "account": {"address": BUSINESS, "exists": True, "active": True,
                              "code_hash": CODE, "data_hash": "00"*32, "balance": "100000000000", "gen_utime": NOW},
                  "live": {"max_age_seconds": 300}}
        self.mutate(result)
        stdout.write(canonical(result))
        return subprocess.CompletedProcess(command, 0)

    def mutate(self, result):
        pass

    def verify(self, **kwargs):
        with patch("tos_custody.proofs.subprocess.run", side_effect=self.result):
            return self.verifier.verify_account(account=BUSINESS, target=TARGET, material=self.tmp.name,
                                                now=NOW, max_age=300, expected_code_hash=CODE,
                                                state_file=self.native_state, **kwargs)

    def test_pinned_boundary_and_historical_not_fresh(self):
        self.assertTrue(self.verify().fresh)
        self.assertFalse(self.verify(historical=True).fresh)

    def test_substituted_full_target_and_anchor(self):
        for field in ("root_hash", "file_hash"):
            self.mutate = lambda result: result["target"].update({field: "11"*32})
            with self.assertRaises(CustodyError):
                self.verify()
        self.mutate = lambda result: result.update(anchor={**ANCHOR, "root_hash": "11"*32})
        with self.assertRaises(CustodyError):
            self.verify()

    def test_request_digest_mode_and_verdict(self):
        for changes in ({"request_sha256": "11"*32}, {"mode": "historical"}, {"status": "refused"},
                        {"interface": "untrusted-rpc/1"}):
            self.mutate = lambda result: result.update(changes)
            with self.assertRaises(CustodyError):
                self.verify()

    def test_deployment_and_lifecycle_state(self):
        for changes in ({"code_hash": "11"*32}, {"address": "0:"+"99"*32}, {"exists": False}, {"active": False}):
            self.mutate = lambda result: result["account"].update(changes)
            with self.assertRaises(CustodyError):
                self.verify()

    def test_stale_shard_and_future_target(self):
        self.mutate = lambda result: result["account"].update(gen_utime=NOW-301)
        with self.assertRaises(CustodyError):
            self.verify()
        self.mutate = lambda result: result["target"].update(gen_utime=NOW+1)
        with self.assertRaises(CustodyError):
            self.verify()

    def test_changed_backend_and_missing_native_state(self):
        self.verifier.executable_sha256 = "00"*32
        with self.assertRaises(CustodyError):
            self.verify()
        self.setUp()
        self.native_state.unlink()
        with self.assertRaises(CustodyError):
            self.verify()

    def test_native_exit_and_timeout(self):
        args = {"account": BUSINESS, "target": TARGET, "material": self.tmp.name, "now": NOW, "max_age": 300,
                "historical": True}
        with patch("tos_custody.proofs.subprocess.run", return_value=subprocess.CompletedProcess([], 1)):
            with self.assertRaises(CustodyError):
                self.verifier.verify_account(**args)
        with patch("tos_custody.proofs.subprocess.run", side_effect=subprocess.TimeoutExpired([], 60)):
            with self.assertRaises(CustodyError):
                self.verifier.verify_account(**args)
