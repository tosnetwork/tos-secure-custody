"""API boundaries; real OpenSSL verification is covered by check_crypto_vectors.py."""
import subprocess
import unittest
from unittest.mock import patch

from tos_custody.errors import CustodyError
from tos_custody.verification import OpenSslVerifier, stored_bytes, verify_highload, verify_multisig
from test_highload import submission, stored_signature
from test_multisig import CTX, encode, state, submit


class RecordingVerifier:
    def __init__(self):
        self.calls = []

    def verify(self, *args):
        self.calls.append(args)


class VerificationTests(unittest.TestCase):
    def test_highload_uses_exact_wire_bytes_and_preserves_trust_boundary(self):
        verifier = RecordingVerifier()
        out = verify_highload(encode(submission()), public_key=bytes(1312), verifier=verifier)
        self.assertEqual(len(verifier.calls), 1)
        self.assertEqual(verifier.calls[0][1], bytes(2420))
        self.assertEqual(verifier.calls[0][2].hex(), out["inspection"]["signing_message_hex"])
        self.assertEqual(verifier.calls[0][3], "TOS-PQ-HIGHLOAD-v1")
        for field in ("signing_authorized", "state_authenticated", "freshness_checked", "replay_checked"):
            self.assertFalse(out[field])

    def test_multisig_verifies_every_old_quorum_member(self):
        verifier = RecordingVerifier()
        out = verify_multisig(encode(submit()), context=CTX, state_raw=encode(state()), verifier=verifier)
        self.assertEqual(len(verifier.calls), 2)
        self.assertEqual(out["verified_signature_count"], 2)
        self.assertNotEqual(verifier.calls[0][0], verifier.calls[1][0])
        self.assertTrue(all(call[3] == "TOS-PQ-QUORUM-v1" for call in verifier.calls))
        self.assertFalse(out["state_authenticated"])

    def test_unsigned_forms_refused(self):
        with self.assertRaises(CustodyError):
            verify_highload(b"", public_key=b"", verifier=RecordingVerifier(), form="request")
        with self.assertRaises(CustodyError):
            verify_multisig(b"", context=CTX, state_raw=b"", verifier=RecordingVerifier(), form="request")

    def test_wrong_quorum_rejected_before_backend(self):
        verifier = RecordingVerifier()
        with self.assertRaises(CustodyError):
            verify_multisig(encode(submit(ids=(0,))), context=CTX, state_raw=encode(state()), verifier=verifier)
        self.assertFalse(verifier.calls)

    def test_stored_bytes_full_consumption(self):
        self.assertEqual(stored_bytes(stored_signature(), 2420), bytes(2420))
        with self.assertRaises(CustodyError):
            stored_bytes(stored_signature(), 1312)

    def test_backend_errors_and_timeout_fail_closed(self):
        # Existing interpreter serves only as an absolute executable fixture.
        import sys
        backend = OpenSslVerifier(sys.executable)
        args = (bytes(1312), bytes(2420), bytes(32), "TOS-PQ-HIGHLOAD-v1")
        for result in (subprocess.CompletedProcess([], 1), subprocess.CompletedProcess([], -9)):
            with patch("tos_custody.verification.subprocess.run", return_value=result):
                with self.assertRaises(CustodyError):
                    backend.verify(*args)
        with patch("tos_custody.verification.subprocess.run", side_effect=subprocess.TimeoutExpired([], 15)):
            with self.assertRaises(CustodyError):
                backend.verify(*args)

    def test_invalid_inputs_never_reach_backend(self):
        import sys
        backend = OpenSslVerifier(sys.executable)
        with patch("tos_custody.verification.subprocess.run") as run:
            for args in ((bytes(1311), bytes(2420), bytes(32), "TOS-PQ-HIGHLOAD-v1"),
                         (bytes(1312), bytes(2419), bytes(32), "TOS-PQ-HIGHLOAD-v1"),
                         (bytes(1312), bytes(2420), bytes(31), "TOS-PQ-HIGHLOAD-v1"),
                         (bytes(1312), bytes(2420), bytes(32), "unknown")):
                with self.assertRaises(CustodyError):
                    backend.verify(*args)
            run.assert_not_called()
        with self.assertRaises(CustodyError):
            OpenSslVerifier("openssl")

    def test_backend_preserves_pure_wallet_context(self):
        import sys
        backend = OpenSslVerifier(sys.executable)
        with patch("tos_custody.verification.subprocess.run", return_value=subprocess.CompletedProcess([], 0)) as run:
            backend.verify(bytes(1312), bytes(2420), bytes(32), "TOS-PQ-QUORUM-v1")
        command = run.call_args.args[0]
        self.assertIn("context-string:TOS-PQ-QUORUM-v1", command)
        self.assertIn("-rawin", command)
        self.assertNotIn("-digest", command)
