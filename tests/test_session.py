from contextlib import redirect_stdout
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tos_custody.boc import serialize_boc
from tos_custody.canonical import canonical
from tos_custody.cli import main
from tos_custody.errors import CustodyError
from tos_custody.proofs import initialize_native_state
from tos_custody.session import appraise_session
from test_batch_state import batch_policy, wallet_data, vault_data, evidence, TARGET, BUSINESS, VAULT, NOW, ANCHOR
from test_highload import wallet_request
from test_proofs import ANCHOR as NATIVE_ANCHOR


class SessionTests(unittest.TestCase):
    def test_session_derives_all_accounts_instead_of_host_verdicts(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            data = {BUSINESS: wallet_data(), VAULT: vault_data()}
            accounts = {}
            for index, (address, cell) in enumerate(data.items()):
                path = root / f"{index}.boc"
                path.write_bytes(serialize_boc(cell))
                accounts[address] = {"data": str(path), "material": str(root), "native_state": str(root / "state")}
            session = {"schema": "tos.custody.proof-session.v1", "verifier": "/operator/verifier",
                       "verifier_sha256": "00"*32, "anchor": NATIVE_ANCHOR, "target": TARGET, "accounts": accounts}
            with patch("tos_custody.session.ProofVerifier") as verifier:
                verifier.return_value.anchor_digest = ANCHOR
                verifier.return_value.verify_account.side_effect = lambda **kw: evidence(kw["account"], data[kw["account"]])
                result = appraise_session(serialize_boc(wallet_request()), policy=batch_policy(), session=session, now=NOW)
                self.assertTrue(result["state_authenticated"])
                self.assertFalse(result["signing_authorized"])
                self.assertEqual(verifier.return_value.verify_account.call_count, 2)
            session["accounts"].pop(VAULT)
            with self.assertRaises(CustodyError):
                appraise_session(b"", policy=batch_policy(), session=session, now=NOW)

    def test_native_state_enrollment_is_explicit_and_exclusive(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.json"
            self.assertTrue(initialize_native_state(path, NATIVE_ANCHOR)["initialized"])
            with self.assertRaises(FileExistsError):
                initialize_native_state(path, NATIVE_ANCHOR)
            self.assertNotIn("head", json.loads(path.read_text()))

    def test_cli_journal_provisioning_refuses_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            policy = root / "policy.json"
            policy.write_bytes(canonical(batch_policy()))
            arguments = ["init-journal", str(root / "journal.db"), "--policy", str(policy)]
            with redirect_stdout(io.StringIO()):
                self.assertEqual(main(arguments), 0)
            from contextlib import redirect_stderr
            with redirect_stderr(io.StringIO()):
                self.assertEqual(main(arguments), 2)
