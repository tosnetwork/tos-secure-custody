"""Run pinned native wallet/Vault suites and custody-parser differential checks.

Requires a separately obtained TOS checkout and native build. Test signer seeds
are public. Existing build binaries are fingerprinted, not claimed reproducible.
"""
import argparse
import hashlib
import importlib
import json
from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
COMMIT = "def735f3ad9c57a4b8fc8de43537075baec2271a"


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def main():
    if not __debug__:
        raise SystemExit("native upstream assertions require Python without -O")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tos", type=Path, required=True)
    parser.add_argument("--build", type=Path, required=True)
    parser.add_argument("--signer", type=Path, required=True)
    parser.add_argument("--openssl", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    tos, build = args.tos.resolve(), args.build.resolve()
    head = subprocess.check_output(["git", "-C", str(tos), "rev-parse", "HEAD"], text=True).strip()
    if head != COMMIT:
        raise SystemExit("TOS checkout must match the pinned baseline")
    subprocess.run(["git", "-C", str(tos), "diff", "--exit-code", "HEAD"], check=True)
    if subprocess.check_output(["git", "-C", str(tos), "ls-files", "--others", "--exclude-standard"]):
        raise SystemExit("TOS checkout contains untracked files")
    sys.path[:0] = [str(ROOT / "src"), str(tos / "test/pq-contracts"),
                    str(tos / "test/treasury-vault"), str(tos / "test/auth-extensions")]
    import pqtest
    pqtest.configure(build, args.signer)
    wallets = importlib.import_module("test_pq_wallets")
    cold = importlib.import_module("test_pq_cold")
    vault = importlib.import_module("test_native")
    from tos_custody.highload import inspect_highload
    from tos_custody.multisig import inspect_multisig
    from tos_custody.verification import OpenSslVerifier, verify_highload, verify_multisig
    from source_bundle import source_digest
    verifier = OpenSslVerifier(args.openssl.resolve())
    counts = {"highload_preimages": 0, "highload_signatures": 0, "multisig_submissions": 0}
    requests = {}
    original_request = wallets.PqWallet.request
    original_sign = pqtest.sign
    original_submission = cold.PqMultisig.submission

    def wallet_request(self, *a, **kw):
        request = original_request(self, *a, **kw)
        parsed = inspect_highload(request.boc())
        if parsed["signing_message_hex"] != request.hash.hex():
            raise AssertionError("custody/native highload preimages differ")
        requests[request.hash] = request
        counts["highload_preimages"] += 1
        return request

    def sign(key, message, context):
        signature = original_sign(key, message, context)
        if context == wallets.CONTEXT and message in requests:
            submission = (pqtest.Cell().uint(wallets.SUBMIT_OP, 32).uint(0, 64)
                          .ref(requests[message]).ref(pqtest.stored(signature)))
            verified = verify_highload(submission.boc(), public_key=pqtest.public_key(key), verifier=verifier)
            if not verified["cryptographically_verified"] or verified["signing_authorized"]:
                raise AssertionError("incorrect diagnostic verification result")
            counts["highload_signatures"] += 1
        return signature

    def submission(self, kind, payload, expiry, signers, **kw):
        result = original_submission(self, kind, payload, expiry, signers, **kw)
        context = {"network_global_id": cold.GLOBAL_ID,
                   "account": f"0:{self.address[1]:064x}", "seqno": self.seqno}
        parsed = inspect_multisig(result.boc(), context=context, form="submission", state_raw=self.data.boc())
        expected = self.signing_hash(kind, payload, expiry, **kw).hex()
        if parsed["signing_message_hex"] != expected:
            raise AssertionError("custody/native quorum preimages differ")
        verify_multisig(result.boc(), context=context, state_raw=self.data.boc(), verifier=verifier)
        counts["multisig_submissions"] += 1
        return result

    # First run every upstream scenario unchanged, including malformed requests.
    baseline = unittest.TestSuite([unittest.defaultTestLoader.loadTestsFromTestCase(vault.TreasuryTests),
                                   unittest.defaultTestLoader.loadTestsFromTestCase(wallets.PqWalletTests),
                                   unittest.defaultTestLoader.loadTestsFromTestCase(cold.PqColdTests)])
    first = unittest.TextTestRunner(verbosity=2).run(baseline)
    wallets.PqWallet.request, pqtest.sign = wallet_request, sign
    cold.PqMultisig.submission = submission
    # Supported positive paths are inspected before signing/execution; the wallet
    # suite also executes wrong-key and role-separation negative transactions.
    integrated = unittest.TestSuite([unittest.defaultTestLoader.loadTestsFromTestCase(wallets.PqWalletTests)])
    for name in ("test_quorum_schedules_and_the_vault_still_waits",
                 "test_quorum_veto_and_pause_are_accepted", "test_full_post_quantum_lifecycle"):
        integrated.addTest(cold.PqColdTests(name))
    second = unittest.TextTestRunner(verbosity=2).run(integrated)
    artifacts = [build / "crypto/func", build / "crypto/fift", build / "tol/tol", args.signer.resolve()]
    artifacts += list((build / "emulator").glob("libemulator.*"))
    report = {"schema": "tos.custody.native-conformance.v1", "tos_commit": head,
              "custody_source_digest": source_digest(ROOT), "comparisons": counts,
              "baseline_tests": first.testsRun, "integrated_tests": second.testsRun,
              "failures": len(first.failures) + len(second.failures),
              "errors": len(first.errors) + len(second.errors),
              "skips": len(first.skipped) + len(second.skipped),
              "artifacts_sha256": {str(p): digest(p) for p in artifacts if p.is_file()},
              "openssl": subprocess.check_output([str(args.openssl), "version"], text=True).strip(),
              "hardware_tested": False, "state_authenticated": False,
              "build_provenance": "existing local binaries; not a reproduced pinned emulator build"}
    args.report.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    if (not first.wasSuccessful() or not second.wasSuccessful() or report["skips"]
            or not all(counts.values())):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
