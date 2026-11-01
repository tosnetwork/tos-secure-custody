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
    parser.add_argument("--require-pinned-build", action="store_true")
    args = parser.parse_args()
    tos, build = args.tos.resolve(), args.build.resolve()
    head = subprocess.check_output(["git", "-C", str(tos), "rev-parse", "HEAD"], text=True).strip()
    if head != COMMIT:
        raise SystemExit("TOS checkout must match the pinned baseline")
    cache = build / "CMakeCache.txt"
    configured_source = None
    if cache.is_file():
        for line in cache.read_text().splitlines():
            if line.startswith("CMAKE_HOME_DIRECTORY:INTERNAL="):
                configured_source = Path(line.split("=", 1)[1]).resolve()
    pinned_build = configured_source == tos
    if args.require_pinned_build and not pinned_build:
        raise SystemExit("native build is not configured from the pinned checkout")
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
    from tos_custody.state import highload_state, vault_state
    from source_bundle import source_digest
    verifier = OpenSslVerifier(args.openssl.resolve())
    counts = {"highload_preimages": 0, "highload_signatures": 0, "multisig_submissions": 0,
              "highload_state_comparisons": 0, "vault_state_comparisons": 0}
    requests = {}
    original_request = wallets.PqWallet.request
    original_sign = pqtest.sign
    original_submission = cold.PqMultisig.submission
    original_send = wallets.PqWallet.send

    def wallet_request(self, *a, **kw):
        request = original_request(self, *a, **kw)
        parsed = inspect_highload(request.boc())
        if parsed["signing_message_hex"] != request.hash.hex():
            raise AssertionError("custody/native highload preimages differ")
        decoded_state = highload_state(wallets.account_data(self.shard)[0].boc())
        if (decoded_state["public_key"] != pqtest.public_key(self.key)
                or decoded_state["subwallet_id"] != wallets.SUBWALLET or decoded_state["timeout"] != wallets.TIMEOUT):
            raise AssertionError("custody/native highload state differs")
        counts["highload_state_comparisons"] += 1
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

    def wallet_send(self, vault, *a, **kw):
        decoded = vault_state(vault.data.boc(), f"0:{vault.address[1]:064x}")
        expected = vault.state
        for name in ("epoch", "payment_nonce", "admin_nonce", "paused"):
            if decoded[name] != expected[name]:
                raise AssertionError("custody/native Vault counters differ: " + name)
        budget, actual = decoded["assets"]["00"*32], vault.budget()
        for decoded_name, native_name in (("per_payment", "per"), ("window_limit", "window"),
                                          ("cumulative_limit", "total"), ("cumulative_spent", "cumulative")):
            if budget[decoded_name] != actual[native_name]:
                raise AssertionError("custody/native Vault budget differs")
        counts["vault_state_comparisons"] += 1
        return original_send(self, vault, *a, **kw)

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
    wallets.PqWallet.send = wallet_send
    cold.PqMultisig.submission = submission
    # Supported positive paths are inspected before signing/execution; the wallet
    # suite also executes wrong-key and role-separation negative transactions.
    integrated = unittest.TestSuite([unittest.defaultTestLoader.loadTestsFromTestCase(wallets.PqWalletTests)])
    for name in ("test_quorum_schedules_and_the_vault_still_waits",
                 "test_quorum_veto_and_pause_are_accepted", "test_full_post_quantum_lifecycle"):
        integrated.addTest(cold.PqColdTests(name))
    second = unittest.TextTestRunner(verbosity=2).run(integrated)
    # Lifecycle probes use the actual native account states and messages. A
    # deleted/reinitialized snapshot can lose on-chain replay history; local
    # reservations must survive it rather than treating redeployment as a reset.
    class LifecycleTests(wallets.PqWalletTests):
        def signed_message(self):
            req = self.business.request(self.v.address, wallets.envelope(wallets.SUBMIT, self.v.req()),
                                        wallets.COIN // 2, self.v.now)
            sig = pqtest.stored(pqtest.sign(self.business.key, req.hash, wallets.CONTEXT))
            return pqtest.Cell().uint(wallets.SUBMIT_OP, 32).uint(1, 64).ref(req).ref(sig)

        def test_serialized_restart_retains_replay(self):
            import native
            body = self.signed_message()
            relay = native.internal(wallets.RELAYER, self.business.address, body, wallets.RELAY_VALUE)
            first = self.v.e.send(self.business.shard, relay)
            self.assertEqual(pqtest.details_of(first)["exit"], 0)
            restored = pqtest.from_boc(first["shard_account"])
            second = self.v.e.send(restored, relay)
            self.assertEqual(pqtest.details_of(second)["exit"], 0x1701)
            self.assertEqual(native.account_data(restored)[0].hash,
                             native.account_data(pqtest.from_boc(second["shard_account"]))[0].hash)

        def test_frozen_deleted_and_redeployed_boundaries(self):
            import native
            wallet = self.business
            initial_data = native.account_data(wallet.shard)[0]
            init = native.state_init(wallets.WALLET_CODE, initial_data)
            body = self.signed_message()
            relay = native.internal(wallets.RELAYER, wallet.address, body, wallets.RELAY_VALUE)
            accepted = self.v.e.send(wallet.shard, relay)
            self.assertEqual(pqtest.details_of(accepted)["exit"], 0)
            executed_data = native.account_data(pqtest.from_boc(accepted["shard_account"]))[0]
            frozen_init = native.state_init(wallets.WALLET_CODE, executed_data)
            c = pqtest.Cell
            account = (c().uint(1, 1).addr(wallet.address).varuint(0, 7).varuint(0, 7).uint(0, 3)
                       .uint(native.NOW, 32).uint(0, 1).uint(0, 64).coins(100 * wallets.COIN)
                       .uint(0, 1).uint(1, 2).uint(int.from_bytes(frozen_init.hash, "big"), 256))
            frozen = c().uint(0, 256).uint(0, 64).ref(account)
            absent = c().uint(0, 256).uint(0, 64).ref(c().uint(0, 1))
            for label, shard in (("frozen", frozen), ("absent", absent), ("uninitialized", native.uninitialized_account(wallet.address))):
                refused = self.v.e.send(shard, relay)
                self.assertTrue(refused["success"], f"{label}: {refused}")
                self.assertTrue(refused["details"]["skipped"])
                self.assertEqual(pqtest.details_of(refused)["verifications"], 0)
            # Explicit native StateInit activation at the original address.
            deploy = (c().uint(4, 4).addr(wallets.RELAYER).addr(wallet.address).coins(wallets.RELAY_VALUE)
                      .uint(0, 1).coins(0).coins(0).uint(0, 64).uint(native.NOW, 32)
                      .uint(1, 1).uint(1, 1).ref(init).uint(1, 1).ref(body))
            redeployed = self.v.e.send(native.uninitialized_account(wallet.address), deploy)
            self.assertEqual(pqtest.details_of(redeployed)["exit"], 0)
            self.assertEqual(pqtest.details_of(redeployed)["verifications"], 1)

        def test_real_pq_pauser_can_pause_but_cannot_pay(self):
            from wire import control, PAUSE, roles
            pauser = wallets.PqWallet(13)
            v = wallets.Vault(role_cell=roles(self.business.address, self.guardian.address, wallets.COLD, pauser.address))
            self.addCleanup(v.close)
            unauthorized = pauser.send(v, wallets.envelope(wallets.SUBMIT, v.req()))
            self.assertEqual(len(unauthorized), 1)
            v.send(message=unauthorized[0], expected=2401)
            messages = pauser.send(v, control(PAUSE, v.state["epoch"], v.state["admin_nonce"]))
            self.assertEqual(len(messages), 1)
            v.send(message=messages[0])
            self.assertTrue(v.state["paused"])
            self.assertEqual(v.budget()["cumulative"], 0)

    lifecycle = unittest.TextTestRunner(verbosity=2).run(unittest.TestSuite([
        LifecycleTests("test_serialized_restart_retains_replay"),
        LifecycleTests("test_frozen_deleted_and_redeployed_boundaries"),
        LifecycleTests("test_real_pq_pauser_can_pause_but_cannot_pay")]))
    artifacts = [build / "crypto/func", build / "crypto/fift", build / "tol/tol", args.signer.resolve()]
    artifacts += list((build / "emulator").glob("libemulator.*"))
    report = {"schema": "tos.custody.native-conformance.v1", "tos_commit": head,
              "custody_source_digest": source_digest(ROOT), "comparisons": counts,
              "baseline_tests": first.testsRun, "integrated_tests": second.testsRun,
              "lifecycle_tests": lifecycle.testsRun,
              "failures": len(first.failures) + len(second.failures) + len(lifecycle.failures),
              "errors": len(first.errors) + len(second.errors) + len(lifecycle.errors),
              "skips": len(first.skipped) + len(second.skipped) + len(lifecycle.skipped),
              "artifacts_sha256": {str(p): digest(p) for p in artifacts if p.is_file()},
              "openssl": subprocess.check_output([str(args.openssl), "version"], text=True).strip(),
              "hardware_tested": False, "state_authenticated": False,
              "build_provenance": "locally built from pinned checkout" if pinned_build else "existing local binaries",
              "pinned_build_configured": pinned_build,
              "cmake_cache_sha256": digest(cache) if cache.is_file() else None}
    args.report.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    if (not first.wasSuccessful() or not second.wasSuccessful() or not lifecycle.wasSuccessful() or report["skips"]
            or not all(counts.values())):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
