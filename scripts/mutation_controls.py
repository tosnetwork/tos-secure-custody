"""Require targeted assertion failures when selected protections are removed.

These are software sensitivity controls, not a penetration test or hardware audit.
"""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from source_bundle import ROOT, source_digest

MUTATIONS = [
    ("domain-binding", "vault.py", "if domain != expected_domain:", "if False:",
     "test_vault.VaultTests.test_wrong_domain"),
    ("positive-payment", "vault.py", "if not amount or attachment >", "if attachment >",
     "test_vault.VaultTests.test_zero_payment"),
    ("full-consumption", "vault.py", "    s.end()\n    return result", "    # MUTATED: end check removed\n    return result",
     "test_vault.VaultTests.test_extra_reference"),
    ("recipient-allowlist", "policy.py", 'if not rule or payload["recipient"] not in rule["recipients"]:', 'if not rule:',
     "test_policy_offline.PolicyOfflineTests.test_substituted_recipient"),
    ("local-signature-verification", "adapters/nethsm.py",
     'Ed25519PublicKey.from_public_bytes(self._config.public_key).verify(signature, message)', 'pass  # MUTATED',
     "test_adapters.AdapterTests.test_wrong_key_signature_rejected"),
    ("attestation-replay", "attestation.py",
     'challenges.consume(claims["nonce"], claims["device_id"], claims["counter"], now=now)', 'pass  # MUTATED',
     "test_attestation.AttestationTests.test_replay"),
    ("measurement-allowlist", "attestation.py",
     'if (claims["firmware_hash"], claims["boot_hash"]) not in allowed_measurements:', 'if False:',
     "test_attestation.AttestationTests.test_unapproved_firmware"),
    ("tls-hostname-verification", "adapters/nethsm.py", 'self._tls.check_hostname = True', 'self._tls.check_hostname = False',
     "test_adapters.AdapterTests.test_tls_verification_not_optional"),
    ("untrusted-display", "offline.py", 'exact_keys(bundle, {"schema", "boc_hex"})', 'pass  # MUTATED',
     "test_policy_offline.PolicyOfflineTests.test_untrusted_host_display_forbidden"),
]


def run_test(root, target):
    environment = dict(os.environ, PYTHONPATH=os.pathsep.join((str(root / "src"), str(root / "tests"))),
                       PYTHONDONTWRITEBYTECODE="1")
    return subprocess.run([sys.executable, "-m", "unittest", target, "-v"], cwd=root, env=environment,
                          text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=30)


def main():
    results = []
    for name, path, before, after, target in MUTATIONS:
        baseline = run_test(ROOT, target)
        if baseline.returncode:
            raise SystemExit("baseline failed: " + target + "\n" + baseline.stdout)
        with tempfile.TemporaryDirectory(prefix="tos-custody-mutation-") as temporary:
            root = Path(temporary)
            shutil.copytree(ROOT / "src", root / "src", ignore=shutil.ignore_patterns("__pycache__"))
            shutil.copytree(ROOT / "tests", root / "tests", ignore=shutil.ignore_patterns("__pycache__"))
            file = root / "src/tos_custody" / path
            data = file.read_text()
            if before not in data:
                raise SystemExit("mutation anchor missing: " + name)
            file.write_text(data.replace(before, after))
            result = run_test(root, target)
            killed = result.returncode != 0 and "FAIL:" in result.stdout and "AssertionError" in result.stdout and "ERROR:" not in result.stdout
            if not killed:
                raise SystemExit("mutation not detected by a targeted assertion: " + name + "\n" + result.stdout)
            results.append({"name": name, "target": target, "baseline_passed": True,
                            "targeted_assertion_failed_after_mutation": True})
            print("PASS sensitivity control:", name)
    report = {"schema": "tos.custody.mutation-results.v1", "source_digest": source_digest(ROOT),
              "controls": results, "hardware_testing": "NOT RUN"}
    (ROOT / "evidence").mkdir(exist_ok=True)
    (ROOT / "evidence/mutations.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")

if __name__ == "__main__":
    main()
