"""Offline genuine PQ-finality/account-proof integration and tamper controls.

The saved development-network account is the elector, not a deployed custody
wallet/Vault. Historical verification is intentionally never fresh authorization.
"""
import argparse
from dataclasses import asdict
from hashlib import sha256
import json
from pathlib import Path
import shutil
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from tos_custody.errors import CustodyError
from tos_custody.proofs import ProofVerifier
from source_bundle import source_digest

TRUSTED_ROOT = "1bdb1208416a1103bdb7ff6082f7effe047bac45313e27d4043ca04d16377b64"
TRUSTED_FILE = "c9f382c9119eb7f3ab3bd6ae88fa1af59ab500bda3b5d794480e83ee24477686"
ELECTOR_CODE = "db1752ed1038937dd5de08c5a4f451121418db98187401c4304f7f6b7bf0b467"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixtures", type=Path, required=True)
    parser.add_argument("--verifier", type=Path, required=True)
    parser.add_argument("--verifier-sha256", required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    anchor = {"kind": "zerostate", "workchain": -1, "shard": "8000000000000000", "seqno": 0,
              "root_hash": TRUSTED_ROOT, "file_hash": TRUSTED_FILE}
    # This fixture is always replayed against our explicitly provisioned test anchor.
    request = json.loads((args.fixtures / "historical-request.json").read_text())
    target = {k: value.lower() if isinstance(value, str) else value for k, value in request["target"].items()}
    native = ProofVerifier(executable=args.verifier.resolve(), executable_sha256=args.verifier_sha256, anchor=anchor)
    parameters = {"account": request["account"], "target": target, "material": args.fixtures / "historical",
                  "now": 1791200930, "max_age": 300, "historical": True, "expected_code_hash": ELECTOR_CODE,
                  "config_params": (34,), "get_methods": ("active_election_id", "participant_list")}
    proven = native.verify_account(**parameters)
    if proven.fresh:
        raise SystemExit("historical proof was incorrectly marked fresh")
    passed = ["genuine-historical-PQ-finality-and-account-proof"]

    def reject(label, verifier=native, **changes):
        try:
            verifier.verify_account(**{**parameters, **changes})
        except CustodyError:
            passed.append(label)
            return
        raise SystemExit("tampered proof accepted: " + label)

    reject("wrong-code", expected_code_hash="00"*32)
    reject("wrong-account", account="-1:" + "44"*32)
    reject("same-height-wrong-root", target={**target, "root_hash": "00"*32})
    reject("same-height-wrong-file", target={**target, "file_hash": "00"*32})
    other = ProofVerifier(executable=args.verifier.resolve(), executable_sha256=args.verifier_sha256,
                          anchor={**anchor, "root_hash": "00"*32})
    reject("wrong-trust-anchor", verifier=other)
    with tempfile.TemporaryDirectory(prefix="custody-proof-tamper-") as directory:
        material = Path(directory) / "material"
        shutil.copytree(args.fixtures / "historical", material)
        chain = material / "chain-0000.tl"
        raw = chain.read_bytes()
        chain.write_bytes(bytes(4) + raw[4:])
        reject("malformed-chain-carrier", material=material)
    report = {"schema": "tos.custody.state-proof-checks.v1", "source_digest": source_digest(ROOT),
              "checks_passed": passed, "proven_historical_account": asdict(proven),
              "native_verifier_sha256": args.verifier_sha256,
              "fixture_hashes": {str(p.relative_to(args.fixtures)): sha256(p.read_bytes()).hexdigest()
                                  for p in sorted((args.fixtures / "historical").iterdir()) if p.is_file()},
              "custody_deployment_proven": False, "hardware_tested": False}
    args.report.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(f"PASS: {len(passed)} genuine proof/tamper checks; historical elector fixture, not custody deployment")


if __name__ == "__main__":
    main()
