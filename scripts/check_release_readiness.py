"""Hard-coded bootstrap gate; editing a JSON checkbox never enables signing."""
import argparse
import json

BLOCKERS = [
    "Complete wallet authentication is missing: diagnostic ML-DSA verification does not authenticate supplied keys or state",
    "Native proof/batch adapters exist; fresh custody deployment proof acceptance and independent trust-anchor provisioning remain outstanding",
    "No post-quantum hardware signer has been qualified",
    "Trusted-display firmware and physical confirmation have not been tested",
    "Production hardware attestation and durable anti-replay state are not implemented",
    "Firmware/toolchain/dependency reproducibility has not been established",
    "Full native custody operational acceptance and institutional hardware attacks remain outstanding",
    "Independent expert code/hardware review and final deployment ceremony are outstanding",
]

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expect-blocked", action="store_true", help="CI check that this bootstrap remains blocked")
    args = parser.parse_args()
    print(json.dumps({"production_release_allowed": False, "blockers": BLOCKERS}, indent=2))
    raise SystemExit(0 if args.expect_blocked else 1)
