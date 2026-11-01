"""Hard-coded bootstrap gate; editing a JSON checkbox never enables signing."""
import argparse
import json

BLOCKERS = [
    "External wallet signing profile and exact signing preimage are not implemented",
    "Authenticated finality, code-hash and role/state proof verification is not implemented",
    "No post-quantum hardware signer has been qualified",
    "Trusted-display firmware and physical confirmation have not been tested",
    "Production hardware attestation and durable anti-replay state are not implemented",
    "Firmware/toolchain/dependency reproducibility has not been established",
    "Native TOS custody integration and institutional hardware attacks have not run",
    "Independent expert code/hardware review and final deployment ceremony are outstanding",
]

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expect-blocked", action="store_true", help="CI check that this bootstrap remains blocked")
    args = parser.parse_args()
    print(json.dumps({"production_release_allowed": False, "blockers": BLOCKERS}, indent=2))
    raise SystemExit(0 if args.expect_blocked else 1)
