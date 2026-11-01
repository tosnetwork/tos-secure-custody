"""Inspection-only command line. No secrets, signing or broadcast commands."""
import argparse
import json
from pathlib import Path
import sys
from .canonical import loads
from .errors import CustodyError
from .offline import inspect_bundle, check_bundle
from .vault import inspect_boc


def _read(path, limit=131072):
    with Path(path).open("rb") as handle:
        raw = handle.read(limit + 1)
    if len(raw) > limit:
        raise CustodyError("input file exceeds limit")
    return raw


def main(argv=None):
    parser = argparse.ArgumentParser(prog="tos-custody", description="Experimental TOS custody inspection; production signing disabled")
    commands = parser.add_subparsers(dest="command", required=True)
    boc = commands.add_parser("inspect-boc", help="decode the exact supported Vault BOC")
    boc.add_argument("file")
    boc.add_argument("--form", choices=("internal", "body"), default="internal")
    bundle = commands.add_parser("inspect-bundle", help="decode an offline request without trusting host labels")
    bundle.add_argument("file")
    check = commands.add_parser("check-bundle", help="diagnostic policy comparison; not authorization")
    check.add_argument("file")
    check.add_argument("--policy", required=True)
    check.add_argument("--now", required=True, type=int, help="trusted timestamp for diagnostic fixtures")
    commands.add_parser("status", help="show implementation boundaries")
    args = parser.parse_args(argv)
    try:
        if args.command == "inspect-boc":
            result = inspect_boc(_read(args.file), form=args.form)
        elif args.command == "inspect-bundle":
            result = inspect_bundle(_read(args.file))
        elif args.command == "check-bundle":
            result = check_bundle(_read(args.file), loads(_read(args.policy)), now=args.now)
        else:
            result = {"stage": "experimental-inspection-only", "production_signing_enabled": False,
                      "hardware_qualified": False, "post_quantum_hardware_qualified": False,
                      "supported_parser": "ordinary BOC + Treasury Vault V1 bodies/internal messages",
                      "external_wallet_parser": "not implemented", "hardware_attestation": "not implemented"}
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    except (CustodyError, OSError) as exc:
        print("Rejected: " + str(exc), file=sys.stderr)
        return 2

if __name__ == "__main__":
    raise SystemExit(main())
