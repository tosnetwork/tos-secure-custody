"""Inspection-only command line. No secrets, signing or broadcast commands."""
import argparse
import json
from pathlib import Path
import sys
import sqlite3
from .canonical import loads
from .errors import CustodyError
from .offline import inspect_bundle, check_bundle
from .vault import inspect_boc
from .highload import FORMS, inspect_highload
from .multisig import inspect_multisig, inspect_multisig_state
from .verification import OpenSslVerifier, verify_highload, verify_multisig
from .session import appraise_session
from .journal import Journal
from .proofs import initialize_native_state
from .batch import validate_policy as validate_batch_policy


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
    highload = commands.add_parser("inspect-highload", help="inspect internally relayed PQ wallet bytes; never sign")
    highload.add_argument("file")
    highload.add_argument("--form", choices=FORMS, default="request")
    multisig = commands.add_parser("inspect-multisig", help="inspect cold quorum bytes; context is NOT authenticated")
    multisig.add_argument("file")
    multisig.add_argument("--form", choices=FORMS, default="request")
    multisig.add_argument("--context", required=True, help="diagnostic network/account/seqno JSON, not a state proof")
    multisig.add_argument("--state", help="optional untrusted account-data BOC for structural comparisons")
    state = commands.add_parser("inspect-multisig-state", help="check member IDs/count/quorum; NOT state authentication")
    state.add_argument("file")
    for command in ("verify-highload", "verify-multisig"):
        verify = commands.add_parser(command, help="diagnostic ML-DSA verification against supplied keys; not authorization")
        verify.add_argument("file")
        verify.add_argument("--form", choices=("submission", "relay"), default="submission")
        verify.add_argument("--openssl", required=True, help="operator-configured absolute OpenSSL 3.5+ path")
        if command == "verify-highload":
            verify.add_argument("--public-key", required=True, help="raw 1312-byte supplied public key")
        else:
            verify.add_argument("--context", required=True)
            verify.add_argument("--state", required=True, help="supplied account data; not authenticated state")
    bundle = commands.add_parser("inspect-bundle", help="decode an offline request without trusting host labels")
    bundle.add_argument("file")
    check = commands.add_parser("check-bundle", help="diagnostic policy comparison; not authorization")
    check.add_argument("file")
    check.add_argument("--policy", required=True)
    check.add_argument("--now", required=True, type=int, help="trusted timestamp for diagnostic fixtures")
    commands.add_parser("status", help="show implementation boundaries")
    batch = commands.add_parser("appraise-batch", help="local proof-backed policy appraisal; signing remains disabled")
    batch.add_argument("file")
    batch.add_argument("--policy", required=True, help="independently provisioned local policy")
    batch.add_argument("--session", required=True, help="operator-only proof session configuration")
    batch.add_argument("--now", required=True, type=int)
    batch.add_argument("--form", choices=FORMS, default="request")
    batch.add_argument("--openssl", help="absolute software verifier path, required for signed forms")
    batch.add_argument("--journal", help="reserve atomically in an explicitly provisioned journal")
    batch.add_argument("--checkpoint", help="independently retained journal checkpoint JSON")
    init = commands.add_parser("init-journal", help="explicit local journal provisioning; refuses existing file")
    init.add_argument("file")
    init.add_argument("--policy", required=True)
    init_state = commands.add_parser("init-proof-state", help="explicit native-state enrollment; refuses existing file")
    init_state.add_argument("file")
    init_state.add_argument("--anchor", required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "init-journal":
            policy = validate_batch_policy(loads(_read(args.policy)))
            result = {"checkpoint": Journal.create(args.file, anchor_digest=policy["anchor_digest"]),
                      "warning": "Retain this checkpoint independently; losing both storage copies permits rollback."}
        elif args.command == "init-proof-state":
            result = initialize_native_state(args.file, loads(_read(args.anchor)))
        elif args.command == "appraise-batch":
            if bool(args.journal) != bool(args.checkpoint):
                raise CustodyError("journal and independent checkpoint must be supplied together")
            policy = loads(_read(args.policy))
            result = appraise_session(_read(args.file), policy=policy, session=loads(_read(args.session)),
                                      now=args.now, form=args.form,
                                      verifier=OpenSslVerifier(args.openssl) if args.openssl else None)
            if args.journal:
                result["reservation"] = Journal(args.journal, anchor_digest=policy["anchor_digest"]).reserve(
                    result, expected_tip=loads(_read(args.checkpoint)), now=args.now)
        elif args.command == "verify-highload":
            result = verify_highload(_read(args.file), form=args.form,
                                     public_key=_read(args.public_key, 1312), verifier=OpenSslVerifier(args.openssl))
        elif args.command == "verify-multisig":
            result = verify_multisig(_read(args.file), form=args.form,
                                     context=loads(_read(args.context)), state_raw=_read(args.state),
                                     verifier=OpenSslVerifier(args.openssl))
        elif args.command == "inspect-boc":
            result = inspect_boc(_read(args.file), form=args.form)
        elif args.command == "inspect-highload":
            result = inspect_highload(_read(args.file), form=args.form)
        elif args.command == "inspect-multisig":
            result = inspect_multisig(_read(args.file), form=args.form,
                                     context=loads(_read(args.context)),
                                     state_raw=_read(args.state) if args.state else None)
        elif args.command == "inspect-multisig-state":
            result = inspect_multisig_state(_read(args.file))
        elif args.command == "inspect-bundle":
            result = inspect_bundle(_read(args.file))
        elif args.command == "check-bundle":
            result = check_bundle(_read(args.file), loads(_read(args.policy)), now=args.now)
        else:
            result = {"stage": "experimental-proof-backed-diagnostics", "production_signing_enabled": False,
                      "hardware_qualified": False, "post_quantum_hardware_qualified": False,
                      "supported_parser": "ordinary BOC + Treasury Vault V1 bodies/internal messages",
                      "pq_highload_parser": "Vault-only request/submission/relay inspection; not authentication",
                      "pq_multisig_parser": "cold request/submission/relay and account-data inspection; not authentication",
                      "pq_signature_verification": "optional OpenSSL ML-DSA-44 against supplied keys; no state authentication",
                      "proof_sessions": "operator-pinned native verifier, anchor, code/data and same-block account binding",
                      "durable_reservations": "SQLite + independently retained checkpoints; no automatic release",
                      "external_wallet_parser": "not implemented", "hardware_attestation": "not implemented"}
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    except (CustodyError, OSError, sqlite3.Error) as exc:
        print("Rejected: " + str(exc), file=sys.stderr)
        return 2

if __name__ == "__main__":
    raise SystemExit(main())
