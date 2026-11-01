"""Real Pure ML-DSA-44 positive/negative checks using public test-key vectors.

--write --signer regenerates the vectors with the pinned TOS TEST ONLY signer.
The verifier is an independent OpenSSL implementation. Never use these keys for funds.
"""
import argparse
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "src"), str(ROOT / "tests")]
from tos_custody.errors import CustodyError
from tos_custody.verification import OpenSslVerifier, verify_highload, verify_multisig


def generate(signer):
    from test_highload import wallet_request, submission, stored_signature
    from test_multisig import CTX, encode, key_id, state, submit, req

    def sign(number, message, context):
        result = subprocess.run([str(signer)], input=f"{number} {message.hex()} {context.hex()}\n",
                                text=True, capture_output=True, check=True, timeout=30)
        return [bytes.fromhex(x) for x in result.stdout.split()]

    request = wallet_request()
    pk, sig = sign(0, request.hash, b"TOS-PQ-HIGHLOAD-v1")
    highload = {"public_key_hex": pk.hex(), "signature_hex": sig.hex(),
                "message_hex": request.hash.hex(), "context": "TOS-PQ-HIGHLOAD-v1",
                "submission_hex": encode(submission(request, signature=stored_signature(sig))).hex()}
    from tos_custody.multisig import inspect_multisig
    request = req()
    message = bytes.fromhex(inspect_multisig(encode(request), context=CTX)["signing_message_hex"])
    keys, signatures = {}, {}
    for number in (21, 22):
        public, signature = sign(number, message, b"TOS-PQ-QUORUM-v1")
        identifier = key_id(public)
        keys[identifier] = stored_signature(public)
        signatures[identifier] = stored_signature(signature)
    multisig = {"context": CTX, "state_hex": encode(state(count=2, entries=keys)).hex(),
                "submission_hex": encode(submit(request, entries=signatures)).hex()}
    return {"schema": "tos.custody.public-signature-vectors.v1",
            "warning": "PUBLIC TEST KEYS; never fund. Pinned TOS test signer keys 0,21,22.",
            "tos_commit": "def735f3ad9c57a4b8fc8de43537075baec2271a",
            "highload": highload, "multisig": multisig}


def check(document, verifier):
    count = 0

    def reject(function):
        nonlocal count
        try:
            function()
        except CustodyError:
            count += 1
            return
        raise RuntimeError("negative signature vector was accepted")

    highload, multisig = document["highload"], document["multisig"]
    pk, sig, message = [bytes.fromhex(highload[k]) for k in ("public_key_hex", "signature_hex", "message_hex")]
    raw = bytes.fromhex(highload["submission_hex"])
    verify_highload(raw, public_key=pk, verifier=verifier)
    count += 1
    # Genuine signatures against mutated exact bytes, keys and both wallet domains.
    for public, signature, msg, context in (
            (pk, bytes([sig[0] ^ 1]) + sig[1:], message, highload["context"]),
            (pk, sig, bytes([message[0] ^ 1]) + message[1:], highload["context"]),
            (bytes([pk[0] ^ 1]) + pk[1:], sig, message, highload["context"]),
            (pk, sig, message, "TOS-PQ-QUORUM-v1"),
            (pk, bytes(2420), message, highload["context"])):
        reject(lambda: verifier.verify(public, signature, msg, context))
    cold_raw, state = [bytes.fromhex(multisig[k]) for k in ("submission_hex", "state_hex")]
    verify_multisig(cold_raw, context=multisig["context"], state_raw=state, verifier=verifier)
    count += 1
    # Keep one valid quorum signature and corrupt the other while preserving its
    # canonical container. Verification must not stop after the first valid signer.
    from tos_custody.boc import Cell, parse_boc, serialize_boc
    from tos_custody.multisig import LIMITS, _dictionary
    root = parse_boc(cold_raw, **LIMITS)
    signatures = _dictionary(root.refs[1], limit=12)
    chain = signatures[max(signatures)].refs[0]
    altered = Cell(bytes([chain.data[0] ^ 1]) + chain.data[1:], chain.bit_length, chain.refs)

    def replace(node):
        if node is chain:
            return altered
        return Cell(node.data, node.bit_length, tuple(replace(ref) for ref in node.refs))

    corrupt = serialize_boc(replace(root), **LIMITS)
    reject(lambda: verify_multisig(corrupt, context=multisig["context"], state_raw=state, verifier=verifier))
    for field, value in (("seqno", 10), ("network_global_id", 123), ("account", "0:" + "99" * 32)):
        reject(lambda: verify_multisig(cold_raw, context={**multisig["context"], field: value},
                                        state_raw=state, verifier=verifier))
    print(f"PASS: {count} real ML-DSA positive/negative checks; supplied state remains unauthenticated")
    return count


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--openssl", type=Path, required=True)
    parser.add_argument("--write", action="store_true")
    parser.add_argument("--signer", type=Path)
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    path = ROOT / "fixtures/public-signature-vectors.json"
    if args.write:
        if args.signer is None:
            parser.error("--write requires --signer")
        path.write_text(json.dumps(generate(args.signer.resolve()), indent=2, sort_keys=True) + "\n")
    count = check(json.loads(path.read_text()), OpenSslVerifier(args.openssl.resolve()))
    if args.report:
        from source_bundle import source_digest
        report = {"schema": "tos.custody.real-signature-checks.v1", "checks_passed": count,
                  "source_digest": source_digest(ROOT), "hardware_tested": False,
                  "state_authenticated": False,
                  "openssl": subprocess.check_output([str(args.openssl), "version"], text=True).strip()}
        args.report.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
