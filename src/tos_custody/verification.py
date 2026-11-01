"""Optional software ML-DSA verification; supplied keys/state are not trust anchors.

OpenSSL 3.5+ Pure ML-DSA with the wallet's explicit context. No signing API,
algorithm negotiation, external executable selection from request data, or approval.
"""
from pathlib import Path
import subprocess
import tempfile

from .boc import parse_boc
from .errors import CustodyError
from .highload import _internal, inspect_highload
from .multisig import LIMITS, _dictionary, inspect_multisig

# SubjectPublicKeyInfo: id-ml-dsa-44 (2.16.840.1.101.3.4.3.17), absent params,
# BIT STRING with zero unused bits and exactly 1312 public-key bytes.
SPKI_PREFIX = bytes.fromhex("30820532300b06096086480165030403110382052100")


def stored_bytes(stored, length):
    s = stored.slice()
    if s.uint(32) != length:
        raise CustodyError("unexpected stored-byte length")
    node = s.ref()
    s.end()
    result = bytearray()
    while len(result) < length:
        size = min(127, length - len(result))
        more = len(result) + size < length
        if node.bit_length != size * 8 or len(node.refs) != int(more):
            raise CustodyError("noncanonical stored-byte chain")
        result.extend(node.data)
        if more:
            node = node.refs[0]
    return bytes(result)


class OpenSslVerifier:
    """Executable path is operator configuration, never an offline-request field."""
    def __init__(self, executable):
        path = Path(executable)
        if not path.is_absolute() or not path.is_file():
            raise CustodyError("configure an absolute OpenSSL executable path")
        self.executable = str(path)

    def verify(self, public_key, signature, message, context):
        if (type(public_key) is not bytes or len(public_key) != 1312
                or type(signature) is not bytes or len(signature) != 2420
                or type(message) is not bytes or len(message) != 32
                or context not in ("TOS-PQ-HIGHLOAD-v1", "TOS-PQ-QUORUM-v1")):
            raise CustodyError("invalid ML-DSA-44 verification inputs")
        with tempfile.TemporaryDirectory(prefix="custody-public-verify-") as directory:
            root = Path(directory)
            for name, data in (("key.der", SPKI_PREFIX + public_key),
                               ("signature", signature), ("message", message)):
                (root / name).write_bytes(data)
            try:
                result = subprocess.run(
                    [self.executable, "pkeyutl", "-verify", "-rawin", "-pubin",
                     "-keyform", "DER", "-inkey", str(root / "key.der"),
                     "-sigfile", str(root / "signature"), "-in", str(root / "message"),
                     "-pkeyopt", "context-string:" + context],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15,
                    check=False)
            except (OSError, subprocess.TimeoutExpired) as exc:
                raise CustodyError("ML-DSA verification backend unavailable") from exc
            if result.returncode != 0:
                raise CustodyError("ML-DSA verification failed or backend unsupported")


def _submission(raw, form, limits):
    root = parse_boc(raw, **limits)
    return _internal(root, outbound=False, max_depth=limits.get("max_depth", 32))[1] if form == "relay" else root


def _result(inspection, count):
    return {"schema": "tos.custody.signature-verification.v1", "inspection": inspection,
            "cryptographically_verified": True, "verified_signature_count": count,
            "key_source": "caller-supplied-untrusted", "state_authenticated": False,
            "freshness_checked": False, "replay_checked": False, "signing_authorized": False,
            "warning": "Valid signatures against supplied keys do not authenticate an account or authorize custody."}


def verify_highload(raw, *, public_key, verifier, form="submission"):
    if form not in ("submission", "relay"):
        raise CustodyError("verification requires a signed submission or relay")
    inspection = inspect_highload(raw, form=form)
    stored = _submission(raw, form, {}).refs[1]
    verifier.verify(public_key, stored_bytes(stored, 2420),
                    bytes.fromhex(inspection["signing_message_hex"]), inspection["signing_context_ascii"])
    return _result(inspection, 1)


def verify_multisig(raw, *, context, state_raw, verifier, form="submission"):
    if form not in ("submission", "relay"):
        raise CustodyError("verification requires a signed submission or relay")
    inspection = inspect_multisig(raw, context=context, state_raw=state_raw, form=form)
    root = parse_boc(state_raw, **LIMITS)
    keys = _dictionary(root.refs[0], limit=64)
    submission = _submission(raw, form, LIMITS)
    signatures = _dictionary(submission.refs[1], limit=12)
    for identifier, stored in signatures.items():
        verifier.verify(stored_bytes(keys[identifier], 1312), stored_bytes(stored, 2420),
                        bytes.fromhex(inspection["signing_message_hex"]), inspection["signing_context_ascii"])
    return _result(inspection, len(signatures))
