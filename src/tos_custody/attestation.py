"""Device-attestation protocol prototype and SOFTWARE-FIXTURE verifier.

Signed software claims do not prove secure boot, genuine silicon, key isolation,
or an uncompromised display. Production hardware appraisal is disabled.
"""
from dataclasses import dataclass
import threading
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from .canonical import canonical, exact_keys, hex_bytes, uint
from .errors import CustodyError, UnsupportedProfile

DOMAIN = b"TOS-CUSTODY-ATTESTATION-FIXTURE-V1\x00"
CLAIM_KEYS = {"schema", "device_id", "nonce", "audience", "intent_hash", "policy_hash",
              "signer_key_hash", "firmware_hash", "boot_hash", "security_version",
              "counter", "issued_at", "expires_at", "secure_boot", "debug_enabled"}

@dataclass(frozen=True)
class ExpectedBindings:
    device_id: str
    audience: str
    intent_hash: str
    policy_hash: str
    signer_key_hash: str

class ChallengeBook:
    """Process-local test state. NOT durable, not suitable for production."""
    def __init__(self):
        self._pending = {}
        self._counters = {}
        self._lock = threading.Lock()

    def issue(self, nonce, *, expires_at):
        hex_bytes(nonce, 32, "challenge")
        uint(expires_at, 32, "challenge expiry")
        with self._lock:
            if nonce in self._pending:
                raise CustodyError("challenge already exists")
            self._pending[nonce] = expires_at

    def consume(self, nonce, device_id, counter, *, now):
        with self._lock:
            expiry = self._pending.get(nonce)
            if expiry is None or expiry <= now:
                raise CustodyError("unknown, expired or replayed challenge")
            if counter <= self._counters.get(device_id, -1):
                raise CustodyError("device counter rollback or replay")
            del self._pending[nonce]
            self._counters[device_id] = counter


def verify_fixture(envelope, *, expected, pinned_key, allowed_measurements,
                   min_security_version, revoked_devices, challenges, now,
                   allow_software_fixture=False):
    if allow_software_fixture is not True:
        raise UnsupportedProfile("software-signed claims cannot satisfy hardware attestation")
    exact_keys(envelope, {"claims", "signature"})
    claims = envelope["claims"]
    exact_keys(claims, CLAIM_KEYS)
    if claims["schema"] != "tos.custody.attestation.software-fixture.v1":
        raise CustodyError("unsupported attestation schema")
    for field in ("nonce", "intent_hash", "policy_hash", "signer_key_hash", "firmware_hash", "boot_hash"):
        hex_bytes(claims[field], 32, field)
    for field in ("issued_at", "expires_at", "security_version"):
        uint(claims[field], 32, field)
    uint(claims["counter"], 64, "counter")
    uint(now, 32, "trusted time")
    uint(min_security_version, 32, "minimum security version")
    if type(claims["secure_boot"]) is not bool or type(claims["debug_enabled"]) is not bool:
        raise CustodyError("attestation flags must be booleans")
    for field in ("device_id", "audience", "intent_hash", "policy_hash", "signer_key_hash"):
        if claims[field] != getattr(expected, field):
            raise CustodyError("attestation session, device, key or intent binding mismatch")
    if claims["device_id"] in revoked_devices:
        raise CustodyError("device has been revoked")
    signature = hex_bytes(envelope["signature"], 64, "signature")
    if type(pinned_key) is not bytes or len(pinned_key) != 32:
        raise CustodyError("invalid pinned fixture key")
    try:
        Ed25519PublicKey.from_public_bytes(pinned_key).verify(signature, DOMAIN + canonical(claims))
    except InvalidSignature:
        raise CustodyError("invalid attestation signature") from None
    if not claims["issued_at"] <= now < claims["expires_at"] or not 0 < claims["expires_at"] - claims["issued_at"] <= 60:
        raise CustodyError("stale, future or overlong attestation")
    if (claims["firmware_hash"], claims["boot_hash"]) not in allowed_measurements:
        raise CustodyError("unapproved measurements")
    if claims["security_version"] < min_security_version or not claims["secure_boot"] or claims["debug_enabled"]:
        raise CustodyError("rollback, insecure boot or debug mode")
    challenges.consume(claims["nonce"], claims["device_id"], claims["counter"], now=now)
    return {"valid_software_fixture": True, "hardware_assurance": False,
            "production_authorized": False, "device_id": claims["device_id"]}


def verify_hardware(*args, **kwargs):
    raise UnsupportedProfile("No TPM/DICE/secure-element evidence profile has been implemented or qualified")
