"""Bounded offline request transport; intentionally no real-fund signing path."""
from .canonical import exact_keys, loads
from .errors import CustodyError, UnsupportedProfile
from .policy import appraise_payment
from .vault import inspect_boc


def inspect_bundle(raw):
    bundle = loads(raw)
    exact_keys(bundle, {"schema", "boc_hex"})
    if bundle["schema"] != "tos.custody.offline-inspection.v1":
        raise CustodyError("unsupported offline schema")
    encoded = bundle["boc_hex"]
    if type(encoded) is not str or not encoded or len(encoded) % 2 or len(encoded) > 120000:
        raise CustodyError("invalid offline BOC encoding")
    if any(c not in "0123456789abcdef" for c in encoded):
        raise CustodyError("offline BOC must be lowercase hexadecimal")
    return inspect_boc(bytes.fromhex(encoded), form="internal")


def check_bundle(raw, policy, *, now):
    inspection = inspect_bundle(raw)
    return {"inspection": inspection, "diagnostic": appraise_payment(inspection, policy, now=now)}


class OfflineSigner:
    """A hard release gate, not a mock that returns a fake signature."""
    def sign(self, *args, **kwargs):
        raise UnsupportedProfile(
            "Production signing is disabled: external wallet decoding, state proofs, "
            "trusted-display firmware and hardware acceptance are not implemented.")
