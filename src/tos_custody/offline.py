"""Bounded offline request transport; intentionally no real-fund signing path."""
from .canonical import exact_keys, loads
from .errors import CustodyError, UnsupportedProfile
from .policy import appraise_payment
from .vault import inspect_boc
from .highload import FORMS, inspect_highload
from .multisig import inspect_multisig


def inspect_bundle(raw):
    bundle = loads(raw)
    if type(bundle) is not dict:
        raise CustodyError("offline bundle must be an object")
    highload = bundle.get("schema") == "tos.custody.offline-highload-inspection.v1"
    multisig = bundle.get("schema") == "tos.custody.offline-multisig-inspection.v1"
    if multisig:
        exact_keys(bundle, {"schema", "form", "boc_hex", "context"})
        if bundle["form"] not in FORMS:
            raise CustodyError("unsupported PQ multisig inspection form")
    elif highload:
        exact_keys(bundle, {"schema", "form", "boc_hex"})
        if bundle["form"] not in FORMS:
            raise CustodyError("unsupported PQ highload inspection form")
    else:
        exact_keys(bundle, {"schema", "boc_hex"})
        if bundle["schema"] != "tos.custody.offline-inspection.v1":
            raise CustodyError("unsupported offline schema")
    encoded = bundle["boc_hex"]
    if type(encoded) is not str or not encoded or len(encoded) % 2 or len(encoded) > 120000:
        raise CustodyError("invalid offline BOC encoding")
    if any(c not in "0123456789abcdef" for c in encoded):
        raise CustodyError("offline BOC must be lowercase hexadecimal")
    if multisig:
        return inspect_multisig(bytes.fromhex(encoded), context=bundle["context"], form=bundle["form"])
    if highload:
        return inspect_highload(bytes.fromhex(encoded), form=bundle["form"])
    return inspect_boc(bytes.fromhex(encoded), form="internal")


def check_bundle(raw, policy, *, now):
    inspection = inspect_bundle(raw)
    if inspection["schema"] != "tos.custody.inspection.v1":
        raise UnsupportedProfile("Wallet state and batch policy appraisal are not implemented")
    return {"inspection": inspection, "diagnostic": appraise_payment(inspection, policy, now=now)}


class OfflineSigner:
    """A hard release gate, not a mock that returns a fake signature."""
    def sign(self, *args, **kwargs):
        raise UnsupportedProfile(
            "Production signing is disabled: complete wallet authentication, state proofs, "
            "trusted-display firmware and hardware acceptance are not implemented.")
