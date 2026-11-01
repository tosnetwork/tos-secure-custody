"""Complete consumption of the pinned Treasury Vault V1 control schemas.

This profile covers body BOCs and internal messages, NOT external wallet
messages, wallet action lists, deployment StateInit, or state proofs.
"""
from hashlib import sha256
from .boc import parse_boc
from .errors import CustodyError

OPERATIONS = {0x54560000 + i: name for i, name in enumerate((
    "submit", "approve", "cancel_payment", "expire_payment", "pause",
    "schedule", "apply", "veto", "expire_admin"), start=1)}
PAYMENT_DOMAIN = 0x54565031
ADMIN_DOMAIN = 0x54564731
UPSTREAM_COMMIT = "def735f3ad9c57a4b8fc8de43537075baec2271a"


def _payment(cell):
    s = cell.slice()
    asset = s.uint(256)
    amount = s.coins()
    recipient = s.address()
    attachment = s.coins()
    s.end()
    if not amount or attachment > 1_000_000_000 or (asset == 0) != (attachment == 0):
        raise CustodyError("invalid payment amount or Token attachment")
    return {"kind": "payment", "asset_id": f"{asset:064x}", "amount_base_units": amount,
            "recipient": recipient, "token_attachment_base_units": attachment}


def _management(cell, vault):
    s = cell.slice()
    kind = s.uint(8)
    if kind == 1:
        asset = s.uint(256)
        enabled = bool(s.uint(1))
        wallet = s.address(allow_none=True)
        per_payment, window, cumulative = s.coins(), s.coins(), s.coins()
        if (asset == 0) != (wallet is None) or min(window, cumulative) < per_payment or (enabled and not per_payment):
            raise CustodyError("invalid asset configuration")
        result = {"kind": "set_asset", "asset_id": f"{asset:064x}", "enabled": enabled,
                  "source_token_wallet": wallet, "per_payment": per_payment,
                  "fixed_window_limit": window, "cumulative_limit": cumulative}
    elif kind == 2:
        role_root = s.ref().slice()
        hot, cold = role_root.ref().slice(), role_root.ref().slice()
        role_root.end()
        roles = {"business": hot.address(), "guardian": hot.address(),
                 "cold_administrator": cold.address(), "pauser": cold.address()}
        hot.end()
        cold.end()
        if len(set(roles.values())) != 4 or vault in roles.values():
            raise CustodyError("roles must be distinct and different from the vault")
        result = {"kind": "set_roles", **roles}
    elif kind == 3:
        result = {"kind": "unpause"}
    else:
        raise CustodyError("unknown management payload")
    s.end()
    return result


def decode_body(cell):
    s = cell.slice()
    opcode, query_id = s.uint(32), s.uint(64)
    if opcode not in OPERATIONS:
        raise CustodyError("unknown Vault opcode")
    operation = OPERATIONS[opcode]
    result = {"operation": operation, "opcode": f"{opcode:08x}", "query_id": query_id,
              "body_cell_hash": cell.hash.hex()}
    if operation in {"submit", "approve", "schedule", "apply"}:
        request_cell = s.ref()
        request = request_cell.slice()
        admin = operation in {"schedule", "apply"}
        expected_domain = ADMIN_DOMAIN if admin else PAYMENT_DOMAIN
        domain = request.uint(32)
        if domain != expected_domain:
            raise CustodyError("Vault request domain mismatch")
        network = request.sint(32)
        vault = request.address()
        epoch, nonce, deadline = request.uint(64), request.uint(64), request.uint(32)
        payload_cell = request.ref()
        request.end()
        result["request"] = {"domain": f"{domain:08x}", "network_global_id": network,
                             "vault": vault, "epoch": epoch, "nonce": nonce, "deadline": deadline,
                             "request_cell_hash": request_cell.hash.hex(),
                             "payload": _management(payload_cell, vault) if admin else _payment(payload_cell)}
    else:
        result["epoch"], result["nonce"] = s.uint(64), s.uint(64)
    s.end()
    return result


def inspect_boc(raw, *, form="internal"):
    root = parse_boc(raw)
    if form == "body":
        result = decode_body(root)
        result["outer_message"] = None
    elif form == "internal":
        s = root.slice()
        if s.uint(1) != 0:
            raise CustodyError("external wallet messages are not implemented; refusing blind inspection")
        ihr_disabled, bounce, bounced = bool(s.uint(1)), bool(s.uint(1)), bool(s.uint(1))
        source = s.address(allow_none=True)
        destination = s.address()
        value = s.coins()
        if s.uint(1):
            raise CustodyError("extra currencies are outside the custody profile")
        ihr_fee, forward_fee = s.coins(), s.coins()
        created_lt, created_at = s.uint(64), s.uint(32)
        if s.uint(1):
            raise CustodyError("StateInit is forbidden in this custody profile")
        body_by_reference = bool(s.uint(1))
        body = s.ref() if body_by_reference else s.remainder()
        s.end()
        if bounced:
            raise CustodyError("bounced messages cannot authorize custody operations")
        result = decode_body(body)
        if "request" in result and result["request"]["vault"] != destination:
            raise CustodyError("outer destination differs from the bound Vault address")
        result["outer_message"] = {
            "source": source, "destination": destination, "value_base_units": value,
            "ihr_disabled": ihr_disabled, "bounce": bounce, "bounced": bounced,
            "ihr_fee": ihr_fee, "forward_fee": forward_fee,
            "created_lt": created_lt, "created_at": created_at,
            "body_by_reference": body_by_reference}
    else:
        raise CustodyError("unknown BOC form")
    return {"schema": "tos.custody.inspection.v1", "profile": "treasury-vault-v1/" + form,
            "upstream_commit": UPSTREAM_COMMIT, "boc_sha256": sha256(raw).hexdigest(),
            "root_cell_hash": root.hash.hex(), "signing_authorized": False, **result}
