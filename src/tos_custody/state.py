"""Bounded decoders for operator-pinned custody account data.

These functions decode data only. Bind its hash to ProvenAccount before appraisal.
"""
from hashlib import sha256

from .boc import Cell, parse_boc
from .errors import CustodyError
from .multisig import _dictionary
from .verification import stored_bytes
from .vault import decode_body

LIMITS = {"max_cells": 1024, "max_depth": 96}


def commitment(cell):
    return cell.commitment(max_depth=96)[1].hex()


def vault_state(raw, vault):
    s = parse_boc(raw, **LIMITS).slice()
    result = {"epoch": s.uint(64), "payment_nonce": s.uint(64), "admin_nonce": s.uint(64),
              "paused": bool(s.uint(1)), "asset_count": s.uint(8)}
    roles = s.ref().slice()
    hot, cold = roles.ref().slice(), roles.ref().slice()
    roles.end()
    result["roles"] = {"business": hot.address(), "guardian": hot.address(),
                       "cold_administrator": cold.address(), "pauser": cold.address()}
    hot.end()
    cold.end()
    if len(set(result["roles"].values())) != 4 or vault in result["roles"].values():
        raise CustodyError("invalid Vault roles")
    dictionary = s.ref() if s.uint(1) else None
    payment = s.ref() if s.uint(1) else None
    admin = s.ref() if s.uint(1) else None
    result["pending_payment_hash"] = commitment(payment) if payment is not None else None
    result["pending_payment"] = (decode_body(Cell(bytes.fromhex("545600010000000000000000"), 96, (payment,)))["request"]
                                 if payment is not None else None)
    result["pending_admin_hash"], result["admin_ready_at"], result["pending_admin"] = None, None, None
    if admin is not None:
        queued = admin.slice()
        result["admin_ready_at"] = queued.uint(32)
        admin_request = queued.ref()
        queued.end()
        result["pending_admin_hash"] = commitment(admin_request)
        result["pending_admin"] = decode_body(Cell(bytes.fromhex("545600060000000000000000"), 96, (admin_request,)))["request"]
    s.end()
    assets = _dictionary(dictionary, limit=16)
    if len(assets) != result["asset_count"]:
        raise CustodyError("Vault asset count mismatch")
    result["assets"] = {}
    for identifier, record in assets.items():
        row = record.slice()
        item = {"enabled": bool(row.uint(1)), "source_token_wallet": row.address(allow_none=True),
                "per_payment": row.coins(), "window_limit": row.coins(), "cumulative_limit": row.coins(),
                "window_start": row.uint(32), "window_spent": row.coins(), "cumulative_spent": row.coins()}
        row.end()
        if ((identifier == 0) != (item["source_token_wallet"] is None)
                or min(item["window_limit"], item["cumulative_limit"]) < item["per_payment"]):
            raise CustodyError("invalid Vault asset state")
        result["assets"][f"{identifier:064x}"] = item
    return result


def highload_state(raw):
    s = parse_boc(raw, **LIMITS).slice()
    public_key = stored_bytes(s.ref(), 1312)
    subwallet = s.uint(32)
    generations = []
    for _ in range(2):
        root = s.ref() if s.uint(1) else None
        rows = _dictionary(root, limit=8192, key_bits=13)
        for row in rows.values():
            if row.bit_length != 1023 or row.refs:
                raise CustodyError("invalid highload replay bitmap")
        generations.append(rows)
    last_clean, timeout = s.uint(64), s.uint(22)
    s.end()
    if timeout == 0:
        raise CustodyError("invalid wallet timeout")
    return {"public_key": public_key, "key_id": sha256(b"TOS-PQ-CONSENSUS-KEY-v1\x01\x00" + public_key).hexdigest(),
            "subwallet_id": subwallet, "old_queries": generations[0], "queries": generations[1],
            "last_clean_time": last_clean, "timeout": timeout}


def highload_unused(state, *, query_id, created_at, now):
    if not 0 <= query_id < 1 << 23 or query_id & 1023 == 1023:
        raise CustodyError("invalid highload replay ID")
    if not now - state["timeout"] < created_at <= now or state["last_clean_time"] > now:
        raise CustodyError("wallet request is stale, future or state time rolled back")
    old, current = state["old_queries"], state["queries"]
    last, timeout = state["last_clean_time"], state["timeout"]
    if last < now - timeout:
        old, current = current, {}
        if last < now - 2 * timeout:
            old = {}
    shift, bit = query_id >> 10, query_id & 1023
    for rows in (old, current):
        row = rows.get(shift)
        if row is not None and int.from_bytes(row.data, "big") >> (len(row.data) * 8 - bit - 1) & 1:
            raise CustodyError("wallet query has already executed")
