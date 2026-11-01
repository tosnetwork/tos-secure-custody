"""Pinned cold PQ multisig inspection, never signature or state authentication.

The Request does NOT contain network/account/seqno. Its cell hash is NOT the
signing message. Context and optional account data are untrusted diagnostic inputs.
"""
from hashlib import sha256

from .boc import Cell, parse_boc
from .canonical import exact_keys, hex_bytes, uint
from .errors import CustodyError
from .highload import FORMS, _actions, _internal, _signature
from .vault import UPSTREAM_COMMIT

SUBMIT = 0x504D5353
CONTEXT = "TOS-PQ-QUORUM-v1"
DOMAINS = {1: 0x504D5331, 2: 0x504D5332}
MAX_SEQNO = (1 << 64) - 1
# 64 full keys / 12 full signatures exceed the ordinary 256-cell profile.
LIMITS = {"max_cells": 1024, "max_depth": 96}


def _hash(cell):
    return cell.commitment(max_depth=96)[1].hex()


def _dictionary(root, *, limit):
    """Hashmap 256, all three HmLabel encodings; bounded even for shared DAGs."""
    entries = {}
    visited = 0

    def walk(cell, width, prefix):
        nonlocal visited
        visited += 1
        if visited > 2 * limit - 1:
            raise CustodyError("dictionary traversal limit exceeded")
        s = cell.slice()
        if s.uint(1) == 0:  # hml_short, unary length
            length = 0
            while s.uint(1):
                length += 1
                if length > width:
                    raise CustodyError("dictionary label exceeds key width")
            label = s.uint(length)
        elif s.uint(1) == 0:  # hml_long
            length = s.uint(width.bit_length())
            if length > width:
                raise CustodyError("dictionary label exceeds key width")
            label = s.uint(length)
        else:  # hml_same
            bit = s.uint(1)
            length = s.uint(width.bit_length())
            if length > width:
                raise CustodyError("dictionary label exceeds key width")
            label = ((1 << length) - 1) if bit else 0
        key = (prefix << length) | label
        remaining = width - length
        if remaining == 0:
            if key in entries or len(entries) >= limit:
                raise CustodyError("duplicate or excessive dictionary entries")
            value = s.ref()
            s.end()  # each leaf is exactly ^StoredKey or ^StoredSignature
            entries[key] = value
        else:
            left, right = s.ref(), s.ref()
            s.end()
            walk(left, remaining - 1, key << 1)
            walk(right, remaining - 1, (key << 1) | 1)

    if root is not None:
        walk(root, 256, 0)
    return entries


def _key(stored):
    s = stored.slice()
    length, chain = s.uint(32), s.ref()
    s.end()
    if length != 1312:
        raise CustodyError("ML-DSA-44 public key must declare 1312 bytes")
    data = bytearray()
    remaining = length
    while remaining:
        size = min(127, remaining)
        more = remaining > 127
        if chain.bit_length != size * 8 or len(chain.refs) != int(more):
            raise CustodyError("noncanonical ML-DSA key byte chain")
        data.extend(chain.data)
        remaining -= size
        if more:
            chain = chain.refs[0]
    # The algorithm ID in this key-identity domain is uint16 LITTLE endian.
    key_id = sha256(b"TOS-PQ-CONSENSUS-KEY-v1" + b"\x01\x00" + data).hexdigest()
    return {"key_id": key_id, "length_bytes": length,
            "public_key_sha256": sha256(data).hexdigest(), "shape_checked": True}


def inspect_multisig_state(raw):
    """Check supplied account-data structure and key IDs, NOT its origin/finality."""
    root = parse_boc(raw, **LIMITS)
    s = root.slice()
    dictionary = s.ref() if s.uint(1) else None
    count, quorum, seqno = s.uint(8), s.uint(8), s.uint(64)
    s.end()
    if not 1 <= count <= 64 or not 1 <= quorum <= min(count, 12):
        raise CustodyError("invalid multisig member count or quorum")
    entries = _dictionary(dictionary, limit=64)
    if len(entries) != count:
        raise CustodyError("stored member count differs from dictionary")
    members = []
    for identifier, stored in sorted(entries.items()):
        key = _key(stored)
        if int(key["key_id"], 16) != identifier:
            raise CustodyError("member dictionary key ID does not match public key")
        members.append(key)
    return {"schema": "tos.custody.multisig-state-inspection.v1",
            "upstream_commit": UPSTREAM_COMMIT, "data_cell_hash": _hash(root),
            "member_count": count, "quorum": quorum, "seqno": seqno, "members": members,
            "state_authenticated": False, "deployment_verified": False,
            "warnings": ["Supplied account data is not a state proof or a code/address check."]}


def _context(value):
    exact_keys(value, {"network_global_id", "account", "seqno"})
    network, account, seqno = value["network_global_id"], value["account"], value["seqno"]
    if type(network) is not int or not -(1 << 31) <= network < 1 << 31:
        raise CustodyError("network_global_id must be int32")
    if type(account) is not str or not account.startswith("0:"):
        raise CustodyError("account must be a canonical workchain-0 address")
    hex_bytes(account[2:], 32, "account")
    uint(seqno, 64, "seqno")
    if seqno == MAX_SEQNO:
        raise CustodyError("multisig sequence number is exhausted")
    return network, account, seqno


def _preimage(network, domain, account, seqno, expiry, payload):
    # Exact pq_quorum::signing_hash cell; no JSON or request hash substitution.
    fields = ((network & 0xFFFFFFFF, 32), (domain, 32), (4, 3), (0, 8),
              (int(account[2:], 16), 256), (seqno, 64), (expiry, 32))
    bits = "".join(format(value, f"0{width}b") for value, width in fields)
    data = (int(bits, 2) << ((-len(bits)) % 8)).to_bytes((len(bits) + 7) // 8, "big")
    return Cell(data, len(bits), (payload,))


def _change(payload, state):
    s = payload.slice()
    kind = s.uint(8)
    if kind == 1:
        result = {"operation": "add_member", "member": _key(s.ref())}
    elif kind == 2:
        result = {"operation": "remove_member", "key_id": f"{s.uint(256):064x}"}
    elif kind == 3:
        quorum = s.uint(8)
        if not 1 <= quorum <= 12:
            raise CustodyError("new quorum must be 1..12")
        result = {"operation": "set_quorum", "new_quorum": quorum}
    else:
        raise CustodyError("unknown multisig membership change")
    s.end()
    result["effect"] = "Immediate account change, authorized by the PRE-CHANGE quorum"
    result["vault_delay_bypassed"] = False
    result["compared_with_untrusted_state"] = state is not None
    if state is not None:
        members = {member["key_id"] for member in state["members"]}
        count, quorum = state["member_count"], state["quorum"]
        if kind == 1:
            if result["member"]["key_id"] in members or count == 64:
                raise CustodyError("duplicate member or full member set")
            count += 1
        elif kind == 2:
            if result["key_id"] not in members or count - 1 < quorum:
                raise CustodyError("unknown member or removal below current quorum")
            count -= 1
        else:
            quorum = result["new_quorum"]
            if quorum > count:
                raise CustodyError("new quorum exceeds supplied member count")
        result.update({"before_member_count": state["member_count"],
                       "before_quorum": state["quorum"],
                       "after_member_count": count, "after_quorum": quorum})
    return result


def inspect_multisig(raw, *, context, form="request", state_raw=None):
    """Inspect Request/submission/internal relay; no signing, crypto or state proof.

    Context is mandatory even for a full relay: chain ID and sequence number are
    absent from the wire Request. Optional state comparisons are diagnostics only.
    """
    if form not in FORMS:
        raise CustodyError("unsupported PQ multisig inspection form")
    network, account, seqno = _context(context)
    state = inspect_multisig_state(state_raw) if state_raw is not None else None
    if state is not None and state["seqno"] != seqno:
        raise CustodyError("context sequence differs from supplied account data")
    root = parse_boc(raw, **LIMITS)
    request = root
    relay = None
    relay_query = None
    signature_entries = None
    if form == "relay":
        relay, request = _internal(root, outbound=False, max_depth=LIMITS["max_depth"])
        if relay["destination"] != account:
            raise CustodyError("relay destination differs from contextual multisig account")
    if form != "request":
        s = request.slice()
        if s.uint(32) != SUBMIT:
            raise CustodyError("unknown PQ multisig submission opcode")
        relay_query, request = s.uint(64), s.ref()
        dictionary = s.ref() if s.uint(1) else None
        s.end()
        signature_entries = _dictionary(dictionary, limit=12)
        if not signature_entries:
            raise CustodyError("submission signature dictionary must not be empty")
        if state is not None:
            if len(signature_entries) != state["quorum"]:
                raise CustodyError("signature count differs from PRE-CHANGE quorum")
            members = {int(member["key_id"], 16) for member in state["members"]}
            if not set(signature_entries).issubset(members):
                raise CustodyError("signature dictionary includes a non-member")
    s = request.slice()
    kind, expiry, payload = s.uint(8), s.uint(32), s.ref()
    s.end()
    if kind not in DOMAINS:
        raise CustodyError("unknown PQ multisig request kind")
    actions = _actions(payload, network) if kind == 1 else []
    change = _change(payload, state) if kind == 2 else None
    signatures = None if signature_entries is None else [
        {"key_id": f"{key_id:064x}", **_signature(stored)}
        for key_id, stored in sorted(signature_entries.items())]
    signing_hash = _hash(_preimage(network, DOMAINS[kind], account, seqno, expiry, payload))
    return {"schema": "tos.custody.multisig-inspection.v1",
            "profile": "pq-multisig-v1/vault-only/" + form,
            "upstream_commit": UPSTREAM_COMMIT, "boc_sha256": sha256(raw).hexdigest(),
            "root_cell_hash": _hash(root), "request_cell_hash": _hash(request),
            "network_global_id": network, "account": account, "seqno": seqno,
            "context_origin": "caller-supplied-untrusted", "kind": kind,
            "operation": "execute" if kind == 1 else "configure",
            "valid_until_inclusive": expiry, "signing_domain": f"0x{DOMAINS[kind]:08x}",
            "signing_message_hex": signing_hash, "signing_message_length_bytes": 32,
            "signing_context_ascii": CONTEXT, "algorithm": "ML-DSA-44",
            "actions": actions, "action_count": len(actions), "membership_change": change,
            "signatures": signatures, "supplied_state": state,
            "signature_set_compared_with_untrusted_state": state is not None and signatures is not None,
            "unsigned_relayer_query_id": relay_query, "unsigned_relay": relay,
            "cryptographically_verified": False, "state_authenticated": False,
            "signing_authorized": False, "freshness_checked": False, "replay_checked": False,
            "warnings": [
                "Network/account/seqno are NOT in Request; derive them from authenticated state before signing.",
                "The quorum preimage cell hash, NOT the Request/BOC/JSON hash, is the signing message.",
                "Membership/count comparisons against supplied data do not verify signatures or chain state.",
                "Account membership changes are immediate; Vault governance retains its separate delay.",
                "Sends are best effort (+2 forced); sequence consumption is not settlement proof.",
                "Relayer routing/value/query ID are outside the quorum signature.",
            ]}
