"""Inspection-only PQ highload-wallet profile pinned to the TOS baseline.

The wallet is internally relayed, NOT an external-message wallet. This deliberately
narrower custody profile accepts 1..16 fixed-value sends of known Vault V1 bodies.
It never verifies a signature, authenticates state, checks replay, or authorizes funds.
"""
from hashlib import sha256

from .boc import MAX_DEPTH, Cell, parse_boc
from .errors import CustodyError
from .vault import UPSTREAM_COMMIT, decode_body

CONTEXT = "TOS-PQ-HIGHLOAD-v1"
SUBMIT = 0x50514857
SEND_MSG = 0x0EC3C86D
MAX_ACTIONS = 16
SIGNATURE_BYTES = 2420
CHUNK_BYTES = 127
FORMS = ("request", "submission", "relay")


def _internal(cell: Cell, *, outbound: bool, max_depth=MAX_DEPTH) -> tuple[dict, Cell]:
    """Decode the full supported message; never treat a claimed sender as proof."""
    s = cell.slice()
    if s.uint(1) != 0:
        raise CustodyError("PQ highload custody requires an internal message")
    ihr_disabled, bounce, bounced = bool(s.uint(1)), bool(s.uint(1)), bool(s.uint(1))
    source, destination = s.address(allow_none=True), s.address()
    if bounced or not ihr_disabled:
        raise CustodyError("bounced or IHR-enabled messages are outside this profile")
    if outbound and source is not None:
        raise CustodyError("outbound source must be addr_none; the wallet fills it")
    if not outbound and source is None:
        raise CustodyError("a relayed submission must have a canonical relayer address")
    value = s.coins()
    if s.uint(1):
        raise CustodyError("extra currencies are outside this custody profile")
    # This field is extra_flags, NOT ihr_fee, in the pinned TVM v16 profile.
    extra_flags, forward_fee = s.coins(), s.coins()
    created_lt, created_at = s.uint(64), s.uint(32)
    if extra_flags > 3:
        raise CustodyError("unsupported message extra_flags")
    if outbound and (forward_fee or created_lt or created_at):
        raise CustodyError("outbound fee and creation placeholders must be zero")
    if s.uint(1):
        raise CustodyError("StateInit is forbidden in this custody profile")
    by_reference = bool(s.uint(1))
    body = s.ref() if by_reference else s.remainder()
    s.end()
    return {
        "source": source, "destination": destination, "value_base_units": value,
        "ihr_disabled": ihr_disabled, "bounce": bounce, "bounced": bounced,
        "extra_flags": extra_flags, "forward_fee": forward_fee,
        "created_lt": created_lt, "created_at": created_at,
        "body_by_reference": by_reference,
        "message_cell_hash": cell.commitment(max_depth=max_depth)[1].hex(),
    }, body


def _actions(root: Cell, network: int) -> list[dict]:
    actions = []
    node = root
    while node.refs:
        if len(actions) >= MAX_ACTIONS:
            raise CustodyError("custody batch exceeds 16 actions")
        s = node.slice()
        previous = s.ref()
        if s.uint(32) != SEND_MSG:
            raise CustodyError("only send_msg actions are supported")
        mode = s.uint(8)
        message = s.ref()
        s.end()
        # TOS allows +128; custody deliberately forbids dynamic balance sweeps.
        if mode not in (0, 1, 2, 3):
            raise CustodyError("only fixed-value modes 0..3 are allowed")
        envelope, body = _internal(message, outbound=True)
        decoded = decode_body(body)
        request = decoded.get("request")
        if request is not None:
            if request["network_global_id"] != network:
                raise CustodyError("wallet and Vault network IDs differ")
            if request["vault"] != envelope["destination"]:
                raise CustodyError("action destination differs from bound Vault address")
        actions.append({"send_mode": mode, "effective_send_mode": mode | 2,
                        "message": envelope, "vault_body": decoded})
        node = previous
    node.slice().end()
    if not actions:
        raise CustodyError("custody batch must not be empty")
    # OutList stores newest first. Display in the wallet's actual execution order.
    actions.reverse()
    for index, action in enumerate(actions):
        action["execution_index"] = index
    return actions


def _signature(stored: Cell) -> dict:
    s = stored.slice()
    length, chain = s.uint(32), s.ref()
    s.end()
    if length != SIGNATURE_BYTES:
        raise CustodyError("ML-DSA-44 signature must declare 2420 bytes")
    remaining = length
    digest = sha256()
    while remaining:
        expected = min(CHUNK_BYTES, remaining)
        has_next = remaining > CHUNK_BYTES
        if chain.bit_length != expected * 8 or len(chain.refs) != int(has_next):
            raise CustodyError("noncanonical ML-DSA signature byte chain")
        digest.update(chain.data)
        remaining -= expected
        if has_next:
            chain = chain.refs[0]
    return {"length_bytes": length, "sha256": digest.hexdigest(),
            "shape_checked": True, "cryptographically_verified": False}


def inspect_highload(raw: bytes, *, form: str = "request") -> dict:
    """Decode exact signing bytes and all supported actions, without authorizing.

    request: unsigned Request BOC. submission: submit body plus signature bytes.
    relay: full internal message carrying a submission. Signature-shaped garbage
    can pass structural inspection; cryptographic verification is explicitly false.
    """
    if form not in FORMS:
        raise CustodyError("unsupported PQ highload inspection form")
    root = parse_boc(raw)
    request = root
    relay = None
    relayer_query_id = None
    signature = None
    if form == "relay":
        relay, request = _internal(root, outbound=False)
    if form != "request":
        submission = request.slice()
        if submission.uint(32) != SUBMIT:
            raise CustodyError("unknown PQ highload submission opcode")
        relayer_query_id = submission.uint(64)
        request, stored = submission.ref(), submission.ref()
        submission.end()
        signature = _signature(stored)
    s = request.slice()
    network, wallet = s.sint(32), s.address()
    subwallet, query_id = s.uint(32), s.uint(23)
    created_at, timeout = s.uint(64), s.uint(22)
    actions = s.ref()
    s.end()
    if not timeout or query_id & 1023 == 1023:
        raise CustodyError("invalid timeout or reserved replay-query bit")
    if relay is not None and relay["destination"] != wallet:
        raise CustodyError("relay destination differs from signed wallet address")
    decoded_actions = _actions(actions, network)
    request_hash = request.hash.hex()
    return {
        "schema": "tos.custody.highload-inspection.v1",
        "profile": "pq-highload-v1/vault-only/" + form,
        "upstream_commit": UPSTREAM_COMMIT,
        "boc_sha256": sha256(raw).hexdigest(), "root_cell_hash": root.hash.hex(),
        "request_cell_hash": request_hash,
        "network_global_id": network, "wallet": wallet, "subwallet_id": subwallet,
        "query_id": query_id, "created_at": created_at, "timeout": timeout,
        "expires_at_exclusive": created_at + timeout,
        "signing_message_hex": request_hash, "signing_message_length_bytes": 32,
        "signing_context_ascii": CONTEXT, "algorithm": "ML-DSA-44",
        "action_count": len(decoded_actions), "actions": decoded_actions,
        "unsigned_relayer_query_id": relayer_query_id, "unsigned_relay": relay,
        "signature": signature,
        "signing_authorized": False, "state_authenticated": False,
        "freshness_checked": False, "replay_checked": False,
        "warnings": [
            "Inspection is not signature verification, account authentication or approval.",
            "All sends are best effort (+2 forced); execution is not atomic or guaranteed.",
            "Relayer routing/value/query ID are outside the wallet signature.",
            "The 32-byte request cell hash is signed under the stated ML-DSA context, not BOC bytes or JSON.",
        ],
    }
