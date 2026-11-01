"""Reproduce cold-multisig vectors with the whole-blob-pinned upstream Python codec.

This is independent codec compatibility, NOT native TVM, real ML-DSA or hardware.
No upstream implementation is vendored; an unpinned local file is never executed.
"""
import argparse
import hashlib
import json
from pathlib import Path
import sys
import types

from check_upstream_highload import CODEC_BLOB, COMMIT, ROOT


def vectors(codec_path):
    raw = codec_path.read_bytes()
    actual = hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
    if actual != CODEC_BLOB:
        raise ValueError("upstream codec blob mismatch; refusing to execute it")
    module = types.ModuleType("pinned_multisig_codec")
    exec(compile(raw, str(codec_path), "exec"), module.__dict__)
    C = module.Cell
    network, expiry, seqno = -777777, 1793491500, 9
    account, vault = (0, int("44" * 32, 16)), (0, int("11" * 32, 16))
    context = {"network_global_id": network, "account": "0:" + "44" * 32, "seqno": seqno}

    def stored(data):
        chain = None
        for offset in reversed(range(0, len(data), 127)):
            chunk = data[offset:offset + 127]
            next_cell = C().raw(chunk)
            if chain is not None:
                next_cell.ref(chain)
            chain = next_cell
        return C().uint(len(data), 32).ref(chain)

    def key(i):
        return i.to_bytes(2, "big") + bytes(1310)

    def key_id(i):
        return int.from_bytes(hashlib.sha256(b"TOS-PQ-CONSENSUS-KEY-v1\x01\x00" + key(i)).digest(), "big")

    def actions(ops):
        result = C()
        for op in ops:
            body = C().uint(op, 32).uint(0, 64).uint(7, 64).uint(42, 64)
            message = (C().uint(0x18, 6).addr(vault).coins(100000000).uint(0, 1)
                       .coins(0).coins(0).uint(0, 64).uint(0, 32).uint(0, 1).uint(1, 1).ref(body))
            result = C().ref(result).uint(0x0EC3C86D, 32).uint(1, 8).ref(message)
        return result

    cases = [("execute-pause", 1, actions([0x54560005])),
             ("execute-pause-veto", 1, actions([0x54560005, 0x54560008])),
             ("add-member", 2, C().uint(1, 8).ref(stored(key(7)))),
             ("remove-member", 2, C().uint(2, 8).uint(key_id(0), 256)),
             ("lower-quorum", 2, C().uint(3, 8).uint(1, 8))]
    output = []
    for name, kind, payload in cases:
        request = C().uint(kind, 8).uint(expiry, 32).ref(payload)
        preimage = (C().sint(network, 32).uint(0x504D5330 + kind, 32).addr(account)
                    .uint(seqno, 64).uint(expiry, 32).ref(payload))
        output.append({"name": name, "context": context, "boc_hex": request.boc().hex(),
                       "request_cell_hash": request.hash.hex(), "signing_message_hex": preimage.hash.hex()})
    # Exercise independently built state/signature dictionaries at the full limits.
    dictionary = module.make_dict({key_id(i): C().ref(stored(key(i))) for i in range(64)}, 256)
    state = C().maybe(dictionary).uint(64, 8).uint(12, 8).uint(seqno, 64)
    signatures = module.make_dict({key_id(i): C().ref(stored(bytes([i]) * 2420)) for i in range(12)}, 256)
    request = C().uint(1, 8).uint(expiry, 32).ref(cases[0][2])
    submission = C().uint(0x504D5353, 32).uint(8, 64).ref(request).maybe(signatures)
    sys.path.insert(0, str(ROOT / "src"))
    from tos_custody.multisig import inspect_multisig, inspect_multisig_state
    inspected_state = inspect_multisig_state(state.boc())
    inspected = inspect_multisig(submission.boc(), context=context, form="submission", state_raw=state.boc())
    if (inspected_state["data_cell_hash"] != state.hash.hex() or inspected_state["member_count"] != 64
            or len(inspected["signatures"]) != 12 or inspected["signing_message_hex"] != output[0]["signing_message_hex"]):
        raise ValueError("full-limit state/signature dictionaries differ from upstream codec")
    for vector in output:
        inspected = inspect_multisig(bytes.fromhex(vector["boc_hex"]), context=vector["context"])
        for field in ("request_cell_hash", "signing_message_hex"):
            if inspected[field] != vector[field]:
                raise ValueError("custody parser differs from upstream: " + vector["name"])
    return {"schema": "tos.custody.upstream-multisig-vectors.v1", "upstream_commit": COMMIT,
            "codec_path": "test/auth-extensions/cells.py", "codec_git_blob_sha1": CODEC_BLOB,
            "evidence_level": "upstream Python codec; NOT native TVM, signatures or hardware",
            "vectors": output, "full_limit_state_cell_hash": state.hash.hex(),
            "full_limit_submission_cell_hash": submission.hash.hex(),
            "full_limit_members": 64, "full_limit_signature_shapes": 12}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cells", required=True, type=Path)
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args()
    document = vectors(args.cells)
    expected = ROOT / "fixtures/pq-multisig-vectors.json"
    if args.write:
        expected.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n")
    elif document != json.loads(expected.read_text()):
        raise SystemExit("FAIL: frozen upstream multisig vectors differ")
    print("PASS: 5 upstream-codec vectors + 12-of-64 structural comparison; native/crypto/hardware NOT RUN")


if __name__ == "__main__":
    main()
