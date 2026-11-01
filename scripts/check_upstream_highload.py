"""Reproduce frozen vectors using the pinned upstream Python cell codec.

Pass test/auth-extensions/cells.py from the documented TOS commit. Its entire blob
is checked BEFORE executing it. This is codec-level evidence, not native execution
or ML-DSA signing. No upstream source or cryptographic implementation is vendored.
"""
import argparse
import hashlib
import json
from pathlib import Path
import sys
import types

ROOT = Path(__file__).resolve().parents[1]
COMMIT = "def735f3ad9c57a4b8fc8de43537075baec2271a"
CODEC_BLOB = "a2038cde8a5165ac21e84ae34d4f550299250d2c"


def vectors(codec_path):
    raw = codec_path.read_bytes()
    actual = hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
    if actual != CODEC_BLOB:
        raise ValueError("upstream codec blob mismatch; refusing to execute it")
    module = types.ModuleType("pinned_upstream_cells")
    exec(compile(raw, str(codec_path), "exec"), module.__dict__)
    C = module.Cell
    vault, wallet, recipient = ((0, int(x * 32, 16)) for x in ("11", "22", "33"))
    network, now = -777777, 1793491200
    output = []
    for amounts in ([1_000_000_000], [1, 2]):
        actions = C()
        for amount in amounts:
            payment = C().uint(0, 256).coins(amount).addr(recipient).coins(0)
            req = (C().uint(0x54565031, 32).sint(network, 32).addr(vault)
                   .uint(7, 64).uint(42, 64).uint(now + 300, 32).ref(payment))
            body = C().uint(0x54560001, 32).uint(0, 64).ref(req)
            msg = (C().uint(0x18, 6).addr(vault).coins(100_000_000).uint(0, 1)
                   .coins(0).coins(0).uint(0, 64).uint(0, 32).uint(0, 1).uint(1, 1).ref(body))
            actions = C().ref(actions).uint(0x0EC3C86D, 32).uint(1, 8).ref(msg)
        unsigned = (C().sint(network, 32).addr(wallet).uint(7, 32).uint(1, 23)
                    .uint(now - 10, 64).uint(3600, 22).ref(actions))
        output.append({"name": "native-" + str(len(amounts)) + "-send",
                       "form": "request", "boc_hex": unsigned.boc().hex(),
                       "request_cell_hash": unsigned.hash.hex(),
                       "amounts_in_execution_order": amounts})
    return {"schema": "tos.custody.upstream-highload-vectors.v1", "upstream_commit": COMMIT,
            "codec_path": "test/auth-extensions/cells.py", "codec_git_blob_sha1": CODEC_BLOB,
            "evidence_level": "upstream Python codec; NOT native TVM or real signatures",
            "vectors": output}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cells", required=True, type=Path)
    parser.add_argument("--write", action="store_true", help="regenerate reviewed public synthetic vectors")
    args = parser.parse_args()
    document = vectors(args.cells)
    expected = ROOT / "fixtures/pq-highload-vectors.json"
    if args.write:
        expected.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n")
    elif document != json.loads(expected.read_text()):
        raise SystemExit("FAIL: frozen upstream vectors differ")
    sys.path.insert(0, str(ROOT / "src"))
    from tos_custody.highload import inspect_highload
    for vector in document["vectors"]:
        parsed = inspect_highload(bytes.fromhex(vector["boc_hex"]), form=vector["form"])
        observed = [a["vault_body"]["request"]["payload"]["amount_base_units"] for a in parsed["actions"]]
        if (parsed["signing_message_hex"] != vector["request_cell_hash"]
                or observed != vector["amounts_in_execution_order"]):
            raise SystemExit("FAIL: custody parser differs from upstream codec vector")
    print("PASS: 2 upstream-codec vectors; native TVM/signature/hardware tests NOT RUN")


if __name__ == "__main__":
    main()
