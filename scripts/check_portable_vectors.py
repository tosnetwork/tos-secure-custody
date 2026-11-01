"""Language-neutral parser corpus for future device implementations.

Each case contains exact input bytes/context and expected complete JSON output,
or an expected rejection. A firmware implementation can consume the same cases.
--write explicitly regenerates the reviewed reference outputs.
"""
import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from tos_custody.errors import CustodyError
from tos_custody.highload import inspect_highload
from tos_custody.multisig import inspect_multisig


def inspect(case):
    raw = bytes.fromhex(case["boc_hex"])
    if case["profile"] == "highload":
        return inspect_highload(raw, form=case["form"])
    return inspect_multisig(raw, context=case["context"], form=case["form"])


def generate():
    cases = []
    for profile in ("highload", "multisig"):
        source = json.loads((ROOT / f"fixtures/pq-{profile}-vectors.json").read_text())
        for vector in source["vectors"]:
            case = {"name": profile + "/" + vector["name"], "profile": profile,
                    "form": vector.get("form", "request"), "boc_hex": vector["boc_hex"]}
            if profile == "multisig":
                case["context"] = vector["context"]
            case["expected"] = inspect(case)
            cases.append(case)
        sample = cases[-1]
        for label, raw in (("truncated", sample["boc_hex"][:-2]),
                           ("trailing-byte", sample["boc_hex"] + "00"),
                           ("bad-magic", "00000000" + sample["boc_hex"][8:])):
            cases.append({**{k: v for k, v in sample.items() if k != "expected"},
                          "name": profile + "/" + label, "boc_hex": raw, "reject": True})
    return {"schema": "tos.custody.portable-parser-corpus.v1", "cases": cases}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args()
    path = ROOT / "fixtures/portable-parser-corpus.json"
    if args.write:
        path.write_text(json.dumps(generate(), indent=2, sort_keys=True) + "\n")
    cases = json.loads(path.read_text())["cases"]
    for case in cases:
        try:
            result = inspect(case)
        except CustodyError:
            if not case.get("reject"):
                raise
        else:
            if case.get("reject") or result != case["expected"]:
                raise SystemExit("FAIL: " + case["name"])
    print(f"PASS: {len(cases)} portable parser cases")


if __name__ == "__main__":
    main()
