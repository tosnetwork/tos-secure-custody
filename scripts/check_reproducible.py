"""Compare source bundles from two paths with changed filesystem mtimes."""
import os
from pathlib import Path
import tempfile
from source_bundle import ROOT, build, entries


def check():
    with tempfile.TemporaryDirectory(prefix="tos-custody-repro-") as temporary:
        work = Path(temporary)
        left, right = work / "one", work / "different-path/two"
        for index, target in enumerate((left, right)):
            for name, data in entries(ROOT):
                path = target / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(data)
                os.utime(path, (1000000000 + index * 50000, 1000000000 + index * 50000))
        first = build(left, work / "first.tar")
        second = build(right, work / "second.tar")
        if first != second or (work / "first.tar").read_bytes() != (work / "second.tar").read_bytes():
            raise SystemExit("FAIL: source archives differ")
        print("PASS: byte-identical source archives across paths and mtimes: " + first)
        return first

if __name__ == "__main__":
    check()
