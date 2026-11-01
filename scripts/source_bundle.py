"""Deterministic SOURCE archive. This does not build firmware or Python wheels."""
import argparse
import hashlib
import io
import json
from pathlib import Path
import tarfile

ROOT = Path(__file__).resolve().parents[1]
EXCLUDED = {".git", ".venv", "__pycache__", ".pytest_cache", ".ruff_cache", "dist", "build"}
EXTENSIONS = {".md", ".py", ".json", ".yml", ".yaml", ".toml", ".txt", ".sh", ".boc"}
SPECIAL = {"LICENSE", "NOTICE", "Makefile", ".gitignore"}
EPOCH = 1793491200


def entries(root):
    result = []
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root)
        if relative.as_posix() == "SOURCE-MANIFEST.json":
            continue
        if any(part in EXCLUDED or part.endswith(".egg-info") for part in relative.parts):
            continue
        if path.is_symlink():
            raise ValueError("source symlinks are forbidden: " + str(relative))
        if path.is_dir():
            continue
        if path.suffix not in EXTENSIONS and path.name not in SPECIAL:
            raise ValueError("unrecognized source file; refusing to package: " + str(relative))
        result.append((relative.as_posix(), path.read_bytes()))
    return result


def manifest(items):
    return {name: hashlib.sha256(data).hexdigest() for name, data in items}


def source_digest(root):
    items = [(name, data) for name, data in entries(root) if not name.startswith("evidence/")]
    encoded = json.dumps(manifest(items), sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def build(root, destination):
    if destination.resolve().is_relative_to(root.resolve()) and destination.parent.name != "dist":
        raise ValueError("write archives outside the source tree or directly under dist/")
    items = entries(root)
    listing = json.dumps({"schema": "tos.custody.source-manifest.v1", "sha256": manifest(items)},
                         indent=2, sort_keys=True).encode() + b"\n"
    items.append(("SOURCE-MANIFEST.json", listing))
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(destination, "w", format=tarfile.USTAR_FORMAT) as archive:
        for name, data in sorted(items):
            info = tarfile.TarInfo("tos-secure-custody/" + name)
            info.size = len(data)
            info.mtime = EPOCH
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            info.mode = 0o644
            archive.addfile(info, io.BytesIO(data))
    return hashlib.sha256(destination.read_bytes()).hexdigest()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "dist/tos-secure-custody-source.tar")
    parser.add_argument("--root", type=Path, default=ROOT)
    args = parser.parse_args()
    print(build(args.root, args.output), args.output)
