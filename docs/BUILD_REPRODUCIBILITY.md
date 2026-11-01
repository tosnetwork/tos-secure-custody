# Build and provenance requirements

## What is reproducible now

The bootstrap includes a deterministic **source TAR**, not a firmware build or a hermetic Python
runtime. For identical source contents, the builder sorts paths, normalizes archive ownership,
permissions and timestamp, uses an uncompressed USTAR container and includes a SHA-256 content manifest.
It refuses symlinks and unrecognized file types. Build/cache/Git directories are excluded.

```sh
python3 scripts/source_bundle.py --output dist/tos-secure-custody-source.tar
python3 scripts/check_reproducible.py
```

The comparison reconstructs the same snapshot in two different directories, changes filesystem
mtimes and requires byte-for-byte identical archives. This verifies those sources of packaging
nondeterminism in one environment. It is not proof of cross-toolchain firmware reproducibility.
Saved test evidence is part of the source snapshot; rerunning tests changes that evidence and creates
a new snapshot. The `source_digest` in test reports excludes `evidence/` to avoid self-reference.

## Current limitations

Python and the operating-system image are not hermetically built or independently reproduced.
`cryptography==46.0.4` and the build backend version are pinned by version but are not a hash-locked,
vendor-audited dependency closure. No wheel, firmware binary, FPGA image or hardware BOM is released.
The CI workflow has a full-SHA checkout action and read-only repository permissions, but has not run
in GitHub during this preparation. These limits prohibit a production release claim.

## Production build acceptance

Lock compiler/toolchain, dependencies, firmware configuration and board revision by content hash.
Build offline from a verified dependency mirror. Record the complete dependency and license inventory,
SBOM, source revision, toolchain identity, build recipe and output hashes. Separate key custody and
release signing from the build workers. Never place production custody keys in CI.

Two independently operated builders must reproduce each release binary, not just its source archive.
Verify artifact equivalence before signing a release. Include firmware rollback/debug behavior,
measurement derivation and the connection between the published image and the running device.
A reproducible malicious source tree remains malicious; reproducibility does not replace review.

Release provenance, transparency publication and firmware-signing keys need their own recovery and
post-quantum migration plan. A mutable container tag or a green hosted-CI badge is insufficient.

An exported bundle also supports `python3 scripts/verify_source_manifest.py`. This checks content
integrity only; authenticate the archive digest through a trusted independent release channel.
