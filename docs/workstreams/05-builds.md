# Workstream 5: Reproducible firmware and release provenance

## Objective

Allow independent parties to rebuild the exact firmware that is reviewed, released and measured on
signing devices, with transparent dependencies and controlled release keys.

## Current baseline

Deterministic source packaging and a two-directory byte-equivalence check exist. The checkout action
is SHA-pinned. Python/runtime dependencies, wheels, toolchains and firmware are not hermetically
reproduced. The CI workflow is authored but has not run remotely during bootstrap preparation.

## Implementation tasks

- [ ] Pin the full compiler, dependency, board and configuration closure by content hash.
- [ ] Build offline from reviewed inputs; record licenses and an SBOM.
- [ ] Define deterministic firmware/FPGA outputs and remove timestamp/path/randomness leakage.
- [ ] Operate two administratively independent builders and compare exact artifacts.
- [ ] Bind source, recipe, toolchains, artifact hashes and device measurements in signed provenance.
- [ ] Protect release keys separately from CI and custody keys; publish recovery/revocation procedures.
- [ ] Validate secure update, rollback protection and installed-image measurement derivation.
- [ ] Record the components that remain closed or cannot be independently reproduced.

## Acceptance criteria

Independent clean builds must produce byte-identical release firmware and map to the device's
appraised measurement. A source TAR comparison or version-pinned package installation is insufficient.
No release may claim certification or complete open-silicon verification without matching evidence.
