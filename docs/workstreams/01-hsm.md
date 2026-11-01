# Workstream 1: HSM adapters and post-quantum key custody

## Objective

Implement vendor-neutral hardware signing adapters without converting an unsupported PQ operation
into a classical or software signature. Preserve a distinct independent authorization boundary.

## Current baseline

Capability interface and experimental NetHSM Ed25519 transport exist. The transport uses verified
TLS and independently pinned public-key verification, but only mocked transport has been tested.
PKCS#11 is a fail-closed placeholder. No PQ hardware signer is implemented or qualified.

## Implementation tasks

- [ ] Define stable key handles, suite identifiers, exact signing-input conventions and adapter errors.
- [ ] Implement and review PKCS#11 sessions, device selection, key attributes and token identity.
- [ ] Qualify a real device supporting the chosen ML-DSA-44 security boundary; do not assume vendor support.
- [ ] Generate custody keys within that boundary and prove the required non-exportability properties.
- [ ] Verify every signature locally against a separately provisioned key and exact approved preimage.
- [ ] Isolate operator credentials from the business host; prohibit key-admin API access in the signing plane.
- [ ] Handle partial failure, timeouts, reconnect, session loss, concurrency and idempotent request reconciliation.
- [ ] Specify and test offline provisioning, backup, rotation, revocation and loss recovery.

## Acceptance criteria

Actual device-generated PQ signatures must verify through the exact supported TOS wallet profile on
the native emulator. Wrong device, wrong key, unsupported suite, stale policy, ambiguous timeout,
malicious transport and insufficient authentication must fail closed. Publish device/firmware IDs,
exact source/configuration, commands and observations; no secret or live credential enters reports.
A software token or mocked HTTP response cannot close the physical-device requirement.

Dependencies: complete transaction/signing-plan workstream and production release gates.
