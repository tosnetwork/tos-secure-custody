# Implementation status

Snapshot: 2026-11-01. Stage: **experimental, inspection-only**.

## Implemented and locally executable

- Strict TCJ-1 ASCII JSON with duplicate-key, size, depth and numeric bounds.
- Bounded ordinary level-zero BOC decoding, CRC32C and index checks, representation hashes,
  and rejection of hidden/trailing/unreachable/exotic data.
- All nine pinned Treasury Vault V1 control bodies, native/Token payment payloads,
  asset/role/unpause management payloads, and the supported internal-message envelope.
- An inspection-only CLI and offline format that reject host-supplied display labels and secret fields.
- Diagnostic payment appraisal against independently supplied policy inputs. It is not authentication.
- An experimental NetHSM Ed25519 adapter with TLS validation, pinned public-key verification,
  bounded responses, no redirects and no algorithm fallback. Only mocked transport was tested.
- A software-fixture attestation verifier using real Ed25519 verification, explicit fixture opt-in,
  binding checks, fresh challenges, process-local atomic replay protection and counter checks.
- Unit/adversarial tests, guard-removal sensitivity controls and deterministic source packaging.
- Draft CI and local GitHub publication/issue scripts.

## Specified but not implemented or qualified

| Requirement | Status | Blocking reason |
|---|---|---|
| Full role-wallet transaction parsing | BLOCKED | External wallet envelopes, action batches and exact signing preimages are not implemented |
| Authenticated state and finality | BLOCKED | No trusted light-client/state-proof implementation or native conformance run |
| Native custody end-to-end | NOT RUN | No TOS native emulator/toolchain was available in the preparation environment |
| Physical NetHSM | NOT RUN | No device/credentials were available; no network request was made to an HSM |
| PKCS#11 | NOT IMPLEMENTED | Placeholder always raises `UnsupportedProfile` |
| PQ hardware signing | NOT IMPLEMENTED | No ML-DSA key generation/storage/signing inside a qualified hardware boundary |
| Offline signing firmware | NOT IMPLEMENTED | No board, firmware, display or button integration |
| Hardware attestation | NOT IMPLEMENTED | Production verifier always refuses; fixture claims are not hardware evidence |
| Durable verifier/spend state | NOT IMPLEMENTED | Process-local fixture replay state cannot survive restarts or backup rollback |
| Firmware/toolchain reproducibility | NOT IMPLEMENTED | Current reproducibility covers a fixed source snapshot only |
| Independent audit | NOT RUN | Local self-tests are not third-party approval |
| GitHub publication | NOT PERFORMED | Repository creation was not exposed by the connected tool |
| GitHub Actions | NOT RUN | Workflow is authored but has not executed remotely |

## Non-negotiable boundary

`OfflineSigner.sign()` and `verify_hardware()` deliberately reject all requests. Do not remove these
gates merely to make a demo look complete. Replacing them requires implementing the missing boundary,
adding native and hardware tests, and obtaining an independent review of the exact source revision.

The software fixture uses Ed25519 only for testing the attestation protocol. It does not implement,
emulate, or stand in for post-quantum hardware. The NetHSM prototype advertises Ed25519 only and
rejects ML-DSA, SLH-DSA and Falcon requests instead of substituting a classical signature.
