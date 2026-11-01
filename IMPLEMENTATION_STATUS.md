# Implementation status

Snapshot: 2026-11-01. Stage: **experimental, inspection-only**.

## Implemented and locally executable

- Strict TCJ-1 ASCII JSON with duplicate-key, size, depth and numeric bounds.
- Bounded ordinary level-zero BOC decoding, CRC32C and index checks, representation hashes,
  and rejection of hidden/trailing/unreachable/exotic data.
- All nine pinned Treasury Vault V1 control bodies, native/Token payment payloads,
  asset/role/unpause management payloads, and the supported internal-message envelope.
- PQ highload Vault-only request/submission/relay inspection, 1..16 fixed-value actions in execution order,
  exact 32-byte signing message/context, canonical signature shape (NOT cryptographic verification),
  and two frozen vectors reproduced with the pinned upstream Python codec. See RFC 0003.
- Cold PQ multisig request/submission/relay and 64-member account-data inspection, exact contextual
  quorum preimage, all three membership changes, old-quorum diagnostic comparisons and five frozen
  upstream-codec vectors plus a 12-of-64 structural comparison. NOT crypto/state verification; RFC 0004.
- An inspection-only CLI and offline format that reject host-supplied display labels and secret fields.
- Diagnostic payment appraisal against independently supplied policy inputs. It is not authentication.
- An experimental NetHSM Ed25519 adapter with TLS validation, pinned public-key verification,
  bounded responses, no redirects and no algorithm fallback. Only mocked transport was tested.
- A software-fixture attestation verifier using real Ed25519 verification, explicit fixture opt-in,
  binding checks, fresh challenges, process-local atomic replay protection and counter checks.
- Unit/adversarial tests, guard-removal sensitivity controls and deterministic source packaging.
- Optional OpenSSL 3.5+ Pure ML-DSA-44 verification of highload and cold multisig submissions/relays
  against supplied public keys/account data; key/state provenance remains unauthenticated.
- Pinned native wallet/Vault runner with parser preimage comparisons and independent OpenSSL verification.
  Local evidence covers 65 upstream tests, seven integrated and three lifecycle/pauser scenarios;
  the native tools are built from the pinned TOS checkout and fingerprinted.
- Public signature vectors with negative checks and a 13-case language-neutral parser corpus for firmware ports.
- Draft CI and local GitHub publication/issue scripts.
- Native proof-verifier adapter with operator-pinned executable/anchor/full target, live age checks,
  code/account/data-hash binding and explicit persistent-state enrollment. Genuine historical PQ
  account proofs are reverified locally; fresh custody deployment proofs remain outstanding.
- Independent batch policy for all nine supported Vault operations and allowlisted cold membership
  changes, with proven role/state binding, highload bitmap checks and separate wallet/treasury limits.
- Durable SQLite reservations, external hash-chain checkpoints, concurrent admission, code/target
  rollback rejection and sticky lifecycle quarantine. No automatic settlement-based release exists.

## Specified but not implemented or qualified

| Requirement | Status | Blocking reason |
|---|---|---|
| Full role-wallet transaction parsing | PARTIAL | Bounded highload/cold profiles and proof-backed appraisal exist; other profiles and deployment-specific acceptance remain |
| Authenticated state and finality | IMPLEMENTED ADAPTER / ACCEPTANCE OPEN | Native PQ proof core is integrated; real historical proof checks pass; fresh custody wallet/Vault material and trusted deployment anchor still required |
| Native custody end-to-end | PARTIAL / LOCAL | PQ wallet-to-Vault scenarios executed locally; full operational/Token/hardware acceptance remains outstanding |
| Physical NetHSM | NOT RUN | No device/credentials were available; no network request was made to an HSM |
| PKCS#11 | NOT IMPLEMENTED | Placeholder always raises `UnsupportedProfile` |
| PQ hardware signing | NOT IMPLEMENTED | No ML-DSA key generation/storage/signing inside a qualified hardware boundary |
| Offline signing firmware | NOT IMPLEMENTED | No board, firmware, display or button integration |
| Hardware attestation | NOT IMPLEMENTED | Production verifier always refuses; fixture claims are not hardware evidence |
| Durable approval/spend state | IMPLEMENTED CONSERVATIVE RESERVATIONS | Restart/concurrency/external-checkpoint rollback guards exist; proven settlement reconciliation and operational recovery remain |
| Durable hardware-attestation state | NOT IMPLEMENTED | Fixture challenge replay state is still process-local; no hardware monotonic counter or verified persistent attestation backend |
| Firmware/toolchain reproducibility | NOT IMPLEMENTED | Current reproducibility covers a fixed source snapshot only |
| Independent audit | NOT RUN | Local self-tests are not third-party approval |
| GitHub publication | PUBLISHED | The independent repository exists; changes require review before merge |
| GitHub Actions | REVISION-SPECIFIC | Consult the exact PR/commit checks; local reports are not remote CI approval |

## Non-negotiable boundary

`OfflineSigner.sign()` and `verify_hardware()` deliberately reject all requests. Do not remove these
gates merely to make a demo look complete. Replacing them requires implementing the missing boundary,
adding native and hardware tests, and obtaining an independent review of the exact source revision.

The inspection parsers do not verify signatures. Separate diagnostic verification entry points
verify ML-DSA against supplied keys; they do not authenticate a wallet, state, freshness or replay status.
Their offline schemas cannot enter the old single-payment diagnostic policy path. S1 is not complete.

`appraise-batch` obtains verdicts by executing the pinned native proof verifier, then binds
the wallet/Vault data hashes and independent policy. It accepts no host-supplied serialized
"verified" verdict. Historical evidence is never fresh. State-authentication flags in this
separate API do not enable signing. See RFC 0005 and the Issue #2 acceptance record.

The software fixture uses Ed25519 only for testing the attestation protocol. It does not implement,
emulate, or stand in for post-quantum hardware. The NetHSM prototype advertises Ed25519 only and
rejects ML-DSA, SLH-DSA and Falcon requests instead of substituting a classical signature.
