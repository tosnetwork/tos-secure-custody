# Delivery roadmap

Stages are evidence gates, not promised dates.

| Stage | Outcome | Exit evidence |
|---|---|---|
| S0: foundation | English charter/specifications, parser reference, protocol adapters, software attacks and source packaging | Local software results with accurate blocked-capability status |
| S1: exact-byte integration | Full supported external wallet/action/preimage decoding plus authenticated state/finality | Native differential vectors and real wallet-to-Vault positive/negative execution |
| S2: hardware custody | Qualified PQ HSM boundary and offline display/confirmation prototype | Real-device key generation/signing, native PQ verification and malicious-host tests |
| S3: verifiable devices/releases | Hardware evidence appraisal, persistent anti-replay, independently reproducible firmware | Actual evidence/revocation transcripts and two independent matching builds |
| S4: institutional acceptance | Full attack/recovery suite and external expert review | Signed exact-candidate acceptance record; deployment/funding ceremony |

S1 parsing, S2 hardware selection and S3 build/attestation design may proceed in parallel. No parallel
workstream may bypass a signing or deployment dependency. Completing a class/interface or passing a
software fixture is not the exit criterion for a hardware workstream.

Use the six issue-ready workstream files for implementation tasks. The project epic is the charter.
Closing any issue requires links to exact source hashes, commands, outputs, device/firmware identities,
and outstanding exceptions. Missing native or hardware tools block the corresponding acceptance.
