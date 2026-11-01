# Institutional adversarial acceptance matrix

**Evidence levels:** REF = executable local software test; NATIVE = actual TOS wallet/contract execution;
HIL = actual hardware-in-the-loop; LAB = independent physical-security assessment.
REF success never substitutes for NATIVE, HIL or LAB evidence.

| ID | Scenario | Required observation | Current evidence |
|---|---|---|---|
| A01 | Host substitutes recipient/amount | Diagnostic rejection; no production signature | REF `test_policy_offline` |
| A02 | Wrong chain, Vault, epoch or nonce | Reject exact mismatch | REF `test_policy_offline`, `test_vault` |
| A03 | Stale/oversized deadline or stale policy | Reject | REF `test_policy_offline` |
| A04 | Host-supplied display/approval/secret field | Reject unknown transport fields | REF `test_policy_offline` |
| A05 | Unknown opcode, payload or trailing refs/bits | Reject; no opaque signing fallback | REF `test_vault` |
| A06 | StateInit, external wallet or unsupported cell | Reject unsupported profile | REF `test_vault`, `test_boc` |
| A07 | Malformed BOC graph, size, index or CRC | Bounded controlled rejection | REF `test_boc` |
| A08 | Seeded malformed parser input | No uncontrolled exception or authorization | REF 2,000 inputs inside one test; not a fuzzing completeness claim |
| A09 | Zero/native-attachment/invalid-Token payment | Reject invalid typed payload | REF `test_vault` |
| A10 | Unexpected role or excess role-wallet value | Reject diagnostic policy mismatch | REF `test_policy_offline`; source fields alone are not authentication |
| A11 | Algorithm downgrade or unimplemented PKCS#11 | Reject before fallback; never software-substitute | REF `test_adapters` |
| A12 | HSM signature uses wrong key or message | Local verification rejects | REF mocked transport `test_adapters`; HIL outstanding |
| A13 | Redirect, response overflow or TLS downgrade | No redirect; bounded reply; mandatory TLS verification settings | REF `test_adapters`; real TLS/device tests outstanding |
| A14 | Evidence replay including concurrent attempts | Only one fixture challenge consumption | REF `test_attestation`; durable HIL evidence outstanding |
| A15 | Wrong device/key/intent/policy/audience | Fixture verification rejects | REF `test_attestation` |
| A16 | Stale evidence, revoked device or rollback | Fixture verification rejects | REF `test_attestation`; real hardware provenance outstanding |
| A17 | Debug enabled, insecure boot or unknown firmware | Reject signed fixture claims | REF `test_attestation`; does not prove hardware state |
| A18 | Attempt to turn inspection into signing | Offline production API refuses | REF `test_policy_offline` |
| A19 | Remove a security guard | Named baseline passes; named assertion fails after mutation | REF nine sensitivity controls |
| A20 | Different source paths/mtimes | Identical source TAR bytes | REF source packaging only |
| A21 | Business host root + business key abuse | Guardian and Vault prevent unilateral treasury payout | NATIVE + HIL NOT RUN |
| A22 | Real PQ role-wallet request and cold quorum | Exact signed messages execute; insufficient quorum fails | NATIVE + HIL NOT RUN |
| A23 | Malicious RPC state/finality and code substitution | Independent proof verification rejects | NATIVE NOT IMPLEMENTED |
| A24 | Device shows A but signs B | Hardware confirmation cannot authorize substituted preimage | HIL NOT RUN |
| A25 | Policy/check/sign TOCTOU and process restart | Approval invalidated or exact state/intent preserved | NATIVE + HIL NOT RUN |
| A26 | Token bounce/receipt/retry amplification | No unauthorized budget restoration or duplicate payout | NATIVE NOT RUN for this project |
| A27 | Compromised hot role blocks recovery | Exact cold/pauser rules and delay preserved | NATIVE + HIL NOT RUN |
| A28 | Device loss and backup/restore rollback | Recovery maintains quorum, replay state and cold authority | HIL NOT RUN |
| A29 | Malicious update/unsigned firmware/rollback | Device rejects or verifier blocks it | HIL NOT RUN |
| A30 | Side-channel/fault-injection/debug/chip substitution | Meets declared physical threat class | LAB NOT RUN |
| A31 | Concurrent institutional spending and outages | Durable limits/idempotency and bounded availability | NATIVE + HIL NOT IMPLEMENTED |
| A32 | Reproduce actual firmware independently | Exact binary match and running measurement verification | NOT IMPLEMENTED |

## Required acceptance record

Record source commit/digest, exact commands, toolchain versions, device model/revision/firmware,
public key IDs (never secrets), policy/code/role configuration, attack transcript, expected and actual
outcome, test count including skips, and independent reviewer identity. Preserve failed runs too.
A missing native tool/device must be a blocked test, not an invisible skip or a fabricated success.

The checked-in local reports record only executed REF tests. An upstream project's historical test
counts and results are not counted as this project's acceptance evidence.
