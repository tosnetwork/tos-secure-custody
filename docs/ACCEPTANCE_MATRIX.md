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
| A19 | Remove a security guard | Named baseline passes; named assertion fails after mutation | REF mutation controls, including ML-DSA backend/context guards |
| A20 | Different source paths/mtimes | Identical source TAR bytes | REF source packaging only |
| A21 | Business host root + business key abuse | Guardian and Vault prevent unilateral treasury payout | NATIVE role-separation scenarios passed locally; host compromise/HIL outstanding |
| A22 | Real PQ role-wallet request and cold quorum | Exact signed messages execute; insufficient quorum fails | NATIVE pinned local wallet/cold suites passed; HIL outstanding |
| A23 | Malicious RPC state/finality and code substitution | Independent proof verification rejects | Native proof adapter and genuine historical proof/tamper controls pass; fresh custody deployment acceptance open |
| A24 | Device shows A but signs B | Hardware confirmation cannot authorize substituted preimage | HIL NOT RUN |
| A25 | Policy/check/sign TOCTOU and process restart | Approval invalidated or exact state/intent preserved | REF bound appraisal + atomic journal/expiry/restart tests; NATIVE restart probe; full signing/HIL outstanding |
| A26 | Token bounce/receipt/retry amplification | No unauthorized budget restoration or duplicate payout | NATIVE Vault suite and real Token transfer passed locally; complete operational acceptance outstanding |
| A27 | Compromised hot role blocks recovery | Exact cold/pauser rules and delay preserved | NATIVE delay/pause/recovery scenarios passed locally; HIL outstanding |
| A28 | Device loss and backup/restore rollback | Recovery maintains quorum, replay state and cold authority | HIL NOT RUN |
| A29 | Malicious update/unsigned firmware/rollback | Device rejects or verifier blocks it | HIL NOT RUN |
| A30 | Side-channel/fault-injection/debug/chip substitution | Meets declared physical threat class | LAB NOT RUN |
| A31 | Concurrent institutional spending and outages | Durable limits/idempotency and bounded availability | REF SQLite atomic reservations, concurrency and independent-checkpoint recovery guards; live operational/HIL acceptance open |
| A32 | Reproduce actual firmware independently | Exact binary match and running measurement verification | NOT IMPLEMENTED |

## Additional S1 reference coverage

| ID | Scenario | Required observation | Current evidence |
|---|---|---|---|
| A33 | Highload request hash vs BOC/JSON hash | Exact request hash and context; no signing authorization | REF `test_highload`; two pinned upstream Python-codec vectors |
| A34 | Hidden action, reordered batch or balance-sweep mode | Inspect every action in execution order; reject unsupported modes/actions | REF `test_highload`; targeted mutations |
| A35 | Wallet/Vault network or destination substitution | Reject mismatched nested binding and relayed wallet target | REF `test_highload`; targeted mutations |
| A36 | Malformed PQ signature or forged "verified" label | Inspection checks shape; separate verification requires valid signatures; reject host labels | REF plus real OpenSSL vectors; local NATIVE; HIL outstanding |
| A37 | Documentation PNG breaks source packaging | Include image bytes/hash; retain unknown-type and symlink rejection | REF `test_source_bundle`; full source reproducibility check |

## Required acceptance record

Record source commit/digest, exact commands, toolchain versions, device model/revision/firmware,
public key IDs (never secrets), policy/code/role configuration, attack transcript, expected and actual
outcome, test count including skips, and independent reviewer identity. Preserve failed runs too.
A missing native tool/device must be a blocked test, not an invisible skip or a fabricated success.

The checked-in unit reports record REF tests. The separate native-conformance report records
the native suites actually executed locally and fingerprints the existing compiler/emulator artifacts.
An upstream project's historical results are not counted as this project's acceptance evidence.

## S1b cold multisig reference additions

| Scenario | Evidence level | Current reference coverage |
|---|---|---|
| Context versus Request/signing hash; purpose domain | REF | Distinct hash and network/account/seqno/expiry mutation tests |
| Full member set, key identities, dictionary labels | REF | 64 keys, stored-count mismatch, aliases, label/tail/DAG bounds |
| Old quorum for membership change | REF | Proposed lower threshold cannot approve itself; exact signature count/membership |
| Member loss and quorum bounds | REF | Duplicate/full addition, unknown removal, removal below threshold, invalid quorum |
| Cold request/submission/internal relay | REF | Ordered fixed-value actions; target/shape/tail rejection; no auth claim |
| Independent upstream Python codec | CODEC | Five frozen vectors and 12-of-64 structural comparison; NOT native TVM |

These inspection additions alone do not satisfy authenticated state, signature verification,
native execution, hardware or external-review acceptance gates. The later local verification
increment adds separate cryptographic/native evidence; see [local acceptance](LOCAL_ACCEPTANCE.md).
