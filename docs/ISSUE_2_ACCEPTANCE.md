# Issue #2 progress and remaining acceptance

The original S1 issue is broader than a parser, a valid signature or local VM tests.
Do not close it solely because this implementation increment passes software checks.

| Required item | Implementation/evidence | Remaining acceptance |
|---|---|---|
| Cold PQ multisig inspection | RFC 0004 and prior merged tests | Already delivered; review any new policy behavior |
| Finality/code/account state and freshness | RFC 0005 native-verifier session, pinned anchor/executable/full target, code/data binding; seven real historical proof/tamper checks | Independently provision an actual custody network anchor and code profiles; obtain and verify fresh wallet/Vault proofs together, including registry/budget state |
| Independent batch policy/roles | Separate strict operator policy; all nine Vault operations, exact governance intents and cold configuration preimages; distinct wallet and treasury limits | Deployment-specific limits and operational approval distribution; not arbitrary host policy |
| Pinned native toolchain and real wallet/Vault execution | Pinned source `def735f3ad9c57a4b8fc8de43537075baec2271a`; fresh func/fift/tol/emulator/proof-verifier build; 65 upstream + seven integrated + three lifecycle/pauser scenarios | Independently reproduce/accept the candidate; toolchain/dependency closure remains separate |
| Lifecycle replay | Serialized restart keeps bitmap; frozen/deleted/uninitialized snapshots skip; explicit StateInit redeployment demonstrates replay reset; journal survives restart/quarantine and protects reserved intents | Proven automatic inactivity ingestion, migration/recovery and downstream settlement reconciliation; freezing snapshots do not simulate every storage-debt transition |
| Mutation/CI/non-author review | Expanded guard-removal controls and exact-head CI are part of this PR | Independent non-author review and findings disposition still required |

The real proof fixture is a historical development-network **elector**, not a
deployed custody wallet or Vault. The native wallet/Vault scenarios use the real
executor and fresh compiled contracts but a synthetic test account environment.
These are two complementary evidence sources; they are not one live custody proof.

The software APIs needed to connect those boundaries are implemented. Closing the
deployment-specific gate requires independently chosen network/anchor/code inputs
and proof material for the actual custody accounts; it cannot be obtained by
marking synthetic state as authenticated or choosing a production anchor silently.

Production signing and hardware authorization remain disabled. Offline hardware,
protected PQ keys, attestation/firmware qualification and funding remain separate.
