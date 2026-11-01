# RFC 0005: Native proof sessions, independent batch policy and durable reservations

Status: software implementation; signing remains disabled. S1 acceptance is still
conditional on deployment-specific proofs, native evidence and independent review.

## Trust boundary

The business host supplies transaction bytes. A separate operator provisions:

- The native `tos-proof-verify` executable and its exact SHA-256.
- A zerostate/key-block anchor, independently established full block identity and
  the anchor-to-network-global-ID mapping. RPC JSON never chooses these values.
- The wallet/Vault addresses and code hashes, policy, maximum state age, trusted
  clock, native-state paths, journal path and independently retained journal tip.

These inputs belong on the independent approval system. Providing them all from
the compromised business host would collapse the intended trust separation.

`ProofVerifier` executes the pinned native verifier on raw material for each account.
It checks exit status/interface, echoed anchor/request digest/mode, full target
root/file/height, account identity, active status and pinned code. Live requests
require an explicitly enrolled persistent native state file and bound both target
and account-shard time. Missing state is a recovery error, not a new enrollment.
The native core verifies finality signatures, source validator/session derivation,
state/account proofs and live descent/rollback. A historical result is never fresh.

Native output is bounded to 2 MiB; unused BOCs/stacks are discarded before the
small strict metadata view is validated. Account-data BOCs are separately bounded
to 128 KiB, 1024 cells/depth 96 and must hash exactly to the proven data hash.
The native verifier remains part of the trusted software base. This adapter is
not an independent implementation of PQ consensus or proof verification.

## State and policy appraisal

The batch API reparses exact wallet bytes. It binds highload key/subwallet/timeout
and replay bitmaps, or cold multisig members/quorum/sequence, to proven data. Signed
forms verify actual ML-DSA signatures with those keys. It decodes Vault roles,
epoch/nonces, pending intents, asset registry and window/cumulative budgets.

All accounts must be fresh at the same complete masterchain target. Independent
policy additionally constrains role, operation, recipient, per-payment/aggregate
limits, Token attachments and wallet control value. Wallet balance/fee reserve is
separate from treasury asset amounts. A fee reserve is not a measured maximum fee.

Supported batches contain at most one action per Vault, across at most 16 Vaults.
This conservative profile avoids guessing sequential pending-state effects in one
Vault. Unsupported state size/action patterns reject. All nine Vault entry points
are checked, including exact pending approvals, pause/veto role rules, expiry and
the 48-hour governance delay. Schedule/apply need an independently allowlisted
Vault request hash. Cold membership/quorum changes need the exact independently
allowlisted quorum **signing preimage**, including account/network/seqno/purpose.
The existing single-payment diagnostic shortcut is not used.

## Durable reservations and lifecycle

`Journal.create` is explicit and exclusive. Reopening never creates a missing DB.
SQLite `BEGIN IMMEDIATE` and `synchronous=FULL` serialize reservations and persist
events. Every mutation compares an externally retained `{revision,digest}` with
the verified event hash chain. A restored old DB or modified event is refused when
the operator retains the newer tip independently. Losing/rolling back both copies
is outside this protection; this is not a hardware monotonic counter.

Reservations bind intent, wallet replay slot, policy digest, code hash, complete
block identity and each asset charge. Duplicate intent/active highload query IDs,
reused multisig seqnos, stale appraisal/proofs, lower targets, same-height forks,
changed wallet code and over-reservation reject atomically. The validity bound is
the earliest policy/proof/request expiry. Failed transactions do not consume slots.

No timer, restart, request timeout, seqno advancement or host receipt releases
treasury reservations. Reservations remain conservative even if this double-counts
an already settled debit. Reconciliation/release requires a separate proven
downstream settlement design; no unsafe release shortcut is implemented.
The bounded journal holds 10,000 events; reaching it requires a reviewed migration.

Freezing, deletion or redeployment must quarantine the wallet. The journal offers
an explicit operator quarantine event with no automatic reset. An inactive account
proof already fails appraisal. Automatic ingestion of authenticated inactivity and
operational recovery remain acceptance work. A regenerated StateInit may reset
on-chain replay state, so the durable journal must not be discarded with the wallet.

## Local API and CLI

```sh
PYTHONPATH=src python3 -m tos_custody init-proof-state native-state.json --anchor anchor.json
PYTHONPATH=src python3 -m tos_custody init-journal reservations.db --policy batch-policy.json
PYTHONPATH=src python3 -m tos_custody appraise-batch request.boc \
  --policy batch-policy.json --session proof-session.json --now TRUSTED_UNIX_TIME \
  --journal reservations.db --checkpoint independent-checkpoint.json
```

Keep the returned new journal checkpoint on independent storage before relying on
the reservation. A crash between DB commit and checkpoint retention requires
explicit recovery; it never silently retries as an unused intent. Signed forms
add `--form submission` or `relay` and `--openssl /absolute/path/to/openssl`.
Policy/session files are operator inputs, not fields in a host offline bundle.

The session schema is `tos.custody.proof-session.v1` with `verifier`,
`verifier_sha256`, `anchor`, `target` and exactly the configured `accounts`.
Each account maps to local `data`, raw proof `material` directory and `native_state`
paths. Policy fields are defined strictly by `batch.validate_policy`; unknown fields
reject. Test builders illustrate synthetic policies without implying deployment.

Appraisal/reservation results keep `signing_authorized=false`. There is no signer,
submission service, new production trust anchor or deployment in this increment.

## Acceptance evidence

Unit tests use explicitly synthetic proof-boundary doubles to exercise rejection
and reservation semantics. `check_state_proofs.py` separately invokes the real
native verifier on saved development-network PQ finality/account proofs, with
wrong anchor/account/full target/code and malformed-carrier controls. Its positive
account is historical elector state: it proves the adapter boundary, not a fresh
custody deployment. Do not mark that as live Vault/wallet proof acceptance.

`check_native_custody.py` adds restart/frozen/deleted/redeployment and real PQ pauser
scenarios. Frozen/deleted states are explicit lifecycle snapshots; they do not
simulate years of storage debt. Initial attempts and toolchain issues are retained
in the setup ledger. Exact-source native build evidence is distinguished from
hermetic dependency/firmware reproducibility, which remains outstanding.
