# RFC 0004: inspection-only cold post-quantum multisig profile

Status: reference implementation, not authorization. Depends on RFC 0003. Baseline:
`tosnetwork/tos@def735f3ad9c57a4b8fc8de43537075baec2271a`.
Normative wire references are `pq-multisig-code.fc`, `pq-quorum-signatures.fc` and
`pq-bytes.fc`; exact observed blob IDs are recorded in `UPSTREAM_BASELINE.json`.

## Critical distinction: Request is not the signing preimage

The internally relayed account has no external-message handler:

```text
submit#504d5353 relayer_query_id:uint64 request:^Request
                signatures:(HashmapE 256 ^StoredSignature)
Request = kind:uint8 valid_until:uint32 payload:^Cell
```

The Request DOES NOT encode the network, account or sequence number. The account
constructs a different cell and signs its 32-byte representation hash:

```text
global_id:int32 domain:uint32 account:MsgAddressInt
seqno:uint64 valid_until:uint32 payload:^Cell
```

Domain is `0x504d5331` for execute and `0x504d5332` for configure. ML-DSA-44 context is
`TOS-PQ-QUORUM-v1`. Expiry is inclusive: the account refuses `now > valid_until`.
This inspector does NOT check current time or chain freshness. The sequence value
`2^64-1` cannot authorize another request. The Request hash, BOC digest, and off-chain
JSON digest MUST NOT be substituted for the quorum signing hash.

Inspection requires explicit `network_global_id`, canonical workchain-0 `account`,
and `seqno`. These are marked **caller-supplied-untrusted**. Optional account-data
comparisons never promote them to trusted state. A future signing pipeline must
obtain finalized network/account/code/state evidence independently of the business
host. A relay's destination is compared with the contextual account, not trusted as
an authenticated identity. Relay source/value/query ID remain outside the signature.

## Supported operations

Execute inspects every send in actual oldest-first execution order. It reuses the
narrow RFC 0003 Vault-only profile: 1..16 fixed-value sends, modes 0..3, no StateInit,
extra currencies, claimed outbound sender, unknown actions or trailing content.
The chain supports additional modes; this custody profile deliberately rejects them.
The wallet forces +2, so sends are best effort and sequence advancement is NOT proof
that any downstream Vault or Token action succeeded. This inspector does not enforce
cold-role-specific Vault permissions; only authenticated state and native execution
can establish those. Parsing a known payment opcode is not permission for cold to pay.

Configure supports exactly add member, remove member, and change quorum. These are
**immediate account changes authorized by the PRE-CHANGE quorum**, unlike the Vault's
separate delayed governance. Display the old/new member count and threshold when
supplied account data is available. Reject unknown changes and all trailing fields.
Without account data, only shape and intrinsic bounds can be checked.

## Keys, dictionaries and diagnostic state comparisons

Account data: `verifiers:(HashmapE 256 ^StoredKey) count:uint8 quorum:uint8 seqno:uint64`.
Re-derive every key ID, require 1..64 members, count equality and
`1 <= quorum <= min(count, 12)`. Each leaf must contain exactly one reference.
Hashmap short/long/same labels are accepted with complete consumption, bounded label
length and bounded logical traversal (including repeated references to shared cells).
Do not require one particular legal label representation.

Stored ML-DSA-44 keys contain 1312 bytes; stored signatures contain 2420 bytes.
Each wrapper is `len:uint32 ^chain`, with byte-aligned 127-byte chunks, exactly one
continuation except at the last chunk, and no empty or hidden tail.

Key ID is SHA-256 over `TOS-PQ-CONSENSUS-KEY-v1 || 01 00 || public_key_bytes`.
The algorithm number here is little-endian uint16. Filing the same key under another
ID is rejected; two labels cannot turn one key into two independent members.

Submission dictionaries require 1..12 structurally valid entries. With supplied state,
require exactly the OLD quorum entries and membership in that OLD set. A threshold
reduction must not authenticate itself with its proposed smaller quorum. For changes,
reject duplicate/full additions, unknown removals, removals leaving fewer members than
the current threshold, and a proposed threshold greater than the supplied member count.
These are comparisons with untrusted bytes, not evidence of genuine signatures.

All results retain `signing_authorized=false`, `cryptographically_verified=false`,
`state_authenticated=false`, `freshness_checked=false` and `replay_checked=false`.
The production signer and hardware-attestation verifier remain disabled.

## Resource bounds and transport

The multisig profile opts into at most 1024 cells and depth 96, needed for full
64-key/12-signature structures and skewed bounded dictionaries. Other BOC callers
retain 256 cells/depth 32. Absolute configurable ceilings are 1024/96; all profiles
retain the 131072-byte input bound and reject exotic/stored-hash/higher-level cells.
A state or submission beyond a bound is refused, not partially inspected.

Offline schema `tos.custody.offline-multisig-inspection.v1` contains only `schema`,
`form`, `context`, and lowercase `boc_hex`. The existing 131072-byte JSON and
60000-byte BOC-in-JSON limits remain: use separate bounded binary files to inspect
large state/signature sets. Optional state is accepted only by the direct API/CLI,
not smuggled through bundle metadata. No host-provided display/approval labels are
accepted. The single-payment diagnostic policy cannot evaluate a wallet batch.

```sh
PYTHONPATH=src python3 -m tos_custody inspect-bundle examples/pq-cold-quorum.offline.json
PYTHONPATH=src python3 -m tos_custody inspect-multisig request.boc \
  --context context.json --state account-data.boc --form request
PYTHONPATH=src python3 -m tos_custody inspect-multisig-state account-data.boc
python3 scripts/check_upstream_multisig.py --cells /path/to/pinned/tos/test/auth-extensions/cells.py
```

## Evidence boundary

Five frozen vectors and a 12-of-64 structural comparison are independently generated
using the whole-blob-pinned upstream Python codec (checked BEFORE execution). No
upstream implementation is vendored. The reference suite checks malformed labels,
DAG expansion, truncated/key/signature tails, wrong network/account/sequence/domain,
old-quorum enforcement, ordered actions, loss-of-quorum changes and safe CLI rejection.
Targeted guard-removal controls must fail by assertion, not by a setup/import error.

These are software/codec results, not native TVM conformance, ML-DSA verification,
hardware protection, state finality, key independence, physical approval or audit.
RFC 0004 does not close S1 or authorize deployment, funding or a membership change.
