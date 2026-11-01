# RFC 0003: PQ highload exact-byte inspection (S1 increment)

Status: implemented reference inspection; **not authorization and not completion of S1**.
The compatibility baseline is `def735f3ad9c57a4b8fc8de43537075baec2271a` in `tosnetwork/tos`.
Source paths and blob identities are recorded in `../UPSTREAM_BASELINE.json`.

## Why this boundary matters

Decoding a Vault payment body alone does not show everything the role wallet will authorize.
The outer request also binds a wallet, network, subwallet, replay query, creation time, timeout
and an ordered list of outgoing messages. A correct first payment can hide a malicious second
operation. An off-chain manifest hash, BOC byte hash and wallet signing message are different.

The pinned PQ highload wallet has **no external-message handler**. A relayer submits an internal
message. Calling this an external-wallet transaction format would misdescribe the actual protocol.

## Implemented forms

| CLI form | Root cell | Structural checks |
|---|---|---|
| `request` | Unsigned Request | Complete header and every supported action |
| `submission` | `submit#50514857 query_id:uint64 ^Request ^StoredSignature` | Exact envelope, signature length/chain, Request |
| `relay` | Internal message to the role wallet | Full relay header/body; target equals signed wallet; submission checks |

`signing_message_hex` is exactly the 32-byte, big-endian Request representation hash.
`signing_context_ascii` is `TOS-PQ-HIGHLOAD-v1`; the intended primitive is ML-DSA-44.
This is the message and context passed to the wallet's PQ verification, not a claim about a
new hashing construction. BOC index/CRC transport changes do not change the signing message.

Relayer source/refund routing, relay value and relayer query ID are **not signed by the wallet key**.
They are explicitly labeled unsigned in the inspection. The wallet's effective send mode forces
`+2`: accepted requests do not guarantee atomic delivery or downstream Vault acceptance.

## Deliberately narrow custody profile

Accept 1..16 `send_msg` actions, in execution order, carrying only fully decoded Vault V1 bodies.
The chain wallet supports up to 254 actions; accepting fewer is a documented custody restriction.
Only modes 0..3 are accepted. In particular, the chain-valid `+128` balance sweep is rejected;
so are `+32`, `+64`, code changes, unknown actions and empty or over-limit batches.

Outgoing messages require `addr_none` source, canonical workchain-0 destinations, no extra
currencies, no StateInit, IHR disabled, no bounced flag, zero forwarding-fee/creation placeholders
and `extra_flags` in 0..3. At the pinned TVM version this is **extra_flags, not legacy ihr_fee**.
Referenced and inline bodies are consumed completely. Nested Vault network/address binding is
checked where the Vault schema contains those fields. Controls without their own Vault address
still have their destination bound by the signed action message.

Reserved replay bit 1023 and zero timeout are refused. The parser displays the expiry boundary
but does not claim the request is fresh or unused. No authenticated chain time, replay map,
wallet code/key/subwallet/timeout state, role mapping, registry or budget proof is implemented.

A submitted signature must have the canonical 2420-byte ML-DSA-44 stored shape (32-bit length,
127-byte continuation chunks and exact final chunk). **Shape checking is not verification.**
Even 2420 zero bytes may pass inspection and are never labeled a valid signature. No fallback
algorithm, software signing, signature submission or HSM invocation is introduced.

## Offline format and CLI

The original Vault-only offline schema remains unchanged. The new schema is:

```json
{"schema":"tos.custody.offline-highload-inspection.v1","form":"request","boc_hex":"..."}
```

Only these fields are accepted; host-supplied display labels, approvals, signature status or
precomputed signing hashes are rejected. `check-bundle` refuses this new profile rather than
applying a single-Vault-payment policy to a wallet batch. `OfflineSigner.sign()` remains disabled.

```sh
PYTHONPATH=src python3 -m tos_custody inspect-bundle examples/pq-highload.offline.json
PYTHONPATH=src python3 -m tos_custody inspect-highload request.boc --form request
PYTHONPATH=src python3 -m tos_custody inspect-highload relayed-message.boc --form relay
```

All example data are synthetic and contain no real signatures or secrets.

## Evidence and limits

`test_highload.py` covers preimage binding, ordering, all supported forms, malformed signatures,
truncation, hidden actions, mode abuse, cross-network/target mismatch, unsupported fields and
permanently false authorization flags. Targeted guard-removal controls exercise the new boundaries.

Two frozen vectors are generated using the **exact pinned upstream Python cell codec**, independently
of this project's cell implementation. Reproduce them with a separately obtained TOS source file:

```sh
python3 scripts/check_upstream_highload.py --cells /path/to/tos/test/auth-extensions/cells.py
```

The script checks the entire upstream Git blob before executing that codec. This validates byte/hash
compatibility with the Python reference only. It does not compile or execute a TOS contract, prove
ML-DSA correctness, verify a real signature or qualify hardware. The upstream codec is not vendored.

Remaining S1 gates: PQ cold multisig request/membership/quorum inspection; native differential and
real role-wallet-to-Vault execution; authenticated code/state/finality and account-lifecycle replay
validation; trusted batch-policy/role evaluation. Hardware, durable attestation, physical confirmation,
independent review and funding gates remain unchanged and blocked.
