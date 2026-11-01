# RFC 0001: Exact-byte transaction intent and supported signing profiles

Status: draft; the production signing profile is not implemented.

## Principles

Transport a bounded original BOC, never only a host-selected digest or human-readable summary.
The trusted device must independently derive the supported transaction semantics and the exact
wallet-specific preimage. A schema version is not permission to ignore unknown fields.

The bootstrap offline schema is deliberately inspection-only:

```json
{"schema":"tos.custody.offline-inspection.v1","boc_hex":"<lowercase hex of an internal-message BOC>"}
```

No `display`, `approved`, `seed`, `private_key`, host-supplied token decimals or algorithm negotiation
fields are accepted. Its TCJ-1 encoding is bounded printable-ASCII JSON with sorted keys, integers only,
no duplicate fields, no Unicode controls and no floating-point values. It is not RFC 8785 and must
never be treated as the signed TOS wire format.

## Production intent requirements

A future version must bind the network global ID; exact role-wallet and Vault addresses; supported
code hashes and state-proof/finality anchor; role and operation; policy epoch; wallet replay state;
Vault nonce and expiry; asset master and registered source wallet; recipient; amount; attachments;
all action modes and fee exposure; the original BOC hash; the relevant cell hashes; and the
wallet-specific algorithm/context/preimage definition. Bind the intended device's custody key ID.

Do not duplicate authoritative values into an unsigned summary and later sign a different source.
The display and preimage must be derived from one immutable parsed structure inside the trusted
boundary. Bind state to the transaction and reject stale or unauthenticated observations.

The device must reject unsupported wallet versions, unknown actions, unparsed refs/bits, arbitrary
calls, StateInit/deployment, extensions, code replacement, hidden asset movement and unknown token
implementations. Recovery/administration requires a distinct supported profile, not a payment override.

## Display and approval

Show full canonical addresses or a verified address book with a way to inspect the full address.
Show integer base units and the exact asset identifier. Decimal presentation is supplementary and
requires independently verified metadata. Never rely on a host-provided Token symbol. Show the
business/Guardian role, request hash, freshness and total role-wallet fee/attachment exposure.

Bind physical confirmation to the immutable request instance. Replacing any byte, state anchor,
policy revision, key, network, recipient or amount invalidates the approval. Timeout, cancellation,
device restart or detached display must invalidate pending approval. A host Boolean is never enough.

## Hash semantics

For ordinary cells, the representation hash commits to descriptors, padded data, child depths and
child hashes, not to arbitrary BOC serialization order or a JSON digest. The Vault compares its request
cell hash. The role wallet may authenticate a different enclosing object. The exact wallet source and
native tests define that convention; no guessed prehash or context is allowed.

Acceptance requires native positive/negative vectors and malicious A-on-screen/B-in-signature tests.
The bootstrap refuses all production signatures until those layers exist.
