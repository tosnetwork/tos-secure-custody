# TOS integration contract

## Pinned baseline

Use `def735f3ad9c57a4b8fc8de43537075baec2271a` for initial wire comparison.
Read `doc/treasury-vault-v1.md`, `test/treasury-vault/wire.py` and the contract itself from that commit.
Pinned source locations and observed blob identifiers are in `UPSTREAM_BASELINE.json`.
Moving to another TOS revision requires new differential vectors and compatibility review.

## Vault constraints that the custody project must preserve

Business proposes and a distinct Guardian approves the same domain-bound request. The Vault uses
VM-authenticated internal senders; a serialized source address in an unexecuted message is not proof
of authority. Vault V1 itself owns no signing key and does not verify a new hardware-attestation signature.

Payment and management domains and counters differ. Requests bind the network global ID, exact Vault,
policy epoch, nonce, deadline and payload cell. Native asset ID is zero; a Token ID is the nonzero
workchain-0 master-address hash. The source Token wallet is independently verified in the cold-managed
registry. Do not trust a display symbol or substitute the source wallet for the Token master.

Native payments have no arbitrary application body or Token attachment. Token payments use the
supported transfer format, no custom payload, zero forwarded application value and the Vault as
excess-return destination. The Guardian funds control fees and Token attachments; the role wallet's
own exposure requires separate limits and must be included in the hardware review screen.

Budgets include a per-payment ceiling, a fixed 24-hour window and a non-resetting cumulative ceiling.
A fixed window is not a strict sliding-24-hour guarantee. Dispatch consumes budget; bounces must not
automatically refund it. V1 has one pending payment, one pending management request and at most 16 assets.

Cold management waits the immutable 48-hour delay. It can rotate hot roles and adjust supported
policies, not replace the cold-administrator address or execute an arbitrary asset sweep. Key rotation
inside the cold multisig is a separate verified account operation. Guardian/pauser self-replacement
veto rules and the bounded additional pause delay must remain unchanged.

The pinned documentation requires post-quantum accounts for all four production roles and a
post-quantum cold multisig, with TVM global version 16 or later. A classical-only hardware adapter is
therefore a development/protocol target, not a production substitute for these requirements.

## Parser coverage

Implemented: all nine Vault control opcodes; payment and three management payload kinds; strict
workchain-0 addresses; exact consumption of bits and references; ordinary BOC structure; and the
supported internal-message wrapper including source, destination, value, fees, flags and timestamps.

Also implemented: a deliberately bounded PQ highload profile for unsigned Requests, submission
bodies and relayed internal messages; exact signing message/context; all supported send actions in
execution order; and canonical signature-container shape checks. See
[RFC 0003](rfcs/0003-pq-highload-inspection.md) for the restrictions and unsigned relay fields.
This wallet has no external-message handler. Shape checks are not signature verification.

Not implemented: PQ cold multisig and other wallet profiles, cryptographic wallet authentication,
code/state/finality proofs, account-lifecycle replay analysis and actual native VM execution.
These missing pieces prohibit signatures. Unknown cell types and all StateInit are refused.
The existing Vault-only inspector and new highload inspector are separate explicit profiles.

## Integration acceptance

Build the pinned TOS toolchain in a separate controlled checkout. Generate requests using TOS's
native builders; compare complete decoded fields and hashes with this independently written parser.
Exercise real PQ business, Guardian, pauser and cold wallets, deliver each emitted message unchanged,
and verify actual outgoing Vault actions and downstream Token settlement. Include negative raw
messages that a friendly builder would never produce. Retest on the exact release candidate.

The upstream repository's earlier test results are not evidence that this new project passed its own
integration tests. No native or hardware acceptance was run during bootstrap preparation.
