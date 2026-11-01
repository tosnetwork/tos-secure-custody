# Architecture and trust boundaries

## Components

The coordinator accepts business withdrawal proposals but is untrusted for transaction truth. It
may queue requests and observe settlement; it must never hold cold keys or HSM administrator credentials.

The signing boundary independently parses exact bytes. It derives display text and the signing
preimage from those same bytes, verifies the supported wallet/Vault code profile and authenticated
state, and evaluates a locally provisioned policy. No host-provided summary, token symbol, simulation
result or `approved: true` flag is an authorization input.

The business and Guardian signing devices are separately provisioned. The Guardian receives the
business intent through an independent channel and must not simply repeat an API response controlled
by the business host. Their authenticated TOS role wallets deliver the matching internal requests to
the existing Vault. The Vault is the final enforceable boundary for its supported rules.

The cold administrator is a separate post-quantum multisig account. Its address is immutable in
Vault V1; rotation occurs inside the verified cold account, not by replacing the Vault's cold root.
Emergency pausing cannot transfer funds. Device attestation informs whether to trust a device and
never substitutes for payment authorization or permits a bypass around on-chain governance.

## Data flow

1. Receive a bounded request containing exact transaction bytes and versioned evidence references.
2. Validate framing, schema, canonical encodings, cell resource bounds and the entire supported graph.
3. Parse the outer role wallet, every action and internal message, and the full Vault request.
4. Independently authenticate chain/network, finality, account code/state, role bindings and policy epoch.
5. Derive a typed intent and a wallet-specific signing plan. Match amounts, recipients, attachments,
   modes, fees, nonce, expiry and all nested targets. Reject every unknown or unconsumed field.
6. Evaluate locally provisioned limits and obtain confirmation on the trusted device display.
7. Verify current device eligibility and locally produce the exact approved wallet signature.
8. Reverify the returned signature against an independently pinned custody public key and exact bytes.
9. Broadcast through an untrusted transport. Confirm final execution and downstream settlement.

Steps 3-7 are not fully implemented in the bootstrap. No approved signing plan can currently be
created. Inspecting a valid body or completing diagnostic appraisal cannot unlock signing.

## Cryptographic separation

Maintain separate keys and domains for custody, device attestation, firmware release signing,
policy administration and operator authentication. Do not repurpose an attestation key as a treasury
key. Bind evidence to the custody key, exact request, verifier audience, challenge and policy version.

The following commitments are distinct: source/archive SHA-256, serialized BOC SHA-256, cell
representation hash, Vault request-cell hash, off-chain manifest hash, and role-wallet signing preimage.
A generic `sign(hash)` endpoint must not infer which one was intended. The final trusted component
must validate the wallet-specific signing plan rather than accept a host-selected digest.

Target ML-DSA-44 through the existing TOS account profile. Validate context/prehash conventions,
encodings and suite identifiers against that exact profile. Use ordinary independent signatures and
the existing on-chain multisig threshold; no new threshold-ML-DSA primitive is introduced here.

## Failure handling

Unknown suite, stale evidence, ambiguous parser output, unavailable state proof, missing native tools,
unsupported firmware, exhausted counters or uncertain signing outcome must fail closed. After an HSM
timeout, reconcile request identity before any retry; do not assume no signature was produced.
A failed or bounced downstream transfer does not justify restoring Vault budgets automatically.

A privileged signing-plane compromise remains a serious threat. HSM non-exportability alone does not
prevent malicious use of an authorized signing API. Independent devices and on-chain rules must remain
meaningful even when the coordinator and a low-level adapter are malicious.
