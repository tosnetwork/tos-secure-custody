# Workstream 3: Complete wallet-to-Vault transaction parsing

## Objective

Decode every value that can affect authorization or asset movement before signing, including the
actual external role-wallet envelope and nested actions. Complete parsing is mandatory within each
explicitly supported profile; unsupported profiles are rejected.

## Current baseline

The reference parser consumes the supported ordinary BOC, internal-message envelope and all nine
pinned Vault V1 entry points, including payment and three management payload kinds. External wallet
formats, exact signing preimages, state proofs and native differential execution are not implemented.

## Implementation tasks

- [ ] Pin exact production business/Guardian/pauser and cold-multisig code profiles and suites.
- [ ] Parse signed/unsigned external wallet envelopes, replay fields, signature containers and all actions.
- [ ] Derive the exact native signing preimage; distinguish JSON, BOC, cell and wallet commitments.
- [ ] Verify authenticated chain/finality/code/state evidence and current role/registry/epoch/counter bindings.
- [ ] Decode all supported native/Token transfers, amount units, master/source wallet, fees and attachments.
- [ ] Reject unknown actions, hidden references, StateInit, unsafe modes, arbitrary calls and trailing data.
- [ ] Bind the displayed intent to the immutable structure that creates the wallet signature.
- [ ] Generate differential fixtures from the pinned native TOS builders and emulator.
- [ ] Add fuzzing, parser differentials, resource bounds, canonical encodings and action-phase outcomes.

## Acceptance criteria

Every accepted request must have complete field equality and exact signing-hash equality with native
TOS execution. Byte mutations and hidden-action cases must either produce a fully decoded new intent
requiring new approval or be rejected. Include all four real PQ roles, native and Token settlement,
business/Guardian independence, cold quorum and replay/expiry/governance checks. No model-only test
may be described as native acceptance. Enabling signing before this gate passes is prohibited.
