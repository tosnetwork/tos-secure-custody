# Threat model

## Protected assets

Treasury funds; business/Guardian/cold/pauser keys and authority; policy versions; immutable code and
role identities; signing intent; firmware supply chain; device endorsement and revocation records;
operator availability; and auditable settlement records.

## Adversaries and required defenses

| Adversary | Assumed capability | Required defense |
|---|---|---|
| Compromised business host | Root, stolen CI credentials, altered withdrawals and UI | Independent Guardian intent source; exact parsing; Vault dual authorization |
| Malicious RPC/indexer | False balances, code, state, network and finality | Locally anchored light-client/state proof verification; never trust one unsigned response |
| Deceptive transaction builder | Amount/address substitution, hidden actions, StateInit, send modes | Full nested decoding and consumption; supported-profile allowlist |
| Stolen HSM operator credentials | Invoke signing without extracting the private key | Trusted policy boundary, isolated credentials, separate payment authority and on-chain caps |
| Insider or colluding approver | One compromised role, malicious policy change | Independent cold quorum; role separation; delayed governance; immediate limited pause |
| Supply-chain attacker | Replace dependencies, firmware or release artifacts | Pinned inputs, reproducible artifacts, independent builders, reviewed firmware measurements |
| Attestation replay/proxy attacker | Replay old quotes or borrow evidence from another device | Fresh challenge, custody-key and request binding, audience binding, endorsement validation |
| Physical attacker | Debug probes, chip replacement, voltage/clock/laser faults, side channels | Explicit physical threat class, secure boundary, independent laboratory qualification |
| Recovery attacker | Restore old backup, reset replay counters or weaken quorum | Durable monotonic state, approved recovery ceremony, no hidden sweep or downgrade |
| Availability attacker | Refuse signatures, pause repeatedly, exhaust inputs | Bounded parser/queues, independent pauser, tested delayed role recovery and reserves |

## Limits and exclusions

No prevention claim covers compromise of all necessary approvers, the final cold quorum, the supported
asset's own malicious implementation, broken cryptographic assumptions or malicious chain consensus.
Physical protection depends on a measured threat class, not on open-source status. Availability may
be lost even when funds remain safe. A malicious hot role may cause pauses; recovery must preserve
the verified Vault's governance constraints rather than introduce a bypass.

Attestation cannot prove a human intended the payment, establish token economics, prove a device has
no hardware implant, or repair a malicious but correctly signed firmware release. Two branded devices
are not independent if they share compromised provisioning, administrator credentials or intent input.

## Bootstrap-specific risks

The Python core is a reference and not a constant-time embedded firmware implementation. Its
attestation state is process-local, and its policy comparison does not authenticate chain state or
track durable cumulative spending. The NetHSM transport is unqualified and classical-only. There is
no native execution evidence for this new project. These are explicit release blockers, not hidden
assumptions. The no-signing gate prevents the CLI from advertising those incomplete checks as approval.
