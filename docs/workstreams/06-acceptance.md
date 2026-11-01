# Workstream 6: Institutional attack, recovery and deployment acceptance

## Objective

Demonstrate the actual asset-protection boundary against compromised business hosts, malicious
transactions, credential theft, firmware substitution, evidence replay and operational recovery attacks.

## Current baseline

Executable software adversarial tests and nine guard-removal sensitivity controls exist. The attack
matrix distinguishes REF, NATIVE, HIL and LAB evidence. Native TOS custody integration, physical-device
attacks, firmware reproduction and independent audit have not run for this project.

## Implementation tasks

- [ ] Build deterministic native wallet-to-Vault tests for all supported roles/assets and signing paths.
- [ ] Add physical HSM and offline-device runners with no silent skip or software fallback.
- [ ] Exercise business-host root, stolen operator credentials and deceptive withdrawal inputs.
- [ ] Exercise malicious RPC/code/state/finality, A-on-screen/B-in-signature, hidden actions and fee abuse.
- [ ] Test replay/races, outages, crash recovery, device loss, backup rollback and cumulative spending.
- [ ] Verify pause, delayed unpause, immutable cold authority and hot-role replacement under attack.
- [ ] Commission appropriate independent code, firmware, side-channel and fault-injection assessment.
- [ ] Record exact source/device/policy/account configuration and reproduce every claimed result.
- [ ] Complete the final multisig membership/quorum and deployment/funding ceremony with expert sign-off.

## Acceptance criteria

All applicable entries in `docs/ACCEPTANCE_MATRIX.md` must have concrete expected/actual observations
and independently reviewable evidence. No unexecuted device test, upstream historical result or
third-party marketing claim counts as a pass. There must be no unresolved fund-safety blocker.
Passing tests alone does not authorize deployment, asset migration or real-fund use.
