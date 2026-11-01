# Project charter: TOS Secure Custody

## Objective

Launch `tosnetwork/tos-secure-custody` as an independent, English-language, open-source engineering
project for institution-grade custody infrastructure. Deliver HSM adapters, offline hardware signers,
complete transaction parsing, device attestation, reproducible builds and an adversarial acceptance suite.

The primary security objective is that control of a business workstation, CI account, deployment
credentials or online business-role signing capability is insufficient for unilateral treasury theft.
This claim is conditional on independent Guardian/cold authorities, correct supported contract code,
trusted hardware/firmware boundaries and correct chain execution. It is not a promise of zero loss.

## Scope

Six workstreams have separate specifications, test gates and issue-ready definitions in
`docs/workstreams/`. Interfaces must remain vendor-neutral. Hardware components may be evaluated
without claiming they support TOS or post-quantum algorithms until that support is demonstrated.

The project is additive to the TOS ecosystem. Do not modify consensus, generic wallets, deployed
Vault semantics, or token supply as part of this bootstrap. Do not require the proposed Energy
mechanism; its implementation is not assumed. Never import user secrets, fund a deployment, or
change production roles during ordinary development or tests.

## Deliverables

A reviewed custody request protocol; independent transaction decoders and native differential vectors;
capability-explicit HSM adapters; offline device firmware and an open hardware bill of materials;
attestation profiles with evidence appraisal; deterministic, independently reproduced release artifacts;
and reproducible attack/recovery transcripts for the exact production candidate.

Publish implementation status beside every capability. Separate software fixtures, device simulations,
physical-device evidence, native contract execution and independent audit evidence. Missing equipment
must produce a blocked gate, not a successful skipped test.

## Governance

Assign maintainers for protocol, transaction parsing, firmware, hardware, operations and independent
security review. Separate business, Guardian, cold-governance and emergency identities operationally;
multiple keys controlled by one administrator do not satisfy independent authorization.

Protect the release branch with required review, tests and signed release provenance. No maintainer
may treat a self-authored test report as an independent audit. Security-affecting protocol changes
need an RFC, migration/recovery analysis and negative tests. Do not silently broaden a signing profile.

## Definition of done

The six workstream acceptance criteria, native tests, hardware attacks, independent review, immutable
contract/role verification and deployment ceremony must all pass on the exact release candidate.
A compromised host exercise must demonstrate that only policy-authorized transfers succeed and that
recovery remains possible without bypassing the Vault's immutable authority and delay.

The initial delivery is an inspection-only engineering foundation. It is not the completed production
system. Repository publication and issue creation are separate steps from local source preparation.
