# Delivery roadmap

Stages are evidence gates, not promised dates. This document describes a **proposed TOS+ hardware product strategy**, not completed, qualified, certified, or production-ready devices. The independent repository remains `tosnetwork/tos-secure-custody`; "TOS+" is the proposed visual label for the hardware products, not a change to the TOS chain, Treasury Vault, or protocol names.

## Mission and security outcome

Build **open, verifiable, post-quantum institutional custody infrastructure** for TOS. A compromised business workstation, DevOps host, or online signer must not be sufficient to unilaterally transfer institutional treasury assets. Protecting a private key against extraction is necessary but insufficient: the system must also independently verify what is being authorized and preserve the on-chain Treasury Vault's enforced separation of duties.

The end-to-end security boundary is:

```text
Untrusted business host / transaction coordinator
             |
             v
Independent TOS transaction parser + independently obtained policy/state
             |
        +----+----+
        |         |
TOS+ Institutional HSM Gateway     TOS+ PQ Hardware Signer
  bounded online signing          offline display + physical approval
        |         |
        +----+----+
             |
TOS authenticated business / guardian / cold role accounts
             |
TOS Treasury Vault (limits, role separation, delay, pause)
             |
          TOS chain
```

The diagram is architectural intent, not evidence of working hardware or production custody. An HSM, gateway, attestation server, firmware update authority, business system, or single hardware vendor must never become a unilateral withdrawal authority.

## Hardware ownership decision: integrate first, design our own devices second

**Adopt a hybrid hardware strategy.** Do not attempt a new secure-silicon design at project inception, and do not make institutional custody permanently dependent on one hardware vendor.

| Approach | Advantage | Constraint | Decision |
|---|---|---|---|
| Design a secure chip and entire hardware stack from scratch | Maximum potential design control | Expensive, slow, specialized silicon/physical-security expertise; open RTL alone does not establish secure manufacture | **Defer** until justified by demonstrated requirements and independent review |
| Depend exclusively on existing commercial/open hardware | Rapid prototyping and mature interfaces | Vendor dependencies, non-open components, limited PQ and trusted-display capabilities | **Use for initial integration**, not as the permanent product boundary |
| Existing evaluated security components + **TOS+ designed PCB/device/firmware and protocols** | Practical control over host isolation, independent display, verification, updates and product identity | Requires embedded design, hardware qualification, supply-chain controls and external audits | **Target product architecture** |

The project's differentiated intellectual and engineering work is the independently reviewable **TOS transaction interpretation, hardware-enforced signing intent, post-quantum key custody, firmware, device attestation and Treasury Vault integration**—not inventing a commodity chip for its own sake.

### Candidate platforms to evaluate, not endorse

1. **Nitrokey NetHSM:** candidate for institutional HSM API integration and isolation studies. The current software adapter exercises an experimental Ed25519 interface against mocked transport only. **Do not imply that ML-DSA hardware support, production compatibility, or physical-device testing exists.**
2. **Tillitis TKey:** reference for auditable programmable security-device architecture, FPGA/firmware design and measured loading. Its standard form has **no trusted transaction display**; it is not by itself a complete institutional signing terminal.
3. **TROPIC01 / open secure-element ecosystem:** possible trust-root or security-component evaluation for a TOS+ custom PCB. Review hardware revisions, vendor disclosures, fault-injection/side-channel evidence and all non-open parts before choosing it. A classical secure element does **not** protect ML-DSA private keys if ML-DSA executes outside its protected boundary.
4. **OpenTitan and other open roots of trust:** research options for secure boot, device identity and firmware measurement. A root of trust is **not** a ready-to-use custody HSM or post-quantum signer.

Evaluate each candidate against actual ML-DSA-44 generation/storage/signing, bounded parser execution, isolation, entropy, memory, debug policy, tamper threat model, update/recovery design, verifiable bill of materials and procurement continuity. Record every closed/unverifiable component and residual risk; openness and certification are separate claims.

## Two TOS+ product tracks

### Product A — TOS+ PQ Hardware Signer

An **offline, open-design transaction-authorization device** intended for independent institutional approvals and cold governance.

Required design properties:

- **Device-owned display and physical confirmation.** The trusted processor, not the host, derives every displayed field from the exact bytes that will be signed. Reject blind signing and unrecognized actions.
- Show TOS network/domain, vault/account, asset and Token master identity, recipient, amount and unit precision, fee/attachment, nonce, epoch, expiry, governance consequences and **every action** in a batch; reject unsupported or ambiguous inputs.
- Air-gapped or tightly controlled bounded optical/removable-media transport; no host-driven display labels, remote unlock, unreviewed firmware, or optional "sign arbitrary digest" bypass.
- Hardware-controlled authenticated boot, update and rollback policy, debug lockdown, key lifecycle and secure recovery.
- **Real protected ML-DSA-44 signing**, with exact TOS wallet signing-preimage and native-wallet/Vault verification evidence. A classical secure element plus software PQ on an exposed host does not meet this gate.
- Publish available schematics, PCB design, BOM, firmware, build recipes, reproducible binaries and evidence; clearly disclose any closed silicon or factory trust assumptions.

Concept renders and device mockups must use the text **TOS+** (rather than third-party names or misleading device branding); do not confuse conceptual imagery with a functioning or approved product.

### Product B — TOS+ Institutional HSM Gateway

A **vendor-neutral institutional integration layer** for professional HSMs and the TOS authorization/policy pipeline.

Required design properties:

- Pluggable HSM adapters with explicit algorithms/capabilities, bounded APIs, authenticated transport, fail-closed unsupported profiles, strict key identity and **no implicit downgrade from ML-DSA to Ed25519**.
- Authenticated independent policy and finalized TOS state, exact-byte transaction parsing, request/replay binding, spend monitoring and signed audit events.
- Distinct business and guardian authorization paths, cold-governance quorum and emergency pauser; never allow the gateway or an HSM administrator to bypass Vault-enforced payment rules.
- Hardware-backed device/service identity, measured firmware and revocation when supported by **real, independently verified** device evidence.
- HSM-agnostic recovery, key rotation and availability procedures with two-vendor interoperability trials where feasible.

A gateway is not itself an HSM unless a separately qualified protected key boundary exists. It must not advertise external software policy checks as equivalent to Vault enforcement.

## Five TOS-controlled engineering deliverables

1. **TOS Transaction Parser:** independently parse the complete supported wallet envelopes, signing preimages, action lists and Vault requests; reject unknown formats and prove display-to-signature exactness.
2. **TOS Secure Firmware:** reviewable, reproducibly built device firmware with verified boot, update, rollback and debug controls.
3. **Post-Quantum Signing:** real protected ML-DSA key generation, storage, signing and wallet-native verification with constant-time/physical-security review appropriate to the threat model.
4. **Device Attestation:** challenge-bound device, firmware, signing-key, intent and policy evidence; independently validate hardware endorsements, freshness, revocation and persistent anti-rollback state.
5. **Treasury Vault Integration:** real role-wallet to Vault execution for native TOS and supported Tokens, with policy ceilings, guardian independence, immutable cold authority, delayed governance and emergency pause.

These are **ownership and acceptance objectives**, not declarations of implementation completeness.

## Evidence-gated implementation stages

| Stage | Outcome | Exit evidence |
|---|---|---|
| **S0: foundation** | English charter/specifications, parser reference, protocol adapters, software attacks and source packaging | Local software results with accurate blocked-capability status |
| **S1: exact-byte integration** | Full supported external wallet/action/preimage decoding plus authenticated state/finality | Native differential vectors and real wallet-to-Vault positive/negative execution |
| **S2a: evaluate existing devices** | Purchase or obtain a real HSM and programmable/open security-device prototypes; evaluate secure elements/roots of trust | Published candidate threat matrix, procurement/revision records, real-device API/signature measurements and documented exclusions |
| **S2b: TOS+ custom device prototypes** | Custom reference PCB, offline display/buttons, independently controlled confirmation, gateway integrations and protected PQ implementation | Device/firmware source, exact displayed-intent-to-preimage traces, actual protected ML-DSA signatures, native PQ wallet execution and hostile-host tests |
| **S3: verifiable devices/releases** | Hardware evidence appraisal, persistent anti-replay and independently reproducible firmware | Actual evidence/revocation transcripts, two independent matching firmware builds, supply-chain/BOM record, update/rollback tests |
| **S4: institutional acceptance** | Full attack/recovery suite, independent expert review and operational acceptance | Signed exact-candidate acceptance record, tested incident recovery, security findings disposition and deployment/funding ceremony |
| **S5: optional custom silicon/FPGA acceleration** | Study proprietary silicon only if measurements prove a need that open hardware/integration cannot safely satisfy | Published justification, feasibility/security cost comparison, independent design reviews and a separately approved funding decision |

S1 parsing, S2a hardware selection and S3 build/attestation design may proceed in parallel. S2b needs an independently reviewed key-custody architecture; S4 cannot begin until the security-critical real-device and native execution gates are met. No parallel workstream may bypass a signing or deployment dependency.

## Institutional acceptance scenarios to demonstrate

- Business-host or DevOps-root compromise cannot unilaterally withdraw funds; business and guardian have independent intent sources and administrators.
- A host displays transaction **A** but submits transaction **B**: the device rejects mismatched bytes, targets, assets, amounts, network/domain, or preimage.
- Blind signing, unknown action types, batch action hiding, malformed cells, duplicate JSON fields, nonce replay, expiry bypass and chain-ID substitution are rejected.
- Extracted gateway credentials, HSM API misuse, unauthorized firmware update, debug access, device swap or rolled-back attestation state do not silently authorize funds.
- ML-DSA cannot silently downgrade to a classical algorithm; hardware identities and key storage assumptions are verified with real-device evidence.
- Vault limits, guardian separation, 48-hour cold governance, pause/recovery and Token accounting cannot be bypassed by an off-chain gateway.
- Physical-device loss, backup/key rotation, split-site approval, signing-device recovery and revocation are rehearsed without introducing a single-operator withdrawal path.
- Independent specialists reproduce applicable source/firmware artifacts and assess hardware physical risks, including fault injection and side channels where required.

## Release and claims policy

Use **"TOS+ — advancing open, verifiable post-quantum hardware custody"** as proposed product messaging. Do **not** claim hardware qualification, hardware-backed PQ custody, full silicon openness, third-party certification or readiness to secure real institutional funds without evidence tied to the exact device revision, firmware hash, source commit, role-account code and deployment configuration.

The current `0.1.0.dev0` repository is **experimental and inspection-only**: the offline signer and production hardware-attestation entry points deliberately refuse authorization. The NetHSM Ed25519 experiment, software attestation fixtures and reproducible *source archives* are not hardware or post-quantum production evidence.

Use the six issue-ready workstream files for implementation tasks. The project epic is the charter. Closing any issue requires links to exact source hashes, commands, outputs, device/firmware identities, native test evidence and outstanding exceptions. Missing native or hardware tools block the corresponding acceptance.

## S1b reference implementation increment (2026-11-01)

RFC 0004 implements cold PQ multisig exact-preimage and account-data inspection,
including execute/add/remove/quorum and OLD-quorum structural comparisons. It builds
on RFC 0003 and remains inspection-only. Full 64-member/12-signature-shaped inputs are
software tests, not hardware, genuine ML-DSA verification or authenticated state.
S1 remains open pending independently authenticated finality/code/state, native
wallet-to-Vault execution, cryptographic verification and independent review.

## Local verification increment

Optional diagnostic ML-DSA verification and local native wallet-to-Vault parser
comparisons are now available. See [local acceptance](LOCAL_ACCEPTANCE.md) for the
exact scope, artifact provenance and portable firmware corpus. Authenticated
state/finality and full S1 acceptance remain outstanding.

## Proof-backed policy and persistence increment

RFC 0005 integrates the existing native PQ finality/account verifier, binds decoded
data and deployed code, adds independently provisioned batch/role appraisal and
durable conservative reservations. Native lifecycle probes include serialized
restart, frozen/deleted snapshots, explicit StateInit redeployment and a PQ pauser.
Historical real proof checks establish the adapter boundary. Fresh proofs for an
actual custody deployment, settlement reconciliation and non-author acceptance
remain required before closing S1; signing remains disabled.
