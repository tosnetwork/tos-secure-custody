# Workstream 4: Hardware evidence, freshness and revocation

## Objective

Appraise real device evidence that binds the protected custody key and running approved firmware to
the current request. Attestation is supporting trust evidence, not a treasury authority.

## Current baseline

RFC 0002 and a software-fixture verifier exist. Fixture signatures, bindings, nonce replay,
measurement/security-version policy and counters are tested. The state is process-local. No TPM,
DICE, secure-element or vendor evidence profile is implemented; hardware verification always refuses.

## Implementation tasks

- [ ] Choose and specify actual hardware evidence profiles and endorsement roots.
- [ ] Validate endorsements, measurement origins and custody-key generation/residency binding.
- [ ] Bind device, key suite, verifier audience, fresh challenge, request and policy.
- [ ] Implement durable atomic replay/counter state and backup/restore rollback defenses.
- [ ] Authenticate revocation, firmware reference values and policy updates independently of the business host.
- [ ] Specify offline freshness, clock/nonce assumptions and device re-enrollment/recovery.
- [ ] Resist quote proxying, device substitution, debug mode and revoked/unapproved firmware.
- [ ] Assess PQ migration separately for attestation, firmware signing, transport and custody keys.

## Acceptance criteria

Verify actual evidence from physical hardware and reject fabricated software claims, untrusted roots,
stale/replayed/misbinding evidence, rollback and revoked devices. Restart and restore the verifier
without resurrecting authorizations. Record the exact device/firmware/configuration and independent
review. The fixture verifier cannot satisfy or be renamed into this acceptance.
