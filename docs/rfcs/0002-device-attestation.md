# RFC 0002: Device evidence, appraisal and key-bound authorization context

Status: draft. Hardware evidence verification is not implemented.

## Model

Separate Attester, Verifier and Relying Party roles following the RATS architecture. Evidence is
appraised against independently trusted endorsements, reference measurements, revocation and local
policy. An attestation result supports a trust decision; it is not a payment approval.

The trusted signing application must prove a binding among its device identity, security boundary,
firmware/boot measurement, custody public key and the current exact transaction. Prevent a compromised
host from proxying a quote from an unrelated healthy device while using an unapproved signer.

## Required production evidence

Include profile/version, endorsement chain, attestation-key identity, custody key commitment and suite,
firmware and boot measurements, security version, lifecycle/debug state, anti-rollback counter,
fresh verifier nonce, verifier audience, request/intent commitment, policy commitment and validity
context. Authenticate the full set using the hardware profile's actual evidence format.

A verifier must validate endorsement roots and revocation, measurement provenance and allowlists,
key origin/binding, nonce freshness, audience, exact request/policy binding, security version and
lifecycle policy. Persist nonce/counter/rollback state atomically across restarts and recovery. Time
checks require a trusted local clock or a documented nonce-based freshness construction.

Do not accept a self-signed certificate uploaded by the host as a root. Do not treat a signed `true`
value as evidence of secure boot unless the hardware profile guarantees the origin of that measurement.
A TPM quote may measure a host without proving that a particular custody key remains protected there.

## Bootstrap fixture

`verify_fixture()` verifies a domain-separated Ed25519 signature over TCJ-1 software claims. It checks
session bindings, freshness, revocation input, measurement allowlists, security versions, debug flags
and an atomic process-local replay book. It requires explicit `allow_software_fixture=True` and
returns `hardware_assurance=false` and `production_authorized=false` even on success.

No field in this fixture proves real silicon state. It does not parse TPM quotes, DICE chains,
secure-element endorsements, COSE/EAT evidence or a vendor firmware report. The replay book is not
durable. `verify_hardware()` always refuses. The fixture exercises protocol failure handling only.

## Recovery and failure

Revocation must be independently authenticated and refreshed without allowing the business host to
re-enable a device. Offline devices need an explicit expiry/revocation/update ceremony; being offline
does not make a stale device permanently trustworthy. Device replacement must preserve the Vault's
cold authority, on-chain delays and independent quorum. Lost final cold authority has no magic bypass.

Remote attestation, firmware release signing and custody algorithms require separate PQ migration
assessment. A PQ transaction signature does not automatically make the whole attestation or transport
chain post-quantum. Never collapse these separate claims into one “PQ-ready” checkmark.
