# Workstream 2: Offline signer with trusted display

## Objective

Deliver an open reference device that independently parses, displays and confirms the same transaction
it signs. A compromised host must not be able to display transaction A and request a signature for B.

## Current baseline

A bounded offline inspection schema, CLI, host-label rejection and hard production-signing gate exist.
No hardware board, firmware, screen, physical confirmation or QR transport has been implemented.

## Implementation tasks

- [ ] Select a qualified hardware boundary and publish the open/closed component inventory.
- [ ] Publish firmware, available schematics/PCB/BOM, build instructions and board revisions.
- [ ] Port or independently implement the bounded parser in the trusted firmware environment.
- [ ] Drive the display and physical approval input directly from the trusted boundary.
- [ ] Implement bounded optical/removable-media transport; reject frame mixing, replay and excessive input.
- [ ] Display exact network, account, role, Vault, asset/master, amount, recipient, fees, nonce and expiry.
- [ ] Bind confirmation to immutable bytes, code/state evidence, policy and custody key; reject TOCTOU.
- [ ] Add secure boot, update/rollback controls, debug lifecycle restrictions and power-loss behavior.
- [ ] Rehearse device loss, replacement and recovery without weakening the cold quorum or Vault delay.

## Acceptance criteria

Run physical-device tests with a malicious coordinator, swapped recipients/amounts/actions, fake
screens, replaced QR frames, interrupted confirmation, reboot and stale firmware. The native wallet
must verify the actual emitted PQ signature for exactly what the device displayed. Unknown formats
must never fall back to blind signing. Independent firmware/hardware review is required.

Dependencies: full parser/signing profile, hardware-key adapter, build/attestation workstreams.
