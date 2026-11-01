# Open and verifiable hardware requirements

## Product boundary

Do not begin by manufacturing a new security chip. First qualify an existing hardware platform
against the TOS transaction, post-quantum signing, independent-display and operational requirements.
No hardware vendor has been selected or certified by this bootstrap.

An institution needs a signing boundary, not merely an encrypted USB token. The device must make a
host-displayed transaction A incapable of silently authorizing transaction B. For online operations,
a separately administered Guardian and on-chain limits remain necessary even when a business key
is held in a non-exportable HSM.

## Required properties

| Area | Requirement | Evidence required |
|---|---|---|
| Key boundary | Key generation and signing inside the stated protected boundary; no plaintext host export | Provisioning transcript, architecture review, device tests and physical threat classification |
| PQ signing | Correct ML-DSA-44 implementation and exact TOS signing convention | Known-answer vectors, native wallet verification, actual device timing/memory measurements |
| Display | Device-owned display and physical confirmation input | Trace from decoded bytes to displayed fields to signed preimage; malicious-host exercise |
| Firmware | Authenticated boot, rollback resistance, controlled updates and debug policy | Signed measurements, independent build reproduction and rollback/debug tests |
| Openness | Publish available firmware, schematics, PCB, BOM, FPGA/RTL and licenses | Versioned files and a precise inventory of every closed/unverifiable component |
| Evidence | Bind device, firmware, custody key and exact request to fresh attestation | Actual hardware evidence and endorsement appraisal, not software-generated claims |
| Isolation | No unrestricted remote administration in the payment plane | Network/process boundary review and stolen-credential exercises |
| Recovery | Independent quorum backups and rehearsed rotation without a treasury bypass | Device-loss and disaster-recovery transcripts on the exact account configuration |
| Physical security | Defined attack class and residual risks | External side-channel/fault-injection assessment where required by the deployment |

## Offline device profile

The trusted processor must control parsing, display, confirmation and the signature operation.
The USB/network host may transport bytes but may not supply the approved screen or a preselected
opaque digest. Display the canonical network, Vault/account, operation, native/Token asset identity,
recipient, integer base units, separately derived decimal presentation, fees/attachments, epoch,
nonce and expiry. Reveal every action in a batch; V1 may instead reject all multi-action requests.

Use a bounded optical transport or explicitly controlled removable medium with strict framing and
resource limits. QR transport is planned, not implemented. No wireless interface is required for the
offline reference. An operating-system terminal window on a compromised host is not a trusted display.

## Hardware candidate evaluation

An open HSM, programmable security token, secure element, FPGA or silicon root of trust is a candidate,
not a plug-compatible TOS signer. Evaluate memory, entropy, constant-time behavior, update process,
display control, PQ key custody, deterministic parsing and actual signatures independently. A root of
trust is not automatically a complete HSM; a classical secure element does not become a PQ secure
element by running ML-DSA outside it on an unprotected host.

The included NetHSM adapter targets the documented EdDSA API for disposable-key experiments only.
It is not evidence of NetHSM ML-DSA support or a production-compatible TOS role account. PKCS#11 is a
reserved interface; a software implementation must not be presented as a hardware-qualified backend.

## Claims policy

Use “advancing post-quantum hardware custody” for the project mission. Do not use “quantum-proof,”
“certified,” “tamper-proof,” “fully open silicon,” or “production-safe” without narrowly scoped,
verifiable evidence. Open-source availability, reproducible binaries, hardware attestation,
certification and actual operational independence are separate properties.
