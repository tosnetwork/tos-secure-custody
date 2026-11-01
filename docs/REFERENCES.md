# Primary references

These sources informed the initial design. They are not endorsements or qualification reports.

- TOS Treasury Vault V1, pinned commit `def735f3ad9c57a4b8fc8de43537075baec2271a`:
  https://github.com/tosnetwork/tos/blob/def735f3ad9c57a4b8fc8de43537075baec2271a/doc/treasury-vault-v1.md
- TOS Vault wire builders at the same commit:
  https://github.com/tosnetwork/tos/blob/def735f3ad9c57a4b8fc8de43537075baec2271a/test/treasury-vault/wire.py
- TOS ordinary-cell test codec at the same commit:
  https://github.com/tosnetwork/tos/blob/def735f3ad9c57a4b8fc8de43537075baec2271a/test/auth-extensions/cells.py
- TON BOC serialization and TL-B layout:
  https://docs-next.ton.org/foundations/serialization/boc
- Nitrokey NetHSM operation/API documentation (EdDSA protocol baseline only):
  https://docs.nitrokey.com/nethsm/operation
- NIST FIPS 204, Module-Lattice-Based Digital Signature Standard:
  https://csrc.nist.gov/pubs/fips/204/final
- IETF RFC 9334, Remote ATtestation procedureS Architecture:
  https://www.rfc-editor.org/rfc/rfc9334.html

Public standards and vendor behavior must be rechecked when implementing a production profile.
Use the actual approved standard plus applicable errata, not a marketing label or an unreviewed
algorithm variant. The current core neither implements ML-DSA nor claims RATS protocol certification.
