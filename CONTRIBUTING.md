# Contributing

Use English for code, comments, documentation, issues and pull requests. Keep the project independent
from `tosnetwork/tos`; pin integration sources instead of silently changing consensus or generic wallets.

Every change must state its trust boundary, supported/unsupported inputs, upstream assumptions and
new tests. Add negative vectors for parser and authorization changes and a targeted mutation control
where practical. No secret, live HSM credential, production address configuration or funded transaction
belongs in a fixture. Synthetic examples must remain clearly labeled.

Run `make test`, `python3 scripts/mutation_controls.py`, `make repro`, and the blocked-release check.
Native and hardware work needs its own exact reproduction transcript. Tests must not claim hardware
or native execution when they use mocks or models. Missing required tools block acceptance.

Do not introduce new cryptographic primitives. Reuse independently reviewed implementations and the
exact TOS account conventions. Keep key management separate from attestation and administrative trust.

Security-affecting work requires review by someone other than its author. Maintain accurate
`IMPLEMENTATION_STATUS.md`, attack coverage and release gates in the same change as the implementation.
