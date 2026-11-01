# Release gates and deployment ceremony

## Current gate

`python3 scripts/check_release_readiness.py` returns `production_release_allowed=false` and a nonzero
exit status. The bootstrap's offline signer and hardware verifier refuse use. Flipping documentation
checkboxes cannot enable the production path.

The low-level NetHSM prototype can sign exact bytes for controlled experiments with disposable test
keys; it is not connected to a production authorization flow and must never be exposed to business
hosts or supplied with production key credentials.

## Mandatory production evidence

| Gate | Evidence required |
|---|---|
| G1: independent intent | Documented separation of business, Guardian, cold quorum and emergency control, including administrator and build/provisioning access |
| G2: complete parsing | Full supported wallet/Vault/Token path; exact preimages; native differential tests; no unknown bits/actions |
| G3: authenticated state | Verified chain anchor, network, finality, code/state hashes, roles, policy epoch, counters and asset registry |
| G4: hardware PQ boundary | Real in-boundary key generation and ML-DSA signing; exact native verification; no classical fallback |
| G5: trusted approval | Device-owned display/input; immutable approval binding; malicious-host and fault/restart exercises |
| G6: hardware evidence | Actual endorsement/measurement/key-binding validation, revocation and durable replay/rollback state |
| G7: reproducible release | Pinned dependency closure, SBOM and two independent byte-matching firmware builds |
| G8: attacks and recovery | Full institutional native/hardware matrix, bounded-loss analysis and cold/pauser recovery drills |
| G9: independent review | Expert code and hardware review on the exact candidate; no unresolved blocker or undisclosed exception |
| G10: funding ceremony | Exact deployed code, multisig membership/quorum, four PQ roles and initial state verified independently |

## Funding ceremony

Record immutable Vault/cold-account identities, supported code hashes, configured network, role
addresses and actual cold members/quorum. Verify fresh deployed state; register assets through the
real delay; rehearse a minimal-value payment, pause, delayed unpause and hot-role recovery. Verify
actual recipient settlement, not just submission or wallet sequence advancement. Confirm role-wallet
fee balances and storage reserves. Migrate only explicitly approved bounded balances after sign-off.

Do not deploy, fund, migrate assets, modify multisig members or collect private keys during bootstrap.
An issue being closed or CI being green does not authorize funding.
