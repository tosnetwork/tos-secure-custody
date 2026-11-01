"""Publish English kickoff issues to the exact target repository, idempotently."""
import json
from pathlib import Path
import subprocess

REPO = "tosnetwork/tos-secure-custody"
ROOT = Path(__file__).resolve().parents[1]
ISSUES = [
    ("[Epic] TOS Secure Custody: open, verifiable post-quantum custody", "docs/PROJECT_CHARTER.md"),
    ("[HSM] Hardware adapters and no-downgrade ML-DSA capability", "docs/workstreams/01-hsm.md"),
    ("[Offline] Trusted-display signer and physical approval", "docs/workstreams/02-offline.md"),
    ("[Parser] Complete wallet-to-Vault transaction decoding", "docs/workstreams/03-parser.md"),
    ("[Attestation] Hardware evidence, freshness and revocation", "docs/workstreams/04-attestation.md"),
    ("[Build] Hermetic firmware and independent reproducible builds", "docs/workstreams/05-builds.md"),
    ("[Acceptance] Institutional adversarial and recovery qualification", "docs/workstreams/06-acceptance.md"),
]


def gh(*args):
    return subprocess.check_output(["gh", *args], text=True)


def main():
    found = gh("repo", "view", REPO, "--json", "nameWithOwner", "--jq", ".nameWithOwner").strip()
    if found != REPO:
        raise SystemExit("repository identity mismatch")
    existing = json.loads(gh("issue", "list", "--repo", REPO, "--state", "all", "--limit", "1000", "--json", "title"))
    if len(existing) >= 1000:
        raise SystemExit("issue listing hit its bound; refusing an incomplete duplicate check")
    titles = {issue["title"] for issue in existing}
    for title, path in ISSUES:
        if title in titles:
            print("Already exists:", title)
            continue
        print(gh("issue", "create", "--repo", REPO, "--title", title, "--body-file", str(ROOT / path)).strip())
        titles.add(title)

if __name__ == "__main__":
    main()
