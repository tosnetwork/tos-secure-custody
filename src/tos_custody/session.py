"""Operator-configured local proof session; host input is only transaction bytes."""
from pathlib import Path

from .batch import appraise_batch, validate_policy
from .canonical import exact_keys
from .errors import CustodyError
from .proofs import ProofVerifier


def read_data(path):
    with Path(path).open("rb") as handle:
        raw = handle.read(131073)
    if len(raw) > 131072:
        raise CustodyError("account-data file exceeds custody bound")
    return raw


def appraise_session(raw, *, policy, session, now, verifier=None, form="request"):
    validate_policy(policy)
    exact_keys(session, {"schema", "verifier", "verifier_sha256", "anchor", "target", "accounts"})
    if session["schema"] != "tos.custody.proof-session.v1":
        raise CustodyError("unsupported local proof session")
    expected = {policy["wallet"]} | set(policy["vaults"])
    if type(session["accounts"]) is not dict or set(session["accounts"]) != expected:
        raise CustodyError("proof session must supply exactly the policy accounts")
    native = ProofVerifier(executable=session["verifier"], executable_sha256=session["verifier_sha256"],
                           anchor=session["anchor"])
    if native.anchor_digest != policy["anchor_digest"]:
        raise CustodyError("proof session anchor is not the independent policy anchor")
    accounts = {}
    for account in sorted(expected):
        entry = session["accounts"][account]
        exact_keys(entry, {"data", "material", "native_state"})
        if any(type(path) is not str or not path for path in entry.values()):
            raise CustodyError("proof session paths must be explicit operator strings")
        code = policy["wallet_code_hash"] if account == policy["wallet"] else policy["vaults"][account]["code_hash"]
        proof = native.verify_account(account=account, target=session["target"], material=entry["material"],
                                      now=now, max_age=policy["max_state_age"], expected_code_hash=code,
                                      state_file=entry["native_state"])
        data = read_data(entry["data"])
        proof.bind_data(data)
        accounts[account] = (proof, data)
    wallet_proof, wallet_data = accounts.pop(policy["wallet"])
    return appraise_batch(raw, wallet_proof=wallet_proof, wallet_data=wallet_data, vaults=accounts,
                          policy=policy, now=now, verifier=verifier, form=form)
