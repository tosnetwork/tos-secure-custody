"""Synthetic data binding and independent policy tests; not chain-proof fixtures."""
from copy import deepcopy
from dataclasses import replace
import unittest

from tos_custody.batch import appraise_batch
from tos_custody.boc import serialize_boc
from tos_custody.errors import CustodyError
from tos_custody.proofs import ProvenAccount
from tos_custody.state import highload_state, highload_unused, vault_state
from helpers import Builder, BUSINESS, COLD, GUARDIAN, PAUSER, NETWORK, NOW, VAULT, RECIPIENT, body, request
from test_highload import wallet_request, action, message, stored_signature
from test_multisig import hashmap, state as multisig_data, req as multisig_req

ANCHOR = "aa" * 32
CODE = "bb" * 32
TARGET = {"workchain": -1, "shard": "8000000000000000", "seqno": 100,
          "root_hash": "cc" * 32, "file_hash": "dd" * 32}


def wallet_data(*, old=None, current=None, last=NOW, timeout=3600):
    b = Builder().ref(stored_signature(bytes(1312))).u(7, 32)
    for rows in (old, current):
        b.u(int(rows is not None), 1)
        if rows is not None:
            b.ref(rows)
    return b.u(last, 64).u(timeout, 22).cell()


def vault_data(*, pending=None, paused=False, epoch=7, nonce=42, amount_spent=0, enabled=True,
               role_wallet=BUSINESS, source_wallet=None, admin_pending=None, admin_ready=NOW):
    roles = (Builder().ref(Builder().addr(role_wallet).addr(GUARDIAN).cell())
             .ref(Builder().addr(COLD).addr(PAUSER).cell()).cell())
    asset = (Builder().u(int(enabled), 1).addr(source_wallet).coins(2_000_000_000)
             .coins(3_000_000_000).coins(5_000_000_000).u(NOW, 32)
             .coins(amount_spent).coins(amount_spent).cell())
    b = (Builder().u(epoch, 64).u(nonce, 64).u(42, 64).u(int(paused), 1).u(1, 8)
         .ref(roles).u(1, 1).ref(hashmap({0: asset})).u(int(pending is not None), 1))
    if pending is not None:
        b.ref(pending)
    b.u(int(admin_pending is not None), 1)
    if admin_pending is not None:
        b.ref(Builder().u(admin_ready, 32).ref(admin_pending).cell())
    return b.cell()


def evidence(account, cell, **changes):
    return replace(ProvenAccount(account, TARGET, ANCHOR, CODE, cell.commitment(max_depth=96)[1].hex(),
                                 100_000_000_000, NOW, NOW, True), **changes)


def batch_policy():
    return {"schema": "tos.custody.batch-policy.v1", "anchor_digest": ANCHOR, "network_global_id": NETWORK,
            "wallet": BUSINESS, "wallet_profile": "highload", "wallet_code_hash": CODE,
            "allowed_configuration_preimages": [],
            "valid_until": NOW + 3600, "max_state_age": 300, "fee_reserve": 100_000_000,
            "vaults": {VAULT: {"code_hash": CODE, "role": "business", "operations": ["submit"],
                                "max_control_value": 200_000_000, "allowed_governance_requests": [],
                                "assets": {"00" * 32: {"max_payment": 2_000_000_000,
                                                       "cumulative_limit": 4_000_000_000,
                                                       "max_attachment": 0, "recipients": [RECIPIENT]}}}}}


def appraisal(*, req=None, wallet=None, vault=None, policy=None, proof_changes=None):
    wallet = wallet if wallet is not None else wallet_data()
    vault = vault if vault is not None else vault_data()
    return appraise_batch(serialize_boc(req if req is not None else wallet_request()),
                          wallet_proof=evidence(BUSINESS, wallet, **(proof_changes or {})),
                          wallet_data=serialize_boc(wallet), vaults={VAULT: (evidence(VAULT, vault), serialize_boc(vault))},
                          policy=policy if policy is not None else batch_policy(), now=NOW)


class BatchStateTests(unittest.TestCase):
    def test_governance_requires_independent_intent_and_timelock(self):
        governance = request(admin=True, pay=Builder().u(3, 8).cell(), deadline=NOW+200000)
        p = batch_policy()
        p.update(wallet=COLD, valid_until=NOW+210000)
        p["vaults"][VAULT].update(role="cold_administrator", operations=["schedule", "apply"])
        wallet, vault = wallet_data(), vault_data()

        def appraise(op, vault):
            signed = wallet_request(wallet=COLD, actions=action(message(content=body(op=op, req=governance))))
            return appraise_batch(serialize_boc(signed), wallet_proof=evidence(COLD, wallet),
                                  wallet_data=serialize_boc(wallet), policy=p, now=NOW,
                                  vaults={VAULT: (evidence(VAULT, vault), serialize_boc(vault))})
        with self.assertRaises(CustodyError):
            appraise(0x54560006, vault)
        p["vaults"][VAULT]["allowed_governance_requests"] = [governance.hash.hex()]
        self.assertTrue(appraise(0x54560006, vault)["diagnostic_policy_match"])
        with self.assertRaises(CustodyError):
            appraise(0x54560007, vault_data(admin_pending=governance, admin_ready=NOW+1))
        self.assertTrue(appraise(0x54560007, vault_data(admin_pending=governance))["diagnostic_policy_match"])

    def test_retiring_guardian_cannot_veto_its_own_replacement(self):
        replacement = (Builder().ref(Builder().addr(BUSINESS).addr(RECIPIENT).cell())
                       .ref(Builder().addr(COLD).addr(PAUSER).cell()).cell())
        governance = request(admin=True, pay=Builder().u(2, 8).ref(replacement).cell())
        p = batch_policy()
        p["vaults"][VAULT].update(role="guardian", operations=["veto"])
        wallet, vault = wallet_data(), vault_data(admin_pending=governance)
        for account, role, accepted in ((GUARDIAN, "guardian", False), (COLD, "cold_administrator", True)):
            p["wallet"] = account
            p["vaults"][VAULT]["role"] = role
            raw = serialize_boc(wallet_request(wallet=account, actions=action(message(content=body(op=0x54560008)))))
            args = {"wallet_proof": evidence(account, wallet), "wallet_data": serialize_boc(wallet),
                    "vaults": {VAULT: (evidence(VAULT, vault), serialize_boc(vault))}, "policy": p, "now": NOW}
            if accepted:
                self.assertTrue(appraise_batch(raw, **args)["diagnostic_policy_match"])
            else:
                with self.assertRaises(CustodyError):
                    appraise_batch(raw, **args)

    def test_cold_membership_preimage_needs_independent_allowlist(self):
        from test_multisig import change, CTX
        from tos_custody.multisig import inspect_multisig
        p = batch_policy()
        p.update(wallet=COLD, wallet_profile="multisig")
        p["vaults"][VAULT].update(role="cold_administrator", operations=["pause"])
        wallet, vault = multisig_data(), vault_data()
        raw = serialize_boc(change())
        args = {"wallet_proof": evidence(COLD, wallet), "wallet_data": serialize_boc(wallet),
                "vaults": {VAULT: (evidence(VAULT, vault), serialize_boc(vault))}, "policy": p, "now": NOW}
        with self.assertRaises(CustodyError):
            appraise_batch(raw, **args)
        p["allowed_configuration_preimages"] = [inspect_multisig(raw, context=CTX)["signing_message_hex"]]
        self.assertTrue(appraise_batch(raw, **args)["diagnostic_policy_match"])

    def test_guardian_requires_exact_proven_pending_request(self):
        p = batch_policy()
        p["wallet"] = GUARDIAN
        p["vaults"][VAULT].update(role="guardian", operations=["approve"])
        wallet, vault = wallet_data(), vault_data(pending=request())
        req = wallet_request(wallet=GUARDIAN, actions=action(message(content=body(op=0x54560002))))
        args = {"wallet_proof": evidence(GUARDIAN, wallet), "wallet_data": serialize_boc(wallet),
                "vaults": {VAULT: (evidence(VAULT, vault), serialize_boc(vault))}, "policy": p, "now": NOW}
        self.assertTrue(appraise_batch(serialize_boc(req), **args)["diagnostic_policy_match"])
        wrong = vault_data(pending=request(nonce=41))
        args["vaults"] = {VAULT: (evidence(VAULT, wrong), serialize_boc(wrong))}
        with self.assertRaises(CustodyError):
            appraise_batch(serialize_boc(req), **args)

    def test_pauser_and_cold_multisig_have_pause_only_paths(self):
        p = batch_policy()
        p["wallet"] = PAUSER
        p["vaults"][VAULT].update(role="pauser", operations=["pause"])
        wallet, vault = wallet_data(), vault_data()
        req = wallet_request(wallet=PAUSER, actions=action(message(content=body(op=0x54560005))))
        args = {"wallet_proof": evidence(PAUSER, wallet), "wallet_data": serialize_boc(wallet),
                "vaults": {VAULT: (evidence(VAULT, vault), serialize_boc(vault))}, "policy": p, "now": NOW}
        self.assertEqual(appraise_batch(serialize_boc(req), **args)["charges"], [])
        p["wallet"], p["wallet_profile"] = COLD, "multisig"
        p["vaults"][VAULT]["role"] = "cold_administrator"
        wallet = multisig_data()
        args.update(wallet_proof=evidence(COLD, wallet), wallet_data=serialize_boc(wallet))
        self.assertEqual(appraise_batch(serialize_boc(multisig_req()), **args)["slot"], "multisig:9")

    def test_multiple_vaults_are_checked_individually(self):
        other = "0:" + "88"*32
        p = batch_policy()
        p["vaults"][other] = deepcopy(p["vaults"][VAULT])
        wallet, vault = wallet_data(), vault_data()
        sends = action(message(destination=other, content=body(req=request(vault=other))), prev=action(message()))
        out = appraise_batch(serialize_boc(wallet_request(actions=sends)), wallet_proof=evidence(BUSINESS, wallet),
                             wallet_data=serialize_boc(wallet), policy=p, now=NOW,
                             vaults={v: (evidence(v, vault), serialize_boc(vault)) for v in (VAULT, other)})
        self.assertEqual(len(out["charges"]), 2)
        self.assertEqual(out["wallet_value"], 200_000_000)

    def test_bound_batch_and_separate_budgets(self):
        out = appraisal()
        self.assertTrue(out["diagnostic_policy_match"])
        self.assertFalse(out["signing_authorized"])
        self.assertFalse(out["cryptographically_verified"])
        self.assertEqual(out["wallet_value"], 100_000_000)
        self.assertEqual(out["charges"][0]["amount"], 1_000_000_000)

    def test_mixed_or_stale_proof_refused(self):
        for changes in ({"fresh": False}, {"account_time": NOW-301}, {"code_hash": "00"*32},
                        {"anchor_digest": "01"*32}, {"address": COLD}, {"data_hash": "00"*32}):
            with self.subTest(changes=changes), self.assertRaises(CustodyError):
                appraisal(proof_changes=changes)

    def test_different_vault_target_refused(self):
        wallet, vault = wallet_data(), vault_data()
        with self.assertRaises(CustodyError):
            appraise_batch(serialize_boc(wallet_request()), wallet_proof=evidence(BUSINESS, wallet),
                            wallet_data=serialize_boc(wallet), policy=batch_policy(), now=NOW,
                            vaults={VAULT: (evidence(VAULT, vault, target={**TARGET, "seqno": 101}), serialize_boc(vault))})

    def test_wallet_subwallet_and_timeout_binding(self):
        for req in (wallet_request(subwallet=8), wallet_request(timeout=3601), wallet_request(wallet=COLD)):
            with self.assertRaises(CustodyError):
                appraisal(req=req)

    def test_chain_role_and_policy_both_required(self):
        with self.assertRaises(CustodyError):
            appraisal(vault=vault_data(role_wallet=RECIPIENT))
        p = batch_policy()
        p["vaults"][VAULT]["role"] = "guardian"
        with self.assertRaises(CustodyError):
            appraisal(policy=p)

    def test_nonce_epoch_pause_pending(self):
        for vault in (vault_data(epoch=8), vault_data(nonce=43), vault_data(paused=True), vault_data(pending=request())):
            with self.assertRaises(CustodyError):
                appraisal(vault=vault)

    def test_chain_and_independent_budget_limits(self):
        with self.assertRaises(CustodyError):
            appraisal(vault=vault_data(amount_spent=2_500_000_000))
        with self.assertRaises(CustodyError):
            appraisal(vault=vault_data(enabled=False))
        p = batch_policy()
        p["vaults"][VAULT]["assets"]["00"*32]["max_payment"] = 999_999_999
        with self.assertRaises(CustodyError):
            appraisal(policy=p)

    def test_independent_recipient_policy(self):
        p = batch_policy()
        p["vaults"][VAULT]["assets"]["00"*32]["recipients"] = [COLD]
        with self.assertRaises(CustodyError):
            appraisal(policy=p)

    def test_wallet_fees_not_treasury_spend(self):
        with self.assertRaises(CustodyError):
            appraisal(proof_changes={"balance": 199_999_999})

    def test_repeated_vault_and_hidden_unallowed_operation(self):
        sends = action(message(), prev=action(message()))
        with self.assertRaises(CustodyError):
            appraisal(req=wallet_request(actions=sends))
        with self.assertRaises(CustodyError):
            appraisal(req=wallet_request(actions=action(message(content=body(op=0x54560008)))))

    def test_expired_policy_and_wallet(self):
        p = batch_policy()
        p["valid_until"] = NOW
        with self.assertRaises(CustodyError):
            appraisal(policy=p)
        for created in (NOW - 3600, NOW + 1):
            with self.assertRaises(CustodyError):
                appraisal(req=wallet_request(created=created))

    def test_bitmap_current_old_and_rotation(self):
        row = Builder().u(0, 1).u(1, 1).u(0, 1021).cell()  # query 1
        dictionary = hashmap({0: row}, width=13)
        for wallet in (wallet_data(current=dictionary), wallet_data(old=dictionary)):
            with self.assertRaises(CustodyError):
                appraisal(wallet=wallet)
        # Old generations are discarded only after the second strict timeout.
        state = highload_state(serialize_boc(wallet_data(old=dictionary, last=NOW-7201)))
        highload_unused(state, query_id=1, created_at=NOW-10, now=NOW)

    def test_replay_bitmap_shape(self):
        dictionary = hashmap({0: Builder().u(0, 10).cell()}, width=13)
        with self.assertRaises(CustodyError):
            highload_state(serialize_boc(wallet_data(current=dictionary)))

    def test_vault_roles_count_and_data_tail(self):
        self.assertEqual(vault_state(serialize_boc(vault_data()), VAULT)["asset_count"], 1)
        from test_highload import extended
        with self.assertRaises(CustodyError):
            vault_state(serialize_boc(extended(vault_data(), bit=True)), VAULT)

    def test_unsigned_and_signed_are_distinct(self):
        from test_highload import submission
        with self.assertRaises(CustodyError):
            wallet, vault = wallet_data(), vault_data()
            appraise_batch(serialize_boc(submission()), wallet_proof=evidence(BUSINESS, wallet),
                            wallet_data=serialize_boc(wallet), vaults={VAULT: (evidence(VAULT, vault), serialize_boc(vault))},
                            policy=batch_policy(), now=NOW, form="submission")
