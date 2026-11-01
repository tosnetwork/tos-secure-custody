"""Independently provisioned, bounded batch appraisal using proven account data.

Governance requires independently allowlisted request/preimage hashes. Repeated
actions to one Vault are refused. Signing remains disabled.
"""
from .canonical import canonical, exact_keys, hex_bytes, uint
from .errors import CustodyError
from .highload import inspect_highload
from .multisig import inspect_multisig, inspect_multisig_state
from .policy import address
from .state import highload_state, highload_unused, vault_state
from .verification import verify_highload, verify_multisig
from hashlib import sha256


def validate_policy(policy):
    exact_keys(policy, {"schema", "anchor_digest", "network_global_id", "wallet", "wallet_profile",
                        "wallet_code_hash", "valid_until", "max_state_age", "fee_reserve", "vaults",
                        "allowed_configuration_preimages"})
    if policy["schema"] != "tos.custody.batch-policy.v1" or policy["wallet_profile"] not in ("highload", "multisig"):
        raise CustodyError("unsupported batch policy")
    for field in ("anchor_digest", "wallet_code_hash"):
        hex_bytes(policy[field], 32, field)
    address(policy["wallet"])
    network = policy["network_global_id"]
    if type(network) is not int or not -(1 << 31) <= network < 1 << 31:
        raise CustodyError("invalid policy network")
    uint(policy["valid_until"], 32, "policy expiry")
    uint(policy["fee_reserve"], 120, "wallet fee reserve")
    if type(policy["allowed_configuration_preimages"]) is not list or len(policy["allowed_configuration_preimages"]) > 64:
        raise CustodyError("invalid configuration preimage allowlist")
    for value in policy["allowed_configuration_preimages"]:
        hex_bytes(value, 32, "configuration preimage")
    if type(policy["max_state_age"]) is not int or not 1 <= policy["max_state_age"] <= 3600:
        raise CustodyError("invalid policy state age")
    if type(policy["vaults"]) is not dict or not 1 <= len(policy["vaults"]) <= 16:
        raise CustodyError("invalid batch Vault registry")
    for vault, rule in policy["vaults"].items():
        address(vault)
        exact_keys(rule, {"code_hash", "role", "operations", "max_control_value", "assets", "allowed_governance_requests"})
        hex_bytes(rule["code_hash"], 32, "Vault code hash")
        if rule["role"] not in ("business", "guardian", "pauser", "cold_administrator"):
            raise CustodyError("invalid wallet role")
        if (type(rule["operations"]) is not list or not rule["operations"]
                or any(type(op) is not str for op in rule["operations"])
                or len(set(rule["operations"])) != len(rule["operations"])
                or any(op not in ("submit", "approve", "pause", "cancel_payment", "expire_payment", "schedule",
                                 "apply", "veto", "expire_admin") for op in rule["operations"])):
            raise CustodyError("unsupported batch operation policy")
        if type(rule["allowed_governance_requests"]) is not list or len(rule["allowed_governance_requests"]) > 64:
            raise CustodyError("invalid governance request allowlist")
        for value in rule["allowed_governance_requests"]:
            hex_bytes(value, 32, "governance request")
        uint(rule["max_control_value"], 120, "maximum wallet control value")
        if type(rule["assets"]) is not dict or len(rule["assets"]) > 16:
            raise CustodyError("invalid independent asset rules")
        for asset, limits in rule["assets"].items():
            hex_bytes(asset, 32, "asset ID")
            exact_keys(limits, {"max_payment", "cumulative_limit", "max_attachment", "recipients"})
            for name in ("max_payment", "cumulative_limit", "max_attachment"):
                uint(limits[name], 120, name)
            if type(limits["recipients"]) is not list or not 1 <= len(limits["recipients"]) <= 256:
                raise CustodyError("invalid independent recipient rules")
            for recipient in limits["recipients"]:
                address(recipient)
            if len(set(limits["recipients"])) != len(limits["recipients"]):
                raise CustodyError("duplicate recipient")
    return policy


def _control(body, state, rule, wallet, now, policy):
    op, role = body["operation"], rule["role"]
    if op in ("schedule", "apply"):
        req = body["request"]
        if (role != "cold_administrator" or req["epoch"] != state["epoch"]
                or req["nonce"] != state["admin_nonce"] or req["nonce"] == (1 << 64)-1
                or req["request_cell_hash"] not in rule["allowed_governance_requests"]
                or not now < req["deadline"] <= min(now+777600, policy["valid_until"])):
            raise CustodyError("governance intent, role, counter or expiry violates policy")
        if req["payload"]["kind"] == "set_roles" and req["payload"]["cold_administrator"] != state["roles"]["cold_administrator"]:
            raise CustodyError("Vault cold administrator is immutable")
        if op == "schedule" and (state["pending_admin_hash"] is not None or req["deadline"] <= now+172800):
            raise CustodyError("governance is already pending or lacks the mandatory delay")
        if op == "apply" and (state["pending_admin_hash"] != req["request_cell_hash"] or now < state["admin_ready_at"]):
            raise CustodyError("governance does not match the queued intent or is not ready")
        return req["deadline"]
    payment = op in ("cancel_payment", "expire_payment")
    nonce = state["payment_nonce"] if payment else state["admin_nonce"]
    if body["epoch"] != state["epoch"] or body["nonce"] != nonce or nonce == (1 << 64)-1:
        raise CustodyError("control epoch or nonce mismatch")
    if op == "pause":
        if role not in ("guardian", "pauser", "cold_administrator") or state["paused"]:
            raise CustodyError("pause role or state mismatch")
    elif payment:
        pending = state["pending_payment"]
        if pending is None or op == "cancel_payment" and role not in ("business", "guardian"):
            raise CustodyError("payment cancellation role or pending state mismatch")
        if op == "expire_payment" and now < pending["deadline"]:
            raise CustodyError("pending payment has not expired")
    else:
        pending = state["pending_admin"]
        if pending is None:
            raise CustodyError("no queued governance intent")
        if op == "expire_admin" and now < pending["deadline"]:
            raise CustodyError("queued governance has not expired")
        if op == "veto":
            if role not in ("guardian", "pauser", "cold_administrator"):
                raise CustodyError("role cannot veto governance")
            change = pending["payload"]
            if role != "cold_administrator" and change["kind"] == "set_roles" and change[role] != wallet:
                raise CustodyError("retiring role cannot veto its own replacement")
    return policy["valid_until"]


def _bind(proof, raw, *, account, code, policy, target, now):
    if (proof.address != account or proof.anchor_digest != policy["anchor_digest"] or proof.target != target
            or proof.code_hash != code or proof.fresh is not True
            or not now - policy["max_state_age"] <= proof.account_time <= proof.block_time <= now):
        raise CustodyError("account proof does not match policy, block, freshness or deployment")
    proof.bind_data(raw)


def appraise_batch(raw, *, wallet_proof, wallet_data, vaults, policy, now, verifier=None, form="request"):
    """vaults maps addresses to (ProvenAccount, data BOC), from a local proof session.

    Policy and native-verifier configuration must be provisioned independently of
    the business host. Serialized inspections or host-provided verdicts are not inputs.
    """
    validate_policy(policy)
    uint(now, 32, "trusted time")
    if now >= policy["valid_until"]:
        raise CustodyError("batch policy expired")
    _bind(wallet_proof, wallet_data, account=policy["wallet"], code=policy["wallet_code_hash"],
          policy=policy, target=wallet_proof.target, now=now)
    signed = form in ("submission", "relay")
    if signed and verifier is None:
        raise CustodyError("signed batch requires cryptographic verification")
    if policy["wallet_profile"] == "highload":
        state = highload_state(wallet_data)
        inspection = inspect_highload(raw, form=form)
        if (inspection["wallet"] != policy["wallet"] or inspection["subwallet_id"] != state["subwallet_id"]
                or inspection["timeout"] != state["timeout"]):
            raise CustodyError("wallet identity/subwallet/timeout differs from proven state")
        highload_unused(state, query_id=inspection["query_id"], created_at=inspection["created_at"], now=now)
        if signed:
            verify_highload(raw, public_key=state["public_key"], verifier=verifier, form=form)
        slot = "highload:" + str(inspection["query_id"])
        expiry = inspection["expires_at_exclusive"]
    else:
        state = inspect_multisig_state(wallet_data)
        context = {"network_global_id": policy["network_global_id"], "account": policy["wallet"], "seqno": state["seqno"]}
        inspection = inspect_multisig(raw, context=context, state_raw=wallet_data, form=form)
        if (inspection["operation"] != "execute"
                and inspection["signing_message_hex"] not in policy["allowed_configuration_preimages"]):
            raise CustodyError("multisig configuration preimage is not independently approved")
        if inspection["valid_until_inclusive"] < now:
            raise CustodyError("multisig request expired")
        if signed:
            verify_multisig(raw, context=context, state_raw=wallet_data, verifier=verifier, form=form)
        slot = "multisig:" + str(state["seqno"])
        expiry = inspection["valid_until_inclusive"] + 1
    if inspection["network_global_id"] != policy["network_global_id"] or expiry > policy["valid_until"]:
        raise CustodyError("wallet network or expiry violates independent policy")
    seen, charges, wallet_value = set(), [], 0
    valid_until = min(expiry, policy["valid_until"], wallet_proof.account_time + policy["max_state_age"])
    if inspection.get("operation") == "configure":
        for vault, rule in policy["vaults"].items():
            if vault not in vaults:
                raise CustodyError("cold configuration requires proven Vault authority")
            proof, data = vaults[vault]
            _bind(proof, data, account=vault, code=rule["code_hash"], policy=policy, target=wallet_proof.target, now=now)
            state = vault_state(data, vault)
            if rule["role"] != "cold_administrator" or state["roles"]["cold_administrator"] != policy["wallet"]:
                raise CustodyError("configured multisig is not the proven cold authority")
            valid_until = min(valid_until, proof.account_time + policy["max_state_age"])
    for action in inspection["actions"]:
        message, body = action["message"], action["vault_body"]
        vault = message["destination"]
        if vault in seen or vault not in policy["vaults"] or vault not in vaults:
            raise CustodyError("repeated or unprovisioned Vault in batch")
        seen.add(vault)
        rule = policy["vaults"][vault]
        proof, data = vaults[vault]
        _bind(proof, data, account=vault, code=rule["code_hash"], policy=policy, target=wallet_proof.target, now=now)
        vault_state_data = vault_state(data, vault)
        valid_until = min(valid_until, proof.account_time + policy["max_state_age"])
        if vault_state_data["roles"][rule["role"]] != policy["wallet"]:
            raise CustodyError("wallet is not the role in proven Vault state")
        operation = body["operation"]
        if operation not in rule["operations"] or message["value_base_units"] > rule["max_control_value"]:
            raise CustodyError("operation or wallet control value violates policy")
        wallet_value += message["value_base_units"]
        if operation not in ("submit", "approve"):
            valid_until = min(valid_until, _control(body, vault_state_data, rule, policy["wallet"], now, policy))
            continue
        expected_role = "business" if operation == "submit" else "guardian"
        request, payload = body["request"], body["request"]["payload"]
        valid_until = min(valid_until, request["deadline"])
        if (rule["role"] != expected_role or vault_state_data["paused"] or payload["kind"] != "payment"
                or request["epoch"] != vault_state_data["epoch"]
                or request["nonce"] != vault_state_data["payment_nonce"] or request["nonce"] == (1 << 64) - 1
                or not now < request["deadline"] <= min(now + 3600, policy["valid_until"])):
            raise CustodyError("payment role, state, nonce, epoch or deadline mismatch")
        pending = vault_state_data["pending_payment_hash"]
        if (operation == "submit" and pending is not None
                or operation == "approve" and pending != request["request_cell_hash"]):
            raise CustodyError("payment does not match proven pending state")
        asset = payload["asset_id"]
        limits, record = rule["assets"].get(asset), vault_state_data["assets"].get(asset)
        if (not limits or not record or not record["enabled"] or payload["recipient"] not in limits["recipients"]
                or payload["token_attachment_base_units"] > limits["max_attachment"]):
            raise CustodyError("asset, recipient or Token attachment not permitted")
        spent = 0 if now >= record["window_start"] + 86400 else record["window_spent"]
        remaining = min(limits["cumulative_limit"], record["cumulative_limit"]) - record["cumulative_spent"]
        remaining = min(remaining, record["window_limit"] - spent)
        amount = payload["amount_base_units"]
        if amount > min(remaining, record["per_payment"], limits["max_payment"]):
            raise CustodyError("payment exceeds independent or proven treasury budgets")
        charges.append({"vault": vault, "asset": asset, "amount": amount, "remaining": remaining})
    if wallet_value + policy["fee_reserve"] > wallet_proof.balance:
        raise CustodyError("wallet attachments and fee reserve exceed its proven balance")
    return {"schema": "tos.custody.batch-appraisal.v1", "policy_digest": sha256(canonical(policy)).hexdigest(),
            "anchor_digest": policy["anchor_digest"], "target": wallet_proof.target,
            "wallet": policy["wallet"], "wallet_code_hash": policy["wallet_code_hash"],
            "intent": inspection["signing_message_hex"], "slot": slot, "expires_at": expiry,
            "appraised_at": now, "valid_until": valid_until,
            "charges": charges, "wallet_value": wallet_value, "cryptographically_verified": signed,
            "state_authenticated": True, "replay_checked": True, "diagnostic_policy_match": True,
            "signing_authorized": False,
            "warning": "Appraisal is not settlement. Atomic durable reservation and signing gates remain separate."}
