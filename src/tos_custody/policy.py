"""Diagnostic payment appraisal, not chain-state verification or authorization.

The policy must be provisioned independently of the requesting business host.
This prototype has no persistent spend ledger, finality verifier, or signing gate.
"""
from .canonical import exact_keys, hex_bytes, uint
from .errors import CustodyError

POLICY_KEYS = {"schema", "network_global_id", "vault", "epoch", "next_nonce", "operation",
               "expected_role", "max_control_value", "valid_until", "assets"}


def address(value):
    if type(value) is not str or not value.startswith("0:"):
        raise CustodyError("expected canonical workchain-0 address")
    hex_bytes(value[2:], 32, "account")
    return value


def validate_policy(policy):
    exact_keys(policy, POLICY_KEYS)
    if policy["schema"] != "tos.custody.diagnostic-policy.v1":
        raise CustodyError("unsupported policy schema")
    network = policy["network_global_id"]
    if type(network) is not int or not -(1 << 31) <= network < 1 << 31:
        raise CustodyError("network global ID must fit int32")
    address(policy["vault"])
    address(policy["expected_role"])
    if policy["vault"] == policy["expected_role"]:
        raise CustodyError("role must differ from Vault")
    for name in ("epoch", "next_nonce"):
        uint(policy[name], 64, name)
    uint(policy["max_control_value"], 120, "max_control_value")
    uint(policy["valid_until"], 32, "valid_until")
    if policy["operation"] not in {"submit", "approve"}:
        raise CustodyError("diagnostic policy only supports payments")
    if type(policy["assets"]) is not dict or not 1 <= len(policy["assets"]) <= 16:
        raise CustodyError("invalid asset registry")
    for asset, rules in policy["assets"].items():
        hex_bytes(asset, 32, "asset ID")
        exact_keys(rules, {"max_payment", "recipients", "max_token_attachment"})
        uint(rules["max_payment"], 120, "max_payment")
        uint(rules["max_token_attachment"], 120, "max_token_attachment")
        recipients = rules["recipients"]
        if type(recipients) is not list or not 1 <= len(recipients) <= 256:
            raise CustodyError("invalid recipients")
        for recipient in recipients:
            address(recipient)
        if len(set(recipients)) != len(recipients):
            raise CustodyError("duplicate recipients")
    return policy


def appraise_payment(inspection, policy, *, now):
    validate_policy(policy)
    uint(now, 32, "trusted time")
    if policy["valid_until"] < now:
        raise CustodyError("diagnostic policy has expired")
    if inspection.get("operation") != policy["operation"]:
        raise CustodyError("operation does not match signer role")
    request = inspection.get("request")
    if not request or request["payload"]["kind"] != "payment":
        raise CustodyError("a typed payment is required")
    for request_name, policy_name in (("network_global_id", "network_global_id"), ("vault", "vault"),
                                      ("epoch", "epoch"), ("nonce", "next_nonce")):
        if request[request_name] != policy[policy_name]:
            raise CustodyError("request domain, account, epoch or nonce mismatch")
    if not now < request["deadline"] <= min(now + 3600, policy["valid_until"]):
        raise CustodyError("request deadline is expired or outside policy")
    outer = inspection.get("outer_message")
    if outer is None or outer["source"] != policy["expected_role"]:
        raise CustodyError("an internal message with the expected role address is required")
    if outer["destination"] != policy["vault"] or outer["value_base_units"] > policy["max_control_value"]:
        raise CustodyError("outer message destination or control value violates policy")
    payload = request["payload"]
    rule = policy["assets"].get(payload["asset_id"])
    if not rule or payload["recipient"] not in rule["recipients"]:
        raise CustodyError("asset or recipient is not allowlisted")
    if payload["amount_base_units"] > rule["max_payment"] or payload["token_attachment_base_units"] > rule["max_token_attachment"]:
        raise CustodyError("payment or attachment exceeds policy")
    return {"diagnostic_policy_match": True, "signing_authorized": False,
            "request_cell_hash": request["request_cell_hash"],
            "warning": "Sender fields are not authentication. No finality/state proof or wallet signing profile was verified."}
