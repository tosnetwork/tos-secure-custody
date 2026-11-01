import unittest
from tos_custody.boc import serialize_boc
from tos_custody.canonical import canonical
from tos_custody.errors import CustodyError, UnsupportedProfile
from tos_custody.offline import OfflineSigner, check_bundle, inspect_bundle
from tos_custody.policy import appraise_payment
from tos_custody.vault import inspect_boc
from helpers import NOW, GUARDIAN, body, request, payload, internal, policy, bundle

class PolicyOfflineTests(unittest.TestCase):
    def test_valid_diagnostic_never_authorizes_signing(self):
        result = check_bundle(canonical(bundle()), policy(), now=NOW)
        self.assertTrue(result["diagnostic"]["diagnostic_policy_match"])
        self.assertFalse(result["diagnostic"]["signing_authorized"])
    def test_substituted_recipient(self):
        raw = canonical(bundle(internal(message_body=body(req=request(pay=payload(recipient=GUARDIAN))))))
        with self.assertRaises(CustodyError): check_bundle(raw, policy(), now=NOW)
    def test_substituted_amount(self):
        raw = canonical(bundle(internal(message_body=body(req=request(pay=payload(amount=3_000_000_000))))))
        with self.assertRaises(CustodyError): check_bundle(raw, policy(), now=NOW)
    def test_wrong_chain_epoch_nonce(self):
        for params in ({"network": 1}, {"epoch": 8}, {"nonce": 43}):
            raw = canonical(bundle(internal(message_body=body(req=request(**params)))))
            with self.subTest(params=params), self.assertRaises(CustodyError): check_bundle(raw, policy(), now=NOW)
    def test_expired_and_excessive_deadline(self):
        for deadline in (NOW - 1, NOW, NOW + 3601):
            raw = canonical(bundle(internal(message_body=body(req=request(deadline=deadline)))))
            with self.subTest(deadline=deadline), self.assertRaises(CustodyError): check_bundle(raw, policy(), now=NOW)
    def test_wrong_or_absent_role_source(self):
        for source in (GUARDIAN, None):
            raw = canonical(bundle(internal(source=source)))
            with self.subTest(source=source), self.assertRaises(CustodyError): check_bundle(raw, policy(), now=NOW)
    def test_excess_control_value(self):
        with self.assertRaises(CustodyError): check_bundle(canonical(bundle(internal(value=1_000_000_000))), policy(), now=NOW)
    def test_cross_role_operation(self):
        with self.assertRaises(CustodyError): check_bundle(canonical(bundle(internal(message_body=body(op=0x54560002)))), policy(), now=NOW)
    def test_body_only_cannot_pass_appraisal(self):
        decoded = inspect_boc(serialize_boc(body()), form="body")
        with self.assertRaises(CustodyError): appraise_payment(decoded, policy(), now=NOW)
    def test_untrusted_host_display_forbidden(self):
        b = bundle()
        b["display"] = "Send 0 TOS to a trusted recipient"
        with self.assertRaises(CustodyError): inspect_bundle(canonical(b))
    def test_secret_fields_forbidden(self):
        for key in ("seed", "private_key", "signature", "approved"):
            b = bundle()
            b[key] = "not-a-real-secret"
            with self.subTest(key=key), self.assertRaises(CustodyError): inspect_bundle(canonical(b))
    def test_boolean_nonce_forbidden(self):
        p = policy()
        p["next_nonce"] = True
        with self.assertRaises(CustodyError): check_bundle(canonical(bundle()), p, now=NOW)
    def test_unknown_policy_field(self):
        p = policy()
        p["skip_checks"] = True
        with self.assertRaises(CustodyError): check_bundle(canonical(bundle()), p, now=NOW)
    def test_expired_policy(self):
        p = policy()
        p["valid_until"] = NOW - 1
        with self.assertRaises(CustodyError): check_bundle(canonical(bundle()), p, now=NOW)
    def test_no_production_signing_even_with_approval_flag(self):
        with self.assertRaises(UnsupportedProfile): OfflineSigner().sign(canonical(bundle()), approved=True)
    def test_unknown_asset(self):
        cell = internal(message_body=body(req=request(pay=payload(asset=9, attachment=10))))
        with self.assertRaises(CustodyError): check_bundle(canonical(bundle(cell)), policy(), now=NOW)
