import concurrent.futures
import unittest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from tos_custody.attestation import DOMAIN, ChallengeBook, ExpectedBindings, verify_fixture, verify_hardware
from tos_custody.canonical import canonical
from tos_custody.errors import CustodyError, UnsupportedProfile
from helpers import NOW

class AttestationTests(unittest.TestCase):
    def setUp(self):
        self.key = Ed25519PrivateKey.generate()
        self.public = self.key.public_key().public_bytes_raw()
        self.claims = {"schema": "tos.custody.attestation.software-fixture.v1",
                       "device_id": "fixture-device-1", "audience": "fixture-verifier",
                       "nonce": "01" * 32, "intent_hash": "02" * 32, "policy_hash": "03" * 32,
                       "signer_key_hash": "04" * 32, "firmware_hash": "05" * 32, "boot_hash": "06" * 32,
                       "security_version": 2, "counter": 8, "issued_at": NOW, "expires_at": NOW + 30,
                       "secure_boot": True, "debug_enabled": False}
        self.book = ChallengeBook()
        self.book.issue(self.claims["nonce"], expires_at=NOW + 30)
        self.kwargs = {"expected": ExpectedBindings("fixture-device-1", "fixture-verifier", "02" * 32, "03" * 32, "04" * 32),
                       "pinned_key": self.public, "allowed_measurements": {("05" * 32, "06" * 32)},
                       "min_security_version": 2, "revoked_devices": set(), "challenges": self.book,
                       "now": NOW, "allow_software_fixture": True}
    def envelope(self, claims=None):
        c = self.claims if claims is None else claims
        return {"claims": c, "signature": self.key.sign(DOMAIN + canonical(c)).hex()}
    def test_fixture_is_not_hardware_proof(self):
        result = verify_fixture(self.envelope(), **self.kwargs)
        self.assertTrue(result["valid_software_fixture"])
        self.assertFalse(result["hardware_assurance"])
        self.assertFalse(result["production_authorized"])
    def test_default_disallows_software_claims(self):
        self.kwargs.pop("allow_software_fixture")
        with self.assertRaises(UnsupportedProfile): verify_fixture(self.envelope(), **self.kwargs)
    def test_production_hardware_verifier_disabled(self):
        with self.assertRaises(UnsupportedProfile): verify_hardware(self.envelope())
    def test_replay(self):
        e = self.envelope()
        verify_fixture(e, **self.kwargs)
        with self.assertRaises(CustodyError): verify_fixture(e, **self.kwargs)
    def test_atomic_replay_under_concurrency(self):
        e = self.envelope()
        def attempt(_):
            try:
                verify_fixture(e, **self.kwargs)
                return 1
            except CustodyError:
                return 0
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            self.assertEqual(sum(pool.map(attempt, range(24))), 1)
    def test_wrong_binding(self):
        for field in ("device_id", "audience", "intent_hash", "policy_hash", "signer_key_hash"):
            c = dict(self.claims)
            c[field] = "other-device" if field in {"device_id", "audience"} else "ff" * 32
            with self.subTest(field=field), self.assertRaises(CustodyError): verify_fixture(self.envelope(c), **self.kwargs)
    def test_revoked_device(self):
        self.kwargs["revoked_devices"] = {"fixture-device-1"}
        with self.assertRaises(CustodyError): verify_fixture(self.envelope(), **self.kwargs)
    def test_wrong_key(self):
        self.kwargs["pinned_key"] = Ed25519PrivateKey.generate().public_key().public_bytes_raw()
        with self.assertRaises(CustodyError): verify_fixture(self.envelope(), **self.kwargs)
    def test_tampered_claims_and_nonce_not_consumed(self):
        e = self.envelope()
        e["claims"] = dict(e["claims"], counter=9)
        with self.assertRaises(CustodyError): verify_fixture(e, **self.kwargs)
        self.assertTrue(verify_fixture(self.envelope(), **self.kwargs)["valid_software_fixture"])
    def test_expired_future_overlong(self):
        for update in ({"expires_at": NOW}, {"issued_at": NOW + 1}, {"expires_at": NOW + 61}):
            with self.subTest(update=update), self.assertRaises(CustodyError):
                verify_fixture(self.envelope(dict(self.claims, **update)), **self.kwargs)
    def test_security_version_rollback(self):
        with self.assertRaises(CustodyError): verify_fixture(self.envelope(dict(self.claims, security_version=1)), **self.kwargs)
    def test_unapproved_firmware(self):
        with self.assertRaises(CustodyError): verify_fixture(self.envelope(dict(self.claims, firmware_hash="ff" * 32)), **self.kwargs)
    def test_debug_and_secureboot_flags(self):
        for update in ({"debug_enabled": True}, {"secure_boot": False}, {"secure_boot": 1}):
            with self.subTest(update=update), self.assertRaises(CustodyError):
                verify_fixture(self.envelope(dict(self.claims, **update)), **self.kwargs)
    def test_counter_rollback(self):
        verify_fixture(self.envelope(), **self.kwargs)
        c = dict(self.claims, nonce="ff" * 32, counter=7)
        self.book.issue(c["nonce"], expires_at=NOW + 30)
        with self.assertRaises(CustodyError): verify_fixture(self.envelope(c), **self.kwargs)
    def test_unknown_challenge(self):
        with self.assertRaises(CustodyError): verify_fixture(self.envelope(dict(self.claims, nonce="aa" * 32)), **self.kwargs)
    def test_unknown_claim(self):
        with self.assertRaises(CustodyError): verify_fixture(self.envelope(dict(self.claims, trusted=True)), **self.kwargs)
