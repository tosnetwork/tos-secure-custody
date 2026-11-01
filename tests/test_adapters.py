import base64
from dataclasses import replace
import ssl
import unittest
from unittest.mock import Mock, patch
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from tos_custody.adapters.base import Pkcs11Adapter
from tos_custody.adapters.nethsm import NetHsmAdapter, NetHsmConfig
from tos_custody.canonical import canonical, loads
from tos_custody.errors import CustodyError, UnsupportedProfile

class AdapterTests(unittest.TestCase):
    def setUp(self):
        self.key = Ed25519PrivateKey.generate()
        self.config = NetHsmConfig("hsm.example.invalid", "/fixture/ca.pem", "fixturekey", "fixtureoperator",
                                   "TEST-ONLY-PASSWORD", self.key.public_key().public_bytes_raw())
        with patch("tos_custody.adapters.nethsm.ssl.create_default_context"):
            self.adapter = NetHsmAdapter(self.config)
    def response(self, payload):
        data = loads(payload)
        self.assertEqual(data["mode"], "EdDSA")
        return canonical({"signature": base64.b64encode(self.key.sign(base64.b64decode(data["message"]))).decode()})
    def test_exact_message_and_pinned_key(self):
        with patch.object(self.adapter, "_post", side_effect=self.response) as post:
            sig = self.adapter.sign_exact(b"exact preimage", algorithm="Ed25519")
            self.key.public_key().verify(sig, b"exact preimage")
            self.assertEqual(base64.b64decode(loads(post.call_args.args[0])["message"]), b"exact preimage")
    def test_pq_fallback_refused_before_transport(self):
        with patch.object(self.adapter, "_post") as post:
            for algo in ("ML-DSA-44", "SLH-DSA", "Falcon-512", "ed25519"):
                with self.subTest(algo=algo), self.assertRaises(UnsupportedProfile): self.adapter.sign_exact(b"message", algorithm=algo)
            post.assert_not_called()
    def test_wrong_key_signature_rejected(self):
        other = Ed25519PrivateKey.generate()
        response = canonical({"signature": base64.b64encode(other.sign(b"message")).decode()})
        with patch.object(self.adapter, "_post", return_value=response), self.assertRaises(CustodyError):
            self.adapter.sign_exact(b"message", algorithm="Ed25519")
    def test_wrong_message_signature_rejected(self):
        response = canonical({"signature": base64.b64encode(self.key.sign(b"other")).decode()})
        with patch.object(self.adapter, "_post", return_value=response), self.assertRaises(CustodyError):
            self.adapter.sign_exact(b"message", algorithm="Ed25519")
    def test_malformed_response(self):
        for response in (b'{"signature":"AA=="}', b'{"signature":"!"}', b'{"signature":1}', b'{}', b'{"signature":"AA==","signature":"BB=="}'):
            with self.subTest(response=response), patch.object(self.adapter, "_post", return_value=response), self.assertRaises(CustodyError):
                self.adapter.sign_exact(b"message", algorithm="Ed25519")
    def test_input_size_bound(self):
        with patch.object(self.adapter, "_post") as post:
            for message in (b"", b"x" * 65537, "not bytes"):
                with self.subTest(length=len(message)), self.assertRaises(CustodyError):
                    self.adapter.sign_exact(message, algorithm="Ed25519")
            post.assert_not_called()
    def test_tls_verification_not_optional(self):
        context = Mock()
        with patch("tos_custody.adapters.nethsm.ssl.create_default_context", return_value=context) as factory:
            NetHsmAdapter(self.config)
        factory.assert_called_once_with(cafile="/fixture/ca.pem")
        self.assertTrue(context.check_hostname)
        self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
    def test_credentials_not_in_repr(self):
        self.assertNotIn("TEST-ONLY-PASSWORD", repr(self.config))
    def test_key_id_injection_rejected(self):
        for key_id in ("../admin", "x?y=1", "x/y", "x#y"):
            with self.subTest(key_id=key_id), self.assertRaises(CustodyError): replace(self.config, key_id=key_id)
    def test_redirect_is_refused(self):
        connection = Mock()
        connection.getresponse.return_value.status = 302
        with patch("tos_custody.adapters.nethsm.http.client.HTTPSConnection", return_value=connection), self.assertRaises(CustodyError):
            self.adapter._post(b"{}")
        connection.close.assert_called_once()
    def test_response_size_bound(self):
        connection = Mock()
        connection.getresponse.return_value.status = 200
        connection.getresponse.return_value.read.return_value = b"x" * 65537
        with patch("tos_custody.adapters.nethsm.http.client.HTTPSConnection", return_value=connection), self.assertRaises(CustodyError):
            self.adapter._post(b"{}")
    def test_no_hardware_qualification_claim(self):
        self.assertFalse(self.adapter.capabilities.hardware_qualified)
        self.assertFalse(self.adapter.capabilities.production_approved)
    def test_pkcs11_not_a_fake_implementation(self):
        with self.assertRaises(UnsupportedProfile): Pkcs11Adapter().sign_exact(b"message", algorithm="ML-DSA-44")
