"""Experimental NetHSM EdDSA transport with pinned key verification.

Only protocol tests have run. This is NOT a post-quantum HSM, independent policy
engine, hardware attestation verifier, or production-qualified custody service.
No key generation/import/export, administrator operation, or algorithm fallback.
"""
import base64
from dataclasses import dataclass, field
import http.client
import re
import ssl
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from .base import Capabilities
from ..canonical import canonical, exact_keys, loads
from ..errors import CustodyError

@dataclass(frozen=True)
class NetHsmConfig:
    host: str
    ca_file: str
    key_id: str
    operator: str
    password: str = field(repr=False)
    public_key: bytes = field(repr=False)
    port: int = 8443
    timeout: int = 10

    def __post_init__(self):
        if not re.fullmatch(r"[a-zA-Z0-9.-]+", self.host) or not re.fullmatch(r"[a-zA-Z0-9_]+", self.key_id):
            raise CustodyError("invalid NetHSM host or key ID")
        if not re.fullmatch(r"[a-zA-Z0-9_~.-]+", self.operator) or type(self.password) is not str or not self.password:
            raise CustodyError("operator credentials are required")
        if type(self.public_key) is not bytes or len(self.public_key) != 32:
            raise CustodyError("pin an independently verified Ed25519 public key")
        if type(self.port) is not int or not 1 <= self.port <= 65535 or type(self.timeout) is not int or not 1 <= self.timeout <= 30:
            raise CustodyError("invalid connection bounds")
        if type(self.ca_file) is not str or not self.ca_file:
            raise CustodyError("an explicit trusted CA file is required")

class NetHsmAdapter:
    capabilities = Capabilities("nethsm-experimental", frozenset({"Ed25519"}))

    def __init__(self, config):
        self._config = config
        self._tls = ssl.create_default_context(cafile=config.ca_file)
        self._tls.minimum_version = ssl.TLSVersion.TLSv1_2
        self._tls.check_hostname = True
        self._tls.verify_mode = ssl.CERT_REQUIRED

    def _post(self, payload):
        c = self._config
        conn = http.client.HTTPSConnection(c.host, c.port, timeout=c.timeout, context=self._tls)
        credentials = base64.b64encode((c.operator + ":" + c.password).encode()).decode("ascii")
        try:
            conn.request("POST", "/api/v1/keys/" + c.key_id + "/sign", body=payload,
                         headers={"Content-Type": "application/json", "Authorization": "Basic " + credentials})
            response = conn.getresponse()
            # No redirect handling, retries, proxy environment, or credential logging.
            if response.status != 200:
                raise CustodyError("NetHSM signing request failed; details withheld")
            data = response.read(65537)
            if len(data) > 65536:
                raise CustodyError("NetHSM response exceeds bound")
            return data
        except (OSError, http.client.HTTPException):
            raise CustodyError("NetHSM transport failed") from None
        finally:
            conn.close()

    def sign_exact(self, message, *, algorithm):
        self.capabilities.require(algorithm)
        if type(message) is not bytes or not 1 <= len(message) <= 65536:
            raise CustodyError("invalid signing input size")
        payload = canonical({"mode": "EdDSA", "message": base64.b64encode(message).decode("ascii")})
        result = loads(self._post(payload))
        exact_keys(result, {"signature"})
        try:
            signature = base64.b64decode(result["signature"], validate=True)
            if len(signature) != 64:
                raise ValueError("length")
            Ed25519PublicKey.from_public_bytes(self._config.public_key).verify(signature, message)
        except (TypeError, ValueError, InvalidSignature):
            raise CustodyError("NetHSM returned an invalid or wrong-key signature") from None
        return signature
