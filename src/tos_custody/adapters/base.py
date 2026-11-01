"""Explicit signing capabilities: no algorithm negotiation or fallback."""
from dataclasses import dataclass
from typing import Protocol
from ..errors import UnsupportedProfile

@dataclass(frozen=True)
class Capabilities:
    backend: str
    algorithms: frozenset[str]
    hardware_qualified: bool = False
    production_approved: bool = False

    def require(self, algorithm):
        if algorithm not in self.algorithms:
            raise UnsupportedProfile("algorithm not supported; fallback is forbidden")

class SigningAdapter(Protocol):
    capabilities: Capabilities
    def sign_exact(self, message: bytes, *, algorithm: str) -> bytes: ...

class Pkcs11Adapter:
    """Reserved workstream. Never silently substitutes a software key."""
    capabilities = Capabilities("pkcs11-unimplemented", frozenset())
    def sign_exact(self, message: bytes, *, algorithm: str) -> bytes:
        raise UnsupportedProfile("PKCS#11 adapter has not been implemented or hardware-qualified")
