"""TCJ-1: bounded ASCII JSON; not an implementation of RFC 8785/JCS.

No floats, duplicate keys, Unicode, non-finite numbers, or implicit coercion.
It is an off-chain transport encoding, NEVER a TOS wallet signing preimage.
"""
import json
from .errors import CustodyError

MAX_JSON = 131072

def _pairs(items):
    out = {}
    for key, value in items:
        if key in out:
            raise CustodyError("duplicate JSON key")
        out[key] = value
    return out

def _forbidden(_):
    raise CustodyError("floating-point and non-finite numbers are forbidden")

def _check(value, depth=0):
    if depth > 16:
        raise CustodyError("JSON nesting limit exceeded")
    if value is None or type(value) is bool:
        return
    if type(value) is int:
        if abs(value) >= 1 << 256:
            raise CustodyError("JSON integer exceeds 256 bits")
    elif type(value) is str:
        if not value.isascii() or any(ord(c) < 32 or ord(c) == 127 for c in value):
            raise CustodyError("JSON strings must contain printable ASCII only")
        if len(value) > MAX_JSON:
            raise CustodyError("JSON string too long")
    elif type(value) is list:
        if len(value) > 1024:
            raise CustodyError("JSON list too long")
        for item in value:
            _check(item, depth + 1)
    elif type(value) is dict:
        if len(value) > 128:
            raise CustodyError("too many JSON object keys")
        for key, item in value.items():
            if type(key) is not str:
                raise CustodyError("JSON keys must be strings")
            _check(key, depth + 1)
            _check(item, depth + 1)
    else:
        raise CustodyError("unsupported JSON type")

def canonical(value):
    _check(value)
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    if len(raw) > MAX_JSON:
        raise CustodyError("JSON size limit exceeded")
    return raw

def loads(raw):
    if not isinstance(raw, (str, bytes)) or len(raw) > MAX_JSON:
        raise CustodyError("invalid JSON input or size")
    try:
        obj = json.loads(raw, object_pairs_hook=_pairs, parse_float=_forbidden, parse_constant=_forbidden)
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise CustodyError("invalid strict JSON") from exc
    canonical(obj)
    return obj

def exact_keys(value, keys):
    if type(value) is not dict or set(value) != set(keys):
        raise CustodyError("unknown or missing fields")

def uint(value, bits, name):
    if type(value) is not int or not 0 <= value < 1 << bits:
        raise CustodyError(f"{name} must be uint{bits}")
    return value

def hex_bytes(value, size, name):
    if type(value) is not str or len(value) != size * 2 or any(c not in "0123456789abcdef" for c in value):
        raise CustodyError(f"{name} must be lowercase hexadecimal ({size} bytes)")
    return bytes.fromhex(value)
