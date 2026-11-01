"""Pinned native proof verifier boundary. RPC JSON is never a verdict.

The operator provisions the executable hash and anchor independently. Offline
material is untrusted; it is passed to the native verifier for every invocation.
"""
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
import subprocess
import tempfile
import os
import json

from .canonical import canonical, exact_keys, hex_bytes, loads, uint, _pairs, _forbidden
from .errors import CustodyError
from .boc import parse_boc

MAX_VERDICT = 2 * 1024 * 1024


def _verdict(raw):
    # A full 64-member account includes a large base64 state BOC. Native has
    # already authenticated it; this adapter only consumes its committed hashes.
    if len(raw) > MAX_VERDICT:
        raise CustodyError("native verdict exceeds custody output bound")
    try:
        result = json.loads(raw, object_pairs_hook=_pairs, parse_float=_forbidden, parse_constant=_forbidden)
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise CustodyError("invalid native verifier JSON") from exc
    if type(result) is not dict:
        raise CustodyError("invalid native verdict object")
    for field in ("get_methods", "config_params", "execution_context", "chain"):
        result.pop(field, None)
    if type(result.get("account")) is dict:
        result["account"].pop("state_boc", None)
    canonical(result)
    return result


def block_id(value):
    exact_keys(value, {"workchain", "shard", "seqno", "root_hash", "file_hash"})
    if value["workchain"] != -1 or type(value["workchain"]) is not int or value["shard"] != "8000000000000000":
        raise CustodyError("expected full masterchain block identity")
    uint(value["seqno"], 32, "block sequence")
    for name in ("root_hash", "file_hash"):
        hex_bytes(value[name], 32, name)
    return dict(value)


def account_address(value):
    if type(value) is not str or (value[:3] != "-1:" and value[:2] != "0:"):
        raise CustodyError("invalid proven account address")
    hex_bytes(value.split(":", 1)[1], 32, "account")
    return value


def initialize_native_state(path, anchor):
    """Explicit anchor-only enrollment. Never called as missing-file recovery."""
    exact_keys(anchor, {"kind", "workchain", "shard", "seqno", "root_hash", "file_hash"})
    block_id({key: value for key, value in anchor.items() if key != "kind"})
    if anchor["kind"] not in ("zerostate", "key_block") or (anchor["kind"] == "zerostate") != (anchor["seqno"] == 0):
        raise CustodyError("invalid trusted anchor kind")
    path = Path(path).absolute()
    raw = canonical({"interface": "tos-proof-verify-state/1", "anchor": anchor})
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(raw)
        handle.flush()
        os.fsync(handle.fileno())
    directory = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    return {"initialized": True, "anchor_digest": sha256(canonical(anchor)).hexdigest()}


@dataclass(frozen=True)
class ProvenAccount:
    address: str
    target: dict
    anchor_digest: str
    code_hash: str
    data_hash: str
    balance: int
    account_time: int
    block_time: int
    fresh: bool

    def bind_data(self, raw):
        root = parse_boc(raw, max_cells=1024, max_depth=96)
        if root.commitment(max_depth=96)[1].hex() != self.data_hash:
            raise CustodyError("supplied data differs from the proven account data")
        return root


class ProofVerifier:
    def __init__(self, *, executable, executable_sha256, anchor):
        if not isinstance(executable, (str, Path)):
            raise CustodyError("invalid native verifier path")
        self.executable = Path(executable)
        if not self.executable.is_absolute() or not self.executable.is_file():
            raise CustodyError("configure an absolute native verifier executable")
        hex_bytes(executable_sha256, 32, "verifier digest")
        self.executable_sha256 = executable_sha256
        exact_keys(anchor, {"kind", "workchain", "shard", "seqno", "root_hash", "file_hash"})
        block_id({key: value for key, value in anchor.items() if key != "kind"})
        if anchor["kind"] not in ("zerostate", "key_block") or (anchor["kind"] == "zerostate") != (anchor["seqno"] == 0):
            raise CustodyError("invalid trusted anchor kind")
        self.anchor = dict(anchor)
        self.anchor_digest = sha256(canonical(anchor)).hexdigest()

    def verify_account(self, *, account, target, material, now, max_age, expected_code_hash=None,
                       historical=False, state_file=None, config_params=(), get_methods=()):
        """Historical mode rechecks evidence but never marks it fresh.

        Live mode needs persistent native state and exact target; the native core
        verifies descent, finality and wall-clock freshness. Local checks additionally
        bound both target and shard-account age using the independently supplied time.
        """
        account_address(account)
        if type(historical) is not bool:
            raise CustodyError("invalid proof mode")
        target = block_id(target)
        uint(now, 32, "trusted time")
        if type(max_age) is not int or not 1 <= max_age <= 3600:
            raise CustodyError("custody proof age must be 1..3600 seconds")
        if expected_code_hash is not None:
            hex_bytes(expected_code_hash, 32, "expected account code")
        if not historical and (state_file is None or not Path(state_file).is_file()):
            raise CustodyError("live verification requires operator-provisioned persistent state")
        if sha256(self.executable.read_bytes()).hexdigest() != self.executable_sha256:
            raise CustodyError("native verifier executable hash changed")
        request = {"mode": "historical" if historical else "live", "target": target, "account": account}
        if (len(config_params) > 64 or len(set(config_params)) != len(config_params)
                or any(type(index) is not int or not 0 <= index < 1 << 31 for index in config_params)):
            raise CustodyError("invalid requested configuration parameters")
        if config_params:
            request["config_params"] = list(config_params)
        if get_methods:
            if len(get_methods) > 16 or any(type(name) is not str or not name.isidentifier() or not name.isascii()
                                           for name in get_methods):
                raise CustodyError("invalid requested native get-methods")
            request["get_methods"] = [{"method": name} for name in get_methods]
        if not historical:
            request["max_age_seconds"] = max_age
        request_raw = canonical(request)
        with tempfile.TemporaryDirectory(prefix="custody-proof-") as directory:
            root = Path(directory)
            (root / "anchor.json").write_bytes(canonical(self.anchor))
            (root / "request.json").write_bytes(request_raw)
            command = [str(self.executable), "verify", "--anchor", str(root / "anchor.json"),
                       "--request", str(root / "request.json"), "--material", str(Path(material).resolve())]
            if not historical:
                command += ["--state", str(Path(state_file).resolve())]
            try:
                with (root / "result.json").open("w+b") as output:
                    run = subprocess.run(command, stdout=output, stderr=subprocess.DEVNULL,
                                         timeout=60, check=False)
                    output.seek(0)
                    result_raw = output.read(MAX_VERDICT + 1)
            except (OSError, subprocess.TimeoutExpired) as exc:
                raise CustodyError("native proof verifier unavailable") from exc
        if run.returncode != 0:
            raise CustodyError("native proof verifier refused material")
        result = _verdict(result_raw)
        if type(result) is not dict or result.get("status") != "verified" or result.get("interface") != "tos-proof-verify/1":
            raise CustodyError("invalid native proof verdict")
        if (result.get("anchor") != self.anchor or result.get("request_sha256") != sha256(request_raw).hexdigest()
                or result.get("mode") != request["mode"]):
            raise CustodyError("proof verdict anchor/request/mode mismatch")
        actual = result.get("target")
        if type(actual) is not dict or any(actual.get(key) != value for key, value in target.items()):
            raise CustodyError("proof verdict targets another full block identity")
        record = result.get("account")
        if (type(record) is not dict or record.get("address") != account or record.get("exists") is not True
                or record.get("active") is not True):
            raise CustodyError("account is absent, frozen, uninitialized or mismatched")
        for name in ("code_hash", "data_hash"):
            hex_bytes(record.get(name), 32, name)
        if expected_code_hash is not None and record["code_hash"] != expected_code_hash:
            raise CustodyError("proven deployment code differs from operator-pinned code")
        balance = record.get("balance")
        if type(balance) is not str or not balance.isascii() or not balance.isdigit() or len(balance) > 37:
            raise CustodyError("invalid proven account balance")
        uint(int(balance), 120, "proven wallet balance")
        block_time, account_time = actual.get("gen_utime"), record.get("gen_utime")
        uint(block_time, 32, "block time")
        uint(account_time, 32, "account shard time")
        live = result.get("live")
        if not historical and (type(live) is not dict or not now - max_age <= account_time <= block_time <= now
                               or live.get("max_age_seconds") != max_age):
            raise CustodyError("proof state is stale or in the future")
        return ProvenAccount(account, target, self.anchor_digest, record["code_hash"], record["data_hash"],
                             int(balance), account_time, block_time, not historical)
