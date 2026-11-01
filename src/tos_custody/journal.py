"""Durable conservative reservations with externally retained hash-chain tips.

No timeout/refund automatically releases treasury reservations. This is local
coordination, not chain settlement, hardware anti-rollback, or signing authority.
"""
from hashlib import sha256
from contextlib import closing
import os
from pathlib import Path
import sqlite3

from .canonical import canonical, hex_bytes, loads, uint
from .errors import CustodyError
from .policy import address
from .proofs import block_id

MAX_EVENTS = 10000


def event_hash(previous, payload):
    return sha256(b"TOS-CUSTODY-JOURNAL-v1\x00" + bytes.fromhex(previous) + canonical(payload)).hexdigest()


class Journal:
    @staticmethod
    def create(path, *, anchor_digest):
        """Explicit provisioning only. Existing or missing reopened stores are never reset."""
        hex_bytes(anchor_digest, 32, "anchor digest")
        path = Path(path).absolute()
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.close(fd)
        with closing(sqlite3.connect(path)) as db:
            with db:
                db.execute("PRAGMA synchronous=FULL")
                db.execute("CREATE TABLE events (revision INTEGER PRIMARY KEY, payload TEXT NOT NULL, digest TEXT NOT NULL)")
                payload = {"type": "genesis", "anchor_digest": anchor_digest}
                digest = event_hash("00" * 32, payload)
                db.execute("INSERT INTO events VALUES (0, ?, ?)", (canonical(payload).decode(), digest))
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
        return {"revision": 0, "digest": digest}

    def __init__(self, path, *, anchor_digest):
        self.path = Path(path).absolute()
        hex_bytes(anchor_digest, 32, "anchor digest")
        self.anchor_digest = anchor_digest
        if not self.path.is_file() or self.path.is_symlink():
            raise CustodyError("reservation journal missing or symlinked; provisioning/recovery required")

    def _connect(self):
        # mode=rw prevents a missing journal from becoming an empty replacement.
        db = sqlite3.connect(self.path.as_uri() + "?mode=rw", uri=True, timeout=10, isolation_level=None)
        db.execute("PRAGMA synchronous=FULL")
        db.execute("PRAGMA trusted_schema=OFF")
        return db

    def _load(self, db, expected_tip):
        previous, revision = "00" * 32, -1
        state = {"intents": set(), "slots": {}, "charges": {}, "wallet_codes": {}, "quarantined": set(), "head": None}
        for row in db.execute("SELECT revision, payload, digest FROM events ORDER BY revision LIMIT ?", (MAX_EVENTS + 1,)):
            number, raw, digest = row
            if number != revision + 1 or number >= MAX_EVENTS:
                raise CustodyError("journal sequence gap or capacity exceeded")
            payload = loads(raw)
            if event_hash(previous, payload) != digest:
                raise CustodyError("journal hash-chain integrity failure")
            if number == 0:
                if payload != {"type": "genesis", "anchor_digest": self.anchor_digest}:
                    raise CustodyError("journal belongs to another anchor")
            elif payload["type"] == "quarantine":
                state["quarantined"].add(payload["wallet"])
            elif payload["type"] == "reservation":
                wallet = payload["wallet"]
                state["intents"].add((wallet, payload["intent"]))
                state["slots"][(wallet, payload["slot"])] = payload["expires_at"]
                state["wallet_codes"][wallet] = payload["wallet_code_hash"]
                state["head"] = payload["target"]
                for charge in payload["charges"]:
                    key = (charge["vault"], charge["asset"])
                    state["charges"][key] = state["charges"].get(key, 0) + charge["amount"]
            else:
                raise CustodyError("unknown journal event")
            previous, revision = digest, number
        tip = {"revision": revision, "digest": previous}
        if revision < 0 or tip != expected_tip:
            raise CustodyError("journal differs from independently retained checkpoint; possible rollback")
        return state

    def _append(self, db, payload, expected_tip):
        revision = expected_tip["revision"] + 1
        if revision >= MAX_EVENTS:
            raise CustodyError("journal capacity reached; reviewed migration required")
        digest = event_hash(expected_tip["digest"], payload)
        db.execute("INSERT INTO events VALUES (?, ?, ?)", (revision, canonical(payload).decode(), digest))
        return {"revision": revision, "digest": digest}

    def reserve(self, appraisal, *, expected_tip, now):
        """Only call on a locally computed appraisal, never deserialize a host verdict.

        Successful commit returns a new tip to retain independently before using
        the reservation. A lost response requires recovery, never automatic retry.
        """
        uint(now, 32, "trusted time")
        if (appraisal.get("schema") != "tos.custody.batch-appraisal.v1"
                or appraisal.get("anchor_digest") != self.anchor_digest
                or appraisal.get("state_authenticated") is not True
                or appraisal.get("diagnostic_policy_match") is not True
                or appraisal.get("signing_authorized") is not False):
            raise CustodyError("requires a local checked batch appraisal")
        wallet = address(appraisal["wallet"])
        for field in ("intent", "wallet_code_hash", "policy_digest"):
            hex_bytes(appraisal[field], 32, field)
        target = block_id(appraisal["target"])
        if type(appraisal["slot"]) is not str or not appraisal["slot"].startswith(("highload:", "multisig:")):
            raise CustodyError("invalid wallet replay slot")
        uint(appraisal["expires_at"], 64, "reservation expiry")
        uint(appraisal["valid_until"], 64, "appraisal validity")
        if appraisal["expires_at"] <= now or appraisal["valid_until"] <= now or appraisal["appraised_at"] > now:
            raise CustodyError("batch reservation expired")
        if type(appraisal["charges"]) is not list or len(appraisal["charges"]) > 16:
            raise CustodyError("invalid batch charges")
        seen = set()
        for charge in appraisal["charges"]:
            address(charge["vault"])
            hex_bytes(charge["asset"], 32, "charged asset")
            for name in ("amount", "remaining"):
                uint(charge[name], 120, name)
            key = (charge["vault"], charge["asset"])
            if charge["amount"] == 0 or key in seen:
                raise CustodyError("duplicate or empty budget charge")
            seen.add(key)
        db = self._connect()
        try:
            db.execute("BEGIN IMMEDIATE")
            state = self._load(db, expected_tip)
            if wallet in state["quarantined"]:
                raise CustodyError("wallet lifecycle quarantined")
            head = state["head"]
            if head is not None and (target["seqno"] < head["seqno"]
                                     or target["seqno"] == head["seqno"] and target != head):
                raise CustodyError("proof target rollback or same-height conflict")
            if state["wallet_codes"].get(wallet, appraisal["wallet_code_hash"]) != appraisal["wallet_code_hash"]:
                raise CustodyError("wallet code changed; reviewed lifecycle recovery required")
            if (wallet, appraisal["intent"]) in state["intents"]:
                raise CustodyError("intent already reserved")
            slot = (wallet, appraisal["slot"])
            if slot in state["slots"] and (appraisal["slot"].startswith("multisig:") or state["slots"][slot] > now):
                raise CustodyError("wallet replay slot already reserved")
            for charge in appraisal["charges"]:
                reserved = state["charges"].get((charge["vault"], charge["asset"]), 0)
                if reserved + charge["amount"] > charge["remaining"]:
                    raise CustodyError("outstanding reservations exceed available treasury budget")
            event = {name: appraisal[name] for name in ("wallet", "intent", "slot", "expires_at", "wallet_code_hash",
                                                       "target", "policy_digest", "charges")}
            tip = self._append(db, {"type": "reservation", **event}, expected_tip)
            db.execute("COMMIT")
            return {"checkpoint": tip, "reservation_committed": True, "signing_authorized": False}
        except Exception:
            if db.in_transaction:
                db.execute("ROLLBACK")
            raise
        finally:
            db.close()

    def quarantine(self, wallet, *, expected_tip):
        """Record an operator-observed freeze/delete/redeployment. No automatic reset."""
        address(wallet)
        db = self._connect()
        try:
            db.execute("BEGIN IMMEDIATE")
            self._load(db, expected_tip)
            tip = self._append(db, {"type": "quarantine", "wallet": wallet}, expected_tip)
            db.execute("COMMIT")
            return tip
        finally:
            if db.in_transaction:
                db.execute("ROLLBACK")
            db.close()
