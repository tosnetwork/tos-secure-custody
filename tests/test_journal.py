from copy import deepcopy
from contextlib import closing
from concurrent.futures import ThreadPoolExecutor
from hashlib import sha256
from pathlib import Path
import shutil
import sqlite3
import tempfile
import unittest

from tos_custody.errors import CustodyError
from tos_custody.journal import Journal
from test_batch_state import appraisal, ANCHOR, NOW, BUSINESS, CODE


class JournalTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "journal.db"
        self.tip = Journal.create(self.path, anchor_digest=ANCHOR)
        self.journal = Journal(self.path, anchor_digest=ANCHOR)

    def plan(self, number=0, **changes):
        plan = appraisal()
        plan.update(intent=sha256(str(number).encode()).hexdigest(), slot=f"highload:{number+1}")
        plan.update(changes)
        return plan

    def reserve(self, plan=None, **kwargs):
        return self.journal.reserve(plan if plan is not None else self.plan(), expected_tip=self.tip, now=NOW, **kwargs)

    def test_restart_keeps_intent_and_reservations(self):
        result = self.reserve()
        self.journal = Journal(self.path, anchor_digest=ANCHOR)
        self.tip = result["checkpoint"]
        with self.assertRaises(CustodyError):
            self.reserve()
        self.assertFalse(result["signing_authorized"])

    def test_same_wallet_slot_different_bytes(self):
        self.tip = self.reserve()["checkpoint"]
        with self.assertRaises(CustodyError):
            self.reserve(self.plan(1, slot="highload:1"))

    def test_same_intent_cannot_use_a_new_slot(self):
        original = self.plan()
        self.tip = self.reserve(original)["checkpoint"]
        with self.assertRaises(CustodyError):
            self.reserve({**original, "slot": "highload:99"})

    def test_cumulative_reservation_uses_wide_integers(self):
        plan = self.plan()
        plan["charges"][0].update(amount=1 << 100, remaining=2 << 100)
        self.tip = self.reserve(plan)["checkpoint"]
        other = self.plan(1)
        other["charges"][0].update(amount=(1 << 100)+1, remaining=2 << 100)
        with self.assertRaises(CustodyError):
            self.reserve(other)

    def test_two_concurrent_attempts_only_one_commits(self):
        def reserve(number):
            try:
                Journal(self.path, anchor_digest=ANCHOR).reserve(self.plan(number), expected_tip=self.tip, now=NOW)
                return True
            except CustodyError:
                return False
        with ThreadPoolExecutor(max_workers=2) as pool:
            self.assertEqual(sum(pool.map(reserve, (0, 1))), 1)

    def test_missing_reopen_never_initializes(self):
        with self.assertRaises(CustodyError):
            Journal(Path(self.tmp.name) / "missing.db", anchor_digest=ANCHOR)
        with self.assertRaises(FileExistsError):
            Journal.create(self.path, anchor_digest=ANCHOR)

    def test_backup_restore_refused_with_independent_tip(self):
        backup = Path(self.tmp.name) / "backup.db"
        shutil.copyfile(self.path, backup)
        self.tip = self.reserve()["checkpoint"]
        shutil.copyfile(backup, self.path)
        with self.assertRaises(CustodyError):
            self.reserve(self.plan(1))

    def test_hash_chain_detects_sql_row_tampering(self):
        self.tip = self.reserve()["checkpoint"]
        with closing(sqlite3.connect(self.path)) as db:
            with db:
                db.execute("UPDATE events SET payload = replace(payload, 'highload:1', 'highload:9') WHERE revision = 1")
        with self.assertRaises(CustodyError):
            self.reserve(self.plan(1))

    def test_frozen_deleted_redeployed_wallet_stays_quarantined(self):
        self.tip = self.journal.quarantine(BUSINESS, expected_tip=self.tip)
        self.journal = Journal(self.path, anchor_digest=ANCHOR)
        with self.assertRaises(CustodyError):
            self.reserve(self.plan())

    def test_code_change_and_same_height_fork_refused(self):
        self.tip = self.reserve()["checkpoint"]
        with self.assertRaises(CustodyError):
            self.reserve(self.plan(1, wallet_code_hash="00"*32))
        target = {**self.plan()["target"], "root_hash": "11"*32}
        with self.assertRaises(CustodyError):
            self.reserve(self.plan(1, target=target))

    def test_lower_target_refused(self):
        self.tip = self.reserve()["checkpoint"]
        target = {**self.plan()["target"], "seqno": 99}
        with self.assertRaises(CustodyError):
            self.reserve(self.plan(1, target=target))

    def test_failed_transaction_does_not_consume_intent(self):
        bad = self.plan()
        bad["charges"][0]["remaining"] = 1
        with self.assertRaises(CustodyError):
            self.reserve(bad)
        self.assertTrue(self.reserve()["reservation_committed"])

    def test_multisig_seqno_never_reused_after_expiry(self):
        self.tip = self.reserve(self.plan(slot="multisig:9"))["checkpoint"]
        future = NOW+4000
        with self.assertRaises(CustodyError):
            self.journal.reserve(self.plan(1, slot="multisig:9", expires_at=future+100,
                                           valid_until=future+100, appraised_at=future),
                                 expected_tip=self.tip, now=future)

    def test_duplicate_charge_not_hidden_in_one_batch(self):
        plan = self.plan()
        plan["charges"] *= 2
        with self.assertRaises(CustodyError):
            self.reserve(plan)

    def test_expired_appraisal_cannot_be_reserved_with_live_wallet_expiry(self):
        plan = self.plan()
        with self.assertRaises(CustodyError):
            self.journal.reserve(plan, expected_tip=self.tip, now=NOW+301)

    def test_host_status_flags_do_not_enable_authorization(self):
        for changes in ({"signing_authorized": True}, {"state_authenticated": False}, {"anchor_digest": "00"*32}):
            with self.assertRaises(CustodyError):
                self.reserve(self.plan(**changes))
