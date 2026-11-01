import unittest
from tos_custody.boc import Cell, serialize_boc
from tos_custody.errors import CustodyError
from tos_custody.vault import inspect_boc, OPERATIONS
from helpers import Builder, body, request, payload, internal, VAULT, BUSINESS, RECIPIENT, COLD, GUARDIAN, PAUSER

class VaultTests(unittest.TestCase):
    def inspect(self, cell, form="body"):
        return inspect_boc(serialize_boc(cell), form=form)
    def test_native_payment(self):
        result = self.inspect(body())
        self.assertEqual(result["request"]["payload"]["amount_base_units"], 1_000_000_000)
        self.assertFalse(result["signing_authorized"])
    def test_token_payment(self):
        result = self.inspect(body(req=request(pay=payload(asset=7, attachment=100))))
        self.assertEqual(result["request"]["payload"]["asset_id"], f"{7:064x}")
    def test_all_nine_entrypoints(self):
        for op, name in OPERATIONS.items():
            req = request(admin=True, pay=Builder().u(3, 8).cell()) if name in {"schedule", "apply"} else request()
            with self.subTest(operation=name):
                self.assertEqual(self.inspect(body(op=op, req=req))["operation"], name)
    def test_set_asset(self):
        asset = Builder().u(1, 8).u(0, 256).u(1, 1).addr(None).coins(10).coins(20).coins(100).cell()
        result = self.inspect(body(op=0x54560006, req=request(admin=True, pay=asset)))
        self.assertEqual(result["request"]["payload"]["cumulative_limit"], 100)
    def test_set_roles(self):
        roles = Builder().ref(Builder().addr(BUSINESS).addr(GUARDIAN).cell()).ref(Builder().addr(COLD).addr(PAUSER).cell()).cell()
        change = Builder().u(2, 8).ref(roles).cell()
        result = self.inspect(body(op=0x54560006, req=request(admin=True, pay=change)))
        self.assertEqual(result["request"]["payload"]["cold_administrator"], COLD)
    def test_duplicate_roles_rejected(self):
        roles = Builder().ref(Builder().addr(BUSINESS).addr(BUSINESS).cell()).ref(Builder().addr(COLD).addr(PAUSER).cell()).cell()
        change = Builder().u(2, 8).ref(roles).cell()
        with self.assertRaises(CustodyError): self.inspect(body(op=0x54560006, req=request(admin=True, pay=change)))
    def test_internal_and_inline_body(self):
        for inline in (False, True):
            result = self.inspect(internal(inline=inline), "internal")
            self.assertEqual(result["outer_message"]["destination"], VAULT)
    def test_outer_destination_mismatch(self):
        with self.assertRaises(CustodyError): self.inspect(internal(destination=RECIPIENT), "internal")
    def test_forbidden_stateinit(self):
        with self.assertRaises(CustodyError): self.inspect(internal(state_init=True), "internal")
    def test_bounced_message(self):
        with self.assertRaises(CustodyError): self.inspect(internal(bounced=True), "internal")
    def test_wrong_domain(self):
        with self.assertRaises(CustodyError): self.inspect(body(req=request(admin=True)))
    def test_zero_payment(self):
        with self.assertRaises(CustodyError): self.inspect(body(req=request(pay=payload(amount=0))))
    def test_native_attachment(self):
        with self.assertRaises(CustodyError): self.inspect(body(req=request(pay=payload(attachment=1))))
    def test_token_attachment_required_and_bounded(self):
        for attachment in (0, 1_000_000_001):
            with self.subTest(attachment=attachment), self.assertRaises(CustodyError):
                self.inspect(body(req=request(pay=payload(asset=7, attachment=attachment))))
    def test_unknown_opcode(self):
        with self.assertRaises(CustodyError): self.inspect(body(op=0xFFFFFFFF))
    def test_extra_reference(self):
        c = body()
        c = Cell(c.data, c.bit_length, c.refs + (Builder().cell(),))
        with self.assertRaises(CustodyError): self.inspect(c)
    def test_extra_bit(self):
        c = body()
        b = Builder()
        b.bits = ''.join(f"{x:08b}" for x in c.data)[:c.bit_length] + "0"
        b.refs = list(c.refs)
        with self.assertRaises(CustodyError): self.inspect(b.cell())
    def test_external_wallet_refused(self):
        with self.assertRaises(CustodyError): self.inspect(Builder().u(1, 1).cell(), "internal")
    def test_unsupported_workchain(self):
        c = Builder().u(4, 3).s(-1, 8).u(1, 256).cell()
        with self.assertRaises(CustodyError): c.slice().address()
