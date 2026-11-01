"""Synthetic structural tests; no genuine ML-DSA signature or hardware involved."""
from contextlib import redirect_stderr, redirect_stdout
import io
import json
from pathlib import Path
import random
import tempfile
import unittest

from tos_custody.boc import Cell, serialize_boc
from tos_custody.canonical import canonical
from tos_custody.cli import main
from tos_custody.errors import CustodyError, UnsupportedProfile
from tos_custody.highload import inspect_highload
from tos_custody.offline import OfflineSigner, check_bundle, inspect_bundle
from helpers import Builder, BUSINESS, GUARDIAN, NETWORK, NOW, RECIPIENT, VAULT, body, payload, policy, request

RELAYER = "0:" + "77" * 32


def message(*, content=None, source=None, destination=VAULT, value=100_000_000,
            extra=False, extra_flags=0, fee=0, lt=0, at=0, bounced=False,
            init=False, ihr_disabled=True, inline=False):
    b = (Builder().u(0, 1).u(int(ihr_disabled), 1).u(1, 1).u(int(bounced), 1)
         .addr(source).addr(destination).coins(value).u(int(extra), 1))
    if extra:
        b.ref(Builder().cell())
    b.coins(extra_flags).coins(fee).u(lt, 64).u(at, 32).u(int(init), 1)
    if init:
        b.u(1, 1).ref(Builder().cell())
    c = content or body()
    b.u(0 if inline else 1, 1)
    if inline:
        b.bits += ''.join(f'{x:08b}' for x in c.data)[:c.bit_length]
        b.refs.extend(c.refs)
    else:
        b.ref(c)
    return b.cell()


def action(msg=None, *, prev=None, mode=1, opcode=0x0EC3C86D):
    return (Builder().ref(prev if prev is not None else Builder().cell())
            .u(opcode, 32).u(mode, 8).ref(msg if msg is not None else message()).cell())


def wallet_request(*, actions=None, network=NETWORK, wallet=BUSINESS,
                   subwallet=7, query=1, created=NOW - 10, timeout=3600):
    return (Builder().s(network, 32).addr(wallet).u(subwallet, 32).u(query, 23)
            .u(created, 64).u(timeout, 22).ref(actions if actions is not None else action()).cell())


def stored_signature(data=b"\0" * 2420):
    chain = None
    for offset in reversed(range(0, len(data), 127)):
        chunk = data[offset:offset + 127]
        chain = Cell(chunk, len(chunk) * 8, () if chain is None else (chain,))
    return Builder().u(len(data), 32).ref(chain).cell()


def submission(req=None, *, signature=None, query=99, opcode=0x50514857):
    return (Builder().u(opcode, 32).u(query, 64)
            .ref(req if req is not None else wallet_request())
            .ref(signature if signature is not None else stored_signature()).cell())


def extended(cell, *, bit=False, ref=False):
    b = Builder()
    b.bits = ''.join(f'{x:08b}' for x in cell.data)[:cell.bit_length] + ('0' if bit else '')
    b.refs = list(cell.refs) + ([Builder().cell()] if ref else [])
    return b.cell()


class HighloadTests(unittest.TestCase):
    def inspect(self, cell=None, form="request"):
        return inspect_highload(serialize_boc(cell if cell is not None else wallet_request()), form=form)

    def reject(self, cell, form="request"):
        with self.assertRaises(CustodyError):
            self.inspect(cell, form)

    def test_exact_preimage_and_explicit_unverified_status(self):
        req = wallet_request()
        result = self.inspect(req)
        self.assertEqual(result["signing_message_hex"], req.hash.hex())
        self.assertEqual(result["signing_context_ascii"], "TOS-PQ-HIGHLOAD-v1")
        self.assertEqual(result["signing_message_length_bytes"], 32)
        self.assertNotEqual(result["signing_message_hex"], result["boc_sha256"])
        self.assertEqual(result["expires_at_exclusive"], NOW - 10 + 3600)
        self.assertEqual(result["wallet"], BUSINESS)
        self.assertFalse(result["signing_authorized"])
        self.assertFalse(result["state_authenticated"])
        self.assertFalse(result["freshness_checked"])
        self.assertFalse(result["replay_checked"])
        self.assertIsNone(result["signature"])

    def test_transport_encoding_does_not_change_signing_message(self):
        req = wallet_request()
        expected = self.inspect(req)["signing_message_hex"]
        for index in (False, True):
            for crc in (False, True):
                result = inspect_highload(serialize_boc(req, indexed=index, crc=crc))
                self.assertEqual(result["signing_message_hex"], expected)

    def test_execution_order_and_effective_mode(self):
        first = action(message(content=body(req=request(pay=payload(amount=1)))))
        last = action(message(content=body(req=request(pay=payload(amount=2)))), prev=first, mode=0)
        actions = self.inspect(wallet_request(actions=last))["actions"]
        self.assertEqual([a["vault_body"]["request"]["payload"]["amount_base_units"] for a in actions], [1, 2])
        self.assertEqual([a["execution_index"] for a in actions], [0, 1])
        self.assertEqual([a["effective_send_mode"] for a in actions], [3, 2])

    def test_hidden_second_action_is_rejected(self):
        unknown = Builder().u(0xBADF00D, 32).u(0, 64).cell()
        hidden = action(message(content=unknown))
        self.reject(wallet_request(actions=action(prev=hidden)))

    def test_balances_and_send_mode_restrictions(self):
        for mode in (4, 16, 32, 64, 128, 129, 131, 255):
            with self.subTest(mode=mode):
                self.reject(wallet_request(actions=action(mode=mode)))
        for mode in range(4):
            self.assertEqual(self.inspect(wallet_request(actions=action(mode=mode)))["actions"][0]["send_mode"], mode)

    def test_non_send_action_rejected(self):
        self.reject(wallet_request(actions=action(opcode=0xAD4DE08E)))

    def test_empty_batch_rejected(self):
        self.reject(wallet_request(actions=Builder().cell()))

    def test_action_limit(self):
        node = Builder().cell()
        for _ in range(16):
            node = action(prev=node)
        self.assertEqual(self.inspect(wallet_request(actions=node))["action_count"], 16)
        self.reject(wallet_request(actions=action(prev=node)))

    def test_network_binding(self):
        self.reject(wallet_request(network=NETWORK + 1))

    def test_vault_binding(self):
        self.reject(wallet_request(actions=action(message(destination=RECIPIENT))))

    def test_relay_wallet_binding(self):
        self.reject(message(content=submission(), source=RELAYER, destination=GUARDIAN), "relay")

    def test_outbound_cannot_claim_a_sender(self):
        self.reject(wallet_request(actions=action(message(source=BUSINESS))))

    def test_control_body_still_uses_signed_destination(self):
        result = self.inspect(wallet_request(actions=action(message(content=body(op=0x54560005)))))
        self.assertEqual(result["actions"][0]["vault_body"]["operation"], "pause")
        self.assertEqual(result["actions"][0]["message"]["destination"], VAULT)

    def test_token_payload_identity_and_units(self):
        token = payload(asset=0x1234, amount=23, attachment=1)
        result = self.inspect(wallet_request(actions=action(message(content=body(req=request(pay=token))))))
        pay = result["actions"][0]["vault_body"]["request"]["payload"]
        self.assertEqual(pay["asset_id"], f'{0x1234:064x}')
        self.assertEqual(pay["amount_base_units"], 23)
        self.assertEqual(pay["token_attachment_base_units"], 1)

    def test_unsigned_relay_fields_do_not_change_preimage(self):
        a = self.inspect(message(content=submission(query=8), source=RELAYER, destination=BUSINESS), "relay")
        b = self.inspect(message(content=submission(query=9), source=GUARDIAN, destination=BUSINESS, value=7), "relay")
        self.assertEqual(a["signing_message_hex"], b["signing_message_hex"])
        self.assertNotEqual(a["root_cell_hash"], b["root_cell_hash"])
        self.assertEqual(b["unsigned_relayer_query_id"], 9)
        self.assertEqual(b["unsigned_relay"]["value_base_units"], 7)

    def test_submission_is_not_signature_verification(self):
        result = self.inspect(submission(), "submission")
        self.assertTrue(result["signature"]["shape_checked"])
        self.assertFalse(result["signature"]["cryptographically_verified"])
        self.assertFalse(result["signing_authorized"])

    def test_reserved_query_ids(self):
        for query in (1023, 2047, (1 << 23) - 1):
            self.reject(wallet_request(query=query))
        self.inspect(wallet_request(query=(1 << 23) - 2))

    def test_zero_timeout(self):
        self.reject(wallet_request(timeout=0))
        self.inspect(wallet_request(timeout=(1 << 22) - 1))

    def test_request_trailing_data(self):
        self.reject(extended(wallet_request(), bit=True))
        self.reject(extended(wallet_request(), ref=True))

    def test_action_trailing_data(self):
        self.reject(wallet_request(actions=extended(action(), bit=True)))
        self.reject(wallet_request(actions=extended(action(), ref=True)))

    def test_nonempty_terminator(self):
        self.reject(wallet_request(actions=action(prev=Builder().u(1, 1).cell())))

    def test_submission_trailing_data(self):
        self.reject(extended(submission(), bit=True), "submission")
        self.reject(extended(submission(), ref=True), "submission")

    def test_wrong_submission_opcode(self):
        self.reject(submission(opcode=0x504D5353), "submission")

    def test_message_trailing_reference(self):
        self.reject(wallet_request(actions=action(extended(message(), ref=True))))

    def test_inline_body(self):
        result = self.inspect(wallet_request(actions=action(message(inline=True))))
        self.assertFalse(result["actions"][0]["message"]["body_by_reference"])
        self.assertEqual(result["actions"][0]["vault_body"]["request"]["vault"], VAULT)

    def test_forbidden_message_fields(self):
        cases = ({"extra": True}, {"init": True}, {"bounced": True}, {"fee": 1},
                 {"lt": 1}, {"at": 1}, {"extra_flags": 4}, {"ihr_disabled": False})
        for kwargs in cases:
            with self.subTest(kwargs=kwargs):
                self.reject(wallet_request(actions=action(message(**kwargs))))
        self.assertEqual(self.inspect(wallet_request(actions=action(message(extra_flags=3))))
                         ["actions"][0]["message"]["extra_flags"], 3)

    def test_external_envelope_rejected(self):
        self.reject(Builder().u(2, 2).cell(), "relay")

    def test_missing_relayer_rejected(self):
        self.reject(message(content=submission(), destination=BUSINESS), "relay")

    def test_signature_length(self):
        for size in (2419, 2421):
            self.reject(submission(signature=stored_signature(bytes(size))), "submission")

    def test_signature_chain_shape(self):
        good = stored_signature()
        for bad in (extended(good, bit=True), extended(good, ref=True),
                    Builder().u(2420, 32).ref(Cell(b'\0', 8)).cell()):
            self.reject(submission(signature=bad), "submission")
        chain = good.refs[0]
        # A continuation with two refs, or non-byte aligned payload, must fail.
        for bad_chain in (Cell(chain.data, chain.bit_length, chain.refs * 2),
                          Cell(chain.data, chain.bit_length - 1, chain.refs)):
            bad = Builder().u(2420, 32).ref(bad_chain).cell()
            self.reject(submission(signature=bad), "submission")

    def test_signature_last_chunk_hidden_tail(self):
        good = stored_signature()
        def alter(c):
            if c.refs:
                return Cell(c.data, c.bit_length, (alter(c.refs[0]),))
            return Cell(c.data, c.bit_length, (Builder().cell(),))
        self.reject(submission(signature=Builder().u(2420, 32).ref(alter(good.refs[0])).cell()), "submission")

    def test_signature_bytes_do_not_change_preimage(self):
        a = self.inspect(submission(), "submission")
        b = self.inspect(submission(signature=stored_signature(b'x' * 2420)), "submission")
        self.assertEqual(a["signing_message_hex"], b["signing_message_hex"])
        self.assertNotEqual(a["signature"]["sha256"], b["signature"]["sha256"])

    def test_signed_fields_change_preimage(self):
        baseline = self.inspect()["signing_message_hex"]
        variants = [wallet_request(wallet=GUARDIAN), wallet_request(subwallet=8),
                    wallet_request(query=2), wallet_request(created=NOW), wallet_request(timeout=3599),
                    wallet_request(actions=action(mode=0)),
                    wallet_request(actions=action(message(value=1))),
                    wallet_request(actions=action(message(content=body(req=request(pay=payload(amount=2))))))]
        for req in variants:
            self.assertNotEqual(self.inspect(req)["signing_message_hex"], baseline)

    def test_truncated_submissions(self):
        raw = serialize_boc(submission())
        for n in range(len(raw)):
            with self.subTest(length=n), self.assertRaises(CustodyError):
                inspect_highload(raw[:n], form="submission")

    def test_seeded_malformed_input(self):
        rng = random.Random(418)
        seed = serialize_boc(submission())
        for _ in range(300):
            raw = bytearray(seed)
            raw[rng.randrange(len(raw))] ^= 1 << rng.randrange(8)
            try:
                result = inspect_highload(bytes(raw), form="submission")
                self.assertFalse(result["signing_authorized"])
                self.assertFalse(result["signature"]["cryptographically_verified"])
            except CustodyError:
                pass

    def test_bundle_inspection_and_no_policy_shortcut(self):
        raw = canonical({"schema": "tos.custody.offline-highload-inspection.v1",
                         "form": "request", "boc_hex": serialize_boc(wallet_request()).hex()})
        self.assertFalse(inspect_bundle(raw)["signing_authorized"])
        with self.assertRaises(UnsupportedProfile):
            check_bundle(raw, policy(), now=NOW)
        with self.assertRaises(UnsupportedProfile):
            OfflineSigner().sign(raw)

    def test_host_labels_forbidden(self):
        for name in ("display", "approval", "signing_message_hex", "signature_verified"):
            raw = canonical({"schema": "tos.custody.offline-highload-inspection.v1",
                             "form": "request", "boc_hex": serialize_boc(wallet_request()).hex(), name: "trusted"})
            with self.subTest(name=name), self.assertRaises(CustodyError):
                inspect_bundle(raw)

    def test_cli_success_and_controlled_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / 'request.boc'
            p.write_bytes(serialize_boc(wallet_request()))
            with redirect_stdout(io.StringIO()) as out:
                self.assertEqual(main(['inspect-highload', str(p)]), 0)
            self.assertIn('"signing_authorized": false', out.getvalue())
            p.write_bytes(b'invalid')
            with redirect_stderr(io.StringIO()) as err:
                self.assertEqual(main(['inspect-highload', str(p)]), 2)
            self.assertIn('Rejected:', err.getvalue())

    def test_unknown_form(self):
        with self.assertRaises(CustodyError):
            inspect_highload(serialize_boc(wallet_request()), form="external")

    def test_frozen_upstream_codec_vectors(self):
        path = Path(__file__).resolve().parents[1] / "fixtures/pq-highload-vectors.json"
        vectors = json.loads(path.read_text())
        self.assertEqual(vectors["codec_git_blob_sha1"], "a2038cde8a5165ac21e84ae34d4f550299250d2c")
        for vector in vectors["vectors"]:
            with self.subTest(name=vector["name"]):
                result = inspect_highload(bytes.fromhex(vector["boc_hex"]), form=vector["form"])
                self.assertEqual(result["signing_message_hex"], vector["request_cell_hash"])
                amounts = [a["vault_body"]["request"]["payload"]["amount_base_units"] for a in result["actions"]]
                self.assertEqual(amounts, vector["amounts_in_execution_order"])

    def test_unpinned_upstream_codec_is_not_executed(self):
        import importlib.util
        script = Path(__file__).resolve().parents[1] / "scripts/check_upstream_highload.py"
        spec = importlib.util.spec_from_file_location("check_upstream_vectors_test", script)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory() as tmp:
            marker = Path(tmp) / "executed"
            fake = Path(tmp) / "cells.py"
            fake.write_text(f'from pathlib import Path\nPath({str(marker)!r}).touch()\n')
            with self.assertRaisesRegex(ValueError, "blob mismatch"):
                module.vectors(fake)
            self.assertFalse(marker.exists())
