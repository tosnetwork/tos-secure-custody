"""Synthetic parser/adversarial tests, not ML-DSA verification or native execution."""
from contextlib import redirect_stderr, redirect_stdout
from hashlib import sha256
import io
import json
from pathlib import Path
import random
import tempfile
import unittest

from tos_custody.boc import Cell, parse_boc, serialize_boc
from tos_custody.canonical import canonical
from tos_custody.cli import main
from tos_custody.errors import CustodyError, UnsupportedProfile
from tos_custody.multisig import LIMITS, _dictionary, inspect_multisig, inspect_multisig_state
from tos_custody.offline import OfflineSigner, check_bundle, inspect_bundle
from helpers import Builder, COLD, NETWORK, NOW, VAULT, body, payload, policy, request
from test_highload import action, extended, message, stored_signature

CTX = {"network_global_id": NETWORK, "account": COLD, "seqno": 9}
RELAYER = "0:" + "77" * 32


def key(number):
    # Public synthetic bytes, no signing capability or production secrets.
    return number.to_bytes(2, "big") + bytes(1310)


def key_id(data):
    return int.from_bytes(sha256(b"TOS-PQ-CONSENSUS-KEY-v1\x01\x00" + data).digest(), "big")


def hashmap(entries, width=256, label_form="long"):
    if not entries:
        return None
    keys = list(entries)
    length = width - (min(keys) ^ max(keys)).bit_length()
    label = keys[0] >> (width - length)
    b = Builder()
    if label_form == "short":
        b.u(0, 1).u((1 << length) - 1, length).u(0, 1).u(label, length)
    elif label_form == "same" and label in (0, (1 << length) - 1):
        b.u(3, 2).u(int(label != 0), 1).u(length, width.bit_length())
    else:
        b.u(2, 2).u(length, width.bit_length()).u(label, length)
    if length == width:
        return b.ref(entries[keys[0]]).cell()
    rest = width - length - 1
    for bit in (0, 1):
        b.ref(hashmap({x & ((1 << rest) - 1): v for x, v in entries.items()
                       if (x >> rest) & 1 == bit}, rest, label_form))
    return b.cell()


def state(*, count=3, quorum=2, seqno=9, entries=None, declared=None, label_form="long"):
    if entries is None:
        entries = {key_id(key(i)): stored_signature(key(i)) for i in range(count)}
    dictionary = hashmap(entries, label_form=label_form)
    b = Builder().u(int(dictionary is not None), 1)
    if dictionary is not None:
        b.ref(dictionary)
    return b.u(count if declared is None else declared, 8).u(quorum, 8).u(seqno, 64).cell()


def req(*, kind=1, expiry=NOW+300, content=None):
    if content is None:
        content = action(message(content=body(op=0x54560005)))
    return Builder().u(kind, 8).u(expiry, 32).ref(content).cell()


def change(kind=3, value=1):
    b = Builder().u(kind, 8)
    if kind == 1:
        b.ref(stored_signature(key(value)))
    elif kind == 2:
        b.u(key_id(key(value)), 256)
    elif kind == 3:
        b.u(value, 8)
    return req(kind=2, content=b.cell())


def submit(request=None, *, ids=(0, 1), entries=None, query=8, opcode=0x504D5353):
    if entries is None:
        entries = {key_id(key(i)): stored_signature(bytes([i % 256]) * 2420) for i in ids}
    dictionary = hashmap(entries)
    b = Builder().u(opcode, 32).u(query, 64).ref(request if request is not None else req())
    b.u(int(dictionary is not None), 1)
    if dictionary is not None:
        b.ref(dictionary)
    return b.cell()


def encode(cell, **kwargs):
    return serialize_boc(cell, **LIMITS, **kwargs)


def bundle(cell=None, **context):
    return {"schema": "tos.custody.offline-multisig-inspection.v1", "form": "request",
            "context": {**CTX, **context}, "boc_hex": encode(cell if cell is not None else req()).hex()}


class MultisigTests(unittest.TestCase):
    def inspect(self, cell=None, form="request", **kwargs):
        return inspect_multisig(encode(cell if cell is not None else req()), form=form,
                                context=kwargs.pop("context", CTX), **kwargs)

    def reject(self, cell=None, form="request", **kwargs):
        with self.assertRaises(CustodyError):
            self.inspect(cell, form, **kwargs)

    def test_exact_preimage_not_request_hash(self):
        r = req()
        expected = (Builder().s(NETWORK, 32).u(0x504D5331, 32).addr(COLD)
                    .u(9, 64).u(NOW+300, 32).ref(r.refs[0]).cell().hash.hex())
        out = self.inspect(r)
        self.assertEqual(out["signing_message_hex"], expected)
        self.assertNotEqual(expected, out["request_cell_hash"])
        self.assertNotEqual(expected, out["boc_sha256"])
        self.assertEqual(out["signing_context_ascii"], "TOS-PQ-QUORUM-v1")
        self.assertEqual(out["valid_until_inclusive"], NOW+300)
        self.assertEqual(out["signing_message_length_bytes"], 32)

    def test_context_binding(self):
        expected = self.inspect()["signing_message_hex"]
        for field, value in (("network_global_id", 7), ("account", VAULT), ("seqno", 10)):
            self.assertNotEqual(expected, self.inspect(context={**CTX, field: value})["signing_message_hex"])

    def test_configuration_domain(self):
        r = change()
        expected = (Builder().s(NETWORK, 32).u(0x504D5332, 32).addr(COLD)
                    .u(9, 64).u(NOW+300, 32).ref(r.refs[0]).cell().hash.hex())
        self.assertEqual(self.inspect(r)["signing_message_hex"], expected)
        self.assertEqual(self.inspect(r)["signing_domain"], "0x504d5332")

    def test_expiry_and_payload_binding(self):
        original = self.inspect()["signing_message_hex"]
        self.assertNotEqual(original, self.inspect(req(expiry=NOW+301))["signing_message_hex"])
        other = req(content=action(message(content=body(op=0x54560008))))
        self.assertNotEqual(original, self.inspect(other)["signing_message_hex"])

    def test_context_type_and_schema(self):
        cases = [None, {}, {**CTX, "approved": True}, {**CTX, "network_global_id": True},
                 {**CTX, "network_global_id": 1 << 31}, {**CTX, "network_global_id": -(1 << 31)-1},
                 {**CTX, "seqno": True}, {**CTX, "seqno": -1}, {**CTX, "seqno": 1 << 64},
                 {**CTX, "account": "-1:" + "11"*32}, {**CTX, "account": "0:" + "AA"*32},
                 {**CTX, "account": "0:123"}, {**CTX, "account": 4}]
        for context in cases:
            with self.subTest(context=context):
                self.reject(context=context)

    def test_sequence_exhaustion(self):
        self.reject(context={**CTX, "seqno": (1 << 64)-1})
        self.inspect(context={**CTX, "seqno": (1 << 64)-2})

    def test_context_boundaries(self):
        for network in (-(1 << 31), (1 << 31)-1):
            self.inspect(context={**CTX, "network_global_id": network, "seqno": 0})

    def test_unknown_kind_and_form(self):
        for kind in (0, 3, 255):
            self.reject(req(kind=kind))
        self.reject(form="external")

    def test_request_trailing_data(self):
        for option in ("bit", "ref"):
            self.reject(extended(req(), **{option: True}))

    def test_action_order(self):
        a = action(message(value=1, content=body(op=0x54560005)))
        b = action(message(value=2, content=body(op=0x54560008)), prev=a)
        out = self.inspect(req(content=b))
        self.assertEqual([x["message"]["value_base_units"] for x in out["actions"]], [1, 2])
        self.assertEqual([x["effective_send_mode"] for x in out["actions"]], [3, 3])

    def test_action_bounds(self):
        self.reject(req(content=Builder().cell()))
        batch = Builder().cell()
        for _ in range(16):
            batch = action(message(content=body(op=0x54560005)), prev=batch)
        self.assertEqual(self.inspect(req(content=batch))["action_count"], 16)
        self.reject(req(content=action(prev=batch)))

    def test_sweep_and_hidden_action(self):
        self.reject(req(content=action(mode=128)))
        self.reject(req(content=action(opcode=0xAD4DE08E)))
        self.reject(req(content=action(prev=action(opcode=0xAD4DE08E))))

    def test_vault_network_binding(self):
        self.reject(req(content=action(message(content=body(req=request(network=1))))))

    def test_vault_destination_binding(self):
        self.reject(req(content=action(message(destination=COLD))))

    def test_governance_payload(self):
        unpause = Builder().u(3, 8).cell()
        r = req(content=action(message(content=body(op=0x54560006, req=request(admin=True, pay=unpause)))))
        result = self.inspect(r)
        self.assertEqual(result["actions"][0]["vault_body"]["operation"], "schedule")

    def test_forbidden_messages(self):
        for kwargs in ({"source": COLD}, {"init": True}, {"extra": True}, {"bounced": True}, {"fee": 1}):
            self.reject(req(content=action(message(**kwargs))))

    def test_key_identity_and_state(self):
        result = inspect_multisig_state(encode(state()))
        self.assertEqual(result["member_count"], 3)
        self.assertEqual(result["quorum"], 2)
        self.assertEqual(result["seqno"], 9)
        self.assertEqual({x["key_id"] for x in result["members"]}, {f"{key_id(key(i)):064x}" for i in range(3)})
        self.assertFalse(result["state_authenticated"])
        self.assertFalse(result["deployment_verified"])

    def test_all_label_encodings(self):
        for kind in ("short", "long", "same"):
            for ids in ([0], [(1 << 256)-1], [0, 1, 2, 255]):
                entries = {i: Builder().cell() for i in ids}
                decoded = _dictionary(hashmap(entries, label_form=kind), limit=64)
                self.assertEqual(list(sorted(decoded)), ids)
            inspect_multisig_state(encode(state(label_form=kind)))

    def test_state_full_64_member_set(self):
        raw = encode(state(count=64, quorum=12))
        self.assertEqual(inspect_multisig_state(raw)["member_count"], 64)
        with self.assertRaises(CustodyError):
            parse_boc(raw)  # legacy profile still has its 256-cell bound

    def test_state_member_count_mismatch(self):
        for declared in (2, 4):
            with self.assertRaises(CustodyError):
                inspect_multisig_state(encode(state(declared=declared)))

    def test_state_key_id_mismatch(self):
        with self.assertRaises(CustodyError):
            inspect_multisig_state(encode(state(count=1, quorum=1, entries={0: stored_signature(key(0))})))

    def test_same_key_cannot_fill_two_ids(self):
        stored = stored_signature(key(0))
        with self.assertRaises(CustodyError):
            inspect_multisig_state(encode(state(count=2, entries={key_id(key(0)): stored, 1: stored})))

    def test_invalid_state_ranges(self):
        for count, quorum in ((0, 0), (65, 12), (3, 0), (3, 4), (16, 13)):
            with self.subTest(count=count, quorum=quorum), self.assertRaises(CustodyError):
                inspect_multisig_state(encode(state(count=count, quorum=quorum)))

    def test_state_trailing_and_empty_dictionary(self):
        for cell in (extended(state(), bit=True), extended(state(), ref=True), state(entries={})):
            with self.assertRaises(CustodyError):
                inspect_multisig_state(encode(cell))

    def test_state_sequence_mismatch(self):
        self.reject(state_raw=encode(state(seqno=10)))

    def test_key_length_and_chain(self):
        bad = [stored_signature(bytes(1311)), stored_signature(bytes(1313)),
               Builder().u(1312, 32).ref(Cell(b"\0", 8)).cell(),
               extended(stored_signature(key(0)), bit=True)]
        for stored in bad:
            self.reject(req(kind=2, content=Builder().u(1, 8).ref(stored).cell()))

    def test_key_terminal_hidden_tail(self):
        chain = stored_signature(key(0)).refs[0]
        nodes = []
        while chain.refs:
            nodes.append(chain)
            chain = chain.refs[0]
        for tail in (extended(chain, bit=True), extended(chain, ref=True)):
            for node in reversed(nodes):
                tail = Cell(node.data, node.bit_length, (tail,))
            stored = Builder().u(1312, 32).ref(tail).cell()
            self.reject(req(kind=2, content=Builder().u(1, 8).ref(stored).cell()))

    def test_added_key_identity_without_state(self):
        result = self.inspect(change(1, 7))["membership_change"]
        self.assertEqual(result["member"]["key_id"], f"{key_id(key(7)):064x}")

    def test_add_member(self):
        result = self.inspect(change(1, 7), state_raw=encode(state()))["membership_change"]
        self.assertEqual(result["member"]["key_id"], f"{key_id(key(7)):064x}")
        self.assertEqual((result["before_member_count"], result["after_member_count"]), (3, 4))
        self.assertEqual(result["after_quorum"], 2)
        self.assertFalse(result["vault_delay_bypassed"])

    def test_add_duplicate_or_full(self):
        self.reject(change(1, 1), state_raw=encode(state()))
        self.reject(change(1, 64), state_raw=encode(state(count=64)))

    def test_remove_member(self):
        result = self.inspect(change(2, 0), state_raw=encode(state()))["membership_change"]
        self.assertEqual((result["after_member_count"], result["after_quorum"]), (2, 2))

    def test_remove_unknown_or_below_quorum(self):
        self.reject(change(2, 7), state_raw=encode(state()))
        self.reject(change(2, 0), state_raw=encode(state(count=2)))

    def test_quorum_change(self):
        result = self.inspect(change(3, 1), state_raw=encode(state()))["membership_change"]
        self.assertEqual((result["before_quorum"], result["after_quorum"]), (2, 1))
        self.assertIn("PRE-CHANGE", result["effect"])

    def test_invalid_quorum_change(self):
        for quorum in (0, 13, 255):
            self.reject(change(3, quorum))
        self.reject(change(3, 4), state_raw=encode(state()))

    def test_unknown_or_trailing_change(self):
        for payload in (Builder().u(4, 8).cell(), extended(change().refs[0], bit=True),
                        extended(change().refs[0], ref=True)):
            self.reject(req(kind=2, content=payload))

    def test_change_without_state_not_authenticated(self):
        out = self.inspect(change())
        self.assertFalse(out["membership_change"]["compared_with_untrusted_state"])
        self.assertFalse(out["signing_authorized"])

    def test_submission_signature_structure_only(self):
        out = self.inspect(submit(), "submission", state_raw=encode(state()))
        self.assertEqual(len(out["signatures"]), 2)
        self.assertTrue(out["signature_set_compared_with_untrusted_state"])
        self.assertFalse(out["cryptographically_verified"])
        for signature in out["signatures"]:
            self.assertTrue(signature["shape_checked"])
            self.assertFalse(signature["cryptographically_verified"])

    def test_exact_prechange_quorum(self):
        for ids in ((0,), (0, 1, 2)):
            self.reject(submit(change(3, 1), ids=ids), "submission", state_raw=encode(state()))
        out = self.inspect(submit(change(3, 1)), "submission", state_raw=encode(state()))
        self.assertEqual(out["membership_change"]["after_quorum"], 1)

    def test_signer_membership(self):
        self.reject(submit(ids=(0, 4)), "submission", state_raw=encode(state()))

    def test_empty_or_overlimit_signatures(self):
        self.reject(submit(ids=()), "submission")
        self.reject(submit(ids=range(13)), "submission")

    def test_full_12_of_64_structure(self):
        out = self.inspect(submit(ids=range(12)), "submission", state_raw=encode(state(count=64, quorum=12)))
        self.assertEqual(len(out["signatures"]), 12)
        self.assertFalse(out["signing_authorized"])

    def test_signature_corruption(self):
        for sig in (stored_signature(bytes(2419)), extended(stored_signature(), bit=True)):
            self.reject(submit(entries={key_id(key(0)): sig}), "submission")

    def test_submission_wrong_opcode_and_tail(self):
        self.reject(submit(opcode=0x50514857), "submission")
        self.reject(extended(submit(), bit=True), "submission")
        self.reject(extended(submit(), ref=True), "submission")

    def test_deep_signature_dictionary_relay(self):
        entries = {identifier: stored_signature()
                   for identifier in [0] + [1 << i for i in range(11)]}
        submission = submit(entries=entries)
        relay = message(content=submission, source=RELAYER, destination=COLD)
        self.assertEqual(submission.commitment(max_depth=96)[0], 33)
        self.assertEqual(relay.commitment(max_depth=96)[0], 34)
        standalone = self.inspect(submission, "submission")
        wrapped = self.inspect(relay, "relay")
        self.assertEqual(len(wrapped["signatures"]), 12)
        self.assertEqual(wrapped["signatures"], standalone["signatures"])
        self.assertEqual(wrapped["signing_message_hex"], standalone["signing_message_hex"])
        self.assertEqual(wrapped["unsigned_relay"]["message_cell_hash"],
                         relay.commitment(max_depth=96)[1].hex())
        # The shared decoder keeps the original bound unless a profile opts in.
        from tos_custody.highload import _internal
        with self.assertRaises(CustodyError):
            _internal(relay, outbound=False)

    def test_relay_account_binding(self):
        self.reject(message(content=submit(), source=RELAYER, destination=VAULT), "relay")
        out = self.inspect(message(content=submit(), source=RELAYER, destination=COLD), "relay")
        self.assertEqual(out["account"], COLD)

    def test_relay_external_and_missing_sender(self):
        self.reject(message(content=submit(), destination=COLD), "relay")
        self.reject(Builder().u(2, 2).cell(), "relay")

    def test_relay_unsigned_fields(self):
        left = message(content=submit(query=1), source=RELAYER, destination=COLD, value=1)
        right = message(content=submit(query=2), source=VAULT, destination=COLD, value=100)
        self.assertEqual(self.inspect(left, "relay")["signing_message_hex"], self.inspect(right, "relay")["signing_message_hex"])

    def test_signature_bytes_unsigned(self):
        left = self.inspect(submit(ids=(0,)), "submission")
        right = self.inspect(submit(ids=(1,)), "submission")
        self.assertEqual(left["signing_message_hex"], right["signing_message_hex"])

    def test_crc_index_encoding(self):
        for crc in (False, True):
            for indexed in (False, True):
                out = inspect_multisig(encode(req(), crc=crc, indexed=indexed), context=CTX)
                self.assertEqual(out["signing_message_hex"], self.inspect()["signing_message_hex"])

    def test_every_truncation(self):
        raw = encode(req())
        for i in range(len(raw)):
            with self.assertRaises(CustodyError):
                inspect_multisig(raw[:i], context=CTX)

    def test_untrusted_labels_and_context_flags(self):
        for field in ("approved", "signature_verified", "display"):
            b = bundle()
            b[field] = True
            with self.assertRaises(CustodyError):
                inspect_bundle(canonical(b))
            b = bundle(**{field: True})
            with self.assertRaises(CustodyError):
                inspect_bundle(canonical(b))

    def test_offline_schema(self):
        out = inspect_bundle(canonical(bundle()))
        self.assertEqual(out["schema"], "tos.custody.multisig-inspection.v1")
        self.assertFalse(out["signing_authorized"])
        b = bundle(); b["form"] = "external"
        with self.assertRaises(CustodyError):
            inspect_bundle(canonical(b))

    def test_no_policy_or_signing_shortcut(self):
        with self.assertRaises(UnsupportedProfile):
            check_bundle(canonical(bundle()), policy(), now=NOW)
        with self.assertRaises(UnsupportedProfile):
            OfflineSigner().sign(self.inspect(), approved=True)

    def test_no_authentication_claims(self):
        out = self.inspect(submit(), "submission", state_raw=encode(state()))
        for name in ("signing_authorized", "state_authenticated", "cryptographically_verified", "freshness_checked", "replay_checked"):
            self.assertFalse(out[name])

    def test_cli_and_controlled_error(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)
            (p/"request.boc").write_bytes(encode(req()))
            (p/"state.boc").write_bytes(encode(state()))
            (p/"context.json").write_bytes(canonical(CTX))
            with redirect_stdout(io.StringIO()) as output:
                self.assertEqual(main(["inspect-multisig", str(p/"request.boc"), "--context", str(p/"context.json"), "--state", str(p/"state.boc")]), 0)
                self.assertEqual(json.loads(output.getvalue())["supplied_state"]["quorum"], 2)
            with redirect_stdout(io.StringIO()):
                self.assertEqual(main(["inspect-multisig-state", str(p/"state.boc")]), 0)
            (p/"context.json").write_text('{"account":true}')
            with redirect_stderr(io.StringIO()) as error:
                self.assertEqual(main(["inspect-multisig", str(p/"request.boc"), "--context", str(p/"context.json")]), 2)
                self.assertIn("Rejected:", error.getvalue())

    def test_frozen_upstream_vectors(self):
        fixture = Path(__file__).resolve().parents[1] / "fixtures/pq-multisig-vectors.json"
        for vector in json.loads(fixture.read_text())["vectors"]:
            out = inspect_multisig(bytes.fromhex(vector["boc_hex"]), context=vector["context"])
            self.assertEqual(out["request_cell_hash"], vector["request_cell_hash"])
            self.assertEqual(out["signing_message_hex"], vector["signing_message_hex"])

    def test_unpinned_codec_not_executed(self):
        import sys
        sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
        from check_upstream_multisig import vectors
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "cells.py"
            path.write_text('raise RuntimeError("must not execute")')
            with self.assertRaisesRegex(ValueError, "blob mismatch"):
                vectors(path)

    def test_seeded_malformed_boc(self):
        rng = random.Random(7628)
        raw = encode(submit())
        for _ in range(500):
            changed = bytearray(raw)
            changed[rng.randrange(len(changed))] ^= 1 << rng.randrange(8)
            try:
                result = inspect_multisig(bytes(changed), context=CTX, form="submission")
                self.assertFalse(result["cryptographically_verified"])
                self.assertFalse(result["signing_authorized"])
            except CustodyError:
                pass


class MultisigDictionaryTests(unittest.TestCase):
    def test_label_length_bounds(self):
        cases = [Builder().u(2, 2).u(257, 9).cell(), Builder().u(3, 2).u(0, 1).u(257, 9).cell(),
                 Builder().u(0, 1).u((1 << 257)-1, 257).u(0, 1).cell()]
        for cell in cases:
            with self.assertRaises(CustodyError):
                _dictionary(cell, limit=64)

    def test_leaf_and_fork_full_consumption(self):
        leaf = hashmap({0: Builder().cell()})
        fork = hashmap({0: Builder().cell(), 1: Builder().cell()})
        for cell in (extended(leaf, bit=True), extended(leaf, ref=True), extended(fork, bit=True), extended(fork, ref=True)):
            with self.assertRaises(CustodyError):
                _dictionary(cell, limit=64)

    def test_shared_dag_expansion_bound(self):
        # Seven references to the same shape expand to 128 logical leaves.
        node = Builder().u(3, 2).u(0, 1).u(249, 8).ref(Builder().cell()).cell()
        for width in range(250, 257):
            node = Builder().u(2, 2).u(0, width.bit_length()).ref(node).ref(node).cell()
        with self.assertRaises(CustodyError):
            _dictionary(node, limit=64)

    def test_skewed_dictionary_depth(self):
        entries = {0: Builder().cell(), **{1 << i: Builder().cell() for i in range(62)}}
        root = hashmap(entries)
        raw = encode(root)
        self.assertEqual(len(_dictionary(parse_boc(raw, **LIMITS), limit=64)), 63)
        with self.assertRaises(CustodyError):
            parse_boc(raw)
        self.assertEqual(len(root.commitment(max_depth=96)[1]), 32)

    def test_limit_arguments(self):
        for limits in ({"max_cells": True}, {"max_depth": True}, {"max_cells": 1025}, {"max_depth": 97}, {"max_cells": 0}, {"max_depth": 0}):
            with self.assertRaises(CustodyError):
                parse_boc(encode(req()), **limits)
            with self.assertRaises(CustodyError):
                serialize_boc(req(), **limits)

    def test_absolute_depth_limit(self):
        node = Builder().cell()
        for _ in range(97):
            node = Builder().ref(node).cell()
        with self.assertRaises(CustodyError):
            encode(node)
        with self.assertRaises(CustodyError):
            node.commitment(max_depth=96)


if __name__ == "__main__":
    unittest.main()
