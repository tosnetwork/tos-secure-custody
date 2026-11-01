import random
import unittest
from tos_custody.boc import Cell, parse_boc, serialize_boc, crc32c
from tos_custody.errors import CustodyError
from helpers import Builder, internal

class BocTests(unittest.TestCase):
    def test_empty_cell_known_hash(self):
        self.assertEqual(Cell(b"", 0).hash.hex(), "96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7")
    def test_empty_boc_known_vector(self):
        raw = bytes.fromhex("b5ee9c72010101010002000000")
        self.assertEqual(parse_boc(raw).bit_length, 0)
        self.assertEqual(serialize_boc(Cell(b"", 0)), raw)
    def test_crc32c_known_vector(self):
        self.assertEqual(crc32c(b"123456789").hex(), "839206e3")
    def test_roundtrip_index_and_crc(self):
        root = internal()
        for index in (False, True):
            for crc in (False, True):
                with self.subTest(index=index, crc=crc):
                    self.assertEqual(parse_boc(serialize_boc(root, crc=crc, indexed=index)).hash, root.hash)
    def test_partial_bit_lengths(self):
        for width in range(1, 1024):
            root = Builder().u(1, width).cell()
            self.assertEqual(parse_boc(serialize_boc(root)).hash, root.hash)
    def test_truncation_at_every_byte(self):
        raw = serialize_boc(internal())
        for length in range(len(raw)):
            with self.subTest(length=length), self.assertRaises(CustodyError): parse_boc(raw[:length])
    def test_trailing_bytes(self):
        with self.assertRaises(CustodyError): parse_boc(serialize_boc(internal()) + b"x")
    def test_crc_corruption(self):
        raw = bytearray(serialize_boc(internal(), crc=True))
        raw[-1] ^= 1
        with self.assertRaises(CustodyError): parse_boc(bytes(raw))
    def test_index_corruption(self):
        raw = bytearray(serialize_boc(Cell(b"", 0), indexed=True))
        raw[11] ^= 1
        with self.assertRaises(CustodyError): parse_boc(bytes(raw))
    def test_exotic_and_stored_hash_and_level(self):
        for descriptor in (8, 16, 32, 5, 7):
            raw = bytearray(serialize_boc(Cell(b"", 0)))
            raw[11] = descriptor
            with self.subTest(descriptor=descriptor), self.assertRaises(CustodyError): parse_boc(bytes(raw))
    def test_unsupported_header_flags(self):
        for flag in (8, 16, 32):
            raw = bytearray(serialize_boc(Cell(b"", 0)))
            raw[4] |= flag
            with self.subTest(flag=flag), self.assertRaises(CustodyError): parse_boc(bytes(raw))
    def test_nonforward_reference(self):
        raw = bytearray(serialize_boc(Cell(b"", 0, (Cell(b"", 0),))))
        raw[13] = 0
        with self.assertRaises(CustodyError): parse_boc(bytes(raw))
    def test_unreachable_cell(self):
        raw = bytes.fromhex("b5ee9c720101020100040000000000")
        with self.assertRaises(CustodyError): parse_boc(raw)
    def test_noncanonical_termination(self):
        raw = bytes.fromhex("b5ee9c7201010101000300000180")
        with self.assertRaises(CustodyError): parse_boc(raw)
    def test_noncanonical_coins(self):
        with self.assertRaises(CustodyError): Builder().u(1, 4).u(0, 8).cell().slice().coins()
    def test_depth_bound(self):
        cell = Cell(b"", 0)
        for _ in range(33): cell = Cell(b"", 0, (cell,))
        with self.assertRaises(CustodyError): serialize_boc(cell)
    def test_unused_bits(self):
        with self.assertRaises(CustodyError): Cell(bytes([1]), 1)
    def test_seeded_parser_smoke(self):
        rng = random.Random(20261101)
        seed = serialize_boc(internal())
        for i in range(2000):
            raw = bytearray(seed if i % 2 else rng.randbytes(rng.randrange(0, 300)))
            if raw:
                raw[rng.randrange(len(raw))] ^= 1 << rng.randrange(8)
            try:
                parsed = parse_boc(bytes(raw))
                self.assertEqual(len(parsed.hash), 32)
            except CustodyError:
                pass
