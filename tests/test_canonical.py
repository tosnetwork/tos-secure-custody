import unittest
from tos_custody.canonical import canonical, loads
from tos_custody.errors import CustodyError

class CanonicalTests(unittest.TestCase):
    def test_sorting_and_roundtrip(self):
        self.assertEqual(canonical({"b": 2, "a": 1}), b'{"a":1,"b":2}')
        self.assertEqual(loads(b'{"a":1}'), {"a": 1})
    def test_duplicate_keys(self):
        with self.assertRaises(CustodyError): loads(b'{"a":1,"a":2}')
    def test_floats_and_nonfinite(self):
        for raw in (b'1.0', b'NaN', b'Infinity', b'-Infinity', b'1e3'):
            with self.subTest(raw=raw), self.assertRaises(CustodyError): loads(raw)
    def test_unicode_and_control_characters(self):
        for raw in (b'"\\u202e"', b'"\\n"', b'"\\u007f"'):
            with self.subTest(raw=raw), self.assertRaises(CustodyError): loads(raw)
    def test_size_bound(self):
        with self.assertRaises(CustodyError): loads(b' ' * 131073)
    def test_depth_bound(self):
        with self.assertRaises(CustodyError): loads(b'[' * 18 + b'0' + b']' * 18)
    def test_integer_bound(self):
        with self.assertRaises(CustodyError): canonical(1 << 256)
    def test_non_string_key(self):
        with self.assertRaises(CustodyError): canonical({1: 2})
