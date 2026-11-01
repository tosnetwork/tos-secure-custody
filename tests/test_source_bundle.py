"""Packaging includes documentation images without weakening the allowlist."""
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from source_bundle import build, entries, manifest


class SourceBundleTests(unittest.TestCase):
    def test_uppercase_png_roundtrip(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "source"
            root.mkdir()
            raw = b'\x89PNG\r\n\x1a\nsynthetic-test-payload'
            (root / "ROADMAP.PNG").write_bytes(raw)
            before = manifest(entries(root))
            target = Path(tmp) / 'source.tar'
            build(root, target)
            with tarfile.open(target) as archive:
                self.assertEqual(archive.extractfile('tos-secure-custody/ROADMAP.PNG').read(), raw)
            self.assertIn('ROADMAP.PNG', before)

    def test_image_changes_commitment(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            p = root / "image.png"
            p.write_bytes(b'first')
            before = manifest(entries(root))
            p.write_bytes(b'second')
            self.assertNotEqual(manifest(entries(root)), before)

    def test_unknown_extension_stays_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "unknown.exe").write_bytes(b'no')
            with self.assertRaises(ValueError):
                entries(root)

    def test_image_symlink_stays_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "original.png").write_bytes(b'no')
            (root / "image.PNG").symlink_to(root / "original.png")
            with self.assertRaises(ValueError):
                entries(root)
