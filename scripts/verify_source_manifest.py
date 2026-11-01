"""Verify content integrity; a manifest alone does not authenticate its author."""
import sys
from source_bundle import ROOT, entries, manifest
sys.path.insert(0, str(ROOT / 'src'))
from tos_custody.canonical import loads, exact_keys, hex_bytes


def main():
    path = ROOT / 'SOURCE-MANIFEST.json'
    if not path.is_file():
        raise SystemExit('No SOURCE-MANIFEST.json; use an exported source bundle.')
    with path.open('rb') as handle:
        raw = handle.read(131073)
    data = loads(raw)
    exact_keys(data, {'schema', 'sha256'})
    if data['schema'] != 'tos.custody.source-manifest.v1' or type(data['sha256']) is not dict:
        raise SystemExit('Invalid manifest schema.')
    for value in data['sha256'].values():
        hex_bytes(value, 32, 'file hash')
    current = manifest(entries(ROOT))
    if current != data['sha256']:
        raise SystemExit('FAIL: missing, changed or unexpected source file.')
    print(f'PASS: {len(current)} source-file hashes match the manifest. Verify the archive hash separately.')

if __name__ == '__main__':
    main()
