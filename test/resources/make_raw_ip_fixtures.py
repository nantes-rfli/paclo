"""Deterministic P08-D1 bare-IP captures. Checksums are intentionally zero.

Reuse P08-C IP/L4 bytes; Classic PCAP/PCAPNG use LINKTYPE_RAW=101, not DLT 12.
The top-level capture-format generator includes these artifacts in --check.
"""
import argparse
import json
from pathlib import Path
import struct

import make_capture_format_fixtures as formats
import make_cooked_fixtures as cooked

OUTPUT = Path(__file__).resolve().parent / 'raw-ip'


def artifacts():
    original = json.loads(cooked.artifacts()['manifest.json'])[0]['records']
    rows = []
    for row in original[:13] + original[18:21] + original[22:25]:
        # SLL is exactly 16 bytes; preserve the original IP/L4 payload.
        row = {**row, 'hex': row['hex'][32:]}
        rows.append(row)
    rows += [
        {'name': 'empty', 'hex': '', 'reason': 'short-frame'},
        {'name': 'invalid-version', 'hex': ('50' + '00' * 39), 'reason': 'malformed-packet'},
        {'name': 'ethernet-looking', 'hex': formats.ETH.hex(), 'reason': 'malformed-packet'},
        {'name': 'ipv4-unknown-l4', 'hex': cooked.ip4(b'abc', 253).hex(),
         'version': 4, 'transport': 253, 'l4': 'unknown-l4'},
        {'name': 'ipv6-unknown-l4', 'hex': cooked.ip6(b'abc', 253).hex(),
         'version': 6, 'transport': 253, 'l4': 'unknown-l4'},
        {'name': 'ipv4-options', 'hex': (bytes.fromhex('46000020') +
         cooked.ip4(cooked.udp(), 17)[4:20] + bytes(4) + cooked.udp()).hex(),
         'version': 4, 'transport': 17, 'l4': 'udp'},
        {'name': 'short-ipv4-options', 'hex': (bytes([0x4f]) + cooked.ip4(b'', 253)[1:]).hex(),
         'reason': 'truncated-header'},
        {'name': 'ipv6-extension-chain', 'hex': cooked.ip6(
         bytes([43, 0]) + bytes(6) + bytes([60, 0]) + bytes(6) +
         bytes([51, 0]) + bytes(6) + bytes([17, 0]) + bytes(6) + cooked.udp(), 0).hex(),
         'version': 6, 'transport': 17, 'l4': 'udp'},
        {'name': 'short-ipv6-extension-body', 'hex': cooked.ip6(bytes([17, 1]), 43).hex(),
         'reason': 'truncated-header'},
    ]
    files = {}
    for endian, filename in [('<', 'raw.pcap'), ('>', 'raw-big-endian.pcap')]:
        content = struct.pack(endian + 'IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65536, 101)
        for i, row in enumerate(rows):
            data = bytes.fromhex(row['hex'])
            # Explicitly retain wire length for truncated captures.
            wire = len(data) + (100 if row.get('reason') == 'truncated-header' else 0)
            content += struct.pack(endian + 'IIII', formats.SEC, 100 + i, len(data), wire) + data
        files[filename] = content
    files['raw.pcapng'] = formats.shb() + formats.idb(101) + b''.join(
        formats.epb(ticks=formats.SEC * 1000000 + 100 + i, data=bytes.fromhex(row['hex']),
                    length=len(bytes.fromhex(row['hex'])) +
                    (100 if row.get('reason') == 'truncated-header' else 0))
        for i, row in enumerate(rows))
    files['manifest.json'] = (json.dumps(rows, indent=2) + '\n').encode()
    return files


def generate(check=False):
    OUTPUT.mkdir(exist_ok=True)
    for name, content in artifacts().items():
        path = OUTPUT / name
        if check:
            if not path.exists() or path.read_bytes() != content:
                raise SystemExit('Fixture mismatch: ' + str(path))
        else:
            path.write_bytes(content)
    print(('Verified' if check else 'Generated') + ' 3 Raw IP captures and manifest')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true')
    generate(parser.parse_args().check)
