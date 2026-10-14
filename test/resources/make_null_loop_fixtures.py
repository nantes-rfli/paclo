"""Deterministic P08-D2 AF/endian probes and protocol fixtures.

Container and NULL pseudoheader orders vary independently. LOOP stays big endian.
Reuse the complete Raw IP corpus; retain all existing fixture artifacts.
"""
import argparse
import json
from pathlib import Path
import struct

import make_capture_format_fixtures as formats
import make_raw_ip_fixtures as raw

OUTPUT = Path(__file__).resolve().parent / 'null-loop'


def records(order, loop=False):
    rows = []
    for row in json.loads(raw.artifacts()['manifest.json']):
        data = bytes.fromhex(row['hex'])
        version = data[0] >> 4 if data else 4
        families = [24, 28, 30] if version == 6 else [2]
        for family in families:
            rows.append({**row, 'name': f"{row['name']}-af{family}",
                         'address-family': family,
                         'hex': (struct.pack(order + 'I', family) + data).hex(),
                         **({'reason': 'truncated-header'} if not data else {})})
    ip4 = formats.IP + formats.UDP
    ip6 = bytes.fromhex('600000000000113f') + bytes(32)
    for name, family, data, reason in [
            ('unknown-af', 999, ip4, 'unsupported-address-family'),
            ('linux-af10', 10, ip6, 'unsupported-address-family'),
            ('af4-ip6', 2, ip6, 'address-family-mismatch'),
            ('af6-ip4', 30, ip4, 'address-family-mismatch'),
            ('invalid-ip-version', 2, bytes([0x50]) + bytes(39), 'malformed-packet')]:
        rows.append({'name': name, 'hex': (struct.pack(order + 'I', family) + data).hex(),
                     'reason': reason})
    for size in range(4):
        rows.append({'name': f'short-link-{size}', 'hex': bytes(size).hex(), 'reason': 'short-frame'})
    if loop:
        rows.append({'name': 'little-endian-loop', 'hex': (struct.pack('<I', 2) + ip4).hex(),
                     'reason': 'unsupported-address-family'})
    return rows


def artifacts():
    files, cases = {}, []
    for link, name, orders in [(0, 'null', ['<', '>']), (108, 'loop', ['>'])]:
        for header_order in orders:
            rows = records(header_order, link == 108)
            for container_order in ['<', '>']:
                stem = f"{name}-header-{'le' if header_order == '<' else 'be'}-file-{'le' if container_order == '<' else 'be'}"
                classic = struct.pack(container_order + 'IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65536, link)
                ng = formats.shb(container_order) + formats.idb(link, endian=container_order)
                for i, row in enumerate(rows):
                    data = bytes.fromhex(row['hex'])
                    wire = len(data) + (100 if row.get('reason') == 'truncated-header' else 0)
                    classic += struct.pack(container_order + 'IIII', formats.SEC, 100 + i, len(data), wire) + data
                    ng += formats.epb(ticks=formats.SEC * 1000000 + 100 + i, data=data,
                                      length=wire, endian=container_order)
                for suffix, content in [('pcap', classic), ('pcapng', ng)]:
                    filename = stem + '.' + suffix
                    files[filename] = content
                    cases.append({'file': filename, 'linktype': link, 'container-order': container_order,
                                  'header-order': header_order, 'records': rows})
    files['manifest.json'] = (json.dumps(cases, indent=2) + '\n').encode()
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
    print(('Verified' if check else 'Generated') + ' 12 NULL/LOOP captures and manifest')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true')
    generate(parser.parse_args().check)
