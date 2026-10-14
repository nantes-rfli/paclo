"""Deterministic P08-C SLL/SLL2 packets, including malformed packet bytes.

The original P08-A generator also checks these artifacts with --check.
Cooked layouts: https://github.com/the-tcpdump-group/libpcap/blob/libpcap-1.10.4/pcap/sll.h
Checksums are zero; no decoder checksum validation or live capture is claimed.
"""
import argparse
import json
from pathlib import Path
import struct

import make_capture_format_fixtures as formats

OUTPUT = Path(__file__).resolve().parent / 'cooked'


def ip4(payload, protocol, fragment=0, reply=False):
    src, dst = (0x0a000002, 0x0a000001) if reply else (0x0a000001, 0x0a000002)
    return struct.pack('>BBHHHBBHII', 0x45, 0, 20 + len(payload), 1,
                       fragment, 64, protocol, 0, src, dst) + payload


def ip6(payload, protocol, reply=False):
    src, dst = (2, 1) if reply else (1, 2)
    return struct.pack('>IHBB', 0x60000000, len(payload), protocol, 64) + (
        bytes.fromhex('20010db80000000000000000000000') + bytes([src]) +
        bytes.fromhex('20010db80000000000000000000000') + bytes([dst]) + payload)


def udp(payload=b'', reply=False):
    src, dst = (53, 12000) if reply else (12000, 53)
    return struct.pack('>HHHH', src, dst, 8 + len(payload), 0) + payload


def tcp(payload=b''):
    return struct.pack('>HHIIHHHH', 12000, 443, 1, 0, 0x5018, 65535, 0, 0) + payload


def dns(reply=False):
    return struct.pack('>HHHHHH', 7, 0x8180 if reply else 0x0100, 1, 0, 0, 0) + (
        b'\x07example\x03com\0' + struct.pack('>HH', 1, 1))


TLS = bytes.fromhex(
    '160303004c010000480303' + '00' * 32 +
    '000002002f0100001d00000010000e00000b6578616d706c652e636f6d001000050003026832')


def header(dlt, protocol, length=6):
    address = bytes(range(8))
    if dlt == 113:
        return struct.pack('>HHH8sH', 4, 1, length, address, protocol)
    return struct.pack('>HHIHBB8s', protocol, 9, 0xf0000007, 1, 4, length, address)


def artifacts():
    files, manifest = {}, []
    for dlt in (113, 276):
        rows = []

        def add(name, payload, protocol=0x0800, **expected):
            rows.append({'name': name, 'hex': (header(dlt, protocol) + payload).hex(), **expected})

        for version, ip, protocol in ((4, ip4, 0x0800), (6, ip6, 0x86dd)):
            for reply in (False, True):
                add(f'ipv{version}-dns-' + ('response' if reply else 'query'),
                    ip(udp(dns(reply), reply), 17, reply=reply), protocol,
                    version=version, transport=17, l4='udp')
            add(f'ipv{version}-tcp-tls', ip(tcp(TLS), 6), protocol,
                version=version, transport=6, l4='tcp')
            icmp_proto = 1 if version == 4 else 58
            add(f'ipv{version}-icmp', ip(bytes([8 if version == 4 else 128, 0, 0, 0]), icmp_proto),
                protocol, version=version, transport=icmp_proto,
                l4='icmpv4' if version == 4 else 'icmpv6')
        add('ipv4-first-fragment', ip4(udp(), 17, 0x2000), version=4, transport=17, l4='udp')
        add('ipv4-later-fragment', ip4(bytes(8), 17, 1), version=4, transport=17, l4='ipv4-fragment')
        extension = bytes([44, 0]) + bytes(6)
        first_fragment = struct.pack('>BBHI', 17, 0, 1, 77)
        add('ipv6-extension-first-fragment', ip6(extension + first_fragment + udp(), 0), 0x86dd,
            version=6, transport=17, l4='udp')
        add('ipv6-later-fragment', ip6(struct.pack('>BBHI', 6, 0, 8, 77), 44), 0x86dd,
            version=6, transport=6, l4='ipv6-fragment')
        # A noninitial fragment's next header is not present in this capture.
        add('ipv6-later-fragment-extension', ip6(struct.pack('>BBHI', 60, 0, 8, 77), 44), 0x86dd,
            version=6, transport=60, l4='ipv6-fragment')
        for length in (0, 8):
            rows.append({'name': f'address-length-{length}',
                         'hex': (header(dlt, 0x0800, length) + ip4(udp(), 17)).hex(),
                         'version': 4, 'transport': 17, 'l4': 'udp'})
        add('unknown-protocol', bytes(30), 0x1234, reason='unsupported-protocol')
        rows.append({'name': 'invalid-address-length',
                     'hex': (header(dlt, 0x0800, 9) + ip4(udp(), 17)).hex(),
                     'reason': 'malformed-packet'})
        rows.append({'name': 'short-link-header', 'hex': header(dlt, 0x0800)[:-1].hex(),
                     'reason': 'short-frame'})
        add('short-ipv4', bytes.fromhex('4500'), reason='truncated-header')
        add('short-ipv6', bytes.fromhex('6000'), 0x86dd, reason='truncated-header')
        add('invalid-ipv4-ihl', bytes.fromhex('44000014') + bytes(16), reason='malformed-packet')
        add('invalid-ipv6-version', bytes.fromhex('5000000000001140') + bytes(32), 0x86dd,
            reason='malformed-packet')
        add('short-tcp', ip4(bytes(3), 6), reason='truncated-header')
        add('short-udp', ip4(bytes(3), 17), reason='truncated-header')
        add('short-ipv6-extension', ip6(bytes([17]), 0), 0x86dd, reason='truncated-header')
        # Valid Ethernet framing must never override the explicitly supplied DLT.
        rows.append({'name': 'ethernet-looking', 'hex': formats.ETH.hex(),
                     'reason': 'malformed-packet'})
        filename = f'sll{2 if dlt == 276 else ""}.pcap'
        content = struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65536, dlt)
        for i, row in enumerate(rows):
            data = bytes.fromhex(row['hex'])
            content += struct.pack('<IIII', formats.SEC, 100 + i, len(data), len(data)) + data
        files[filename] = content
        files[filename + 'ng'] = formats.shb() + formats.idb(dlt) + b''.join(
            formats.epb(ticks=formats.SEC * 1000000 + 100 + i, data=bytes.fromhex(row['hex']))
            for i, row in enumerate(rows))
        manifest.append({'file': filename, 'linktype': dlt, 'records': rows})
    files['manifest.json'] = (json.dumps(manifest, indent=2) + '\n').encode()
    return files


def generate(check=False):
    OUTPUT.mkdir(exist_ok=True)
    files = artifacts()
    for name, content in files.items():
        path = OUTPUT / name
        if check:
            if not path.exists() or path.read_bytes() != content:
                raise SystemExit('Fixture mismatch: ' + str(path))
        else:
            path.write_bytes(content)
    print(('Verified' if check else 'Generated') + ' 4 cooked captures and manifest')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true')
    generate(parser.parse_args().check)
