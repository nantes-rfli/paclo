"""Test-only wire inventory and exact arithmetic oracle for the E1 design.

This inspects synthetic blocks, not packet events or arbitrary input streams.
It does not validate a future reader, its memory bound, or writer fidelity.
"""
from fractions import Fraction
import random
import struct
import sys
import unittest

sys.dont_write_bytecode = True

from make_pcapng_contract_fixtures import OUTPUT, artifacts, metadata_flood


def wire_blocks(data):
    rows = []
    offset = 0
    endian = '<'
    while offset < len(data):
        if len(data) - offset < 12:
            raise ValueError('cut block')
        if data[offset:offset+4] == b'\x0a\x0d\x0d\x0a':
            magic = data[offset+8:offset+12]
            endian = {b'\x4d\x3c\x2b\x1a': '<', b'\x1a\x2b\x3c\x4d': '>'}[magic]
        kind, size = struct.unpack_from(endian + 'II', data, offset)
        if size < 12 or size % 4:
            raise ValueError('invalid block length')
        if size > len(data) - offset:
            raise ValueError('cut block')
        if struct.unpack_from(endian + 'I', data, offset+size-4)[0] != size:
            raise ValueError('trailer')
        rows.append((kind, endian, data[offset+8:offset+size-4]))
        offset += size
    return rows


def wire_options(data, endian):
    rows = []
    offset = 0
    while offset < len(data):
        if len(data)-offset < 4:
            raise ValueError('option header')
        code, size = struct.unpack_from(endian + 'HH', data, offset)
        offset += 4
        if code == 0:
            if size or offset != len(data):
                raise ValueError('option terminator')
            return rows
        padded = (size+3)//4*4
        if padded > len(data)-offset:
            raise ValueError('option overrun')
        rows.append((code, data[offset:offset+size]))
        offset += padded
    return rows


class ContractCorpus(unittest.TestCase):
    def test_reproducible_and_existing_corpus(self):
        for name, data in artifacts().items():
            self.assertEqual(data, (OUTPUT / name).read_bytes(), name)
        root = OUTPUT.parent / 'capture-formats'
        for name in ['multi-interface', 'multi-linktype', 'multi-snaplen', 'multi-section',
                     'mixed-endian-section', 'binary-resolution', 'nano', 'simple-packet']:
            self.assertTrue(wire_blocks((root / (name + '.pcapng')).read_bytes()), name)

    def test_rich_wire_metadata(self):
        rows = wire_blocks(artifacts()['rich.pcapng'])
        self.assertEqual([0x0a0d0d0a, 1, 6, 1, 6, 0x80000042, 3], [r[0] for r in rows])
        interface = wire_options(rows[1][2][8:], '<')
        self.assertIn((2, b'synthetic0'), interface)
        self.assertIn((9, b'\x09'), interface)
        self.assertIn((14, struct.pack('<q', -7)), interface)
        packet = rows[2][2]
        self.assertEqual((0, 64, 1500), (struct.unpack_from('<I', packet)[0],
                                       *struct.unpack_from('<II', packet, 12)))
        self.assertEqual(1700000000123456789,
                         (struct.unpack_from('<I', packet, 4)[0] << 32)
                         | struct.unpack_from('<I', packet, 8)[0])
        self.assertEqual([(1, b'first comment'), (1, b'second comment'),
                          (2, struct.pack('<I', 1)), (0x8001, b'opaque\x00\xff')],
                         wire_options(packet[84:], '<'))
        self.assertEqual(b'opaque block', rows[5][2])

    def test_section_id_reuse_and_spb_padding(self):
        rows = wire_blocks(artifacts()['mixed-sections.pcapng'])
        self.assertEqual(['<', '>'], [r[1] for r in rows if r[0] == 0x0a0d0d0a])
        self.assertEqual([(1, 64), (101, 50)],
                         [(struct.unpack_from(e+'H', b)[0], struct.unpack_from(e+'I', b, 4)[0])
                          for k, e, b in rows if k == 1])
        self.assertEqual([0, 0], [struct.unpack_from(e+'I', b)[0] for k, e, b in rows if k == 6])
        body = wire_blocks(artifacts()['spb-truncated.pcapng'])[-1][2]
        self.assertEqual(1500, struct.unpack_from('<I', body)[0])
        self.assertEqual(16, len(body)-4)  # 15 captured bytes plus one padding byte.

    def test_extreme_integer_encoding(self):
        rows = wire_blocks(artifacts()['timestamp-extremes.pcapng'])
        self.assertEqual([b'\x00', b'\x7f', b'\xff'],
                         [dict(wire_options(b[8:], e))[9] for k, e, b in rows if k == 1])
        self.assertEqual([2**63-1, -2**63, 0],
                         [struct.unpack(e+'q', dict(wire_options(b[8:], e))[14])[0]
                          for k, e, b in rows if k == 1])
        self.assertEqual([2**64-1]*3, [(struct.unpack_from(e+'I', b, 4)[0] << 32)
                                      | struct.unpack_from(e+'I', b, 8)[0]
                                      for k, e, b in rows if k == 6])

    def test_malformed_and_growth_corpus(self):
        files = artifacts()
        for name in ['unaligned-length.pcapng', 'oversized-length.pcapng']:
            with self.assertRaises(ValueError):
                wire_blocks(files[name])
        body = wire_blocks(files['option-overrun.pcapng'])[-1][2]
        with self.assertRaisesRegex(ValueError, 'option overrun'):
            wire_options(body[8:], '<')
        # Valid framing but invalid semantics: future E2 must reject these.
        body = wire_blocks(files['bad-offset-length.pcapng'])[-1][2]
        self.assertEqual(4, len(dict(wire_options(body[8:], '<'))[14]))
        body = wire_blocks(files['duplicate-resolution.pcapng'])[-1][2]
        self.assertEqual([9, 9], [code for code, _ in wire_options(body[8:], '<')])
        rows = wire_blocks(files['forward-interface.pcapng'])
        self.assertEqual(1, struct.unpack_from('<I', rows[2][2])[0])
        for count in [4096, 4097]:
            flood = metadata_flood(count)
            self.assertEqual(count, sum(k == 1 for k, _, _ in wire_blocks(flood)))
        self.assertGreater(len(metadata_flood(1, 8*1024*1024+4)), 8*1024*1024)

    def test_exact_time_projection_oracle(self):
        rng = random.Random(80801)
        cases = [(129, 2, 10, 0), (123456789, 10, 9, 0), (1, 10, 9, -1),
                 (2**64-1, 10, 0, 2**63-1), (2**64-1, 10, 127, -2**63)]
        cases += [(rng.randrange(2**64), rng.choice([2, 10]), rng.randrange(128),
                   rng.randrange(-2**63, 2**63)) for _ in range(500)]
        for ticks, base, exponent, offset in cases:
            denominator = base**exponent
            exact = Fraction(ticks, denominator) + offset
            seconds, remainder = divmod(ticks, denominator)
            seconds += offset
            usec = remainder*1000000//denominator
            projection = Fraction(seconds*1000000+usec, 1000000)
            self.assertTrue(0 <= usec < 1000000)
            self.assertTrue(projection <= exact < projection + Fraction(1, 1000000))
        self.assertEqual(125976, (129*1000000)//1024)
        self.assertEqual((-1, 0), (-1 + 1//10**9, (1 % 10**9)*1000000//10**9))


if __name__ == '__main__':
    unittest.main()
