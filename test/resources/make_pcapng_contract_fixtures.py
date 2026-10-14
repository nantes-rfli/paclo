"""P08-E1 design corpus, not a production PCAPNG implementation.

Reuse P08-A's wire builders. --check is read-only. Large-state cases are
constructed in memory by tests, so the repository contains no bulk dataset.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys

sys.dont_write_bytecode = True

from make_capture_format_fixtures import ETH, SEC, block, epb, idb, options, pad, shb

OUTPUT = Path(__file__).resolve().parent / 'pcapng-contracts'


def flagged_packet(endian='<'):
    ticks = SEC * 10**9 + 123456789
    return block(6, struct.pack(endian + 'IIIII', 0, ticks >> 32,
                               ticks & 0xffffffff, len(ETH), 1500) + pad(ETH)
                 + options([(1, b'first comment'), (1, b'second comment'),
                            (2, struct.pack(endian + 'I', 1)),
                            (0x8001, b'opaque\x00\xff')], endian), endian)


def metadata_flood(count=4097, size=1024):
    return shb() + b''.join(idb() for _ in range(count)) + block(0x80000042, bytes(size))


def artifacts():
    rich = (shb() + idb(resolution=9, offset=-7) + flagged_packet()
            + idb(resolution=0x8a) + epb(1, SEC * 1024 + 129)
            + block(0x80000042, b'opaque block')
            + block(3, struct.pack('<I', 64) + ETH))
    mixed = (shb() + idb(snaplen=64) + epb()
             + shb('>') + idb(link=101, snaplen=50, endian='>')
             + epb(data=ETH[14:], endian='>'))
    extremes = shb()
    for index, (resolution, offset) in enumerate([(0, 2**63-1), (127, -2**63), (255, 0)]):
        extremes += idb(resolution=resolution, offset=offset)
        extremes += epb(index, 2**64-1)
    # Non-word-sized captured data: SPB caplen=min(original length, snaplen).
    spb = shb() + idb(snaplen=15) + block(3, struct.pack('<I', 1500) + pad(ETH[:15]))
    base = shb() + idb()
    files = {
        'rich.pcapng': rich,
        'mixed-sections.pcapng': mixed,
        'timestamp-extremes.pcapng': extremes,
        'spb-truncated.pcapng': spb,
        'forward-interface.pcapng': base + epb(1) + idb(),
        'unaligned-length.pcapng': base + struct.pack('<II', 6, 33) + bytes(25),
        'oversized-length.pcapng': base + struct.pack('<II', 6, 0xfffffffc),
        'option-overrun.pcapng': shb() + block(1, struct.pack('<HHIHH', 1, 0, 65536, 1, 65535)),
        'bad-offset-length.pcapng': shb() + block(1, struct.pack('<HHI', 1, 0, 65536)
                                                 + options([(14, bytes(4))])),
        'duplicate-resolution.pcapng': shb() + block(1, struct.pack('<HHI', 1, 0, 65536)
                                                   + options([(9, b'\x06'), (9, b'\x09')])),
    }
    manifest = {
        'purpose': 'physical design corpus; future-reader expectations are not implemented',
        'sha256': {name: hashlib.sha256(data).hexdigest() for name, data in files.items()},
        'rich-native-microseconds': [[SEC-7, 123456], [SEC, 125976], [-7, 0]],
        'future-reader-rejections': {
            'forward-interface.pcapng': 'undefined-interface',
            'unaligned-length.pcapng': 'invalid-block-length',
            'oversized-length.pcapng': 'limit-exceeded',
            'option-overrun.pcapng': 'invalid-option-length',
            'bad-offset-length.pcapng': 'invalid-option-length',
            'duplicate-resolution.pcapng': 'duplicate-option'},
    }
    files['manifest.json'] = (json.dumps(manifest, indent=2) + '\n').encode()
    return files


def generate(check=False):
    files = artifacts()
    if not check:
        OUTPUT.mkdir(exist_ok=True)
    for name, data in files.items():
        path = OUTPUT / name
        if check:
            if not path.exists() or path.read_bytes() != data:
                raise SystemExit('Fixture mismatch: ' + str(path))
        else:
            path.write_bytes(data)
    print(('Verified' if check else 'Generated') + ' 10 P08-E1 captures and manifest')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true')
    generate(parser.parse_args().check)
