"""Build a classic little-endian Ethernet PCAP independently of Paclo/libpcap.

Run from the repository root: python3 test/resources/make_metadata_fixture.py
Records: IP full, ARP full (filtered out), IP truncated, IP large original length.
Payloads are deterministic Ethernet frames; protocol decoding is not required.
"""
from pathlib import Path
import struct

records = [(0, 0, 60, 60, 0x0800, 1),
           (1700000000, 123456, 60, 60, 0x0806, 2),
           (1700000001, 654321, 42, 1500, 0x0800, 3),
           (0x7fffffff, 999999, 60, 0xffffffff, 0x0800, 4)]
output = bytearray(struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65536, 1))
for sec, usec, caplen, length, ethertype, marker in records:
    frame = bytes(range(12)) + struct.pack('>H', ethertype) + bytes([marker]) * (caplen - 14)
    output += struct.pack('<IIII', sec, usec, caplen, length) + frame
Path('test/resources/metadata-roundtrip.pcap').write_bytes(output)
