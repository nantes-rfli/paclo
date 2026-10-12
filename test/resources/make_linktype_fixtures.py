"""Generate classic PCAPs with savefile LINKTYPE 113 (SLL) and 0 (NULL).

Run: python3 test/resources/make_linktype_fixtures.py
Each file contains a proper IPv4/UDP record, a truncated link header, and a
record deliberately resembling valid Ethernet to exercise safe dispatch.
These savefile values are not a general table of platform-specific DLT values.
"""
from pathlib import Path
import struct

ip = bytes.fromhex('4500003200010000401100000a0000010a000002')
udp = struct.pack('>HHHH', 12000, 53, 30, 0) + bytes(22)
ethernet = bytes(range(12)) + bytes.fromhex('0800') + ip + udp
sll = struct.pack('>HHH8sH', 0, 1, 6, bytes(range(6)) + bytes(2), 0x0800)
# NULL's address-family header uses the originating host's byte order.
null = struct.pack('<I', 2)  # AF_INET, little-endian capture origin
for name, linktype, header in [('sll', 113, sll), ('null', 0, null)]:
    proper = header + ip + udp
    records = [(1700000000, 123456, proper, len(proper)),
               (1700000001, 654321, proper[:2], 1500),
               (1700000002, 0, ethernet, len(ethernet))]
    output = bytearray(struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65536, linktype))
    for sec, usec, frame, length in records:
        output += struct.pack('<IIII', sec, usec, len(frame), length) + frame
    Path(f'test/resources/linktype-{name}.pcap').write_bytes(output)
