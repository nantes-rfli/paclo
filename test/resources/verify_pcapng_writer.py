"""Independent test-only physical PCAPNG parser/oracle for writer round trips."""
from pathlib import Path
import struct
import sys

sys.dont_write_bytecode = True
from test_pcapng_contract_fixtures import wire_blocks, wire_options


def semantics(path):
    result = []
    interfaces = []
    section = -1
    for kind, endian, body in wire_blocks(Path(path).read_bytes()):
        if kind == 0x0a0d0d0a:
            section += 1
            interfaces = []
            assert struct.unpack_from(endian + 'HH', body, 4) == (1, 0)
            result.append((kind, section, endian, wire_options(body[16:], endian)))
        elif kind == 1:
            link, reserved, snap = struct.unpack_from(endian + 'HHI', body)
            assert reserved == 0
            options = wire_options(body[8:], endian)
            interfaces.append(snap)
            result.append((kind, section, len(interfaces)-1, link, snap, options))
        elif kind == 6:
            iface, hi, lo, caplen, length = struct.unpack_from(endian + 'IIIII', body)
            assert iface < len(interfaces) and caplen <= length
            assert interfaces[iface] == 0 or caplen <= interfaces[iface]
            end = 20 + (caplen+3)//4*4
            assert end <= len(body)
            result.append((kind, section, iface, (hi << 32) | lo, caplen, length,
                           body[20:20+caplen], wire_options(body[end:], endian)))
        elif kind == 3:
            length, = struct.unpack_from(endian + 'I', body)
            caplen = min(length, interfaces[0]) if interfaces[0] else length
            assert len(body) == 4 + (caplen+3)//4*4
            result.append((kind, section, 0, None, caplen, length, body[4:4+caplen]))
        else:
            result.append((kind, section, endian, body))
    return result


if __name__ == '__main__':
    assert semantics(sys.argv[1]) == semantics(sys.argv[2])
    print('PCAPNG independent wire comparison OK')
