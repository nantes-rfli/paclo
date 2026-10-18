"""P16 offline interoperability gate; requires Wireshark CLI tools and tcpdump.

Run after compiling Java: python3 dev/script/verify_interop.py OUTPUT_DIRECTORY
Only synthetic RFC 5737 traffic is used. No network interface is opened.
Output must be fresh; commands, versions, wire oracles and captures are retained.
"""
import argparse
from decimal import Decimal
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import struct
import subprocess
import sys

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'test/resources'))
from make_capture_format_fixtures import block, options
from test_pcapng_contract_fixtures import wire_blocks, wire_options
from verify_pcapng_writer import semantics

TOOLS = ['text2pcap', 'editcap', 'mergecap', 'tshark', 'capinfos', 'tcpdump']
TIMES = [1700000000123456789, 1700000001987654321]
IP = bytes.fromhex('450000320001000040110000c0000201c0000202')
UDP = struct.pack('>HHHH', 12000, 53, 30, 0) + bytes(22)
FRAMES = {
    1: bytes(range(12)) + bytes.fromhex('0800') + IP + UDP,
    113: struct.pack('>HHH8sH', 0, 1, 6, bytes(range(6)) + bytes(2), 0x800) + IP + UDP,
    276: struct.pack('>HHIHBB8s', 0x800, 0, 7, 1, 0, 6,
                     bytes(range(6)) + bytes(2)) + IP + UDP,
    101: IP + UDP,
    0: struct.pack('<I', 2) + IP + UDP,
    108: struct.pack('>I', 2) + IP + UDP,
}


class Gate:
    def __init__(self, output):
        self.output = output
        self.commands = []

    def run(self, *args, ok=True):
        args = list(map(str, args))
        result = subprocess.run(args, cwd=ROOT, capture_output=True, text=True,
                                timeout=600, env={**os.environ, 'TZ': 'UTC', 'LC_ALL': 'C'})
        entry = dict(command=args, exit=result.returncode, stdout=result.stdout, stderr=result.stderr)
        self.commands.append(entry)
        (self.output / 'commands.json').write_text(json.dumps(self.commands, indent=2) + '\n')
        if ok and result.returncode:
            raise RuntimeError(f'{args}: exit {result.returncode}\n{result.stdout}\n{result.stderr}')
        return result

    def path(self, name):
        return self.output / name


def records(path):
    """Independent physical oracle, including exact tick/resolution/offset values."""
    data = path.read_bytes()
    result = []
    if data[:4] != b'\x0a\x0d\x0d\x0a':
        endian, scale = {b'\xd4\xc3\xb2\xa1': ('<', 10**6),
                         b'\xa1\xb2\xc3\xd4': ('>', 10**6),
                         b'\x4d\x3c\xb2\xa1': ('<', 10**9),
                         b'\xa1\xb2\x3c\x4d': ('>', 10**9)}[data[:4]]
        snap, link = struct.unpack_from(endian + 'II', data, 16)
        position = 24
        while position < len(data):
            sec, fraction, caplen, length = struct.unpack_from(endian + 'IIII', data, position)
            payload = data[position+16:position+16+caplen]
            assert len(payload) == caplen <= snap and caplen <= length
            result.append(dict(hex=payload.hex(), caplen=caplen, len=length,
                               **{'ts-sec': sec, 'ts-usec': fraction * 10**6 // scale,
                                  'linktype': 12 if link == 101 else link}))
            position += 16 + caplen
        return result
    section = -1
    interfaces = []
    for kind, endian, body in wire_blocks(data):
        if kind == 0x0a0d0d0a:
            section += 1
            interfaces = []
        elif kind == 1:
            link, _, snap = struct.unpack_from(endian + 'HHI', body)
            opts = dict(wire_options(body[8:], endian))
            resolution = opts.get(9, b'\x06')[0]
            base, exponent = (2 if resolution & 128 else 10), resolution & 127
            offset = struct.unpack(endian + 'q', opts.get(14, bytes(8)))[0]
            interfaces.append((link, snap, base, exponent, offset))
        elif kind == 6:
            iface, hi, lo, caplen, length = struct.unpack_from(endian + 'IIIII', body)
            link, snap, base, exponent, offset = interfaces[iface]
            ticks = (hi << 32) | lo
            sec, remainder = divmod(ticks, base**exponent)
            assert caplen <= length and (snap == 0 or caplen <= snap)
            result.append(dict(hex=body[20:20+caplen].hex(), caplen=caplen, len=length,
                               **{'ts-sec': sec + offset,
                                  'ts-usec': remainder * 10**6 // base**exponent,
                                  'linktype': 12 if link == 101 else link,
                                  'section-id': section, 'interface-id': iface,
                                  'ticks': str(ticks)}))
    return result


def generate(gate):
    cases = []

    def add(name, native='eof', prefix=None):
        rows = records(gate.path(name))
        cases.append(dict(file=name, records=rows, native=native, prefix=prefix,
                          pcapng=name.endswith('.pcapng')))
        return rows

    for link, frame in FRAMES.items():
        text = ''.join(f'2023-11-14T22:13:{20+i:02d}.{ticks % 10**9:09d}Z\n'
                       f'000000 {frame.hex(" ")}\n\n' for i, ticks in enumerate(TIMES))
        dump = gate.path(f'link-{link}.txt')
        dump.write_text(text)
        for fmt in ['pcap', 'nsecpcap', 'pcapng']:
            name = f'link-{link}-{fmt}.' + ('pcapng' if fmt == 'pcapng' else 'pcap')
            gate.run('text2pcap', '-q', '-t', 'ISO', '-l', link, '-N', f'p16-{link}',
                     '-F', fmt, dump, gate.path(name))
            rows = add(name)
            assert [r['hex'] for r in rows] == [frame.hex()] * 2
            assert [r['ts-usec'] for r in rows] == [123456, 987654]
        # tcpdump reads and serializes, using its own libpcap and BPF compiler.
        name = f'tcpdump-{link}.pcap'
        gate.run('tcpdump', '-n', '-r', gate.path(f'link-{link}-nsecpcap.pcap'),
                 '-w', gate.path(name), 'udp dst port 53')
        assert add(name) == records(gate.path(f'link-{link}-pcap.pcap'))

    base = gate.path('link-1-pcapng.pcapng')
    gate.run('editcap', '-s', 42, '--capture-comment', 'P16 section comment',
             '-a', '1:first comment', base, gate.path('editcap-snap.pcapng'))
    gate.run('editcap', '--preserve-packet-comments', '-a', '1:second comment',
             gate.path('editcap-snap.pcapng'), gate.path('comments.pcapng'))
    rows = add('comments.pcapng')
    assert [(r['caplen'], r['len']) for r in rows] == [(42, 64)] * 2
    for name, inputs, native in [
            ('interfaces.pcapng', [base, base], 'eof'),
            ('links.pcapng', [base, gate.path('link-101-pcapng.pcapng')], 'error'),
            ('snaplens.pcapng', [base, gate.path('link-1-pcap.pcap')], 'error')]:
        if name == 'snaplens.pcapng':
            gate.run('text2pcap', '-q', '-t', 'ISO', '-m', 64, '-F', 'pcap',
                     gate.path('link-1.txt'), gate.path('snap64.pcap'))
            inputs = [base, gate.path('snap64.pcap')]
        gate.run('mergecap', '-a', '-I', 'none', '-w', gate.path(name), *inputs)
        assert len(add(name, native, 0 if native == 'error' else None)) == 4

    # Concatenate independently externally generated sections, rather than merge
    # them (mergecap normally combines sections). Header swapping is a declared
    # lab mutation of externally serialized PCAP, not a claimed editcap feature.
    gate.path('sections.pcapng').write_bytes(base.read_bytes() * 2)
    assert len(add('sections.pcapng')) == 4
    data = gate.path('link-1-nsecpcap.pcap').read_bytes()
    endian = '<' if data[:4] == b'\x4d\x3c\xb2\xa1' else '>'
    swapped = struct.pack('>IHHIIII', *struct.unpack_from(endian+'IHHIIII', data))
    pos = 24
    while pos < len(data):
        header = struct.unpack_from(endian+'IIII', data, pos)
        swapped += struct.pack('>IIII', *header) + data[pos+16:pos+16+header[2]]
        pos += 16 + header[2]
    gate.path('big-endian.pcap').write_bytes(swapped)
    add('big-endian.pcap')

    # Extend a real text2pcap section with binary resolution/offset, ordered
    # unknown options and an unknown block. External interpretation is checked
    # independently; no third-party traffic or private enterprise payload.
    rich = b''
    for kind, endian, body in wire_blocks(base.read_bytes()):
        if kind == 1:
            opts = [(c, v) for c, v in wire_options(body[8:], endian) if c not in (9, 14)]
            body = body[:8] + options(opts + [(9, b'\x8a'),
                                             (14, struct.pack(endian+'q', 7)),
                                             (0xf123, b'P16 unknown')], endian)
        elif kind == 6:
            values = list(struct.unpack_from(endian+'IIIII', body))
            ticks = 1700000000 * 1024 + 129
            values[1:3] = [ticks >> 32, ticks & 0xffffffff]
            end = 20 + (values[3]+3)//4*4
            body = (struct.pack(endian+'IIIII', *values) + body[20:end]
                    + options([(1, b'rich comment'), (0xf123, b'P16 packet')], endian))
        rich += block(kind, body, endian)
    rich += block(4, bytes(4))  # Empty Name Resolution Block (end record).
    rich += block(0x80000f16, b'P16 unknown block')
    gate.path('rich.pcapng').write_bytes(rich)
    assert len(add('rich.pcapng')) == 2
    # Use a big-endian section from the existing synthetic corpus as an additional
    # external-reader case, retaining its provenance rather than relabelling it.
    # Replace the old 0x8001 private-option collision for Wireshark compatibility.
    data = (ROOT / 'test/resources/capture-formats/big-endian.pcapng').read_bytes()
    changed = b''
    for kind, order, body in wire_blocks(data):
        start = {0x0a0d0d0a: 16, 1: 8, 6: 84}[kind]
        opts = [(0xf123 if c == 0x8001 else c, v)
                for c, v in wire_options(body[start:], order)]
        changed += block(kind, body[:start] + options(opts, order), order)
    gate.path('mixed-sections.pcapng').write_bytes(base.read_bytes() + changed)
    assert len(add('mixed-sections.pcapng', 'error', 2)) == 3

    # Deterministic corruptions of actual external output, with a valid prefix.
    data = base.read_bytes()
    gate.path('cut.pcapng').write_bytes(data[:-3])
    gate.path('trailer.pcapng').write_bytes(data[:-4] + bytes(4))
    blocks = wire_blocks(data)
    invalid = b''
    packets = 0
    for kind, order, body in blocks:
        if kind == 6:
            packets += 1
            if packets == 2:
                body = struct.pack(order+'I', 99) + body[4:]
        invalid += block(kind, body, order)
    gate.path('interface.pcapng').write_bytes(invalid)
    data = gate.path('link-1-pcap.pcap').read_bytes()
    gate.path('cut.pcap').write_bytes(data[:-3])
    assert len(cases) == 32
    manifest = dict(cases=cases, malformed=[
        dict(file='cut.pcapng', reason='truncated-block'),
        dict(file='trailer.pcapng', reason='invalid-block-length'),
        dict(file='interface.pcapng', reason='undefined-interface'),
        dict(file='cut.pcap', reason=None)])
    gate.path('manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    return manifest


def tshark_rows(gate, path, ok=True):
    result = gate.run('tshark', '-n', '-r', path, '-T', 'fields',
                      '-e', 'frame.time_epoch', '-e', 'frame.cap_len', '-e', 'frame.len',
                      '-e', 'frame.comment', ok=ok)
    return result, [line.split('\t') for line in result.stdout.splitlines()]


def verify_external(gate, path, expected):
    _, actual = tshark_rows(gate, path)
    assert len(actual) == len(expected), (path, actual, expected)
    for row, record in zip(actual, expected):
        # tshark exposes nanoseconds, while Paclo's native path floors to usec.
        usec = int(Decimal(row[0]) * 10**6)
        assert usec == record['ts-sec'] * 10**6 + record['ts-usec'], (path, row, record)
        assert list(map(int, row[1:3])) == [record['caplen'], record['len']], (path, row)
    # A second reader must consume every Classic record to EOF as well.
    if path.suffix == '.pcap':
        gate.run('tcpdump', '-n', '-r', path, '-w', os.devnull)


def metadata_inventory(path):
    rows = wire_blocks(path.read_bytes())
    return dict(blocks=[kind for kind, _, _ in rows],
                interfaces=[[(code, value.hex()) for code, value in wire_options(body[8:], order)]
                            for kind, order, body in rows if kind == 1],
                packets=[[(code, value.hex()) for code, value in wire_options(
                    body[20 + (struct.unpack_from(order+'I', body, 12)[0]+3)//4*4:], order)]
                         for kind, order, body in rows if kind == 6],
                records=records(path))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    gate = Gate(output)
    for tool in TOOLS:
        if not shutil.which(tool):
            raise SystemExit(f'Missing required interoperability tool: {tool}')
    identity = dict(os=platform.platform(), machine=platform.machine(), tools={})
    identity['cpu'] = gate.run(*(['sysctl', '-n', 'machdep.cpu.brand_string']
                                if sys.platform == 'darwin' else ['lscpu'])).stdout
    identity['source'] = gate.run('git', 'rev-parse', 'HEAD').stdout.strip()
    identity['working_tree'] = gate.run('git', 'status', '--short', '--untracked-files=all').stdout
    identity['harness_sha256'] = {
        name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest()
        for name in ['dev/script/verify_interop.py', 'dev/paclo/dev/interop.clj']}
    for tool in TOOLS:
        version = gate.run(tool, '--version')
        identity['tools'][tool] = dict(path=shutil.which(tool),
                                      version=version.stdout + version.stderr)
    gate.path('environment.json').write_text(json.dumps(identity, indent=2) + '\n')
    manifest = generate(gate)
    for case in manifest['cases']:
        verify_external(gate, gate.path(case['file']), case['records'])
    for case in manifest['malformed']:
        result, _ = tshark_rows(gate, gate.path(case['file']), ok=False)
        assert result.returncode != 0, case
    # The Clojure runner checks native and metadata paths independently, writes
    # both formats, and tests atomic publication using these actual inputs.
    result = gate.run('clojure', '-M:dev', '-m', 'paclo.dev.interop', output)
    print(result.stdout)
    reports = json.loads(gate.path('paclo.json').read_text())
    for case in reports['outputs']:
        path = gate.path(case['file'])
        verify_external(gate, path, case['records'])
        actual_records = [{k: v for k, v in r.items()
                           if k not in ('ticks', 'section-id', 'interface-id')}
                          for r in records(path)]
        assert actual_records == case['records'], case
        if case.get('preserve'):
            assert semantics(gate.path(case['source'])) == semantics(path), case
    # Tool normalization is measured separately, never asserted as preservation.
    gate.run('editcap', gate.path('rich.pcapng'), gate.path('editcap-normalized.pcapng'))
    before = semantics(gate.path('rich.pcapng'))
    after = semantics(gate.path('editcap-normalized.pcapng'))
    gate.path('normalization.json').write_text(json.dumps(dict(
        original=metadata_inventory(gate.path('rich.pcapng')),
        editcap=metadata_inventory(gate.path('editcap-normalized.pcapng')),
        equal=before == after), indent=2) + '\n')
    # All generated/returned files are retained for CI inspection; hashes identify
    # an execution, not cross-version bit-for-bit reproducibility promises.
    hashes = {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
              for p in output.iterdir() if p.suffix in ('.pcap', '.pcapng')}
    gate.path('sha256.json').write_text(json.dumps(hashes, indent=2) + '\n')
    gate.path('success.json').write_text(json.dumps(dict(status='passed',
        input_cases=len(manifest['cases']), malformed=len(manifest['malformed']),
        outputs=len(reports['outputs'])), indent=2) + '\n')
    print(f'P16 interoperability passed: {output}')


if __name__ == '__main__':
    main()
