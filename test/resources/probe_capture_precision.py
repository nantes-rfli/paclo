"""Probe libpcap precision APIs that Paclo's current JNR interface does not bind.

Run: python3 test/resources/probe_capture_precision.py
Checks exact native nanoseconds as well as default microsecond truncation.
This is investigation tooling, not a Paclo backend or metadata API.
"""
import ctypes as c
import ctypes.util
from pathlib import Path
import platform
import json


class Timeval(c.Structure):
    _fields_ = [('sec', c.c_long), ('fraction', c.c_int if platform.system() == 'Darwin' else c.c_long)]


class Header(c.Structure):
    _fields_ = [('time', Timeval), ('caplen', c.c_uint32), ('length', c.c_uint32)]


def main():
    lib = c.CDLL(ctypes.util.find_library('pcap'))
    lib.pcap_lib_version.restype = c.c_char_p
    lib.pcap_open_offline_with_tstamp_precision.argtypes = [c.c_char_p, c.c_uint, c.c_char_p]
    lib.pcap_open_offline_with_tstamp_precision.restype = c.c_void_p
    lib.pcap_next_ex.argtypes = [c.c_void_p, c.POINTER(c.POINTER(Header)), c.POINTER(c.c_void_p)]
    lib.pcap_get_tstamp_precision.argtypes = [c.c_void_p]
    lib.pcap_close.argtypes = [c.c_void_p]
    root = Path(__file__).resolve().parent / 'capture-formats'
    results = []
    for name in ['ethernet-nano.pcap', 'nano.pcapng', 'mixed-resolution.pcapng']:
        for precision in [0, 1]:
            err = c.create_string_buffer(256)
            handle = lib.pcap_open_offline_with_tstamp_precision(str(root / name).encode(), precision, err)
            assert handle, err.value
            try:
                assert lib.pcap_get_tstamp_precision(handle) == precision
                values = []
                while True:
                    header = c.POINTER(Header)()
                    data = c.c_void_p()
                    rc = lib.pcap_next_ex(handle, c.byref(header), c.byref(data))
                    if rc != 1:
                        assert rc == -2, (name, rc)
                        break
                    values.append([header.contents.time.sec, header.contents.time.fraction])
                fractions = ([123456000, 123456789] if name == 'mixed-resolution.pcapng' else [123456789]) if precision else ([123456, 123456] if name == 'mixed-resolution.pcapng' else [123456])
                assert values == [[1700000000, x] for x in fractions], (name, precision, values)
                results.append({'file': name, 'precision': precision, 'timestamps': values})
            finally:
                lib.pcap_close(handle)
    print(json.dumps({'os': platform.platform(), 'arch': platform.machine(),
                      'libpcap': lib.pcap_lib_version().decode(), 'precision-probes': results}))


if __name__ == '__main__':
    main()
