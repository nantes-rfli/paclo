# P08-D2 NULL/LOOP investigation handoff

P08-D1 deliberately adds no NULL/LOOP decoder. This is a source-backed design
inventory and a required measurement plan, not validation on additional hosts.
The existing P08-A fixtures measured native DLT_NULL 0 and DLT_LOOP 108 on
Linux x64/ARM64 and macOS ARM64, but did not cover cross-endian NULL or IPv6 AFs.

## Format and origin boundaries

[LINKTYPE_NULL](https://www.tcpdump.org/linktypes/LINKTYPE_NULL.html) has a
four-byte address-family pseudoheader in the capture origin's host byte order.
[LINKTYPE_LOOP](https://www.tcpdump.org/linktypes/LINKTYPE_LOOP.html) has the same
field in network (big-endian) order. IP starts at offset 4. Both specify IPv4
family 2 and IPv6 families 24, 28 and 30. These identify capture-origin ABIs;
using only the reading machine's AF_INET6 would reject valid foreign captures.

| Origin ABI (source definition, not runtime verification) | AF_INET | AF_INET6 |
| --- | --- | --- |
| [Darwin](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/socket.h) | 2 | 30 |
| [FreeBSD](https://github.com/freebsd/freebsd-src/blob/main/sys/sys/socket.h) | 2 | 28 |
| [NetBSD](https://github.com/NetBSD/src/blob/trunk/sys/sys/socket.h) | 2 | 24 |

Linux's socket AF_INET6 (10) must not be substituted for the documented savefile
families merely because Linux reads the file. Unknown AFs, header/IP-version
mismatch and invalid IP versions require explicit classification; no Ethernet
fallback or speculative OS-family mapping. Live and standalone NULL packets also
need a stated byte-order contract, since ordinary packet maps have no originating
container byte-order metadata.

## Native DLT versus savefile LINKTYPE

[libpcap's pinned DLT header](https://github.com/the-tcpdump-group/libpcap/blob/libpcap-1.10.5/pcap/dlt.h)
defines DLT_NULL 0. DLT_LOOP is 12 on OpenBSD and 108 elsewhere; OpenBSD DLT_RAW
is 14, whereas measured Linux/macOS DLT_RAW is 12. Savefiles use LINKTYPE_NULL 0,
LINKTYPE_LOOP 108 and LINKTYPE_RAW 101. The
[pinned conversion code](https://github.com/the-tcpdump-group/libpcap/blob/libpcap-1.10.5/pcap-common.c)
converts file codes when opening and native DLTs when writing. Retain native
`:linktype`; do not label packets with savefile constants or enable OpenBSD from
these definitions without runtime evidence. D1 rejects DLT_RAW on unverified OSes.

## Cross-endian Classic PCAP and native processing

Classic PCAP's magic establishes file byte order. The
[pinned reader](https://github.com/the-tcpdump-group/libpcap/blob/libpcap-1.10.5/sf-pcap.c)
sets a swapped flag, converts record metadata and invokes `pcapint_post_process`
on packet bytes before returning them. The
[pinned post-processing source](https://github.com/the-tcpdump-group/libpcap/blob/libpcap-1.10.5/pcap-util.c)
only swaps selected pseudoheaders: its `swap_pseudo_headers` switch has no NULL
or LOOP case. Source inspection therefore predicts unchanged NULL/LOOP packet
bytes in that upstream version, rather than automatic host-order normalization.
This is an inference from source, not installed-library runtime evidence. Confirm
Linux 1.10.4 and Apple's 1.10.1 behavior with byte comparisons on the native
matrix. Do not assume the packet is already host-normalized just because record
metadata was swapped. PCAPNG section byte order needs separate native evidence.

Paclo packet maps currently lack container byte-order metadata. Since the defined
AF values are small, checking both byte orders against the explicit known AF set
could avoid requiring container state; evaluate mismatch/ambiguity and unknown
values with the probes before accepting that design. Do not map a value merely
because it is the reader's local AF_INET6. The writer uses native DLT metadata
and copies supplied bytes; decoding must not silently normalize published arrays.

## Required D2 probes and acceptance

- Generate deterministic little/big-endian Classic PCAPs for NULL and LOOP,
  IPv4 AF 2, IPv6 AF 24/28/30, and unknown/mismatched/short pseudoheaders.
  Record both stored bytes and bytes returned by libpcap, native DLT, versions,
  host endian and library version on Linux x64, macOS ARM64 and Linux ARM64.
- For NULL, pair origin pseudoheader order with file order and include deliberately
  inconsistent pairs to establish rejection boundaries. For LOOP, retain big-endian
  AF bytes under both file byte orders. Add original/captured-length round trips.
- Compare direct packet-xf, native offline reads and Classic writer output. Decide
  the standalone/live byte-order contract explicitly; no container state is
  available inside the pure framing function. Assess ambiguous AFs before sniffing.
- Only then extend shared `paclo.linktype` at offset 4, reusing full/numeric IP
  walkers, truthful link wrappers, absolute diagnostics and existing lifecycle
  contracts. Run all gates and the native CI matrix without guessed platforms.

No NULL/LOOP bytes were normalized or decoded by Paclo in D1. D2 feasibility is
supported by existing framing dispatch and the format definitions; exact native
byte handling remains an unfinished measurement prerequisite.
