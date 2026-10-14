# P08-D2 NULL/LOOP verification and decoding contract

The initial P08-D1 handoff below distinguished source inference from required
runtime measurements. D2 completed those measurements before implementing decoding.
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

No NULL/LOOP bytes were normalized or decoded by Paclo in D1. D1 left native byte handling as an unfinished prerequisite.
D2 completes it with the probe-only measurements recorded below.

## D2 pre-implementation probe

The D2 branch starts at merged D1 main `0d06dd1`. Twelve captures in
`test/resources/null-loop/` vary Classic file / PCAPNG section order independently
of NULL pseudoheader order; LOOP always uses big endian, with one deliberately
little-endian negative record. Each NULL capture has 61 records, each LOOP has
62. AFs 2/24/28/30, unknown 999/10, AF/version mismatch, 0–3 framing bytes,
malformed/truncated IP/L4, fragments, extensions, DNS and TLS are included.

`paclo.null-loop-native-test` independently extracts physical Classic record and
PCAPNG EPB bytes, copies `pcap_next_ex`'s pointer bytes directly, and compares both
with public raw packets and the deterministic manifest. It prints native DLT,
OS/version, JVM architecture/version, host order, library version and distinct
pseudoheaders. Bounded reads close in finally. Fixture regeneration runs in CI.

Local macOS 15.4.1 x86_64 / libpcap 1.10.1 / little-endian / JDK 21.0.12.1:
all three byte representations agree on all 12 files, including deliberately
opposed container/header order. Native DLTs are 0 and 108; neither pseudoheader
is normalized. The native matrix results below were inspected before implementation.

Accepted interpretation after those results: NULL recognizes a unique
member of `{2,24,28,30}` under the two uint32 orders; LOOP recognizes only the
big-endian interpretation. Byte reversal of every known AF is outside that set,
so no four bytes can match two supported AFs. Zero matches fails explicitly;
there is no version-only acceptance. IP version must then match AF (2 → 4,
24/28/30 → 6). Origin OS is not deduced from AF. No container-order metadata
exists in packet maps, so container/header consistency and original file
encoding cannot be validated or reconstructed. Standalone and live packet
framing follow the same byte contract, without a live/NIC validation claim.

## Installed-library matrix results

Probe-only commit `9e36c04` preceded all runtime decoder changes.
[Probe CI run 38577395767](https://github.com/nantes-rfli/paclo/actions/runs/38577395767)
passed all 12 jobs. [Exact measurement data](p08-d2-native-evidence.edn) retains
all 12 per-file observations and environment/library strings for each platform.

| Measured environment | Installed library | Host order | Native DLT NULL / LOOP | Stored = native = Paclo bytes |
| --- | --- | --- | --- | --- |
| Ubuntu Linux x64, kernel 6.17.0-1022-azure, JDK 21.0.12.1 | libpcap 1.10.4 (TPACKET_V3) | little | 0 / 108 | All 736 records across 12 files |
| macOS 26.6.2 ARM64, JDK 17.0.20.1 | libpcap 1.10.1 | little | 0 / 108 | All 736 records across 12 files |
| Ubuntu Linux ARM64, kernel 6.17.0-1022-azure, JDK 21.0.12.1 | libpcap 1.10.4 (TPACKET_V3) | little | 0 / 108 | All 736 records across 12 files |

Eight NULL captures each contain 61 records; four LOOP captures each contain
62. Both header orders and both container orders were read on little-endian
hosts; this does not validate a big-endian execution host. Installed libraries
leave all NULL/LOOP bytes unchanged, including deliberately mismatched container
and pseudoheader order. Neither native reader nor Paclo normalizes the AF field.
The pinned upstream 1.10.4/1.10.5 switch has no NULL/LOOP conversion case; that
source inference agrees with, but does not replace, installed-library evidence.
Darwin's library was measured directly; an upstream version string is not proof
that an Apple build has identical source.

## Shared framing and output

`paclo.linktype` owns minimum header bounds, uint32 AF interpretation, AF/version
validation and packed protocol/absolute L3 offset 4. Full and flow reuse their
existing IP/L4 walkers. Full builds `{:type :null :address-family 2 :l3 ...}` or
`:type :loop`, preserving the original packet byte-array reference. It does not
infer OS, emit Ethernet/cooked fields, clone the frame or normalize the header.
Flow produces the existing six numeric IP/protocol/port fields and five capture
metadata fields, without bytes, nested decode or link-detail map. P06/P07 need
no API changes. Existing differences in parser depth and partial results remain.

For NULL the two uint32 interpretations are checked against exactly 2/24/28/30.
Reversing each known AF gives a value outside that set; a double match is
mathematically impossible for this set. Unsupported AFs fail before reading the
IP byte, even if it looks like valid IP. No ambiguous candidate is guessed;
extending the supported set would require revisiting that uniqueness proof.
LOOP only accepts a known big-endian AF. AF 2 requires version 4; all supported
IPv6 AFs require 6. Linux AF_INET6 10 remains unsupported. An AF value alone does
not prove the capture origin's OS.

The same contract applies to explicit standalone packets and packets delivered
by a live handle. This is a framing contract, not new live/NIC measurements.
NULL/LOOP are enabled only on Linux/macOS. OpenBSD's DLT_LOOP 12 collides with
the measured DLT_RAW 12 elsewhere; OpenBSD and other unmeasured systems remain
unsupported without numeric mapping guesses. Savefile LINKTYPE_NULL/LOOP 0/108
happen to agree with native DLTs on the measured systems; use native metadata
and writer options. The existing Classic writer copies bytes unchanged, even
when a NULL pseudoheader order differs from its host-order output container.
It cannot ensure header/container consistency or reproduce the original file
encoding, because packet maps have no source file byte order.

## Failure classification

| Case | Reason / fields | Absolute location |
| --- | --- | --- |
| Unverified or invalid native DLT | `:unsupported-linktype`, `:linktype` | None; dispatch precedes bytes |
| Missing / 0–3 pseudoheader bytes | `:short-frame` | offset 0, required 4 |
| Unknown AF, including 10 / little-endian LOOP | `:unsupported-address-family`, `:field :address-family`, big-endian `:value`; NULL also `:little-endian-value` | offset 0, required 4 |
| Known AF but missing IP byte | `:truncated-header` | offset 4, required 1 |
| Version other than 4/6 | `:malformed-packet`, `:field :ip-version`, `:value` | offset 4, required 1 |
| Valid IP version disagrees with AF | `:address-family-mismatch`, `:field :ip-version`, `:value`, `:address-family`, `:expected-version` | offset 4, required 1 |
| Short base IP header | `:truncated-header` | offset 4, required 20/40 |
| Malformed IP / short L4 / incomplete IPv6 extensions | Existing malformed/truncated diagnostics and partial-result semantics | Original packet offsets, including the 4-byte header |

Both facade paths retain string errors and append EDN diagnostics with their
existing `:decode`/`:flow` stages. Truncated L4 can be successful in flow if the
four port bytes exist, while full requires its complete header. No checksum
validation, reassembly, complete PCAPNG metadata, PCAPNG writer, exact timestamp
precision, new public framing API, version/release or unrelated optimization is
introduced.

## Implementation acceptance evidence

Implementation `93e5cde` [CI run 38582258137](https://github.com/nantes-rfli/paclo/actions/runs/38582258137)
passed all 12 jobs with no failed internal steps. Linux x64 and Linux ARM64
passed 428 tests / 15,744 assertions; macOS ARM64 passed 428 / 15,738. The extra
six Linux assertions exercise existing `/dev/full` writer failures. All three
repeat the 12 native byte comparisons after decoding is present, including
all AF/endian/adversarial records. Fixture, 500 new property cases, writer,
capture-path, fan-out, DNS/TLS and P06/P07 tests pass on each platform. All 28
documentation examples, Java quality/coverage and existing performance gates
also pass. This does not extend validation to live/NIC capture or other OSes.
Independent review/merge remains on [PR #46](https://github.com/nantes-rfli/paclo/pull/46);
final evidence-head checks are maintained there.
