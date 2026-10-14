# P08-A: Capture formats, evidence and P08-B scope

Investigation baseline: main `8312d10` (PR #36), 2026-10-14. This change adds
fixtures, characterization tests and design evidence only. No production decoder,
native binding, public writer API, dependency or quality gate changes.
Performance issues #34 and #37 are outside this investigation.

Current follow-up: [P08-E1](p08-e1-pcapng-contracts.md) owns the detailed future
metadata/time/reader/writer contract. This inventory preserves historical A
measurements; B1/B2 and C/D1/D2 implemented later error, writer and framing changes.

## Evidence boundaries

Three kinds of evidence must remain separate:

- **Code:** Paclo calls `pcap_open_offline`, reads `pcap_pkthdr`, copies captured
  bytes into a fresh Java array, and obtains one DLT per handle. Both full decode
  and flow projection guard for Ethernet. The public writer creates a dead
  Ethernet handle; the internal writer already accepts a single native DLT.
- **Native specification:** the [libpcap open manual][open-manual] permits PCAP
  and a subset of PCAPNG, with precision conversion. Its [dump manual][dump-manual]
  describes savefile output using handle properties. The pinned
  [PCAPNG reader source][native-reader] supplies context for observed restrictions;
  it is not proof of the behavior of every installed libpcap version.
- **Measurement:** `paclo.capture-format-test` directly calls the existing JNR
  binding and separately exercises public reads, transforms and writes. The
  Python precision probe calls native APIs absent from Paclo's binding. All
  conclusions below are limited to the fixtures and recorded native versions.

The [PCAPNG draft][pcapng-draft] is a format reference, not a promise that libpcap
or Paclo supports every block. This pinned March 2026 draft is work in progress.

## Capability matrix

Here, raw means captured bytes and the six current map fields; it does not mean
all source information. Full/flow support means both public transformations.
Faithful output means retaining source format, framing and metadata, not merely
writing an equal byte array into an incorrectly labeled file.

| Input or operation | Native read / write observed | Paclo raw | Full / flow | Public faithful output |
| --- | --- | --- | --- | --- |
| Classic Ethernet PCAP, either byte order | Read | Yes | Yes for valid IP frame | Packet bytes/time/lengths; source header not retained |
| Classic SLL, LINKTYPE 113 | Read (existing P05 fixture) | Yes, DLT 113 | Unsupported diagnostic | No; writer labels bytes Ethernet |
| Classic SLL2, LINKTYPE 276 | Read | Yes, DLT 276 | Unsupported diagnostic | No; writer labels bytes Ethernet |
| Classic BSD NULL, LINKTYPE 0 | Read (existing P05 fixture) | Yes, DLT 0 | Unsupported diagnostic | No; writer labels bytes Ethernet |
| Classic BSD LOOP, LINKTYPE 108 | Read | Yes, DLT 108 | Unsupported diagnostic | No; writer labels bytes Ethernet |
| Classic Raw IP, LINKTYPE 101 | Read | Yes, DLT 12 on measured matrix | Unsupported diagnostic | No; writer labels bytes Ethernet |
| PCAPNG SHB + IDB + Ethernet EPB, either byte order | Read | Yes | Yes | No PCAPNG output; packet subset can become PCAP |
| PCAPNG multiple interfaces, same link/snaplen | Read both packets | Yes; interface identity lost | Yes for Ethernet | No; collapses interfaces |
| PCAPNG multiple link types | First packet then native -1 | Partial prefix, currently normal EOF | Only prefix decoded | No |
| PCAPNG different interface snaplen | First packet then native -1 | Partial prefix, currently normal EOF | Only prefix decoded | No |
| PCAPNG same-byte-order multiple sections | Read both packets | Yes; section identity lost | Yes for Ethernet | No; collapses sections |
| PCAPNG section byte order changes | First packet then native -1 | Partial prefix, currently normal EOF | Only prefix decoded | No |
| Classic nanosecond PCAP | Native nano API retains 123456789 ns | Default read emits 123456 us | Same normalized time | No source precision / sub-us digits |
| PCAPNG decimal 10^-6 / 10^-9, including mixed interfaces | Both resolutions read; nano API retains digits | Microsecond normalization | Same normalized time | No source resolution / sub-us digits |
| PCAPNG binary 2^-10 | Read; 129 ticks -> 125976 us | Normalized time only | Yes | No original ticks / resolution |
| PCAPNG if_tsoffset +7 seconds | Offset applied | Adjusted epoch seconds | Yes | No original offset |
| PCAPNG IDB / section / packet comments and unknown options | Packets read | Metadata absent | Metadata absent | No |
| PCAPNG valid unknown block | Skipped, later EPB read | No unknown block data | Later packet decodes | No |
| PCAPNG Simple Packet Block | Read; no source timestamp | Emits [0 0], indistinguishable from real epoch zero | Yes | Cannot preserve timestamp absence |
| Valid truncated capture (caplen < len) | Read | Both lengths retained | Short L3 gets decode error | Lengths/bytes retained in PCAP subset |
| EPB original length less than caplen | Native accepts inconsistent lengths | Values retained (64/1) | Parses available bytes | Writer rejects :len < :caplen |
| Invalid interface/caplen/block lengths/trailer or cut block | Native -1 before unsafe copy | Empty prefix, currently normal EOF | No packet diagnostic | No |
| Invalid IDB timestamp option length | Open fails with errbuf | Throws ex-info | No packet | No |
| Public PCAP writer | Native dump writes Classic PCAP | Accepts byte arrays/maps | Independent of decode | Ethernet, microseconds, snaplen 65536 only |
| Internal PCAP writer with explicit DLT | SLL/SLL2/NULL/Raw/LOOP round trips measured | Retains subset and DLT | Independent of decode | Single-DLT packet subset only; not public API |
| PCAPNG writer | No binding or implementation | Unavailable | N/A | Unavailable |

DLT and savefile LINKTYPE are different namespaces. The initial test assumption
that Darwin DLT_RAW was 14 failed: the actual macOS library returns 12, consistent
with upstream Linux definitions. Both Linux CI architectures also returned 12.
OpenBSD constants cannot be generalized to macOS. See the
[upstream DLT definitions][dlt-header]. No arbitrary LINKTYPE-to-DLT conversion
is proposed for ordinary packet maps.

## Reproducible fixtures and expectations

Existing `test/resources/dns-sample.pcap`, `linktype-sll.pcap` and
`linktype-null.pcap` remain unchanged and run through `paclo.linktype-test`.
The SLL/NULL generator `make_linktype_fixtures.py` already documents its three
records: proper IPv4/UDP, a two-byte truncated header with original length 1500,
and deliberately Ethernet-looking bytes to protect dispatch.

New files live in `test/resources/capture-formats/`. Run
`python3 test/resources/make_capture_format_fixtures.py` from any directory.
`--check` compares all 28 files and the JSON manifest byte for byte; it never
rewrites files. Python 3 and its standard library are sufficient. The Clojure
suite executes this check and the precision probe on each CI test platform.
No live capture, downloaded binary dataset or packet-generation library is used.

All new packets are synthetic: IPv4 10.0.0.1 -> 10.0.0.2, UDP 12000 -> 53,
50 IP bytes, 22 payload bytes, Ethernet 64 bytes. Checksums are deliberately zero;
these fixtures investigate framing/I/O, not checksum or DNS semantics. Base
seconds are 1700000000, microseconds 123456; nano cases use 123456789 ns.
`manifest.json` specifies ordered byte hex, normalized timestamps, captured and
original lengths, expected native DLT, terminal status and error-message family.
The native version's exact message is printed, not used as a portable string API.

| Files (extension omitted where all are PCAPNG) | Construction and expected result |
| --- | --- |
| ethernet.pcap, ethernet-big-endian.pcap | Classic 2.4, snaplen 65536, LINKTYPE 1; same packet in both byte orders |
| ethernet-nano.pcap | Nanosecond magic; native default truncates digits, precision API retains them |
| sll2.pcap, raw.pcap, loop.pcap | LINKTYPE 276/101/108; SLL2 20-byte header, bare IP, big-endian AF_INET header |
| single, big-endian | SHB 1.0, IDB, EPB; same packet and metadata in each section byte order |
| multi-interface | Two IDBs, two EPBs (IDs 0/1), equal link/snaplen; two equal raw maps |
| multi-linktype, multi-snaplen | Valid first packet, then incompatible IDB; native -1 with one-packet prefix |
| nano, mixed-resolution, binary-resolution | IDB option 9 = 9, mixed default/9, or 0x8a; normalized expectations in manifest |
| offset | Signed IDB option 14 = +7; expected seconds 1700000007 |
| multi-section, mixed-endian-section | Two SHBs and reset interface IDs; equal endian reads, changed endian fails after prefix |
| unknown-block | Valid private block 0x80000042 between IDB and EPB; skipped |
| truncated | EPB caplen 16, original length 1500; safe raw read and full/flow decode errors |
| invalid-original-length | EPB original length 1, caplen 64; native accepts, writer rejects |
| simple-packet | SPB with original length 64; normalized timestamp [0 0] |
| bad-interface | EPB interface ID 9 with only IDB 0; native -1 |
| bad-caplen | EPB capture length 65537 > IDB snaplen 65536; native -1 |
| short-block, bad-trailer, cut-block | Total length 8, mismatched trailing length, or removed final bytes; native -1 |
| bad-idb-option | if_tsresol length 2 instead of 1; open failure |
| bad-pcap-length.pcap | Classic header then caplen 65537 with no payload; native read failure |

Generation references: [PCAPNG block/options reference][pcapng-draft],
[libpcap SLL/SLL2 layouts][sll-header], [NULL host byte order][null-format],
[LOOP network byte order][loop-format], and [savefile format][savefile-source].
Generators use `struct.pack` and 32-bit padding, duplicate block lengths, option
terminators, SHB byte-order magic, IDB scope and 64-bit timestamp ticks explicitly.
Interface comments/names, section and packet comments, and unknown option 0x8001
are deliberately present in ordinary valid fixtures, not only in an isolated
metadata case. Unknown private blocks/options being skipped is measured; it does
not establish support for NRB, ISB, DSB, obsolete PB, arbitrary options or secrets.

## Failures and platform evidence

Native `pcap_next_ex` supplies a nonempty error and -1 for the negative read
fixtures. The native probe is bounded to ten records and closes the handle in
`finally`; no failed native packet is copied. Malformed IDB open fails through
`:reason :pcap-open-failed` with native `:err`. This demonstrates safe bounded
termination for these cases, not exhaustive malformed-input security.

**Current public error reporting is insufficient:** `loop-n-or-ms!` and
`loop-for-ms!` terminate on either negative rc without throwing. Synchronous
reports classify these failures as `:eof` with nil error; lazy and managed reads
also return the prefix normally. The characterization test intentionally records
this defect and must change when P08-B fixes it. A prefix can contain valid
packets and still come from an incomplete capture. Packet diagnostics cannot
represent failures for which no packet exists. Preserve the native rc/error at
capture scope; do not synthesize a corrupt packet or claim faithful replay.

On macOS 1.10.1, a changed-endian section first produces a block-size error;
other versions can report byte order. An EOF can carry a stale `pcap_geterr`
string (observed for SPB), so classify by return code, not by nonempty geterr.

| Environment | Native version and result |
| --- | --- |
| Local macOS 15.4.1 x86_64, JDK 21.0.12.1 | libpcap 1.10.1; focused inventory/precision observations recorded in work log |
| GitHub Ubuntu 24.04 x64, kernel 6.17.0-1022-azure, JDK 21.0.12.1 | libpcap 1.10.4 (TPACKET_V3); full suite 385 tests/3093 assertions passed |
| GitHub macOS 26.6.2 ARM64, JDK 17.0.20.1 | libpcap 1.10.1; full suite 385 tests/3093 assertions passed |
| GitHub Ubuntu 24.04 ARM64, kernel 6.17.0-1022-azure, JDK 21.0.12.1 | libpcap 1.10.4 (TPACKET_V3); full suite 385 tests/3093 assertions passed |

All 28 fixture terminal outcomes, record bytes/lengths, DLTs and precision probe
values agree across these three CI environments. macOS 1.10.1 leaves a stale SPB
error string; Linux 1.10.4 leaves it empty. Both report EOF -2, and both reject the
changed-endian section with a block-size error. This is a diagnostic difference,
not a different packet capability.

[Implementation run 38426344920, attempt 2][implementation-ci] passed all 12 jobs
on `43138ba`. Attempt 1 could not acquire a macOS ARM64 hosted runner and cancelled
that unexecuted job after 15m03s; the required aggregate failed correctly. Retrying
only unsuccessful jobs obtained a runner, passed macOS tests and completed the
aggregate. No platform label or gate was changed.

The existing platform jobs discover the new Clojure test automatically, including
its Python checks. The existing Linux ARM64 monitor is not a dependency of the
required build aggregate; inspect its result separately. No matrix, gate or
threshold is changed. Logs print OS/version, JVM arch/version and libpcap version.
No offline result validates live capture, NIC throughput or other platforms.

## Data contract: what survives and what is missing

| Information | Current representation | Future placement / reason |
| --- | --- | --- |
| Captured bytes | Owned copy in :bytes | Remain owned per packet; read-only after publication |
| Capture / original length | :caplen / :len | Keep names and unsigned integer meanings |
| Handle's native DLT | :linktype | Keep native DLT; do not substitute on-disk LINKTYPE |
| Per-interface framing | Equal DLT only; unequal types rejected natively | Packet reference resolves interface descriptor; native path cannot invent it |
| Interface ID | Missing | Packet reference, qualified by section; IDs reset in each section |
| Section identity | Missing | Capture descriptors plus packet section reference |
| Original timestamp ticks / resolution | Missing after microsecond conversion | Exact packet timestamp plus interface resolution descriptor |
| Timestamp offset | Applied to :ts-sec; origin lost | Interface descriptor; retain ticks before offset for exact reconstruction |
| Interface name/comment/snaplen | Missing | Capture/interface metadata; repeating it on each packet wastes space |
| Packet comment/options/flags | Missing | Optional per-packet metadata, with bounded option sizes |
| Section comment/options | Missing | Section descriptor in separate capture metadata |
| No timestamp (SPB) | Native [0 0], indistinguishable from epoch zero | Explicit absence in a future exact timestamp contract |
| Unknown blocks/options and ordering | Discarded | Ordered capture records only if preservation is an explicit future requirement |
| Source byte order/header/format | Missing | Capture descriptor; PCAP subset writing need not preserve physical encoding |

A future metadata-capable reader should offer an explicit closeable, single-consumer
capture source with descriptors and ordered packet/metadata events. Interfaces can
appear after packets, so eagerly reading every descriptor would defeat streaming.
Ordinary packet maps should carry compact section/interface references and packet
metadata; a separate descriptor stream carries capture-wide information. This is
a design direction, not an API added here. Keep transformation independent of
capture ownership and of output serialization.

For exact timestamps, avoid putting nanoseconds into `:ts-usec`. An opt-in richer
packet representation needs exact ticks with a rational tick duration (decimal or
binary), explicit missing time and offset interpretation. Derived epoch
`:ts-sec`/`:ts-usec` may coexist for existing microsecond workflows, but exact
fields must have documented precedence and rounding. A nano-only key cannot
faithfully represent all binary or finer resolutions. Converting full PCAPNG to
today's raw map is irreversibly lossy; later options cannot recover it.

## Target link-type structure

Use a small internal map from supported native DLT to ordinary framing functions,
with an explicit unsupported result. Do not create a public registration system,
backend selector or plugin framework. Preserve the absent-key legacy Ethernet
assumption and explicit-invalid-key distinction from P05.

A framing function bounds-checks its own header and yields the L3 kind and byte
offset, plus link-specific fields only when full decode needs them. Full decode
reuses IPv4/IPv6/L4 parsers operating at that offset; flow projection reuses its
numeric IPv4/IPv6 walkers. Share framing and protocol selection, not the full
nested decoder or allocated payload arrays on the flow path. Ethernet VLAN
framing remains shared and its current nested shape stays compatible.

- SLL uses 16 bytes and protocol at offset 14; preserve packet type, hardware
  type and bounded address length. It is not an Ethernet MAC-pair header.
- SLL2 uses 20 bytes and protocol at offset 0, with its interface index in the
  link header. That index is not the PCAPNG interface ID.
- NULL uses a four-byte originating-host AF value; LOOP uses network byte order.
  IPv6 AF values vary across origins. Do not assume current-host constants or
  blindly relabel NULL as LOOP. Native savefile byte swapping must be measured
  with cross-endian NULL fixtures before implementation.
- Raw IP has no link header; inspect the version nibble with a byte bound and
  use the platform-native DLT mapping, not savefile code 101.

Full results should have an honest link wrapper (for example :linux-sll / :linux-sll2)
with :l3, never fabricated Ethernet MACs. Share unsupported/malformed/truncated
classification and byte offsets between full and flow paths. Test IPv4/IPv6,
fragments, VLAN where applicable, short headers, unknown protocols, extensions,
all capture paths and fan-out. Native owned arrays must not be mutated by framing
or parsing, and full decode must retain the original array reference. A framing
refactor should add no input clone or synthesized Ethernet header. Measure the
unchanged Ethernet fast path and allocations before accepting a decode slice;
no performance improvement is claimed by P08-A.

## Output API comparison and decision

| Approach | Simplicity and responsibility | Information loss / misuse | Extension consequences |
| --- | --- | --- | --- |
| Extend write-pcap! with single-DLT options | Small, matches its name and current internal writer | Can validate explicit framing; Classic cannot hold mixed DLT or PCAPNG metadata | Recommended now; retain two-arity default and add explicit three-arity options |
| Add :format :pcap / :pcapng to existing function | One entrypoint but write-pcap! becomes misleading | Packet sequence alone lacks descriptors; format option cannot recover lost metadata | Defer; if genuinely needed, use a deliberately named write-capture! with a capture contract |
| Separate write-pcapng! API | Clear container-specific responsibility | Can require capture descriptors/events and explicit loss policy | Preferred for future PCAPNG authoring; needs a real reader/metadata design first |

Do not infer output format from a path suffix. Do not infer one link type from a
heterogeneous lazy input, buffer the whole capture or automatically convert bytes.
An explicit `:linktype` option should be a native DLT for consistency with the raw
contract and the existing internal writer. Validate known per-packet DLT matches
that output, with absent DLT retaining the caller's explicit framing assumption.
Unsupported options/invalid DLT and mixed known DLT must fail clearly. Partial
output on a late sequence failure must be documented; atomic file replacement is
a separate feature. Capture ownership belongs to the source owner, not the writer.

A stricter default rejection of known non-Ethernet packets intentionally changes
today's unsafe success behavior. Valid Ethernet and standalone byte-array callers
retain the two-arity contract; erroneous non-Ethernet relabeling must not be
preserved solely for compatibility. Document this public behavior change and
release compatibility assessment in P08-B; do not rename :ts-usec or :len.
PCAPNG writing should require sufficient descriptors rather than invent them.
If metadata is intentionally discarded, require an explicit loss policy and
report what is omitted. No format can promise byte-identical file reconstruction
from the current packet sequence. The [native flush contract][flush-manual] returns
an error status, but the current JNR binding declares it void. Output failure
reporting was not exercised by these format round trips and remains a separate
I/O risk; no successful-write guarantee beyond the measured cases is inferred.

## P08-B recommendation, priorities and acceptance

**Priority 1 / recommended P08-B:** make the current I/O subset safe and explicit.
Distinguish native read errors from EOF across synchronous, lazy and managed
capture, then expose single-linktype Classic PCAP writing using the existing
internal implementation. These changes address measured silent incompleteness
and framing corruption before expanding formats. Split into B1/B2 commits or
reviewable PRs if the native lifecycle changes warrant separate review.

Candidate files: `src/paclo/pcap.clj`, `src/paclo/capture.clj` (managed source owner using
`pcap/loop-n-or-ms!`), `src/paclo/core.clj`, `test/paclo/capture_format_test.clj`,
existing reduction/managed/PCAP tests, `docs/cljdoc-api-contract.md`, usage docs,
`CHANGELOG.md`, plan and work log. No new production native symbol is needed.

Acceptance:

1. -2 is EOF, -1 is an observable capture failure retaining rc, phase and native
   error. Default policy throws; :pass reports failed stats and preserves the
   valid prefix. No packet is fabricated. Apply consistent on-error/cleanup
   behavior to all capture APIs; preserve early reduced and deterministic close.
2. Every mixed-DLT/snaplen and malformed fixture can no longer report clean EOF.
   Native open failures still close/propagate through the appropriate path.
   Test lazy/managed cancellation, bounded queues and callback failure ownership.
3. Existing write-pcap! two-arity valid inputs remain compatible. Explicit DLT
   output round trips SLL/SLL2/NULL/LOOP/Raw bytes, timestamps and both lengths on
   the supported matrix. Reject known mismatched DLT before that record is written;
   no implicit format conversion, extension-based format choice or mixed-DLT file.
4. State the exact supported subset: Classic PCAP, single DLT, microseconds,
   no capture-level metadata fidelity. Reuse timestamp/length validation, preserve
   raw bytes and explicitly document partial-output and compatibility effects.
5. Focused tests, unchanged full quality gates and all three offline native
   platform jobs pass. No decoder, PCAPNG writer, performance work or version bump.

**Priority 2 / subsequent slice:** share framing and add SLL + SLL2 IPv4/IPv6 to
full and flow transforms together. These have unambiguous protocol fields and
provide value for Linux cooked captures. Candidate files: linktype, parse,
flow/project, core facade, fixture generator, linktype/parser/flow tests and API
docs. First extend fixtures with IPv6 and adversarial short/unknown headers.

**Priority 3:** NULL/LOOP and Raw IP, after cross-endian/AF and native DLT tests.
**Priority 4:** exact timestamp opt-in; precision binding alone fixes nano digits
but cannot expose original IDB information or arbitrary rational ticks.
**Priority 5:** metadata-aware PCAPNG reader/writer. Requires a separate fixture-backed
contract and likely another reader implementation; current libpcap packet API
cannot supply lost section/interface/options data. No backend framework now.

Open risks: version-dependent native validation and error text; default precision
loss; SPB missing-time ambiguity; cross-endian NULL/native mutation; post-2038
reader behavior; unknown-block preservation/order and bounded metadata sizes;
partial output cleanup and unvalidated flush-error reporting (the current
`pcap_dump_flush` binding returns void); JNR 64-bit header ABI portability; choosing future capture
metadata lifecycle and exact timestamp precedence. Live capture and platforms
outside the measured matrix remain unverified. Full PCAPNG fidelity is deferred
explicitly, not advertised as a read/write round trip.

[open-manual]: https://raw.githubusercontent.com/the-tcpdump-group/libpcap/libpcap-1.10.5/pcap_open_offline.3pcap.in
[dump-manual]: https://raw.githubusercontent.com/the-tcpdump-group/libpcap/libpcap-1.10.5/pcap_dump_open.3pcap.in
[native-reader]: https://raw.githubusercontent.com/the-tcpdump-group/libpcap/libpcap-1.10.5/sf-pcapng.c
[pcapng-draft]: https://www.ietf.org/archive/id/draft-ietf-opsawg-pcapng-05.html
[dlt-header]: https://raw.githubusercontent.com/the-tcpdump-group/libpcap/libpcap-1.10.5/pcap/dlt.h
[sll-header]: https://raw.githubusercontent.com/the-tcpdump-group/libpcap/libpcap-1.10.5/pcap/sll.h
[null-format]: https://www.tcpdump.org/linktypes/LINKTYPE_NULL.html
[loop-format]: https://www.tcpdump.org/linktypes/LINKTYPE_LOOP.html
[savefile-source]: https://raw.githubusercontent.com/the-tcpdump-group/libpcap/libpcap-1.10.5/sf-pcap.c

[flush-manual]: https://raw.githubusercontent.com/the-tcpdump-group/libpcap/libpcap-1.10.5/pcap_dump_flush.3pcap

[implementation-ci]: https://github.com/nantes-rfli/paclo/actions/runs/38426344920/attempts/2
