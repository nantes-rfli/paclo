# P08-E1: Metadata-aware PCAPNG and exact timestamps

Design baseline: main `ccebcad` (P08-D2, merged PR #46), 2026-10-15.
This is the authoritative E1 decision and E2/E3 handoff, **not an implemented
public API**. Names and shapes below are proposed. No production source, binding,
dependency, version or CI gate changes in E1.

## Documentation authority and evidence

- [The v1 contract](../docs/cljdoc-api-contract.md) describes available behavior.
- [The accepted plan](codex-plan.md) owns task status and dependencies.
- This document owns PCAPNG metadata, exact time, future reader/writer decisions.
- [P08-A](p08-a-capture-formats.md) is the historical native capability inventory;
  its pre-B1 errors and pre-B2 writer limitations are not current API claims.
- [P08-D2](p08-d2-null-loop.md) owns NULL/LOOP framing and native byte evidence.
- [The work log](work-log.md) owns actual commands, environments and PR/CI evidence.

P08-A supplied 28 container fixtures and precision probes. B1 propagates native
read failures with valid-prefix reporting; B2 writes an explicit single native
DLT to Classic PCAP. C/D1/D2 implement shared Ethernet, SLL/SLL2, Raw IP and
NULL/LOOP full/flow framing. None introduces PCAPNG descriptors or exact time.
The 47 existing container/framing fixtures remain unchanged and exercised.

Code inspection: `pcap/open-offline` uses `pcap_open_offline`; `read-packet`
copies native payload into an owned array and reads one handle DLT plus timeval,
caplen and wire length. `capture/start` adds bounded background delivery and
single-consumer lazy packets; synchronous `reduce-packets` owns cleanup.
`core/packet-xf` is independent of I/O. Raw/full preserve extra keys, whereas
flow projection and its error map retain selected metadata only. `linktype`
uses native DLT, never arbitrary savefile LINKTYPE.

References are pinned work-in-progress [PCAPNG draft 05][format], sections 3–5,
[libpcap 1.10.5 reader source][native] and [offline precision manual][precision].
The draft has expired; it is a reproducible format reference, not a published
standard or a claim about the newest draft. Recheck normative changes in E2.
Native source inference is separate from installed-library measurements.

## Native capability versus independent reader

| Information / operation | Current native Paclo path | E2 independent offline path |
| --- | --- | --- |
| Owned packet bytes, caplen, wire length | Available; inconsistent len may be accepted by native | Retain; validate caplen <= len and snaplen |
| LINKTYPE versus DLT | One native DLT per handle | Retain on-disk LINKTYPE and explicit supported DLT mapping |
| Multiple same-type/snaplen IDBs | Reads packets, loses IDs | Ordered descriptors and qualified references |
| Different DLT/snaplen, changed section order | May fail after valid prefix | Read per-interface framing and per-section byte order |
| Decimal/binary resolution and offset | Normalized microseconds, offset applied | Retain resolution, signed offset and original unsigned ticks |
| Nanoseconds via unbound precision API | Native probe retains nano digits | Exact arithmetic for all 0..127 exponents |
| Section/Interface/Packet options | Omitted | Ordered option octets, selected typed interpretation |
| SPB timestamp absence | Synthesized timeval | Explicit nil exact time; no microsecond fields |
| Unknown blocks | Skipped by native subset | Bounded opaque events with preservation restrictions |
| PCAPNG output | Unavailable; write-pcap! produces Classic PCAP | Separate E3 writer |

A nano native binding would improve a packet-only precision subset, but cannot
recover source ticks, resolution, metadata, absence or mixed interfaces. E2
therefore uses Java file I/O internally; libpcap continues to own current live,
Classic, BPF and existing PCAPNG packet-only reads. No public backend selector,
native extension, live metadata source or automatic format routing is proposed.

## Public API candidates and decision

| Candidate | Benefit | Cost / decision |
| --- | --- | --- |
| Enrich every existing core/packets map | Familiar entrypoint | Repeats metadata or hides mutable lookup; cannot reconstruct native omissions; reject |
| Eager {:sections ... :interfaces ... :packets ...} | Simple small-file inspection | Unbounded upfront scan, prevents streaming; caller can explicitly collect events instead |
| Metadata callbacks plus packet sequence | Small packet map | Two delivery channels, ordering/close races and callback retention; reject as primary API |
| Closeable source reducing ordered event maps | Explicit ownership, descriptor order, ordinary transducers | Recommended; one consumer and bounded active section state |
| Reopenable reducible factory | Easy repeated analysis | Implicit repeated I/O/file changes; defer, explicitly reopen the path |

Propose a small public `paclo.pcapng` namespace in E2/E3:
`open-source` taking an options map with mandatory `:path`, `source-info` for
bounded data-only status, and `write-pcapng!` taking source/events, path, options.
Only the first two belong to E2. A source implements `java.io.Closeable` and
`clojure.lang.IReduceInit`; it has no Seqable/Iterable/background producer.
No new names ship in E1. Keep `core/packets`, `reduce-packets`, managed capture,
and `write-pcap!` signatures and behavior unchanged.

Proposed usage, deliberately not a runnable documentation example:

```clojure
(with-open [source (pcapng/open-source {:path "input.pcapng"})]
  (transduce (comp (filter #(= :packet (:type %))) (map :packet)
                   (core/packet-xf {:decode? true :extensions []}))
             (completing inspect-packet) initial-value source))
```

Dropping descriptor events is an intentional packet-analysis projection and
cannot feed a preserving writer. For event-preserving processing, apply raw/full
`packet-xf` only to `:packet` values and keep their envelope/descriptors. A
filtering/multi-output packet transducer needs explicit event handling; do not
run decode over descriptors. Existing flow mode discards extra keys, so its
output alone is not preservable. E2 documents this fact without changing v1 flow.
No generic pipeline, event framework or registration mechanism is needed.

## Event and descriptor contracts

All IDs below are integers. Section IDs are zero-based SHB occurrence numbers,
unique only within one source execution. Interface IDs are zero-based IDB
occurrence numbers **within that section**, not OS device indices. `[section-id
interface-id]` is the descriptor key. Joining separate captures requires explicit
new IDs/descriptors and belongs outside E2/E3; concatenation cannot reuse IDs.

Every event has `:type`, `:section-id`, zero-based `:block-index` and byte
`:file-offset` (arbitrary-precision nonnegative integers). Envelopes carry file
location, not repeated descriptor data. Proposed event types:

| :type | Payload | Ordering |
| --- | --- | --- |
| :section | :section descriptor | SHB opens section; previous section registry released |
| :interface | :interface descriptor | IDB installed before delivery; before any referencing packet |
| :packet | :packet ordinary map | EPB/SPB; descriptor already delivered |
| :opaque-block | :block opaque descriptor | Original physical position in active section |

EOF is source status, not a synthetic packet/end event. A new SHB implicitly
ends the prior section. Later IDBs are valid after packets from earlier IDBs;
forward packet references to an IDB not yet seen are invalid. Do not scan ahead,
buffer unresolved packets or wait for a descriptor that might never arrive.
The source registry has only current-section interfaces, no capture-wide packet,
section, unknown-block or option accumulator. Callers retaining old events own
that memory. Retained descriptors remain immutable after registry release.

| Section descriptor field | Meaning |
| --- | --- |
| :id | Source-local section ID |
| :byte-order | :little-endian or :big-endian, from SHB magic |
| :version | [major minor], E2 accepts [1 0] only |
| :section-length | nil for -1 (unspecified), otherwise signed nonnegative byte count after SHB |
| :options | Ordered option records, including repeated comments |

A declared section length must end exactly at EOF or the next SHB; E2 tracks
remaining bytes without buffering the section. Other negative values fail.

| Interface descriptor field | Meaning |
| --- | --- |
| :section-id / :id | Qualified identity |
| :file-linktype | Unsigned 16-bit LINKTYPE from IDB |
| :linktype | Supported native DLT integer or explicit nil when mapping is unavailable |
| :snaplen | Unsigned 32-bit; zero means no format snaplen limit, resource limits still apply |
| :timestamp-resolution | {:base 10 or 2 :exponent 0..127}; default 10/6 |
| :timestamp-offset-sec | Signed 64-bit seconds; default zero |
| :options | Ordered authoritative original option octets |

Native DLT mapping is a small closed internal table for the supported Linux/macOS
matrix: LINKTYPE 0/1/108/113/276 -> DLT 0/1/108/113/276 and 101 -> 12. Unknown
LINKTYPE retains bytes, descriptor and explicit packet `:linktype nil`; existing
full/flow then emits its unsupported-linktype diagnostic rather than assuming
Ethernet. Do not promise mapping on other OSes or consult a native capture handle.

Interface name and comments live in `:options`, accessed by ordinary option
selection. No competing typed :name/:comment caches. Section and packet comments
also remain repeated ordered options. Each option record is
`{:code uint16 :value owned-byte-array}`; value excludes padding and TLV header.
Empty value, absent option and repeated options are distinct. Terminator/padding
are validated but excluded from the semantic vector. Unknown option bytes are
retained without conversion. Valid UTF-8 may be decoded by a pure helper; invalid
text stays raw with a bounded diagnostic, never replaced silently for output.
Recognized singleton duplicates are rejected even if equal; comments/custom
repeated options retain order. IDB resolution/offset typed fields must agree with
options when options exist; omitted values use defaults. Writer rejects conflict.

Packet maps keep `:bytes`, `:caplen`, `:len`, `:linktype` and, when timestamped,
derived `:ts-sec` / `:ts-usec`. Extra PCAPNG fields live under one `:pcapng` map:

```clojure
{:bytes packet-bytes :caplen 64 :len 1500 :linktype 1
 :ts-sec 1699999993 :ts-usec 123456
 :pcapng {:section-id 0 :interface-id 0 :block-type :enhanced-packet
          :timestamp {:ticks 1700000000123456789N}
          :options [{:code 1 :value comment-octets}
                    {:code 2 :value flag-octets}]}}
```

Packet timestamp refers to the interface's resolution/offset; it does not copy
those values or interface options. EPB caplen equals array length, unsigned
32-bit wire len must be >= caplen; enforce nonzero snaplen. SPB uses interface 0,
`:block-type :simple-packet`, `:timestamp nil`, `:options []`, no `:ts-sec` or
`:ts-usec`. Its caplen is min(original length, nonzero snaplen), or original
length for zero snaplen. The body must contain exactly caplen bytes rounded up
to four plus original-length field. Padding is not packet data. SPB has no
options or flags. EPB flags option code 2 is uint32 in the section's byte order;
retain the whole word including reserved bits, no frame mutation/FCS stripping.

All payload/option/opaque arrays are fresh owned copies, read-only after
publication. No borrowed buffer, hidden descriptor mutation or fan-out mutation.
Source-info is a snapshot, not a mutable registry or EDN dump of packet bytes.

## Exact timestamp contract

Exact time is `offset-sec + ticks / base^exponent` seconds since Unix epoch UTC.
EPB ticks are unsigned 64-bit on disk and represented as a nonnegative Clojure
integer including BigInt, never a signed-long reinterpretation or float.
Arithmetic uses arbitrary precision for denominator, multiplication and epoch
seconds. PCAPNG cannot encode arbitrary-width ticks: internal edited ticks may
be any nonnegative integer, but E3 must reject values above `2^64-1`, never wrap.
Resolution exponent is bounded by the format to 127; arbitrary arithmetic is
necessary even within those bounds. Offset is signed seconds, not timezone.

For `D = base^exponent`, compute `q = quot(ticks,D)` and `r = rem(ticks,D)`.
Then `:ts-sec = offset-sec + q`, `:ts-usec = quot(r*1000000,D)`.
This floors exact time to a microsecond, including negative epochs; `:ts-usec`
stays 0..999999. No rounding to nearest, saturation, double, java.time coercion,
or submicroseconds in :ts-usec. Exact fields are authoritative for the new
writer. Derived fields must match if supplied; conflict is an error rather than
silent precedence. Removing the derived pair permits intentional exact editing.

| Input | Exact epoch seconds | Derived [sec usec] |
| --- | --- | --- |
| ticks 123456789, decimal 9, offset 0 | 123456789/1000000000 | [0 123456] |
| ticks 129, binary 10, offset 0 | 129/1024 | [0 125976] |
| ticks 1, decimal 9, offset -1 | -999999999/1000000000 | [-1 0] |
| ticks 0, any resolution, offset 0 | 0 (present EPB time) | [0 0] |
| SPB :timestamp nil | Absent, never epoch zero | Both keys absent |

Decimal 6/nano 9 and binary 10 share one representation. Decimal 127 and binary
127 remain exact even when compatibility projection is zero. Derived seconds
can exceed JVM long and Classic uint32; E2 does not clamp them. Pure comparison
may use rational cross multiplication or Clojure ratios; no extra rational key
is stored on every packet. A nano-only :ts-nsec cannot represent binary fractions
or decimal subnano resolution and is rejected as the primary representation.

Preserve mode requires the :pcapng envelope and explicit exact timestamp on
every EPB. For authored EPBs, prefer exact ticks plus a matching descriptor. E3 can
accept a complete integer microsecond pair **only when exact :timestamp is
absent** (missing key in the :pcapng envelope), in :mode :author: solve
`ticks = ((sec-offset-sec)*1000000+usec)*D/1000000` and require an integral,
nonnegative uint64 result. Explicit nil means timestamp absence and never falls
back. Partial microsecond pairs or stale conflicting pairs fail. No default
wall clock, rounding or legacy :sec/:usec fallback in write-pcapng!.
SPB authoring requires explicit absence and interface 0. Converting timestamped
EPB to SPB is explicit loss, not a fallback for unrepresentable time.

Classic write-pcap! retains its current timestamp precedence, fallback and
ranges. A caller exporting exact packets to Classic must explicitly project and
accept loss; the old writer does not validate nested PCAPNG time. Removing exact
metadata cannot later recover it. Existing windows/analysis operate on legacy
microseconds; exact nanosecond/binary ordering is not added to those APIs in E2.

## Reader ownership, termination and diagnostics

Open-source validates options before opening a path, opens synchronously, reads
only the first bounded SHB, holds it as the pending first event, and closes
on failed initialization. It owns its file
channel; no caller-supplied InputStream ownership ambiguity in E2. Reduction
claims the source once; repeat/concurrent consumption throws :source-consumed
without stealing another consumer's handle. No implicit reopen. Close is
idempotent, including unconsumed sources and already failed sources.

The synchronous pull loop reads one bounded block, validates it completely, then
emits its event. Reduction closes on EOF, `reduced`, parse/I/O error or consumer
exception in finally. IReduceInit uses the two-arity reducing step and unwraps
reduced; it does not call completion. `transduce` owns exactly one completion
call, after source cleanup. Source-info distinguishes :open/:reading/:closed/
:failed and terminal :eof/:reduced/:closed/:error, event/packet counts and bounded
error data. Completion exceptions occur after the reader has closed.

No consumer call occurs after reduced; no speculative next-block read. A caller
opening but abandoning a source must with-open/close it; neither GC nor a lazy
sequence owns cleanup. This avoids bringing issue #40 into the new API without
changing the existing lazy API. External close is a cancellation request: a
blocked file read is interrupted by channel close; classify the resulting
AsynchronousCloseException as :closed, not malformed data. Close never waits on
the consumer. Event delivery is claimed atomically against cancellation; no new
delivery is claimed after close, but an already claimed consumer call may run
or finish. Normal reduction remains single-threaded; test this race in E2.

Default error mode is fail-fast only in E2. A malformed file has no recoverable
packet event. Error ex-data proposes `:reason`, `:phase :pcapng-read`,
`:file-offset`, `:block-index`, optional `:section-id`, `:interface-id`,
`:block-type`, `:field`, `:expected`, `:actual`, `:limit`. Reasons include
:invalid-block-length, :truncated-block, :invalid-option-length,
:duplicate-option, :undefined-interface, :invalid-packet-length,
:unsupported-section-version and :limit-exceeded. Never include full raw blocks,
secrets or unbounded strings in diagnostics. Preserve primary consumer/read
exception identity and add close failure as suppressed; a sole close failure
throws. A valid emitted prefix does not mean complete input validation.

### Explicit resource ceilings

Proposed defaults; configuration must be positive integers; byte limits are at most
Integer/MAX_VALUE minus 8 and count limits at most 65536. Unknown options fail
before open. These are policy limits, not
measured throughput targets. E2 benchmarks are not required to justify them.

| Limit option | Default | Accounting / failure point |
| --- | --- | --- |
| :max-block-bytes | 16 MiB | Total declared block bytes; before allocation/read body |
| :max-packet-bytes | 8 MiB | caplen before allocation, independent of snaplen zero |
| :max-options-bytes | 1 MiB | Padded TLV bytes per block before option copies |
| :max-options-per-block | 4096 | Includes known, unknown and repeated options, excludes terminator |
| :max-interfaces-per-section | 4096 | Before adding the next descriptor |
| :max-section-metadata-bytes | 8 MiB | SHB + retained IDB option octets and fixed descriptor accounting |
| :max-opaque-block-bytes | 1 MiB | Opaque body; exceeding this fails, never silently skips |

Section metadata accounting is 256 bytes for SHB and each IDB, plus padded
option TLV bytes and 32 bytes per exposed option record. It includes options
retained by descriptors and tests exact boundaries.
No unlimited/nil setting. Byte limits cap payloads, count limits cap map/vector
and zero-length-option amplification; JVM object overhead is not an exact heap
promise. Temporary memory is at most a bounded block plus copied current event
and bounded active metadata, then released; immutable copies may coexist during
publication. No unknown-block accumulation. Old sections release parser state.
Counters use arbitrary integers, not an ever-growing diagnostic list. Total
file length and section count can grow while active state stays bounded. A
consumer collecting every event defeats its own memory bound explicitly.

Validate unsigned lengths with wide arithmetic before int conversion: minimum
block size 12, four-byte alignment, exact duplicated trailer, SHB magic/version,
known block minimum bodies, options/header/padded extents, EPB payload and option
boundary, SPB computed payload boundary, known singleton lengths, declared
section boundary. EOF is normal only between blocks after a valid section;
partial header/body/trailer fails. Do not trust declared lengths to allocate
near uint32 maximum or try to resynchronize after corruption.

## Supported blocks and options

These are E2/E3 targets, not current support claims. Interpretation is deliberately
narrow; raw preservation and semantic support are distinct.

| Block / code | E2 action | E3 action |
| --- | --- | --- |
| SHB 0x0a0d0d0a | Parse section 1.0 / byte order / length / options | Emit section, regenerate length as unspecified |
| IDB 1 | Parse linktype/snaplen/resolution/offset/options | Emit before referenced packet, retain implicit ID order |
| EPB 6 | Packet bytes/lengths/ticks/options | Exact timestamp and packet options |
| SPB 3 | Interface 0; absent timestamp; computed caplen | Only explicit absence, correct padded size |
| Obsolete PB 2 | Reject :unsupported-packet-block | No authoring; avoids silently dropping real packets |
| NRB 4 / ISB 5 | Bounded opaque event, no semantic interpretation | Only preservation in unchanged context |
| DSB 10 | Reject :unsupported-sensitive-block | No authoring or secret copying in E3 |
| Custom 0x00000bad | Validate minimum PEN prefix, bounded opaque | Copyable in unchanged context |
| Custom 0x40000bad | Retain as opaque marked :copy-policy :never | Preserve mode fails; explicit lossy drop required |
| Other unknown/private block | Bounded opaque :copy-policy :unknown | Unchanged-context retention only; no meaning/fidelity guarantee |

| Options | Typed E2 interpretation | Preservation / validation |
| --- | --- | --- |
| All: end 0, comment 1 | End validated, comments raw UTF-8 octets | Preserve repeated comments/order; end not exposed |
| SHB hardware 2 / os 3 / userappl 4 | Raw values only | Preserve without semantic cache |
| IDB name 2 / description 3 | Raw UTF-8 octets | Singleton; interface scope only |
| IDB tsresol 9 / tsoffset 14 | Base/exponent; signed seconds | Length 1 / 8; singleton; exact arithmetic |
| EPB flags 2 | Optional uint32 interpretation | Length 4; singleton; reserved bits retained |
| EPB hash 3 / dropcount 4 / packetid 5 / queue 6 / verdict 7 | Raw only in E2 | Preserve; validate specified minimum/fixed lengths in E2 |
| Other IDB options 4–8,10–13,15–18 | Raw only | Preserve; E2 validates draft-defined lengths/cardinality |
| Custom options 2988/2989 | Raw UTF-8/binary with PEN | Minimum PEN prefix; marked copyable |
| Custom options 19372/19373 | Raw with PEN | Mark :never; preserve writer refuses, lossy can drop |
| Any other unknown option | Ordered owned octets | Bounds only; no endian conversion or guessed multiplicity |

Opaque descriptors contain `:block-type` uint32, `:body` owned octets,
`:byte-order` and `:copy-policy`. They exclude block framing. Opaque bodies may
contain interface references, counters or packet-dependent data that Paclo
cannot rewrite. Unknown options have analogous context dependence. Secret
blocks, unsupported section versions, compression/vendor packet formats,
malformed data, limits and obsolete PB fail safely. Do not silently skip a
recognized unsupported packet-bearing block. Private unknown block semantics
cannot be detected: report opaque count in source-info, and never advertise
complete packet coverage or semantic fidelity for opaque input.

## Writer preservation and loss contract

E3 is a separate path-based write-pcapng!, implemented without native dumpers.
Input is a single ordered event reduction, with descriptors, not raw packet
maps alone. It must have a coherent section/interface context. Writer returns
bounded `{:status :complete :fidelity :known-semantics :loss-counts ...}` on
success; counts by reason, no unbounded loss list. Failure throws with byte/event
location and output status. API spelling/report finalization occurs in E3.

| Case | Proposed policy / honest guarantee |
| --- | --- |
| Supported blocks and ordered options, unchanged bytes/time/IDs | Retain known semantics, ticks, lengths, comments, flags, resolution and section order |
| Unchanged context plus unknown block/options | Retain raw octets/order and byte order; unknown meaning remains unverified |
| Absent descriptors or microsecond-only native input | Preserve mode rejects :missing-metadata; cannot invent source fidelity |
| Explicit authored descriptors/events | Valid new PCAPNG; no assertion of input preservation |
| Intentional metadata/time/packet transformation | :mode :lossy plus declared drops/context change; report losses |
| Known do-not-copy custom data | Preserve fails; lossy explicitly drops and counts |
| Changed section order, interface IDs, endian, payload or packet subset with opaque data | Reject :opaque-context-changed unless caller explicitly drops affected opaque content |
| Malformed input, invalid lengths, unresolved IDs, unrepresentable time | Fail, never repair under lossy mode |

Default `:mode :preserve` retains known metadata and refuses requested drops.
`:mode :lossy` needs explicit drop categories (:opaque-blocks, :unknown-options,
:comments, etc.); its name alone does not authorize silently discarding anything.
No inference that a six-key packet from core/packets is metadata-complete.
For authored events require `:mode :author` and explicit descriptors/time;
missing metadata is not proof that there originally was none.

The writer checks structure/references, lengths, descriptor/option agreement and
exact/derived time agreement as events arrive. It cannot discover a caller's
undisclosed in-place array edit or removed events. The caller declares transformed
context; preservation claims are conditional on that declaration and the retained
source information. E3 tests this limitation/documentation, does not introduce
hidden provenance, persistent source lookups or packet hashes to imply proof.

Emit SHB then each IDB when encountered, then referencing packets; never preload
all IDBs, reorder events, merge sections or renumber IDs implicitly. Interface
IDs must match emitted IDB ordinal. Retain section byte order whenever opaque
content exists; unknown values cannot be safely swapped. Section length is
written as -1 to allow streaming, options padding is canonical zero, trailers
are regenerated. Thus even supported unchanged semantic output is **not a
byte-for-byte file reproduction**. Finite section length, padding and physical
encoding can change. Exact original file reproduction remains outside E2/E3;
copy the original file when that is the requirement.

Path output uses a new sibling temporary file, validates each block before
writing it, flushes and closes, and atomically moves it to destination only on
successful complete reduction. Default refuses an existing destination; explicit
replacement must be supported atomically or fail without replacing it. E3 must
verify provider no-clobber behavior including destination-creation races; an
existence check plus ATOMIC_MOVE alone is not a portable no-clobber guarantee.
If atomic
move is unsupported, fail, no non-atomic fallback. This is publication atomicity,
not a crash-durability promise or automatic directory fsync. Failed/partial temp
output is removed; cleanup failures are suppressed on the primary error and
include temp path for recovery. Destination remains untouched. Flush/close/move
errors are failures. Stream output/append are deferred because they expose valid
prefixes and have different ownership. No claim of all-file validation on an
intentionally early-stopped read; a source terminal :reduced/:error/:closed fails
the preserving writer before publication. Deliberate subset authoring uses an
explicit lossy/author input ending normally and reports the context change.

Writer consumes a source once; source reduction owns its close, writer owns the
output. Plain event reducibles own their upstream resources; callers wrap other
Closeables explicitly. A writer exception closes a Paclo source via reduction
finally. Output limits mirror block/options/active interface limits; no capture
buffer, unbounded index or whole-file rollback state. End of empty event input
fails :missing-section; a valid empty section capture is permitted.

## E1 verification corpus and actual evidence

Run `python3 test/resources/make_pcapng_contract_fixtures.py --check` and
`python3 test/resources/test_pcapng_contract_fixtures.py`. Ten new small captures
and a SHA-256 manifest supplement the 47 existing fixtures. The Clojure namespace
`paclo.pcapng-contract-design-test` invokes both commands automatically in every
existing suite/platform job; no CI changes or reduced gate coverage.

| E1 corpus | Evidence now | E2/E3 acceptance later |
| --- | --- | --- |
| Existing multi-interface/linktype/snaplen/section/endian fixtures | Native acceptance/failures from existing inventory | All valid sections/interfaces delivered independently |
| rich | Ordered repeated comments, flags, unknown octets, decimal nano, binary 10, negative offset, SPB | Preserve options and timestamp absence; compare semantic round trip |
| mixed-sections | Opposite order, LINKTYPE 1/101, snaplen 64/50, reused ID 0 | Distinct qualified IDs, DLT 1/12, no native restriction |
| timestamp-extremes | uint64 max, offsets int64 min/max, exponents 0/127 and binary 127 | No signed overflow, float, exponent narrowing or tick wrap |
| spb-truncated | caplen 15, len 1500, one padding byte | Omit time, preserve lengths, padding excluded |
| forward-interface | Packet ID 1 before its IDB | Fail at packet; no scan-ahead |
| unaligned/oversized-length | Invalid 33 / declared 0xfffffffc | Reject before allocation; enforce configured ceiling |
| option-overrun/bad-offset-length/duplicate-resolution | Invalid TLV extent / fixed length / singleton | Stable bounded failure, deterministic close |
| In-memory metadata_flood | 4096/4097 IDBs and >8 MiB opaque payload reproducibly constructed | Test exact count/byte limits, including many empty options |

Local macOS x86_64, JDK 21.0.12.1, Clojure 1.12.1, libpcap 1.10.1:
rich native timestamps are `[1699999993 123456]`, `[1700000000 125976]`,
**`[-7 0]` for SPB**. Native applies interface-0 offset even to its synthesized
SPB zero, so absence cannot be inferred from [0 0] or any normalized value.
Only the six existing packet keys emerge; comments/flags/IDs are gone.
Mixed-sections produces one packet then :pcap-read-failed, correctly reported
by B1. Tests deliberately do not feed extreme timestamps or huge lengths to
native as if its behavior were the proposed contract.

Six Python tests inspect physical wire fields/ordering/padding and use Fraction
with a seeded 500-case arithmetic oracle plus boundary examples. They prove
fixture construction and floor-projection math, **not** a future reader/writer,
heap bound, generic parser safety or native extreme support. Metadata-flood
construction produces 345156 bytes for 4096 IDBs, 345240 for 4097 IDBs, and
8388764 bytes for the oversized opaque case. These are wire sizes, not heap
measurements; parser boundedness remains E2 work.
Native precision and complete existing inventory are rerun by the full suite.
Implementation `baaade4` / [PR #47](https://github.com/nantes-rfli/paclo/pull/47)
completed [CI run 38591738169](https://github.com/nantes-rfli/paclo/actions/runs/38591738169).
All 12 jobs report success; actual platform tests and native observations follow.

| CI platform | Native/JDK | Suite and E1 result |
| --- | --- | --- |
| Linux x64, kernel 6.17.0-1022-azure | libpcap 1.10.4, JDK 21.0.12.1 | 431 tests / 15753 assertions; rich timestamps match local |
| macOS ARM64, 26.6.2 | libpcap 1.10.1, JDK 17.0.20.1 | 431 / 15747; rich timestamps match local |
| Linux ARM64, kernel 6.17.0-1022-azure | libpcap 1.10.4, JDK 21.0.12.1 | 431 / 15753; rich timestamps match local |

The six additional Linux assertions are existing /dev/full writer checks. All
platforms pass the six Python corpus/oracle tests and confirm SPB **[-7 0]**.
Documentation runs all 28 examples; build, Java quality/coverage, packaging and
existing performance jobs report success. No live/NIC or other-OS validation.

**CI limitation:** the dedicated Eastwood job exits successfully after
ClassNotFoundException `paclo.jnr.PcapConfigLibrary`; 92 namespaces are left
unanalyzed. Latest main `ccebcad` has the same missing-class exception and 91
unanalyzed namespaces on [baseline run 38586471628](https://github.com/nantes-rfli/paclo/actions/runs/38586471628).
The job does not compile bindings before analyzing namespaces. Its green status
is not complete lint evidence. E1 keeps CI configuration unchanged and records
this existing limitation; the full local lint compiled bindings and completed
with zero exceptions. Future CI maintenance should compile bindings and enforce
an exception-free Eastwood exit without weakening gates.

## P08-E2 implementation plan and acceptance

### E2 format recheck and implementation clarifications

On 2026-10-15, E2 compared the pinned draft 05 with
[draft 06](https://www.ietf.org/archive/id/draft-ietf-opsawg-pcapng-06.html).
SHB/IDB/EPB/SPB framing, resolution and offset arithmetic are unchanged.
EPB option 8 (process/thread IDs), omitted from E1's narrow option table, remains
eight bytes but changes from singleton to repeatable in draft 06 section 4.3.
E2 validates its length and preserves repeats; it does not add a typed cache.
The reviewed E1 contract remains authoritative for strict caplen <= wire len,
section boundaries and unsupported-block policy.

Drafts 05/06 section 3.5 permit an option list ending at the block boundary
without an end marker. E2 accepts that case; a present marker must have length
zero and be last. Padding extents/alignment are validated, but unspecified
padding octets are not required to be zero or exposed as options/packet data.
Metadata accounting includes a present four-byte end TLV. NRB/ISB opaque bodies
check fixed minima of four/twelve bytes, without semantic interpretation.
No text helper is introduced: invalid UTF-8 remains authoritative raw octets,
so E2 never silently replaces text or retains a text diagnostic list.

The implemented public reader contract and runnable examples are now in
[the PCAPNG guide](../docs/pcapng.md). E3 remains unimplemented.

1. Implement an internal bounded block cursor with Java FileChannel, section
   magic switching, wide checked lengths/trailers/options and declared section
   length validation. No production dependency or generic backend mechanism.
2. Implement SHB/IDB/EPB/SPB semantics, closed LINKTYPE mapping, exact integer
   helpers, ordered raw options/opaque events and explicit unsupported policies.
   Reuse E1 fixtures; use real files for boundary/I/O cases, not only byte mocks.
3. Implement Closeable single-use IReduceInit source and bounded source-info,
   then expose proposed open-source/source-info after contract review. Document
   source ownership, absence, legacy projection and raw/full/flow composition;
   add API contract and changelog only when behavior ships.
4. Test EOF/full reduction, reduced on descriptor/packet/opaque, transducer take,
   consumer/parse/open/close exceptions, unconsumed close, repeat/concurrent
   reduction, cancellation race, close suppression and zero post-stop reads.
5. Add property tests of exact normalization/reconstruction and ordered descriptor
   reference invariants; adversarial uint32 lengths, all truncation prefixes,
   repeated singleton/empty/unknown options, invalid text, snaplen zero,
   finite section boundaries and unsupported blocks. Keep seeds/case counts.
6. Exercise each limit at limit and +1, bound live registry across thousands of
   sections, verify no cumulative opaque storage. Use counters/instrumentation
   and a constrained-heap subprocess with streaming consumer; collecting all
   events must not be used to claim parser memory bounds.

E2 accepts mixed DLT/snaplen/order and all format resolution bytes 0..255 within
resource limits, with loss-free exact input representation for supported blocks.
No writer, live metadata, analysis-time migration, issue #40 repair or performance
issue changes. Existing raw/full/flow native paths and Classic writer regression
suite must pass unchanged. Supported-platform CI stays Linux x64/JDK21,
macOS ARM64/JDK17 and separate Linux ARM64 monitor; no inference about other
platforms, big-endian hosts or live capture.

## P08-E3 implementation plan and acceptance

1. Build bounded block/option encoding separate from capture transforms and
   native dumper. Validate authoring and preservation policies before publication.
2. Implement ordered SHB/IDB/EPB/SPB output with mixed DLT/snaplen/section order,
   uint64 ticks, signed offset, raw option octets and opaque-context restrictions.
3. Implement path temp/atomic publication, fail-fast reporting and all cleanup
   paths. Inject write/flush/close/move/delete failures; assert destination intact,
   source closed and partial temp removed or accurately reported. Test concurrent
   destination creation and provider atomic/no-clobber limitations explicitly.
4. Round trip all valid supported E1/P08-A fixtures through E2->E3->E2. Compare
   packet bytes/lengths, qualified identities, exact ticks/resolution/offset,
   absence, comments/flags/option order and permitted opaque octets. Use an
   independent physical wire oracle for block framing, not solely the same codec.
5. Explicit loss tests: native raw-map refusal, flow-map refusal, authored
   descriptors, stale microsecond/exact conflict, partial timestamp, tick >uint64,
   nonintegral conversion, metadata drop counts, no-copy custom data, unknown
   references/endian/context, early-stopped source and malformed suffix.
6. Add public writer documentation/changelog and executable examples when
   implemented. Verify Classic writer output/API remains unchanged.

Both E2/E3 require focused tests, `bash dev/script/codex.sh check`, full static
checks, Markdown/link/executable-doc checks and unchanged existing CI aggregate,
compatibility/package and performance gates. Use change-specific Java quality
checks when Java/native code is introduced; no native change is needed by this
design. A passing E1 oracle is not acceptance of E2/E3. Keep those tasks unfinished
until production behavior and ownership/loss tests pass. No version bump,
publication, merge or P09/P10 work is authorized by this design.

[format]: https://www.ietf.org/archive/id/draft-ietf-opsawg-pcapng-05.html
[native]: https://raw.githubusercontent.com/the-tcpdump-group/libpcap/libpcap-1.10.5/sf-pcapng.c
[precision]: https://raw.githubusercontent.com/the-tcpdump-group/libpcap/libpcap-1.10.5/pcap_open_offline.3pcap.in
