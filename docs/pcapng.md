# Metadata-aware PCAPNG reading and writing

These APIs are available in **v1.4.0**, published on 2026-10-17 (P08-E2/E3),
beyond v1.3.0. See the [migration guide](migration-from-1.3.md),
[release notes](release-notes-1.4.0.md) and
[publication evidence](../dev/release-1.4.0-publication.md).
The native capture API remains a separate input path.

`paclo.pcapng/open-source` reads an offline PCAPNG file through a bounded Java
FileChannel cursor. `source-info` reports its lifecycle and counters. The
existing `core/packets`, `reduce-packets` and Classic `write-pcap!` retain their
native behavior. `write-pcapng!` writes ordered events to a new PCAPNG path,
with explicit preservation, loss and authoring policies.

## External-tool interoperability

The [P16 verification report](../dev/p16-interop-verification.md) records a
reproducible offline matrix using text2pcap, editcap, mergecap, tshark and
tcpdump. The test generates synthetic files at runtime; it never captures a
network interface. Tool versions and Paclo's actually loaded libpcap are recorded
separately because they can use different libraries on the same machine.

| Operation | Retained information / limits |
| --- | --- |
| Native `core/reduce-packets` on PCAP/PCAPNG | Packet bytes, caplen, wire length, one handle DLT and floored microseconds; no sections, interfaces, options or exact ticks |
| `open-source` to default `write-pcapng!` | Supported sections/interfaces, LINKTYPE/snaplen, exact resolution/offset/ticks, ordered comments/options and permitted opaque octets; conditional known semantics, not universal byte equality |
| Native packets to `core/write-pcap!` | Single-DLT Classic PCAP at microsecond precision; select the native DLT explicitly; source container, nanosecond digits and PCAPNG metadata are lost |
| `:mode :lossy` with explicit `:drop` | Only named categories removed, with exact aggregate counts; the mode alone removes nothing |
| editcap/mergecap rewrites | Tool-dependent normalization; inspect the rewritten file rather than assuming its metadata matches the original |

mergecap may put all IDBs before the first packet. With mixed LINKTYPEs or
snaplens, native libpcap can then fail before delivering any packet. Changing
section byte order can fail after a valid prefix. These are native-path limits;
`:error-mode :pass` does not turn that prefix into a complete capture. Use the
metadata-aware path when qualified interfaces, exact time or these layouts matter.

Unknown data can have meanings in another tool. In particular, Wireshark 4.6.8
interprets EPB option `0x8001` as a Darwin-specific field and rejects the arbitrary
length used in historical P08 synthetic fixtures. Paclo retains this as unknown
raw data under its existing contract; successful preservation does not guarantee
acceptance by every external interpreter. An intentional conversion can use
`:mode :lossy :drop #{:unknown-options}` and inspect `:loss-counts`. This removes
all unknown options, not just that code. Do not silently discard them or reuse
private codes as a portable extension mechanism.

The P16 probe observes editcap 4.6.8/4.6.9 removing an unknown block and unknown options
and retaining comments. Its rewrite of the binary-resolution/offset case changes
ticks and even absolute time: `1700000007.125976562` becomes
`1700000014.125000000` in tshark. Treat this as a measured external rewrite
limitation, not an acceptable precision conversion or a Paclo reader defect.
Ubuntu editcap 4.2.2 instead removes the offset option and produces
`1700000007.125000000`, also losing fractional precision. Paclo's direct preserving round trip keeps
the original octets and exact ticks. NRB contents remain opaque in Paclo. Custom
blocks can even appear as additional records in Wireshark, so opaque preservation
still makes no complete packet-coverage claim. Unsupported PB/DSB input retains
its explicit error contract. Neither tool acceptance nor offline replay validates
live capture, production traffic diversity or NIC throughput.

## Packet analysis

Own a source with `with-open` and reduce it once. Filter packet envelopes before
passing packet maps through `core/packet-xf`; descriptors are not packets.
This example uses a real mixed-section fixture from the repository:

<!-- paclo-doc-test: pcapng-packet-analysis -->
```clojure
(require '[paclo.pcapng :as pcapng] '[paclo.core :as core])
(with-open [source (pcapng/open-source
                    {:path "test/resources/pcapng-contracts/mixed-sections.pcapng"})]
  (transduce
   (comp (filter #(= :packet (:type %))) (map :packet)
         (core/packet-xf {:decode? true :extensions []})
         (map #(get-in % [:decoded :type])))
   conj [] source))
```

The result is `[:ethernet :raw-ip]`.

Packet-only analysis intentionally discards descriptors. Raw/full decoding
preserves the packet's `:pcapng` metadata; flow projection discards bytes and
extra keys and cannot retain a preserving event stream. Existing window/DNS
analysis uses derived microseconds, so exact submicrosecond ordering is outside
those APIs. SPBs have no timestamp; choose an explicit missing-time policy for
time-based analysis.

For event-preserving inspection with a one-input/one-output packet transform,
apply the transform only inside packet envelopes:

<!-- paclo-doc-test: pcapng-event-inspection -->
```clojure
(require '[paclo.pcapng :as pcapng] '[paclo.core :as core])
(let [decode (core/packet-xf {:decode? true :extensions []})]
  (with-open [source (pcapng/open-source
                      {:path "test/resources/pcapng-contracts/rich.pcapng"})]
    (transduce
     (comp
      (map (fn [event]
             (if (= :packet (:type event))
               (update event :packet #(first (into [] decode [%])))
               event)))
      (map (fn [event]
             [(:type event) (get-in event [:packet :pcapng :timestamp])])) )
     conj [] source)))
```

This small-fixture example deliberately collects results. A streaming reducer
can instead inspect each event and keep only a bounded accumulator. Packet
filters, multi-output transforms and removal/reordering need explicit envelope
handling; the example assumes exactly one output for each input.

## Events and metadata

Every event contains `:type`, zero-based `:section-id`, `:block-index` and byte
`:file-offset`. Section IDs identify SHB occurrences within one source. Interface
IDs start again at zero in each section; use `[section-id interface-id]` as the
qualified identity. Descriptors arrive before referencing packets. Undefined
or forward interface references fail immediately.

| Event | Payload |
| --- | --- |
| `:section` | `:section` with `:id`, `:byte-order`, `:version [1 0]`, `:section-length`, `:options` |
| `:interface` | `:interface` with `:section-id`, `:id`, `:file-linktype`, `:linktype`, `:snaplen`, `:timestamp-resolution`, `:timestamp-offset-sec`, `:options` |
| `:packet` | `:packet` raw map with nested `:pcapng` metadata |
| `:opaque-block` | `:block` with uint32 `:block-type`, owned `:body`, `:byte-order`, `:copy-policy` |

Section byte order is `:little-endian` or `:big-endian`. Unspecified section
length (-1) becomes nil; other lengths must be nonnegative and end exactly at
EOF or the next SHB. Multiple sections, orders, LINKTYPEs and snaplens are valid.
Only section version 1.0 is supported. Snaplen is uint32; zero removes the format
limit, while resource ceilings still apply.

On Linux/macOS, the closed LINKTYPE-to-native-DLT mapping is
`{0 0, 1 1, 101 12, 108 108, 113 113, 276 276}`. Unknown LINKTYPEs and other OSes
have explicit `:linktype nil`; full/flow decode reports unsupported linktype.
There is no Ethernet fallback or native handle lookup. `:file-linktype` always
retains the original uint16 value.

Options are ordered vectors of `{:code uint16 :value owned-byte-array}`.
Values omit TLV headers/padding. Repeated comments, empty values, unknown octets
and invalid UTF-8 remain raw; no lossy text conversion occurs. Select options by
code rather than expecting typed name/comment caches. Resolution/offset are
interpreted only on IDBs; all other fields, including EPB flags and reserved
bits, remain authoritative original bytes. Recognized singleton duplicates and
invalid fixed/minimum lengths fail. Custom options need a four-byte PEN and add
`:copy-policy :copyable` for 2988/2989 or `:never` for 19372/19373.
EPB option 8 (process/thread IDs) has eight bytes and may repeat under draft 06.
IDB address options 4 (IPv4 address/netmask, eight bytes) and 5 (IPv6
address/prefix, seventeen bytes) may repeat, including identical values. Their
original mixed order and octets are retained under either section byte order;
option byte/count and section metadata ceilings still apply to every occurrence.
An option list may end at the block boundary without a terminator. A present
terminator must have length zero and be last. Padding extents are checked;
padding values are unspecified and need not be zero.

NRB/ISB, custom blocks and other unknown blocks produce bounded opaque events.
NRB/ISB and custom 0x00000bad use `:copyable`; custom 0x40000bad uses `:never`;
other unknown blocks use `:unknown`. These are context-dependent preservation
labels, not guarantees that opaque contents can be interpreted or rewritten.
Obsolete Packet Blocks (2) and Decryption Secrets Blocks (10) fail explicitly.
Unknown/private block semantics cannot be detected, so opaque input has no
complete packet-coverage or semantic-fidelity guarantee.

All packet, option and opaque arrays are fresh owned copies. Treat published
arrays as read-only, including when shared by fan-out. Retained old descriptors
remain unchanged when the reader releases its registry at the next section.

## Exact time and packet fields

EPB packets retain `:bytes`, `:caplen`, `:len`, `:linktype`, `:ts-sec`, `:ts-usec`.
Caplen equals array length, cannot exceed wire length or a nonzero snaplen, and
must fit the configured packet ceiling. PCAPNG information is nested as:

```clojure
{:pcapng {:section-id 0 :interface-id 0 :block-type :enhanced-packet
          :timestamp {:ticks 1700000000123456789N} :options []}}
```

Ticks are exact unsigned 64-bit integers. The referencing interface supplies
resolution `{:base 10-or-2 :exponent 0..127}` (default decimal 6) and signed
64-bit `:timestamp-offset-sec` (default zero). Exact epoch UTC time is
`offset + ticks / base^exponent` seconds. For denominator `D`, compute
`q = quot(ticks,D)`, `r = rem(ticks,D)`, `:ts-sec = offset+q` and
`:ts-usec = quot(r*1000000,D)`. All arithmetic uses arbitrary integers.
Microseconds floor the exact time, including negative epochs; the component is
always 0..999999. Derived seconds can exceed JVM long. Exact ticks remain intact
when submicrosecond detail disappears from the compatibility pair.

SPBs reference interface 0, use `:block-type :simple-packet`, `:timestamp nil`
and `:options []`, and omit both microsecond fields. This distinguishes missing
time from a timestamped EPB at epoch zero. Their caplen is the minimum of wire
length and nonzero snaplen (wire length when snaplen is zero). Padding is excluded.

Classic `write-pcap!` uses its existing microsecond precedence/ranges and does
not validate nested exact time. Exporting there requires explicit acceptance of
precision/metadata loss. The [E1 contract](../dev/p08-e1-pcapng-contracts.md)
defines the shared reader/writer data and exact-time contract.

## Ownership, status and failures

`open-source` accepts `{:path string-or-File-or-Path}` and optional ceilings.
It validates configuration before opening, reads only the first bounded SHB,
and closes if initialization fails. It does not preload packets or IDBs. A
source implements Closeable and IReduceInit, with no Seqable/Iterable interface,
background producer, live capture, BPF or implicit reopening.

Reduction claims the source once. Concurrent/repeat consumption throws
`:source-consumed` without closing the active consumer's channel; consuming an
unused closed source throws `:source-closed`. Close is idempotent. Reduction
closes on EOF, `reduced`, consumer exceptions and parse/I/O errors. It unwraps
`reduced` and does not call completion; `transduce` calls completion once after
cleanup. Consumer/read exception identity is preserved; a cleanup error is
suppressed on the primary exception, while a sole cleanup error is thrown.

External close cancels I/O without waiting on the consumer. Delivery is claimed
atomically against cancellation: an already claimed call may run or finish;
no new event is claimed after close. Interrupted channel reads are classified
as `:closed`, while consumer exceptions remain errors. There is no speculative
next-block read or consumer call after `reduced`. An abandoned unused source
still needs explicit close/with-open.

`source-info` returns a bounded data-only snapshot:

| Field | Meaning |
| --- | --- |
| `:state` | `:open`, `:reading`, `:closed`, `:failed` |
| `:terminal` | nil while active; `:eof`, `:reduced`, `:closed`, `:error` when finished |
| `:consumed?` | Whether reduction has claimed the source |
| `:events`, `:packets`, `:opaque-blocks` | Counts of claimed deliveries, including a consumer call that throws |
| `:blocks-read`, `:bytes-read` | Fully validated blocks/bytes, including the pending first SHB |
| `:active-interfaces`, `:active-metadata-bytes` | Current registry/accounting; zero after cleanup |
| `:error` | nil or bounded error data; no bytes, Throwable or arbitrary consumer message |

Read failures throw ex-info with `:phase :pcapng-read`, `:reason`, block/byte
location and applicable `:field`, `:actual`, `:expected`, `:limit`, qualified
interface and numeric block type. Reasons include invalid/truncated lengths,
invalid options, duplicate options, undefined interfaces, unsupported blocks or
versions and limit violations. Path-open and I/O exceptions propagate; there
is no recovery/resynchronization or `:pass` mode. A valid prefix and a terminal
`:reduced`/`:closed` do not validate the unread suffix. For example:

<!-- paclo-doc-test: pcapng-error-status -->
```clojure
(require '[paclo.pcapng :as pcapng])
(with-open [source (pcapng/open-source
                    {:path "test/resources/pcapng-contracts/forward-interface.pcapng"})]
  (try
    (reduce (fn [n _] (inc n)) 0 source)
    (catch clojure.lang.ExceptionInfo error
      {:reason (:reason (ex-data error))
       :state (:state (pcapng/source-info source))
       :events (:events (pcapng/source-info source))})))
```

The result is `{:reason :undefined-interface :state :failed :events 2}`.

## Resource ceilings

All ceilings must be positive integers. Byte ceilings are at most
Integer/MAX_VALUE minus 8; count ceilings are at most 65536. Unknown options,
nil/unlimited settings and invalid numbers fail before path opening.

| Option | Default | Accounting |
| --- | --- | --- |
| `:max-block-bytes` | 16 MiB | Total declared block size, checked before body allocation/read |
| `:max-packet-bytes` | 8 MiB | Caplen from fixed EPB/SPB prefix, before remaining body allocation/read; independent of snaplen |
| `:max-options-bytes` | 1 MiB | All padded TLV bytes per parsed block, including terminator |
| `:max-options-per-block` | 4096 | Exposed option records; excludes terminator |
| `:max-interfaces-per-section` | 4096 | Current section's IDBs |
| `:max-section-metadata-bytes` | 8 MiB | 256 per SHB/IDB + padded option TLVs + 32 per option record |
| `:max-opaque-block-bytes` | 1 MiB | Opaque body; failure rather than silent skip |

The reader retains only current-section interfaces, a bounded current block and
copied current event; it accumulates no old sections, packets or opaque blocks.
Metadata accounting is a deterministic policy, not an exact JVM object-size
promise. Counts bound zero-length-option/interface amplification. Callers
collecting events own that additional memory. The acceptance probe streams
6000 sections/12000 interfaces/6000 opaque blocks (246336000 wire bytes) in a
separate 48 MiB heap process and checks active registry maxima without collecting
events. This is boundedness evidence for that workload, not a throughput target.

## Writing PCAPNG

`(pcapng/write-pcapng! events path)` reduces ordered events once, synchronously.
The three-argument form accepts an options map. A direct Reader-to-Writer copy
keeps descriptors, packet bytes and lengths, exact time, timestamp absence,
ordered comments/options and allowed opaque octets:

<!-- paclo-doc-test: pcapng-preserving-writer -->
```clojure
(require '[paclo.pcapng :as pcapng])
(let [dir (java.nio.file.Files/createTempDirectory
           "paclo-example-" (make-array java.nio.file.attribute.FileAttribute 0))
      output (.resolve dir "copy.pcapng")]
  (try
    (with-open [source (pcapng/open-source
                        {:path "test/resources/pcapng-contracts/rich.pcapng"})]
      (let [report (pcapng/write-pcapng! source output)]
        (with-open [copy (pcapng/open-source {:path output})]
          {:report report :packets (transduce (filter :packet)
                                              (completing (fn [n _] (inc n))) 0 copy)})))
    (finally
      (java.nio.file.Files/deleteIfExists output)
      (java.nio.file.Files/delete dir))))
```

The report contains `:status :complete`, `:fidelity :known-semantics`,
`:loss-counts {}`, `:blocks-written 7` and `:bytes-written 644`; there are three
packets. Counts use arbitrary integers and do not retain a per-loss list.

| Mode | Behavior |
| --- | --- |
| `:preserve` (default) | Retain supported metadata; refuse drops and declared context changes; missing metadata fails |
| `:lossy` | Apply only the explicit `:drop` categories; the mode alone discards nothing; return `:fidelity :explicit-loss` |
| `:author` | Validate explicitly authored descriptors/packets; return `:fidelity :authored`, without asserting input preservation |

`:drop` is a set, supported only in lossy mode. Categories are `:comments`
(option 1), `:unknown-options` (codes outside the recognized scope table),
`:noncopyable-options` (19372/19373), `:custom-options` (copyable custom options
2988/2989), and `:opaque-blocks` (all opaque events). Each removed option/block
increments that category's loss count. Known options are SHB 2–4, IDB 2–18,
EPB 2–8, comments and the four custom-option codes. Empty options and repeated
comments remain distinct. Malformed data is validated before a requested drop;
lossy mode never repairs invalid lengths, references, options or time.

Set `:context-changed? true` in lossy or author mode when changing section order,
IDs, byte order, payload, timestamps or packet subsets. The report includes
`:context-changed 1`. Every retained opaque block, unknown option or copyable
custom option then fails `:opaque-context-changed`; explicitly drop all affected
categories in lossy mode. Noncopyable custom data fails `:noncopyable-data`
unless explicitly dropped. Opaque bodies must retain their section byte order,
including when being dropped. Unsupported packet/secrets blocks cannot be
smuggled through an opaque event. Paclo cannot detect undisclosed removed events,
in-place array edits or invented provenance. Preservation is conditional on the
caller's declaration and retained source metadata; unknown meanings remain
unverified. No complete semantic fidelity or packet coverage is claimed for
opaque content.

Section IDs must be consecutive from zero, and interface IDs must match the IDB
ordinal within each section. Emit each IDB before any referencing packet. Writer
never preloads, renumbers, merges or reorders. All descriptor fields in the event
table are required, including explicit nil for an unavailable DLT. Resolution
and signed offset must agree with authoritative options; missing options mean
the decimal-6/zero defaults. Packet maps require bytes, caplen, len, linktype and
the PCAPNG envelope. Native six-key maps and flow projections lack that contract.
Event `:block-index`/`:file-offset` are optional input locations, not output
coordinates. Extra packet decoding keys are ignored.

EPBs require exact uint64 ticks in preserve/lossy modes. A complete supplied
microsecond pair must agree with exact time. Author mode also accepts a complete
integer pair when the `:timestamp` key is absent from the envelope, and solves
for ticks exactly; nonintegral, negative or >uint64 results fail. Explicit nil
never falls back to microseconds. No current-clock, rounding or legacy `:sec`
fallback exists. SPB requires interface zero, explicit nil timestamp, no options
or microsecond fields, and its inferred caplen. For example, a new one-byte EPB
at epoch plus one microsecond:

<!-- paclo-doc-test: pcapng-authoring-writer -->
```clojure
(require '[paclo.pcapng :as pcapng])
(let [dir (java.nio.file.Files/createTempDirectory
           "paclo-author-" (make-array java.nio.file.attribute.FileAttribute 0))
      output (.resolve dir "new.pcapng")
      events [{:type :section :section-id 0
               :section {:id 0 :byte-order :little-endian :version [1 0]
                         :section-length nil :options []}}
              {:type :interface :section-id 0
               :interface {:section-id 0 :id 0 :file-linktype 1 :linktype 1
                           :snaplen 64 :timestamp-resolution {:base 10 :exponent 6}
                           :timestamp-offset-sec 0 :options []}}
              {:type :packet :section-id 0
               :packet {:bytes (byte-array [42]) :caplen 1 :len 1 :linktype 1
                        :ts-sec 0 :ts-usec 1
                        :pcapng {:section-id 0 :interface-id 0
                                 :block-type :enhanced-packet :options []}}}]]
  (try
    (pcapng/write-pcapng! events output {:mode :author})
    (with-open [source (pcapng/open-source {:path output})]
      (transduce (comp (filter :packet) (map #(get-in % [:packet :pcapng :timestamp])))
                 conj [] source))
    (finally
      (java.nio.file.Files/deleteIfExists output)
      (java.nio.file.Files/delete dir))))
```

The result is `[{:ticks 1N}]`. Packet bytes need not contain a decodable frame.

### Publication, failure and ownership

Output uses a newly created sibling temporary file. Writer validates each block
before writing, completes reduction, flushes and closes, then publishes via
Linux `renameat2(RENAME_NOREPLACE)` or macOS `renamex_np(RENAME_EXCL)` through the
existing JNR dependency. These primitives atomically refuse existing destination
names, including creation races and dangling symlinks. Only the default file
provider on these OSes is supported, and the filesystem must support the flag.
Missing symbols, unsupported atomic/exclusive operations and move errors fail;
there is no unsafe move/copy/link fallback. Existing paths are refused. There
is no replacement, append, caller-output-stream or crash-durability/fsync API.
See the [Linux rename manual](https://man7.org/linux/man-pages/man2/rename.2.html)
and [Apple rename implementation](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/vfs/vfs_syscalls.c)
for the platform operations.

Success does not reproduce physical input bytes: section length becomes -1,
padding is zero, option terminators may be omitted and trailers regenerated.
Known meaning, exact fields and retained octets/order are the round-trip target.

A validation error has `:phase :pcapng-write`, `:reason`, output `:block-index`,
`:file-offset`, `:section-id`, `:output-status :not-published` and applicable field
or limit data. Input and I/O exceptions retain identity and original ex-data.
After temp creation, a suppressed exception adds output status/location and
`:temp-path`. Close errors are suppressed on the original failure; a sole close
error throws. Cleanup runs after validation, write, flush, close or move failure.
A cleanup failure is suppressed with its temp path and cause for recovery.

Source reduction owns its close, Writer owns its output. Other Closeable
reducibles retain caller/upstream ownership; use `with-open`. Writer checks
Paclo source terminal status even inside synchronous `eduction`: early
`:reduced`, `:closed` or `:error` cannot publish a preserving copy. An intentional
`take` subset needs lossy/author mode with `:context-changed? true`, explicitly
handled opaque options and a normally returning outer reduction. It does not
validate the unread suffix. Plain custom reducibles must enforce their own
upstream completion; Writer cannot inspect an undisclosed upstream source or
undo swallowed upstream failures. Repeat/concurrent consumption still fails
without stealing the active Reader's channel. Empty input fails
`:missing-section`; a valid empty section is permitted.

Writer accepts the same resource ceilings as Reader. It validates option counts,
padded sizes, packet/opaque sizes, block size, interface count and section metadata
before bounded encoding. It retains only current-section descriptors and the
current bounded block/event. Dropped data must also satisfy limits. It holds no
whole-file input, packet index, old-section registry or loss-detail list. The
48 MiB writer acceptance process streams 6000 sections/12000 interfaces/6000
opaque blocks (246264000 bytes), with at most two active interfaces and 33572
metadata accounting bytes. This is a bounded workload test, not a throughput or
live-capture claim.
