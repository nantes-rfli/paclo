# Metadata-aware PCAPNG reading

`paclo.pcapng/open-source` reads an offline PCAPNG file through a bounded Java
FileChannel cursor. `source-info` reports its lifecycle and counters. The
existing `core/packets`, `reduce-packets` and Classic `write-pcap!` retain their
native behavior. There is no PCAPNG writer yet.

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
defines the future E3 writer; it is not available from this namespace.

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
