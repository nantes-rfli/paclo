# Paclo Usage Guide

This guide covers the minimal concepts and common workflows for Paclo.
For installation and CLI entry examples, start from `README.md`.

## Mental model

- `paclo.core` handles capture and packet transformation.
- `paclo.flow` provides pure canonical keys, bounded aggregation and exact Top-N.
- `packets` returns lazy packet maps from a file (`:path`) or device (`:device`).
- `packet-xf` builds a reusable transducer for decoding or flow projection.
- `reduce-packets` synchronously folds large or live captures without an
  intermediate sequence.
- `reduce-packets-report` adds data-only execution statistics to the
  synchronous result.
- `start-capture` owns an explicitly stoppable, single-consumer capture
  lifecycle.
- `paclo.stream/fan-out` distributes one sequence to two or more bounded,
  separately owned, single-consumer branches.
- `bpf` converts a small Clojure DSL to BPF strings.
- `write-pcap!` writes byte records to single-DLT Classic PCAP.
- Optional decode hooks (`paclo.decode-ext`) annotate decoded packets.

## Quick start (offline)

<!-- paclo-doc-test: usage-offline-prefix -->

```clojure
(require '[paclo.core :as core])

(with-open [capture (core/start-capture
                     {:path "test/resources/dns-sample.pcap" :decode? true})]
  (into [] (comp (take 2) (map #(select-keys % [:caplen :decoded :decode-error])))
        (core/capture-packets capture)))
```

## Quick start (live capture)

For a limited prefix of live traffic, own the source explicitly:

```clojure
(require '[paclo.core :as core])

(with-open [capture
            (core/start-capture
             {:device "en0"
              :filter [:and [:udp] [:port 53]]
              :timeout-ms 50
              :max Long/MAX_VALUE
              :max-time-ms 60000
              :idle-max-ms 60000})]
  (into [] (take 10) (core/capture-packets capture)))
```

`with-open` closes the capture even when `take` completes early or the body
throws. Change `en0` to an available interface (see `core/list-devices`);
live capture may require OS permissions.

## Choose a processing model

| Need | Use | Ownership and termination |
| --- | --- | --- |
| Fully consume a finite capture lazily | `core/packets` | Consume through termination; a full queue can prevent source limits and EOF |
| Accumulate or stop as soon as a reducer decides | `core/reduce-packets` or `core/reduce-packets-report` | Synchronous; `reduced` stops and closes the source |
| Cancel externally or inspect running statistics | `core/start-capture` + `core/capture-packets` | One consumer; close the capture with `with-open` |
| Feed independent consumers | `stream/fan-out` + `stream/branch` | Own capture, fan-out, and every acquired branch; configure bounded buffers |

### Lazy capture lifetime

`core/packets` starts a background producer and returns a lazy sequence with
no close/cancel operation. `take`, `first`, a reducing `:xform`, a consumer
exception, or dropping the sequence reference does **not** cancel that producer.
This applies to offline files as well as devices. Lazy transformation can read
ahead; the number of delivered values does not identify the producer position.

With `:queue-mode :blocking`, if the remaining packets exceed the free queue
slots, the producer waits in a packet queue `put` and keeps its native handle.
`:max-time-ms`, `:idle-max-ms`, `:max` and `:stop?` are checked by the read loop;
they cannot interrupt that wait. A predicate changed from another thread cannot
rescue it. Final queue callbacks also wait for producer termination. Bounded
queue memory does not imply bounded resource lifetime.

Paclo cannot distinguish an abandoned sequence from a slow or paused consumer.
Automatic timeout/drop/GC cleanup would change lossless lazy delivery or provide
no deterministic guarantee. This compatibility limitation is documented by
[Issue #40](https://github.com/nantes-rfli/paclo/issues/40) and its
[offline investigation](../dev/work-log.md#issue-40-lazy-capture-lifecycle-investigation).
The lazy API retains its existing behavior.

For predictable early cleanup, use synchronous `reduce-packets` or
`reduce-packets-report` with `reduced` (including a transducer such as `take`),
or own `start-capture` with `with-open` as in the quick start. Materialize the
desired result inside that scope; do not return a lazy managed packet stream.
Close also runs when consumer code throws. Do not use an unbounded queue,
background draining, or `:dropping` as cancellation: dropping is explicitly
lossy and still runs the producer until its source stop condition.

## Composable packet transformations

`packet-xf` is an ordinary transducer, so it composes with `filter`, `map`,
`comp`, and `transduce` without an additional pipeline abstraction:

<!-- paclo-doc-test: usage-packet-xf -->

```clojure
(into []
      (comp (core/packet-xf {:decode-mode :flow})
            (filter #(= 17 (:protocol %))) ; UDP
            (map #(select-keys %
                               [:src-ip :dst-ip :src-port :dst-port])))
      (core/packets {:path "test/resources/dns-sample.pcap"}))
```

Use `{:decode? true}` for the nested `:decoded` packet representation and
selected post-decode extensions (global hooks by default), or `{:decode-mode :flow}` for a flat
numeric flow projection. These options cannot be combined.
`(core/packet-xf {})` passes packets through unchanged. The optional
`:xform` on capture APIs runs **after** their built-in packet transformation.
Do not apply the same decode twice by combining a decode option with another
decode-configured `packet-xf` in `:xform`.

## Synchronous reduction

For flow counts and byte totals, use the reducer in
[reusable flow analysis](#reusable-flow-analysis). For other data, pass any
ordinary two-argument reducing function and its initial value.

The reducer may return `(reduced value)` to stop capture immediately and
close the underlying source. For example, collect just two packet summaries:

<!-- paclo-doc-test: usage-early-reduced -->

```clojure
(core/reduce-packets
 {:path "test/resources/dns-sample.pcap"}
 (fn [acc packet]
   (let [next-acc (conj acc (select-keys packet
                                        [:ts-sec :ts-usec :caplen]))]
     (if (= 2 (count next-acc))
       (reduced next-acc)
       next-acc)))
 [])
```

This path avoids the producer future, blocking queue, and lazy-seq nodes used
by `packets`; use `packets` when interactive lazy consumption is more useful.

Use `reduce-packets-report` when the caller also needs source, timing, packet,
stop-reason, error, and final live libpcap statistics:

```clojure
(let [{:keys [result stats]}
      (core/reduce-packets-report
       {:path "large.pcap"
        :decode-mode :flow
        :max Long/MAX_VALUE
        :max-time-ms 3600000}
       (fn [counts flow]
         (update counts
                 (select-keys flow
                              [:src-ip :dst-ip :protocol
                               :src-port :dst-port])
                 (fnil inc 0)))
       {})]
  {:top-flows result
   :stop-reason (:stop-reason stats)})
```

## Managed capture

Use managed capture when a long-running capture needs explicit ownership,
external cancellation, or in-progress queue statistics. The default
`:idle-max-ms 3000` stops a quiet live capture after roughly three idle
seconds, even if `:max-time-ms` is much longer. Set an explicit idle limit
appropriate to the session, as below:

```clojure
(with-open [capture
            (core/start-capture
             {:device "en0"
              :filter [:and :udp [:port 53]]
              :queue-cap 4096
              :queue-mode :dropping
              :max Long/MAX_VALUE
              :max-time-ms 3600000
              :idle-max-ms 3600000})]
  (run! #(prn (select-keys % [:ts-sec :ts-usec :caplen]))
        (core/capture-packets capture))
  (core/capture-stats capture))
```

`start-capture` does not return until the source is open and BPF installation
has succeeded. The handle implements `java.io.Closeable`; always own it with
`with-open`.

The packet stream may be acquired only once and must not escape its
`with-open` scope. A second call to `capture-packets` throws `ex-info`.

Another thread may request shutdown:

```clojure
(with-open [capture
            (core/start-capture
             {:device "en0"
              :max Long/MAX_VALUE
              :max-time-ms 3600000
              :idle-max-ms 3600000})]
  (future
    (Thread/sleep 2000)
    (core/stop-capture! capture))
  (run! #(prn (:caplen %))
        (core/capture-packets capture)))
```

`stop-capture!` is asynchronous and idempotent. Closing the handle waits for
the producer and releases libpcap resources. Closing abandons values that
remain in the queue, including an offer already in flight at the stop request.
Stop alone unblocks a saturated producer and retains queued values for draining;
always close the handle to end its ownership scope. Concurrent stop/close calls
serialize native break/close so no stop call uses an already freed handle.
Close waits up to 5000 ms for producer completion; a timeout throws
`"managed capture did not stop before close timeout"` and is not confirmation of
native release. Callbacks and native reads must return for producer cleanup to
finish; time limits do not forcibly interrupt arbitrary user callbacks.

`capture-stats` returns a schema-versioned data map:

```clojure
{:schema-version 1
 :state :running
 :source {:type :device :name "en0"}
 :timing {:started-at-ms 1785370000000
          :elapsed-ms 1250}
 :packets {:captured 10000
           :enqueued 9900
           :delivered 9800
           :processed 9800
           :decode-errors 0}
 :queue {:mode :dropping
         :capacity 4096
         :depth 100
         :max-depth 4096
         :enqueued 9900
         :dropped 100
         :blocked-events 0
         :blocked-ns 0}
 :pcap nil
 :stop-reason nil
 :error nil}
```

Live packet and queue counters are available while running. Portable libpcap
counters are finalized at termination. Final statistics remain available
after close.

One managed capture has one direct packet consumer. Version 1.3 adds
`paclo.stream` as a separate, bounded fan-out layer; it does not turn the
capture itself into a multi-consumer handle.

## Bounded fan-out (v1.3)

Each branch must be acquired once and consumed by one consumer. Consume
branches concurrently when a `:blocking` branch might fill its buffer,
otherwise a slow branch can block the dispatcher and other branches.

This complete offline example uses the bundled four-packet fixture:

<!-- paclo-doc-test: usage-bounded-fan-out -->

```clojure
(require '[paclo.stream :as stream])

(with-open [capture (core/start-capture
                     {:path "test/resources/dns-sample.pcap"})
            fanout (stream/fan-out
                    (core/capture-packets capture)
                    {:archive {:buffer-mode :blocking :buffer-cap 16}
                     :metrics {:buffer-mode :dropping :buffer-cap 16}}
                    {:cancel! #(core/stop-capture! capture)})
            archive (stream/branch fanout :archive)
            metrics (stream/branch fanout :metrics)]
  (let [archive-count (future (reduce (fn [n _] (inc n)) 0 archive))
        metrics-count (future (reduce (fn [n _] (inc n)) 0 metrics))]
    {:archive-count @archive-count
     :metrics-count @metrics-count
     :distribution (stream/stats fanout)}))
```

`stream/fan-out` requires at least two keyword-named branches.
`:buffer-cap` defaults to 1024; `:buffer-mode` is required and can be
`:blocking` (backpressure, no branch-local drops) or `:dropping` (discard
new values when that branch is full). Both modes use bounded buffers.
`:cancel!` is useful for unblocking an external source at shutdown, and
must release that source when called.

Own the fan-out and acquired branches with `with-open` along with the
capture. Closing one branch does not close sibling branches. Branch handles
also support `reduce` and `transduce`; returning `reduced` from a branch
reducer closes that branch. Check `stream/stats` for distribution statistics
and `core/capture-stats` for capture statistics; they are separate.
Fan-out shares map and byte-array references rather than copying packets.
Treat packet bytes as read-only across branches.

## Stopping conditions and defaults

All capture paths default to `:max 100` packets, `:max-time-ms 10000`
(10 seconds), and `:idle-max-ms 3000` (3 seconds of continuous idle time,
primarily relevant to live capture). These are safeguards, not settings
that mean “read the entire file.” Specify a sufficiently large `:max` and
`:max-time-ms` when processing a large offline PCAP.

For an offline source, `:eof` means libpcap reached the file's end; a
configured count or time limit can stop processing **before** EOF. In a
`reduce-packets-report` result or final `capture-stats`, inspect
`:stop-reason` to distinguish `:eof`, `:max-packets`, `:max-time`,
`:idle-timeout`, `:predicate`, `:reduced` (synchronous reduction), and
errors where applicable. `:stop?` is an optional source-level predicate.
`reduced` stops synchronous reduction; it is not a resource-management
mechanism for a plain lazy `take`.

`packets` and managed capture use a bounded producer queue (default
`:queue-cap 1024`, `:queue-mode :blocking`). Managed capture is
single-consumer even when used as the source for fan-out.

For live overload experiments, `packets` also accepts a bounded dropping
queue. Blocking remains the default and preserves existing behavior:

```clojure
(core/packets
 {:device "en0"
  :queue-cap 4096
  :queue-mode :dropping
  :on-queue-stats println})
```

The callback receives final enqueued, dropped, blocking, and maximum-depth
counters. A dropping queue never returns dropped packets to the consumer.

## Write PCAP

```clojure
(require '[paclo.core :as core])

(core/write-pcap! [(byte-array (repeat 60 (byte 0)))
                   {:bytes (byte-array (repeat 60 (byte -1)))
                    :sec 1700000000
                    :usec 123456}]
                  "out.pcap")
```

P02 in `v1.4.0` accepts read packet maps directly. A complete
`:ts-sec`/`:ts-usec` pair takes precedence over legacy `:sec`/`:usec`, even when
the pairs conflict. Seconds must be integers in `0..4294967295`, microseconds
in `0..999999`; zero is valid. A partial new pair or invalid complete selected
pair (including `nil`) throws `ex-info`. Missing timestamps and partial legacy
pairs keep the current-time fallback. Released v1.3.0 does not have this behavior.

The byte-array length is `:caplen`; a supplied `:caplen` must match it.
Original `:len` is preserved, or defaults to the byte-array length when omitted.
Explicit lengths must be integers in `0..4294967295`, with `:len >= :caplen`.
Invalid bytes or metadata throw `ex-info`.

This offline example reads, filters, writes the original packet maps, and compares
their metadata and byte contents. The independent fixture includes truncated
packets. Use your own Ethernet PCAP path and output path in an application.

<!-- paclo-doc-test: usage-pcap-roundtrip -->
```clojure
(require '[paclo.core :as core])

(let [out (java.io.File/createTempFile "paclo-roundtrip-" ".pcap")
      snapshot (fn [packet]
                 (update (select-keys packet [:ts-sec :ts-usec :caplen :len :bytes])
                         :bytes vec))
      kept (into [] (core/packets
                     {:path "test/resources/metadata-roundtrip.pcap"
                      :filter "ip" :max Long/MAX_VALUE}))]
  (try
    (core/write-pcap! kept (.getAbsolutePath out))
    (let [saved (into [] (core/packets {:path (.getAbsolutePath out)
                                      :max Long/MAX_VALUE}))]
      {:count (count saved)
       :preserved? (= (mapv snapshot kept) (mapv snapshot saved))
       :truncated? (boolean (some #(< (:caplen %) (:len %)) saved))})
    (finally (.delete out))))
```

P08-B2 in `v1.4.0` adds a third options map. Defaults remain
`{:linktype 1 :snaplen 65536}`; `:linktype` is a nonnegative native libpcap DLT
integer in `0..2147483647`, and `:snaplen` is an integer in `1..2147483647`.
Unknown options (including `:format`) and explicit invalid values such as nil
throw before output is opened. Installed libpcap must support writing the selected
DLT; unsupported values fail at dumper open. DLT_RAW can differ from the saved
LINKTYPE_RAW number: use the native `:linktype` from a reader, not a file header.

Every explicit packet `:linktype` must be valid and equal to the selected writer
DLT. A mismatch or mixed-DLT sequence fails before the offending record is written.
The two-argument form now rejects non-Ethernet packet maps instead of mislabeling
them. Migrate by supplying the matching DLT, as below. For byte-arrays and maps
without `:linktype`, the caller is responsible for matching the chosen framing.
Paclo does not infer framing, change bytes or synthesize Ethernet headers.
Removing metadata does not make a known mismatch safe.

<!-- paclo-doc-test: usage-explicit-pcap-writer -->

```clojure
(require '[paclo.core :as core])

(let [out (java.io.File/createTempFile "paclo-sll-" ".pcap")
      source (core/reduce-packets {:path "test/resources/linktype-sll.pcap"} conj [])
      snapshot #(update (select-keys % [:bytes :ts-sec :ts-usec :caplen :len :linktype])
                        :bytes vec)]
  (try
    (core/write-pcap! source (.getAbsolutePath out) {:linktype 113 :snaplen 65536})
    (let [saved (core/reduce-packets {:path (.getAbsolutePath out)} conj [])]
      {:count (count saved)
       :linktypes (mapv :linktype saved)
       :preserved? (= (mapv snapshot source) (mapv snapshot saved))})
    (finally (.delete out))))
```

Captured length must be <= snaplen; Paclo rejects excess bytes instead of
truncating them or emitting an inconsistent header. Original wire length may
exceed snaplen and is preserved. Output is Classic PCAP with one DLT and
microsecond precision even if the path ends in `.pcapng`. PCAPNG input can be
converted only for the packet fields returned by the reader: interface IDs/names/
options, comments, section information, unknown blocks and original precision
are lost. Source header, snaplen and byte order are not copied automatically;
byte-for-byte source-file reproduction is not guaranteed.

Writing is incremental and overwrites the destination at dumper open. Validation,
source realization or native write failure can leave an empty file or prefix;
I/O failures can also leave incomplete records or headers. There is no atomic
replacement/rollback. Each record is validated before writing.
The writer owns and closes its handle/dumper; it does not own input capture
resources. Prefer synchronous reduction or `with-open` managed capture when input
must be closed after early failure (lazy capture abandonment remains issue #40).
Native open and flush errors throw; Linux/macOS also check the output stream's
sticky error indicator for earlier failed writes. Cleanup always attempts flush, dumper close
and handle close in order, retaining the original failure with cleanup errors
suppressed. Native dump/close return void; OS close-only errors cannot be observed.
Successful flush is not an fsync/durability guarantee. Older libpcap readers may
expose post-2038 seconds as negative; see the
[writer contract](cljdoc-api-contract.md#write-pcap) for this native limitation.

## BPF DSL (examples)

```clojure
(core/bpf [:and [:ipv6] [:udp] [:dst-port-range 8000 9000]])
;; => "(ip6) and (udp) and (dst portrange 8000-9000)"

(core/bpf [:and [:net "10.0.0.0/8"] [:not [:port 22]]])
;; => "(net 10.0.0.0/8) and (not (port 22))"
```

## Decode extensions

Explicit `:extensions` selects a vector of ordinary functions in order,
including duplicates. Omission uses the dynamic global hook registry;
`[]` disables all extensions. Explicit selection requires `:decode? true`;
invalid vectors/elements and raw/flow combinations throw `ex-info` before
source open. Extensions receive successful decoded packet maps before
`:xform`; exceptions and non-map returns preserve the preceding map while
later extensions continue. Registration changes do not affect explicit pipelines.

<!-- paclo-doc-test: usage-explicit-extensions -->

```clojure
(require '[paclo.proto.dns-ext :as dns-ext])

(core/reduce-packets
 {:path "test/resources/dns-sample.pcap"
  :decode? true
  :extensions [dns-ext/annotate-dns]
  :xform (map #(get-in % [:decoded :l3 :l4 :app :summary]))}
 conj [])
```

The same option works with `packet-xf`, `packets`, `reduce-packets-report`,
and `start-capture`. `dns-ext/annotate-dns` and
`paclo.proto.tls-ext/annotate-tls-sni` can also be called directly; existing
DNS/TLS `register!` entrypoints still select global hooks for callers that
omit the option. Repository CLI runs using DNS need `:dns-ext`; the namespace
is included in the dependency JAR.

See [decode extensions](extensions.md) for the full contract and an executable
example of independent DNS/TLS fan-out branches. Treat shared packet bytes as
read-only. Explicit selection and public annotations are in `v1.4.0` (P03).

## CLI workflows

Paclo ships practical CLI examples under `dev/examples`.
Use `README.md` as the command index, and use this guide for API behavior.

## Error model

- `:decode? true` does not throw on parse failure.
- Decode failures are represented as `:decode-error` in each packet map.
- Invalid API inputs (for example unsupported `:filter` type) throw `ex-info`.
Native reads distinguish EOF from failure. A corrupted Classic PCAP or PCAPNG
can contain valid packets before libpcap fails; the default `:error-mode :throw`
throws instead of returning that prefix as a successful capture. The exception's
`ex-data` includes `:reason :pcap-read-failed`, `:phase :pcap-next-ex`, the native
`:rc`, and `:native-error` (string or nil). Use the keyword/code, not diagnostic
text, to classify failures. No synthetic packet or decode-error count is added.

With `:error-mode :pass`, valid prefix packets remain available. Inspect
`reduce-packets-report` or `capture-stats`: failed reads have `:state :failed`,
`:stop-reason :error`, and structured `:error` alongside existing class/message
fields; stats stay schema version 1. For `packets` or `reduce-packets`, provide
`:on-error` to record failures when choosing `:pass`. The callback receives the
original read exception once; its own exception cannot replace the read failure.
A prefix alone does not prove EOF. Count/time/predicate/reduced stops can also
leave an unread corrupt tail.

Failed open/configuration, netmask resolution, BPF setup and DLT acquisition
release the native handle owned by setup. Successful initialization transfers
ownership to reduction, the lazy producer, or the managed capture. Cleanup does
not hide the original setup/read cause. Source-open errors stay synchronous in
`:pass`, as do managed/reduction setup errors. Legacy lazy post-open BPF/DLT/ready
failures follow its background error policy. Lazy error/completion signaling
cannot block behind a full queue, but
abandoning lazy packet delivery while the producer is blocked has the
[lazy capture lifetime](#lazy-capture-lifetime) limitation; use `with-open`
managed capture when consuming only a prefix.

- Managed capture startup errors are thrown synchronously by `start-capture`.
- Managed background errors set state to `:failed`, appear as data in
  `capture-stats`, and throw from the packet stream unless
  `:error-mode :pass` is selected.
- Lower-level libpcap open/filter/capture errors may propagate as exceptions.

## Performance tips

- Use BPF for coarse filtering as early as possible.
- Use `:xform` transducers in `packets` for map/filter composition; capture-level BPF is still the earlier filter.
- For large traces, use `reduce-packets` to fuse transformation and reduction
  without full materialization.
- Prefer `reduce-packets-report` over managed capture when synchronous
  processing is sufficient; it avoids the producer queue and background
  future.

## References

- API docs (cljdoc): <https://cljdoc.org/d/org.clojars.nanto/paclo/CURRENT>
- Public API contract: `./cljdoc-api-contract.md`
- Decode extensions: `./extensions.md`
- Roadmap: `./ROADMAP.md`

## Packet contracts and diagnostics

See the [canonical packet contracts](cljdoc-api-contract.md#packet-data-contracts)
for raw/full/flow types, missing values, mutable shared arrays and timestamp units.
Decode failures retain `:decode-error` strings and add structured diagnostics.
Best-effort unsupported/incomplete decoded values can also carry diagnostics.
Use `:extension-error-mode :report` to observe isolated hook failures.

This example collects EDN diagnostics through a reducer while a later hook still
annotates every successfully decoded packet. The report retains statistics v1;
extension failures alone do not increment its decode-error counter.

<!-- paclo-doc-test: usage-structured-diagnostics -->

```clojure
(require '[clojure.edn :as edn])

(let [{:keys [result stats]}
      (core/reduce-packets-report
       {:path "test/resources/dns-sample.pcap"
        :decode? true
        :extension-error-mode :report
        :extensions [(fn [_] (throw (ex-info "annotation unavailable" {})))
                     dns-ext/annotate-dns]}
       (fn [acc packet] (into acc (:diagnostics packet))) [])]
  {:reasons (mapv :reason result)
   :edn-roundtrip? (= result (edn/read-string (pr-str result)))
   :decode-errors (get-in stats [:packets :decode-errors])})
```

## Reading non-Ethernet captures

Native raw reads retain the actual libpcap DLT as integer `:linktype`. DLT is
not necessarily the savefile's numeric LINKTYPE; see the
[link-type contract](cljdoc-api-contract.md#link-type-dispatch). Detection happens
once after open/activation; it does not infer framing from arbitrary bytes.
Full decode and flow support Ethernet/VLAN (DLT 1), Linux SLL (113) and SLL2
(276), Raw IP (12), NULL (0) and LOOP (108) IPv4/IPv6 on Linux/macOS. TCP, UDP, ICMP,
fragments and IPv6 extension headers use the
existing parsers. Full decode adds `:linux-sll` or `:linux-sll2` link maps and
retains bytes; flow keeps numeric IP/port fields and omits bytes. Explicit
DNS/TLS extensions work under the shared `[:decoded :l3 :l4]` path.

Unknown/invalid DLTs remain unsupported for full/flow, with
`"unsupported linktype"` and `:unsupported-linktype` diagnostics. Raw access is
unchanged. Short cooked headers report `:short-frame` with required lengths
16/20 at offset 0. Address lengths above 8 report `:malformed-packet` with
`:field :address-length`; unknown cooked protocols report `:unsupported-protocol`.
Locations are absolute byte offsets in the original frame. IP/L4 truncation
uses existing diagnostics; flow needs only four transport bytes for TCP/UDP ports.
Thrown decode failures increment existing error counters without changing stats v1;
best-effort full results may carry diagnostics without `:decode-error`.

Raw IP has no link header: IP starts at offset 0 and the first byte's version
nibble selects IPv4 or IPv6. Full results use `{:type :raw-ip :l3 ...}` without
MAC, Ethertype or cooked fields. Flow uses the existing numeric IP projection,
without full decode or extra frame copies. Native DLT_RAW is 12 on the measured
Linux/macOS matrix; savefile LINKTYPE_RAW 101 is converted by libpcap when opening
files, and is rejected as explicit packet DLT. Other platforms remain unsupported.
Empty Raw IP reports `:short-frame` at offset 0 with one required byte; an invalid
version reports `:malformed-packet`, `:field :ip-version` and `:value`, never
falls back to Ethernet. Short IP headers report `:truncated-header` at offset 0.
Unknown IP protocols and incomplete transport headers retain the existing
[partial-parser behavior](cljdoc-api-contract.md#full-decode-packets).
Classic PCAP output uses `{:linktype 12}`; libpcap writes savefile code 101.

<!-- paclo-doc-test: usage-raw-ip-flow -->

```clojure
(require '[paclo.core :as core] '[paclo.flow :as flow])

(let [packets (core/reduce-packets {:path "test/resources/raw-ip/raw.pcap"
                                  :max 8 :decode-mode :flow} conj [])
      rf (flow/aggregate-rf {:max-flows 100})]
  {:versions (set (map :ip-version packets))
   :linktypes (set (map :linktype packets))
   :top (flow/top-n (reduce rf (rf) packets) {:n 10})})
```

NULL/LOOP use native DLT 0/108 on the measured Linux/macOS platforms, with
IP at offset 4. Full wrappers use `:type :null` / `:loop`, numeric
`:address-family` and `:l3`. NULL recognizes a unique AF in either byte order;
LOOP is strictly big endian. AF 2 selects IPv4, 24/28/30 select IPv6, then the
IP version is checked. Linux AF_INET6 10 is not accepted. The origin OS is not
inferred, and arrays retain their bytes and reference in full decode.

Short pseudoheaders use `:short-frame` (offset 0, required 4); unknown AFs use
`:unsupported-address-family`; valid IP versions inconsistent with AF use
`:address-family-mismatch`; other invalid versions use `:malformed-packet`.
Known AF with no IP byte uses `:truncated-header` at offset 4, required 1;
short base IP headers require 20/40 at offset 4. Later IP/L4/extension diagnostics
retain absolute offsets and existing partial-parser semantics. See the
[complete NULL/LOOP contract](cljdoc-api-contract.md#nullloop-framing).

Both Classic PCAP and supported single-linktype PCAPNG have been measured under
both container orders, including NULL headers in the opposite order. Installed
libpcap on Linux x64/ARM64 and macOS ARM64 leaves pseudoheader bytes unchanged.
Standalone and live packets use the same framing contract; live/NIC behavior
is not newly validated. Other operating systems, including OpenBSD's different
DLT_LOOP assignment, remain unsupported. Packet maps do not preserve source
container order, so the decoder cannot validate its consistency with NULL or
reproduce original file encoding. Classic writing with `{:linktype 0}` or
`{:linktype 108}` preserves supplied bytes, without endian normalization.

<!-- paclo-doc-test: usage-null-loop-flow -->

```clojure
(require '[paclo.core :as core] '[paclo.flow :as flow])

(mapv (fn [path]
        (let [packets (core/reduce-packets {:path path :max 14 :decode-mode :flow} conj [])
              rf (flow/aggregate-rf {:max-flows 100})]
          {:versions (set (map :ip-version packets))
           :linktypes (set (map :linktype packets))
           :summary (:summary (reduce rf (rf) packets))}))
      ["test/resources/null-loop/null-header-le-file-be.pcap"
       "test/resources/null-loop/loop-header-be-file-le.pcapng"])
```

This repository example reads the bundled Linux cooked fixture and inspects its
link type and flow diagnostics. Its first packet now decodes; the short and
Ethernet-looking records still fail:

<!-- paclo-doc-test: usage-linktype-raw -->

```clojure
(let [raw (core/reduce-packets {:path "test/resources/linktype-sll.pcap"}
                               conj [])
      flow (into [] (core/packet-xf {:decode-mode :flow}) raw)]
  {:linktypes (mapv :linktype raw)
   :captured-lengths (mapv #(alength ^bytes (:bytes %)) raw)
   :diagnostics (mapv :diagnostics flow)
   :flow-has-bytes? (some #(contains? % :bytes) flow)})
```

For external packet maps, omission of `:linktype` retains the legacy Ethernet
assumption. Explicit nil/unknown/invalid values are rejected by full/flow; raw
`packet-xf {}` remains identity. Do not mutate shared packet arrays in fan-out.
Use `core/write-pcap!` with the matching native DLT to write a single-DLT
Classic PCAP, as in the [explicit writer example](#write-pcap).
The writer preserves bytes without converting framing. The separate
[PCAPNG reader](pcapng.md) retains metadata and exact input time; PCAPNG output,
additional decoders and complete source-file round trips remain future work.

Cooked headers expose numeric `:packet-type`, `:hardware-type`, `:address-length`,
`:protocol` and a colon-separated hex `:address` string containing exactly that
many bytes (0..8; empty string for 0). SLL2 additionally has unsigned
`:interface-index` and numeric `:reserved`. The address is not an Ethernet
source/destination MAC pair; interface index is not a PCAPNG interface ID.

This SLL2 sample projects IPv4 and IPv6 traffic into the existing bounded flow
aggregate. The first eight fixture records are valid DNS, TLS and ICMP packets:

<!-- paclo-doc-test: usage-cooked-flow -->

```clojure
(require '[paclo.core :as core] '[paclo.flow :as flow])

(let [rf (flow/aggregate-rf {:max-flows 8})
      packets (core/reduce-packets {:path "test/resources/cooked/sll2.pcap"
                                    :max 8 :decode-mode :flow} conj [])
      aggregate (reduce rf (rf) packets)]
  {:versions (set (map :ip-version packets))
   :linktypes (set (map :linktype packets))
   :top (flow/top-n aggregate {:n 8})})
```

## Reusable flow analysis

Require `[paclo.flow :as flow]`. Analysis consumes the flat numeric maps produced
by `{:decode-mode :flow}`. Canonical identity is an EDN map:

```clojure
{:ip-version 4 :protocol 17
 :src-ip 167772161 :src-port 12000
 :dst-ip 167772162 :dst-port 53}
```

IPv4 addresses are unsigned integers in `0..4294967295`. IPv6 addresses are
`[high-long low-long]` vectors of signed JVM words. Protocol stays numeric,
including unknown protocols. Both port keys must be present; nil means unknown
(TCP/UDP fragments) or inapplicable (ICMP/other protocols). Ports otherwise range
from 0 to 65535. Metadata, bytes and lengths are excluded from identity.

`(flow/key packet)` defaults to `:unidir`, distinguishing A→B from B→A.
`(flow/key packet {:direction :bidir})` chooses the smaller endpoint as source.
Addresses compare as unsigned numbers, including each IPv6 word; nil ports sort
before zero. IP versions remain distinct. Invalid/incomplete fields, a present
`:decode-error`, or flow-stage diagnostics return nil. Full-decode maps are not
accepted. The legacy full-decode `:flow-key` remains a display descriptor with
string IPs and protocol keywords; it performs no bidirectional normalization.
Migrate analytical code that grouped that descriptor to flow projection plus
`flow/key` or `flow/aggregate-rf`. Full decode output remains compatible.

<!-- paclo-doc-test: usage-flow-analysis -->

```clojure
(require '[paclo.flow :as flow])

(let [rf (flow/aggregate-rf {:direction :bidir :max-flows 10000})
      packets (vec (core/packets {:path "test/resources/dns-sample.pcap"
                                 :decode-mode :flow}))
      result (reduce rf (rf) packets)]
  {:same? (= result (transduce identity rf packets))
   :summary (:summary result)
   :top (flow/top-n result {:metric :wire-bytes :n 2})})
```

The standard reducing function supports initialization `(rf)`, update
`(rf state packet)` and identity completion `(rf state)`. It retains no state
between reductions. Use the same function with `core/reduce-packets`,
`core/reduce-packets-report`, managed `core/capture-packets`, or independent
fan-out branches. Own captures and branch handles with `with-open`; each branch
has its own initial state. Analysis performs no I/O and does not mutate packets.

Results are ordinary immutable data:

```clojure
{:flows {flow-key {:packets 3 :captured-bytes 120 :wire-bytes 150}}
 :summary {:seen 4 :aggregated 3 :skipped 1}}
```

`:seen` counts all inputs; invalid keys increment `:skipped`. Eligible packets
increment `:aggregated` and their flow's counters. Captured bytes sum `:caplen`;
wire bytes sum `:len`. Eligible packets require both integer lengths in
`0..4294967295`, with `:caplen <= :len`; missing/invalid lengths throw `ex-info`.
They are never silently treated as zero. Invalid flows skip length validation.
All counters promote to arbitrary precision integers on overflow. Configuration
remains in the reducer closure and is absent from result data.

`:max-flows` is required and must be a positive integer. New keys beyond that
bound throw `ex-info` with `:reason :max-flows`; existing flows still update at
the bound. No flows are evicted. This is exact finite aggregation; duration and
expiration are the caller's responsibility. For separate bounded time-window
counts and captured bytes, see [time windows](#pure-bounded-time-windows).

`flow/top-n` returns a vector of maps with `:flow` and the three counters.
`:metric` is `:packets` (default), `:captured-bytes`, or `:wire-bytes`; `:n` is a
nonnegative integer (default 10). Rank descending by metric, then ascending by
IP version, protocol, source endpoint and destination endpoint. This total order
also covers mixed IPv4/IPv6 and nil ports; input order cannot change ties.
Exact sorting takes O(F log F) time and O(F) additional memory for F flows.

The example CLI delegates identity, aggregation and ranking to these functions.
It retains legacy display rows (`:flow {:proto ... :src ... :dst ...}`,
`:packets`, `:bytes`), with bytes meaning captured bytes. Its finite default
budget is 100000 unique flows, configurable with `--max-flows N`; formerly
unbounded large captures may now fail and need an explicit larger budget. Ties
are now deterministic numeric order. Async cancellation terminates the producer
early (zero timeout cancels immediately, without scheduling a timer); dropping
statistics count discarded inputs and reader/aggregate failures
propagate after channel cleanup. EDN/JSONL and blocking/dropping modes remain.

## Pure bounded time windows

The P07-A APIs are available in `v1.4.0`. Supply event time and watermark
explicitly; they never read a clock or retain all output. Each consumer starts
with its own state. Here all packet times come from the real offline fixture;
the final watermark is an explicit caller decision. This example intentionally
collects output in the caller, which can instead write/process each returned batch.

<!-- paclo-doc-test: usage-time-windows -->

```clojure
(require '[paclo.window :as window] '[paclo.dns :as dns])
(let [packets (vec (core/packets {:path "test/resources/dns-sample.pcap"}))
      initial (window/init {:width-us 1000000 :max-windows 10 :max-groups 10})
      add (fn [state packet]
            (:state (window/step state {:time-us (dns/packet-time-us packet)
                                        :group :dns :captured-bytes (:caplen packet)})))
      state (reduce add initial packets)
      same (transduce identity (completing add) initial packets)
      watermark (+' (reduce max (map dns/packet-time-us packets)) 1000000)
      closed (window/advance state watermark)]
  {:same? (= state same) :events (:events closed)
   :retained (count (get-in closed [:state :windows]))})
```

Windows are epoch-aligned half-open intervals; negative timestamps use floor
division. Set `:allowed-lateness-us` to keep a window until watermark reaches
end plus lateness. Arrival before that cutoff remains eligible regardless of
order; later input produces `:late-event`, never recreating a window. Required
limits bound windows and total window/group pairs. Exceeding them throws.
Finish emits retained partial windows with `:complete? false`. No empty gaps
are generated. See the [full contract](cljdoc-api-contract.md#paclowindow).

## Pure DNS correlation

Use the existing full decoder and an explicitly selected DNS annotation. The
normalizer drops byte arrays and packet references. Analysis does not register
extensions globally. Question fields are required for a pair; missing qname,
qtype or qclass is classified as `:ambiguous-question`.

<!-- paclo-doc-test: usage-dns-correlation -->

```clojure
(require '[paclo.dns :as dns])
(let [opts {:path "test/resources/dns-sample.pcap"
            :decode? true :extensions [dns-ext/annotate-dns]}
      initial (dns/init {:timeout-us 5000000 :max-pending 100 :max-retired 100})
      collect (fn [{:keys [state events]} event]
                (let [next (dns/step state event)]
                  {:state (:state next) :events (into events (:events next))}))
      result (transduce (keep dns/packet->event) (completing collect)
                        {:state initial :events []} (core/packets opts))
      final (dns/finish (:state result))]
  {:transactions (into (:events result) (:events final))
   :pending (count (get-in final [:state :pending]))})
```

Correlation keys include version, UDP, ID, client/server endpoints and the full
available question (name/type/class). Identical pending queries are retries with
RTT measured from the earliest query. Different questions can reuse an ID;
completed/expired identical keys enter bounded quarantine until a caller watermark
releases them. Queries during quarantine emit `:id-reuse`; duplicate/old responses
emit `:duplicate-or-expired-response`. Choose `:reuse-delay-us` (defaults to timeout)
for your capture's delayed-message horizon. Identical overlapping requests cannot
be distinguished from retries. Unmatched response-before-query is classified
immediately and not buffered. Negative RTT is diagnostic, never a normal pair.

Advance DNS watermark explicitly to expire queries at time plus timeout and
release retired keys. A late event before the watermark is classified. Limits
bound pending and retired cardinality; no silent eviction. Finish emits unfinished
queries and clears retention. Only standard unfragmented UDP/53 with at most one
question is supported. The [full contract](cljdoc-api-contract.md#paclodns) defines
all event/error shapes and assumptions. The DNS CLIs below use these APIs and
own output, quantiles, Top-N and execution adapters.

## Bounded DNS CLI reports (P07-B)

The repository examples now use P07-A's pure analysis APIs. `dns-rtt` decodes
with explicitly selected `annotate-dns`, projects `dns/packet->event`, and uses
`dns/advance`, `step` and `finish`. `dns-qps` extracts groups from full-decode DNS
app data and uses `window/advance`, `step` and `finish`. It counts packets,
including queries and responses; it does not count DNS transactions. A packet
with insufficient question information for RTT can still contribute to QPS.
QPS rows contain counts per bucket; divide by bucket seconds to obtain a rate.
Bytes always mean captured `caplen`, not wire length. QPS client/server
groups use decoded QR to orient IP roles: response destination is the client,
response source is the server; queries use the inverse. Question information
is not required for these packet groups.

Both CLIs retain their positional arguments, `_` placeholders, formats, filters,
rankings, alert and Punycode options. RTT EDN emits a vector for pairs/qstats
and a map for stats; JSONL emits one map per line. QPS also supports CSV with
`t_ms,key,count,bytes`. Analysis and execution metadata go to stderr.

### Event time and strict matching

Native `:ts-sec`/`:ts-usec` are converted to exact integer microseconds. RTT
samples stay in microseconds until display in milliseconds. There is no legacy,
floating timestamp or wall-clock fallback. Before admitting each delivered
packet, the adapter advances the watermark to maximum observed packet time
minus `--reorder-us` (default 0). This expires state across idle gaps and never
moves backward. For windows, allowed lateness is zero: the reorder allowance
is applied once. DNS input older than watermark is late; QPS input remains
eligible until its window end is at/before watermark. EOF calls `finish`.
QPS emits retained tail windows and reports `:open-tail-windows`; these were
not closed by the watermark. Wall time controls async cancellation only.

DNS pairs require the full endpoint/version/ID/question key. Missing questions,
unsupported/incomplete packets, unmatched responses, negative RTT and late
input never become guessed pairs. Identical pending queries are retries using
the earliest query time. Completed/expired identical keys remain quarantined
until their first-query deadline plus reuse delay; immediate reuse/duplicate
responses are diagnostics. Response-before-query is not buffered. Configure
`--timeout-us` and `--reuse-delay-us` (both default 5000000) for the traffic's
horizon. Counts for timeout, unfinished, ambiguity, reuse, duplicate responses,
late/ineligible input and completed-query retransmissions appear in stderr
`:diagnostics`. This cannot disambiguate identical overlapping requests or
arbitrarily delayed duplicates beyond the configured horizon.

### Memory and failure policy

| State | Option | Default | Policy |
| --- | --- | --- | --- |
| Pending DNS queries | `--max-pending` | 100000 | Fail on new key beyond limit |
| Retired DNS keys | `--max-retired` | 100000 | Fail; never silently evict quarantine |
| pairs candidates | positional topN | 50 | Retain only smallest topN RTTs |
| stats/qstats integer RTT samples, total | `--max-samples` | 1000000 | Exact nearest-rank percentiles; fail beyond limit |
| qstats question groups | `--max-qnames` | 100000 | Fail beyond limit |
| Active QPS windows | `--max-windows` | 10000 | Fail beyond limit |
| Active window/group combinations, total | `--max-groups` | 200000 | Independent from output bound |
| Finalized QPS rows, and final filled rows | `--max-buckets` | 200000 | Fail instead of truncating |

Exact percentiles need a sample per matched pair. qstats stores samples only
in its groups, with the same total sample bound; pairs retains no sample
history. Set topN no greater than max-samples. Counters do not retain completed
events or raw packets. Limits count entries, not caller-supplied string bytes;
sorting, filling and serialization need additional bounded working space.
All bounds and bucket width must be positive. Reorder and async timeout are
nonnegative. Empty-bucket fill keeps every group in occupied windows and adds
`:_all` only in wholly empty windows. Empty-per-key takes
precedence and fills the full bucket/key product. Promoting arithmetic checks
the complete row count before generating either fill, including huge gaps.

No stdout report is emitted until analysis, finish, ranking and fill succeed.
Capacity/read/reducer errors exit 5 without a result. Usage exits 1, missing
input 2, invalid enum 3, invalid flags/numeric options 4. Cancellation and drops
may emit a partial report with exit 0; stderr `:complete? false` makes this
explicit. `:complete? true` means all delivered source packets were processed,
not that all network transactions have responses. Late/unsupported packets
are separately counted.

### Delivery and migration

Sync uses `core/reduce-packets`; async uses one owning reduction producer and
an explicitly bounded fixed channel. Both call the same pure packet step and
finish functions. Buffer mode applies backpressure; dropping mode uses `offer!`
and counts packets that could not enter the channel. Dropped packets are not
analyzed. Timeout 0 delivers nothing and does not open the source. Cancellation
stops reads, releases blocked puts, closes the capture and joins the producer;
source and reducer exceptions propagate. Independent runs do not share extension
registration or analysis state. Matching and aggregation are reproducible for
the same delivered packet order, reorder allowance and limits.

Intentional changes: RTT no longer reports nil from the old sec/usec bug; average
no longer truncates fractional milliseconds. Strict question matching, retries,
expiry and quarantine may reduce pair counts compared with the old ID-only
matcher. Async execution metadata is never counted as a pair. QPS removes
floating/partial timestamp fallbacks, floors negative times correctly, orders
count ties by printed key, groups query/response IPs by their client/server roles,
preserves simultaneous groups during empty fill,
and fails on output overflow instead of silently truncating. Punycode decoding
also handles xn-- labels following a plain leading label. The existing QPS
fixture snapshot is unchanged. The before/after contract tables are in the
[CLI migration design](../dev/p07-b-design.md).

<!-- paclo-doc-test: usage-bounded-dns-cli -->

```clojure
(require '[clojure.edn :as edn]
         '[examples.dns-rtt :as rtt] '[examples.dns-qps :as qps])
(let [stats (edn/read-string
             (with-out-str
               (rtt/-main "test/resources/dns-sample.pcap" "_" "_" "stats")))
      rows (edn/read-string
            (with-out-str
              (qps/-main "test/resources/dns-sample.pcap" "_" "1000" "rcode" "edn"
                         "--async" "--async-buffer" "1")))]
  {:pairs (:pairs stats) :average-ms (get-in stats [:rtt :avg])
   :dns-packets (reduce + (map :count rows))})
```

Offline input now runs to EOF rather than inheriting the capture API's default
100-packet/10-second limits (old QPS inherited both; old RTT inherited 10 seconds).
The adapter supplies an effectively unbounded, overflow-safe duration; only
explicit async timeout/cancellation or a report limit ends delivery early.
