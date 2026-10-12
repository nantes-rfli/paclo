# Paclo Usage Guide

This guide covers the minimal concepts and common workflows for Paclo.
For installation and CLI entry examples, start from `README.md`.

## Mental model

- `paclo.core` is the user-facing API.
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
- `write-pcap!` writes byte records back to a PCAP file.
- Optional decode hooks (`paclo.decode-ext`) annotate decoded packets.

## Quick start (offline)

```clojure
(require '[paclo.core :as core])

(->> (core/packets {:path "test/resources/dns-sample.pcap"
                    :decode? true})
     (map #(select-keys % [:caplen :decoded :decode-error]))
     (take 2)
     doall)
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
| Explore a finite capture lazily | `core/packets` | A lazy sequence; source limits and EOF end the producer |
| Accumulate or stop as soon as a reducer decides | `core/reduce-packets` or `core/reduce-packets-report` | Synchronous; `reduced` stops and closes the source |
| Cancel externally or inspect running statistics | `core/start-capture` + `core/capture-packets` | One consumer; close the capture with `with-open` |
| Feed independent consumers | `stream/fan-out` + `stream/branch` | Own capture, fan-out, and every acquired branch; configure bounded buffers |

`(take n (core/packets ...))` only stops consuming the lazy sequence. It
does **not** explicitly stop the underlying producer, which may continue
until a configured limit, time limit, or EOF. For predictable early cleanup,
prefer synchronous `reduced` or an explicitly closed managed capture.
Do not let a managed packet sequence escape its `with-open` scope.

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
existing registered post-decode hooks, or `{:decode-mode :flow}` for a flat
numeric flow projection. These options cannot be combined.
`(core/packet-xf {})` passes packets through unchanged. The optional
`:xform` on capture APIs runs **after** their built-in packet transformation.
Do not apply the same decode twice by combining a decode option with another
decode-configured `packet-xf` in `:xform`.

## Synchronous reduction

```clojure
(core/reduce-packets
 {:path "large.pcap"
  :decode? true
  :max Long/MAX_VALUE
  :max-time-ms 3600000
  :xform (keep #(get-in % [:decoded :l3 :flow-key]))}
 (fn [counts flow]
   (update counts flow (fnil inc 0)))
 {})
```

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
remain in the queue.

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

P02 in `[Unreleased]` accepts read packet maps directly. A complete
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

The writer still outputs Ethernet PCAP with snaplen 65536 and microsecond precision.
It preserves packet metadata, not the source file's global header, byte order,
link type, snaplen, or timestamp precision. PCAPNG and additional link types remain
future work. Older libpcap readers may expose post-2038 seconds as negative; see
the [writer contract](cljdoc-api-contract.md#write-pcap) for this native limitation.

## BPF DSL (examples)

```clojure
(core/bpf [:and [:ipv6] [:udp] [:dst-port-range 8000 9000]])
;; => "(ip6) and (udp) and (dst portrange 8000-9000)"

(core/bpf [:and [:net "10.0.0.0/8"] [:not [:port 22]]])
;; => "(net 10.0.0.0/8) and (not (port 22))"
```

## Decode hooks

```clojure
(require '[paclo.core :as core]
         '[paclo.proto.dns-ext :as dns-ext])

(dns-ext/register!)

(->> (core/packets {:path "test/resources/dns-sample.pcap"
                    :decode? true})
     (take 1)
     doall)
```

See `docs/extensions.md` for hook contract and TLS/DNS extension notes.

## CLI workflows

Paclo ships practical CLI examples under `dev/examples`.
Use `README.md` as the command index, and use this guide for API behavior.

## Error model

- `:decode? true` does not throw on parse failure.
- Decode failures are represented as `:decode-error` in each packet map.
- Invalid API inputs (for example unsupported `:filter` type) throw `ex-info`.
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
