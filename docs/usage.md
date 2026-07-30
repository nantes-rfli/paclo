# Paclo Usage Guide

This guide covers the minimal concepts and common workflows for Paclo.
For installation and CLI entry examples, start from `README.md`.

## Mental model

- `paclo.core` is the user-facing API.
- `packets` returns lazy packet maps from a file (`:path`) or device (`:device`).
- `reduce-packets` synchronously folds large or live captures without an
  intermediate sequence.
- `reduce-packets-report` adds data-only execution statistics to the
  synchronous result.
- `start-capture` owns an explicitly stoppable, single-consumer capture
  lifecycle.
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

```clojure
(require '[paclo.core :as core])

(->> (core/packets {:device "en0"
                    :filter (core/bpf [:and [:udp] [:port 53]])
                    :timeout-ms 50})
     (take 10)
     doall)
```

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

The reducer may return `(reduced value)` to stop capture immediately. This
path avoids the producer future, blocking queue, and lazy-seq nodes used by
`packets`; use `packets` when interactive lazy consumption is more useful.

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
external cancellation, or in-progress queue statistics:

```clojure
(with-open [capture
            (core/start-capture
             {:device "en0"
              :filter [:and :udp [:port 53]]
              :queue-cap 4096
              :queue-mode :dropping
              :max Long/MAX_VALUE
              :max-time-ms 3600000})]
  (run! process-packet
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
              :max-time-ms 3600000})]
  (future
    (wait-for-shutdown-signal)
    (core/stop-capture! capture))
  (run! process-packet
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

One managed capture has one packet consumer. Fan-out, pub/sub, and separate
per-consumer queues are intentionally not provided.

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
- Use `:xform` transducers in `packets` for early map/filter and lower allocation.
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
