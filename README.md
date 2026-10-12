<!-- markdownlint-disable MD013 -->
# Paclo

[![cljdoc](https://cljdoc.org/badge/org.clojars.nanto/paclo)](https://cljdoc.org/d/org.clojars.nanto/paclo/CURRENT)
[![Clojars Project](https://img.shields.io/clojars/v/org.clojars.nanto/paclo.svg)](https://clojars.org/org.clojars.nanto/paclo)

Paclo is a Clojure library for packet capture (PCAP) I/O, BPF filtering, and data-first packet processing.
It provides a small public API plus optional decode hooks for DNS/TLS workflows.

> If cljdoc or Clojars returns `404` right after publishing, indexing can take several minutes.

## Project status

- Stable release: `v1.3.0` (published on August 1, 2026)
- Clojars: `org.clojars.nanto/paclo`
- cljdoc: <https://cljdoc.org/d/org.clojars.nanto/paclo/CURRENT>
- Roadmap status: v1.3.0 released (see `docs/ROADMAP.md`)

Repository `[Unreleased]` captures expose native DLT `:linktype`. Raw reads
support non-Ethernet PCAPs; full/flow decode supports Ethernet and returns
`:unsupported-linktype` diagnostics for other explicit types. Standalone
`packet-xf` without the key retains its Ethernet assumption. The writer still
outputs Ethernet PCAP and does not convert non-Ethernet bytes or preserve source
link types. See the [raw capture example](docs/usage.md#reading-non-ethernet-captures)
and [contract](docs/cljdoc-api-contract.md#link-type-dispatch); broader decoders
and complete PCAPNG/file preservation remain P08.

## Install

### deps.edn (recommended: Clojars)

```edn
{:deps
 {org.clojars.nanto/paclo {:mvn/version "1.3.0"}}}
```

### deps.edn (Git tag)

```edn
{:deps
 {org.clojars.nanto/paclo
  {:git/url "https://github.com/nantes-rfli/paclo.git"
   :git/tag "v1.3.0"}}}
```

If your environment requires Java class prep for git dependencies, run once in your consumer project:

```bash
clojure -X:deps prep
```

## Quick start

<!-- paclo-doc-test: offline-quick-start -->

```clojure
(require '[paclo.core :as core])

;; Read the first two decoded packets from the bundled offline fixture.
(->> (core/packets {:path "test/resources/dns-sample.pcap"
                    :decode? true})
     (take 2)
     (map #(select-keys % [:ts-sec :ts-usec :decoded :decode-error]))
     doall)
```

For live capture, use `start-capture` with `with-open` when taking a
prefix or stopping early. `take` on the lazy `packets` sequence alone does
not stop its producer. The [usage guide](docs/usage.md) explains resource
ownership and the default count/time limits.

For bounded flow analysis, select numeric flow projection and reuse the public
`paclo.flow` reducer. IPv4 addresses are unsigned integers; IPv6 addresses are
two-long vectors. Exact byte totals distinguish captured length from wire length.

<!-- paclo-doc-test: readme-flow-analysis -->

```clojure
(require '[paclo.flow :as flow])

(let [rf (flow/aggregate-rf {:direction :bidir :max-flows 10000})
      result (core/reduce-packets
              {:path "test/resources/dns-sample.pcap" :decode-mode :flow}
              rf (rf))]
  (flow/top-n result {:metric :captured-bytes :n 10}))
```

`flow/key` defines canonical numeric identity; full decode's legacy
`[:decoded :l3 :flow-key]` remains a string-address display descriptor.
Use flow projection for analysis and full decode for protocol inspection.
See the [flow analysis contract](docs/cljdoc-api-contract.md#pacloflow) and
[composition examples](docs/usage.md#reusable-flow-analysis) for ordering,
invalid inputs and cardinality limits.

For transformations outside capture APIs, compose the same numeric projection
with standard transducers:

<!-- paclo-doc-test: readme-packet-xf -->

```clojure
(into []
      (comp (core/packet-xf {:decode-mode :flow})
            (filter #(= 17 (:protocol %))) ; UDP
            (map #(select-keys %
                               [:src-ip :dst-ip :src-port :dst-port])))
      (core/packets {:path "test/resources/dns-sample.pcap"}))
```

Use either `:decode? true` for full decoding with decode extensions, or
`:decode-mode :flow` for a flat flow projection (not both).
Capture APIs apply `:xform` after the built-in packet transformation.

In `[Unreleased]` (P03), full decode accepts an ordered `:extensions` vector
of functions. Omission keeps dynamic global hooks; `[]` disables them, and
explicit selection runs only its functions. Public DNS/TLS annotations and
independent fan-out examples are in [decode extensions](docs/extensions.md).

For synchronous processing with data-only execution statistics:

```clojure
(core/reduce-packets-report
 {:path "large.pcap"
  :decode-mode :flow
  :max Long/MAX_VALUE
  :max-time-ms 3600000}
 (fn [counts flow]
   (update counts
           (select-keys flow
                        [:src-ip :dst-ip :protocol :src-port :dst-port])
           (fnil inc 0)))
 {})
;; => {:result {...}
;;     :stats {:schema-version 1
;;             :state :closed
;;             :stop-reason :eof
;;             ...}}
```

For long-running or externally stopped capture, own a managed capture with
`with-open`. Packet delivery is single-consumer. A quiet device otherwise
stops after the default 3-second idle limit, so this example sets
`:idle-max-ms` explicitly to one hour, matching `:max-time-ms`:

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

To feed two independent consumers, compose a managed capture with bounded
fan-out. This example runs offline with the bundled fixture. Each branch is
single-consumer and must be owned with `with-open`:

<!-- paclo-doc-test: readme-bounded-fan-out -->

```clojure
(require '[paclo.stream :as stream])

(with-open [capture
            (core/start-capture
             {:path "test/resources/dns-sample.pcap"})
            fanout
            (stream/fan-out
             (core/capture-packets capture)
             {:archive {:buffer-mode :blocking :buffer-cap 16}
              :metrics {:buffer-mode :dropping :buffer-cap 16}}
             {:cancel! #(core/stop-capture! capture)})
            archive (stream/branch fanout :archive)
            metrics (stream/branch fanout :metrics)]
  (let [archive-task (future (reduce (fn [n _] (inc n)) 0 archive))
        metrics-task (future (reduce (fn [n _] (inc n)) 0 metrics))]
    {:archive-count @archive-task
     :metrics-count @metrics-task
     :capture (core/capture-stats capture)
     :stream (stream/stats fanout)}))
```

Blocking buffers can backpressure other branches; dropping buffers isolate
slow consumers by discarding new values when full. Both remain bounded.
For full behavior, shutdown rules, and stop defaults, see
[the usage guide](docs/usage.md).

## Run examples

Development examples are under `dev/examples` and loaded with `:dev`.

| Example | What it shows | Output | Typical command |
| --- | --- | --- | --- |
| `bench` | PCAP read performance smoke | `edn` | `clojure -M:dev -m examples.bench` |
| `dns-summary` | DNS summary rows | `edn/jsonl` | `clojure -M:dev:dns-ext -m examples.dns-summary trace.pcap` |
| `pcap-filter` | Filter + write + metadata | `edn/jsonl` | `clojure -M:dev -m examples.pcap-filter in.pcap out.pcap 'udp and port 53' 60 jsonl --async` |
| `pcap-stats` | Packet and endpoint stats | `edn/jsonl` | `clojure -M:dev -m examples.pcap-stats in.pcap 'udp and port 53' 10 jsonl` |
| `flow-topn` | Top flows (unidir/bidir) | `edn/jsonl` | `clojure -M:dev -m examples.flow-topn in.pcap 'udp and port 53' 10 --async` |
| `dns-rtt` | DNS RTT pairs/stats/qstats | `edn/jsonl` | `clojure -M:dev:dns-ext -m examples.dns-rtt in.pcap 'udp and port 53' 50 stats --async` |
| `dns-topn` | DNS top-N by group | `edn/jsonl/csv` | `clojure -M:dev:dns-ext -m examples.dns-topn in.pcap _ 20 rcode edn` |
| `dns-qps` | DNS bucketed QPS/bytes | `edn/jsonl/csv` | `clojure -M:dev:dns-ext -m examples.dns-qps in.pcap _ 1000 rcode edn` |
| `tls-sni-scan` | TLS ClientHello SNI top-N | `edn/jsonl` | `clojure -M:dev -m examples.tls-sni-scan in.pcap 'tcp and port 443' 10 jsonl` |

Notes:

- For repository-local runs, DNS examples require `-M:dev:dns-ext`.
- When used as a library dependency, DNS extension namespaces are included in the published artifact.
- Optional positional arguments can be skipped with `_`.
- `format` defaults to `edn` if omitted.
- Bundled sample PCAPs: `test/resources/dns-sample.pcap`, `test/resources/dns-synth-small.pcap`, `test/resources/tls-sni-sample.pcap`.

### dns-ext alias quick check

<!-- paclo-doc-test: readme-dns-quick-check -->

```bash
clojure -M:dev:dns-ext -e "(require '[paclo.proto.dns-ext :as dns-ext]) (dns-ext/register!) (println :dns-ext-ok)"
```

## CLI reference

### dns-topn

```bash
clojure -M:dev:dns-ext -m examples.dns-topn test/resources/dns-sample.pcap
clojure -M:dev:dns-ext -m examples.dns-topn in.pcap _ 20 qname-suffix csv --punycode-to-unicode
clojure -M:dev:dns-ext -m examples.dns-topn in.pcap _ 20 alpn edn _ --alpn-join
```

### dns-qps

```bash
clojure -M:dev:dns-ext -m examples.dns-qps test/resources/dns-sample.pcap
clojure -M:dev:dns-ext -m examples.dns-qps in.pcap _ 200 qname edn --max-buckets 100000 --warn-buckets-threshold 50000 --emit-empty-per-key
clojure -M:dev:dns-ext -m examples.dns-qps in.pcap _ 500 rrtype jsonl --async --async-mode dropping --async-buffer 256
```

Both DNS CLIs use bounded analysis: RTT delegates strict transaction matching to
`paclo.dns`; QPS counts DNS packets through `paclo.window`. `--reorder-us` controls
the event-time watermark. Exact statistics and finalized output have finite
limits and fail before output on overflow. See [DNS CLI reporting](docs/usage.md#bounded-dns-cli-reports-p07-b)
for defaults, cancellation/drop metadata and intentional migration changes.

### dns-rtt

```bash
clojure -M:dev:dns-ext -m examples.dns-rtt in.pcap
clojure -M:dev:dns-ext -m examples.dns-rtt in.pcap 'udp and port 53' 50 pairs _ edn _ --server 1.1.1.1:53
clojure -M:dev:dns-ext -m examples.dns-rtt in.pcap 'udp and port 53' 20 qstats p95 jsonl --client 192.168.4.28
```

### pcap-stats

```bash
clojure -M:dev -m examples.pcap-stats in.pcap
clojure -M:dev -m examples.pcap-stats in.pcap 'udp and port 53' 10 jsonl
```

### flow-topn

The CLI keeps `packets` and `bytes` metrics (`bytes` means captured bytes), EDN
and JSONL rows, and async buffer/timeout options. Exact aggregation now defaults
to at most 100000 unique flows; `--max-flows N` sets a positive finite budget.
Existing flows can update at the limit; a new flow beyond it throws. Large
captures that previously accumulated without a bound must select a larger budget.
Tied rows now follow canonical numeric key order.

```bash
clojure -M:dev -m examples.flow-topn in.pcap 'udp and port 53' 10 bidir bytes jsonl --max-flows 100000
clojure -M:dev -m examples.flow-topn in.pcap 'udp or tcp' 10 bidir bytes edn --async --async-mode dropping --async-timeout-ms 1000
```

### pcap-filter

```bash
clojure -M:dev -m examples.pcap-filter in.pcap out.pcap
clojure -M:dev -m examples.pcap-filter in.pcap out-dns.pcap 'udp and port 53' 0 jsonl
clojure -M:dev -m examples.pcap-filter /tmp/large.pcap /tmp/out.pcap --async --async-mode dropping --async-buffer 16
```

### tls-sni-scan

```bash
clojure -M:dev -m examples.tls-sni-scan in.pcap
clojure -M:dev -m examples.tls-sni-scan in.pcap 'tcp and port 443' 10 jsonl
```

For full argument tables and behavior details, see `docs/usage.md`.

## Bounded event-time analysis (Unreleased)

`paclo.window` and `paclo.dns` provide pure immutable `init`, `step`, `advance`
and `finish` APIs. Supply integer microsecond event times and monotonic watermarks;
configure explicit retention bounds. DNS normalization reuses full decode and
optional DNS annotations, with question-aware correlation, retry counts, timeout
and bounded ID-reuse quarantine. Missing questions and unmatched responses produce
explicit classifications. Capture, clocks and output remain caller-owned.

<!-- paclo-doc-test: readme-time-window -->

```clojure
(require '[paclo.window :as window])
(let [state (window/init {:width-us 1000000 :max-windows 10 :max-groups 100})
      next (window/step state {:time-us 999999 :group :dns :captured-bytes 128})]
  (:events (window/advance (:state next) 1000000)))
```

See [executable PCAP examples](docs/usage.md#pure-bounded-time-windows) and the
[API contract](docs/cljdoc-api-contract.md#paclowindow). Existing DNS CLIs remain
unchanged; their migration and bounded reporting are P07-B.

## Public API surface (v1.x)

| Namespace | Public functions | Notes |
| --- | --- | --- |
| `paclo.core` | `bpf`, `packets`, `packet-xf`, `reduce-packets`, `reduce-packets-report`, `start-capture`, `capture-packets`, `stop-capture!`, `capture-stats`, `write-pcap!`, `list-devices` | User-facing API |
| `paclo.flow` | `key`, `aggregate-rf`, `top-n` | Bounded flow analysis (Unreleased P06) |
| `paclo.window` | `init`, `step`, `advance`, `finish` | Bounded tumbling windows (Unreleased P07-A) |
| `paclo.dns` | `packet-time-us`, `packet->event`, `init`, `step`, `advance`, `finish` | Pure DNS analysis (Unreleased P07-A) |
| `paclo.stream` | `fan-out`, `branch`, `stats` | Bounded multi-consumer distribution |
| `paclo.decode-ext` | `register!`, `unregister!`, `installed`, `apply!` | Post-decode hook API |

Internal namespaces (`paclo.pcap`, `paclo.parse`, `paclo.proto.*`,
`paclo.stream.impl`) are not part of the compatibility contract, except supported
`paclo.proto.dns-ext/annotate-dns` and `paclo.proto.tls-ext/annotate-tls-sni`.

## Compatibility matrix

| Layer | Supported | CI gate status (2026-07-30) | Notes |
| --- | --- | --- | --- |
| Clojure | `1.12.x` | Required | Baseline in `deps.edn` is `1.12.1` |
| JDK | `17`, `21` | Required | Representative compatibility jobs cover both |
| OS | macOS, Linux | Required | `macos-latest` and Linux runners |
| CPU | x86_64, arm64 | Required | Runner architecture is asserted before tests |
| Babashka | `1.12.x` | Checked | CI validates `bb --version` |
| libpcap | System package | Checked | Linux uses `libpcap-dev`; macOS uses system `pcap` |

The representative matrix is Linux x86_64/JDK 21, macOS arm64/JDK 17, and
Linux arm64/JDK 21. The architecture assertions prevent floating runner labels
from silently changing the coverage represented by a job name.

## Performance baselines

Reference measurements (`:xform` = drop packets shorter than 60 bytes):

| Sample | Packets | `decode?=false` | `decode?=true` |
| --- | ---: | ---: | ---: |
| `test/resources/dns-sample.pcap` | 4 | 11.1ms | 13.3ms |
| synthetic 50k (`/tmp/paclo-mid-50k.pcap`) | 50,000 | 273.7ms | 879.9ms |
| synthetic 100k (`/tmp/bench-100k.pcap`) | 100,000 | 398.5ms | 1291.7ms |

Environment: macOS 14.4 / Intel i7-8700B / JDK 21.

Perf gate:

```bash
clojure -M:perf-gate
```

Current thresholds: `warn=1000ms`, `fail=1200ms`.

The phase-1 runner measures offline stages independently and supports
loopback-live capture with libpcap drop counters:

```bash
clojure -M:perf --mode offline --profile quick --output target/perf-quick
clojure -M:perf --mode live --profile quick --device lo0 --output target/perf-live-quick
```

The live runner compares direct, bounded-blocking, and bounded-dropping paths
and reports sender, libpcap, queue, and consumer stages separately. It writes
schema-versioned EDN and JSON results. An exact-count `:perf-generator` alias
supports end-to-end loss measurement from a separate host over a real NIC.
See `docs/performance.md` for profiles, coordinated external-generator
measurement, metrics, and platform caveats.

## Security scan (NVD)

CI runs `Dependency Audit` with `NVD_API_TOKEN`.

Local reproduction:

```bash
NVD_API_TOKEN=<token> clojure -M:nvd dev/nvd-clojure.edn "$(clojure -Spath -A:dev:dns-ext)"
```

## Documentation

- [Docs index](docs/README.md): current guides and historical reference index
- [Usage guide](docs/usage.md)
- [Public API contract](docs/cljdoc-api-contract.md)
- [Decode extensions](docs/extensions.md)
- [Migration guide (0.4 to 1.0)](docs/migration-0.4-to-1.0.md)
- [Roadmap](docs/ROADMAP.md)
- [Performance measurement](docs/performance.md)
- [Historical releases and measurement evidence](docs/README.md#historical-records)

## Maintainer notes

For development setup, Codex instructions, and the accepted improvement plan, see
[CONTRIBUTING.md](CONTRIBUTING.md).

Clojars publish automation is defined in `.github/workflows/publish.yml`.
Required repository secrets:

- `CLOJARS_USERNAME`
- `CLOJARS_PASSWORD`

## FAQ

**Q. Live capture returns `Permission denied`.**
A. On Linux/macOS, packet capture may require root privileges or specific libpcap permissions.

**Q. What happens with `:decode? true` on parse errors?**
A. Packet decode failures do not throw. Each packet includes `:decode-error` instead.

**Q. Is this optimized for large captures?**
A. Yes for streaming workflows, but use BPF + `:xform` aggressively to reduce allocations.

## License

MIT
