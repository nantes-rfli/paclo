<!-- markdownlint-disable MD013 -->
# Paclo

[![cljdoc](https://cljdoc.org/badge/org.clojars.nanto/paclo)](https://cljdoc.org/d/org.clojars.nanto/paclo/CURRENT)
[![Clojars Project](https://img.shields.io/clojars/v/org.clojars.nanto/paclo.svg)](https://clojars.org/org.clojars.nanto/paclo)

Paclo is a Clojure library for packet capture (PCAP) I/O, BPF filtering, and data-first packet processing.
It provides a small public API plus optional decode hooks for DNS/TLS workflows.

> If cljdoc or Clojars returns `404` right after publishing, indexing can take several minutes.

## Project status

- Stable release: `v1.0.0` (published on February 23, 2026)
- Clojars: `org.clojars.nanto/paclo`
- cljdoc: <https://cljdoc.org/d/org.clojars.nanto/paclo/CURRENT>
- Roadmap status: v1.0 release track is complete (see `docs/ROADMAP.md`)

## Install

### deps.edn (recommended: Clojars)

```edn
{:deps
 {org.clojars.nanto/paclo {:mvn/version "1.0.0"}}}
```

### deps.edn (Git tag)

```edn
{:deps
 {org.clojars.nanto/paclo
  {:git/url "https://github.com/nantes-rfli/paclo.git"
   :git/tag "v1.0.0"}}}
```

If your environment requires Java class prep for git dependencies, run once in your consumer project:

```bash
clojure -X:deps prep
```

## Quick start

```clojure
(require '[paclo.core :as core])

;; Capture 10 UDP/53 packets
(->> (core/packets {:device "en0"
                    :filter (core/bpf [:and [:udp] [:port 53]])
                    :timeout-ms 50})
     (take 10)
     doall)
```

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

```bash
clojure -M:dev:dns-ext -e "(require 'paclo.dns.decode) (println :dns-ext-ok)"
```

## CLI reference (stable v1.0)

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

```bash
clojure -M:dev -m examples.flow-topn in.pcap 'udp and port 53' 10 bidir bytes jsonl
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

## Public API surface (v1.0)

| Namespace | Public functions | Notes |
| --- | --- | --- |
| `paclo.core` | `bpf`, `packets`, `write-pcap!`, `list-devices` | User-facing API |
| `paclo.decode-ext` | `register!`, `unregister!`, `installed`, `apply!` | Post-decode hook API |

Internal namespaces (`paclo.pcap`, `paclo.parse`, `paclo.proto.*`) are not part of the compatibility contract.

## Compatibility matrix

| Layer | Supported | CI gate status (2026-02-23) | Notes |
| --- | --- | --- | --- |
| Clojure | `1.12.x` | Required | Baseline in `deps.edn` is `1.12.1` |
| JDK | `17`, `21` | Required | Compatibility jobs run both |
| OS | macOS, Linux | Required | `macos-latest` and Linux runners |
| CPU | x86_64, arm64 | Required | arm64 runner: `ubuntu-24.04-arm` |
| Babashka | `1.12.x` | Checked | CI validates `bb --version` |
| libpcap | System package | Checked | Linux uses `libpcap-dev`; macOS uses system `pcap` |

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

## Security scan (NVD)

CI runs `Dependency Audit` with `NVD_API_TOKEN`.

Local reproduction:

```bash
NVD_API_TOKEN=<token> clojure -M:nvd dev/nvd-clojure.edn "$(clojure -Spath -A:dev:dns-ext)"
```

## Documentation

- Docs index: `docs/README.md`
- Usage guide: `docs/usage.md`
- Decode extensions: `docs/extensions.md`
- Public API contract: `docs/cljdoc-api-contract.md`
- Migration guide: `docs/migration-0.4-to-1.0.md`
- Roadmap: `docs/ROADMAP.md`

## Maintainer notes

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
