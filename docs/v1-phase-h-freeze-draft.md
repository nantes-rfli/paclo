# v1.0 / Phase H API Freeze Draft (2026-02-23)

This document captures the Phase H API freeze baseline for v1.0.
It separates what is already fixed from what was deferred to Phase I.

## 1. Phase H status

- [x] Public API inventory (`paclo.core`, `paclo.decode-ext`)
- [x] Official CLI contract inventory (5 commands, exit codes, output rules)
- [x] BPF DSL supported forms list
- [x] Compatibility matrix and CI gap review
- [x] Breaking-change decisions for v1.0
- [x] README + cljdoc contract sync

## 2. Public API freeze (draft)

### 2.1 `paclo.core`

- `bpf`
  - Signature: `(bpf form)`
  - Returns: BPF string or `nil`
  - Accepts: `nil`, string, protocol keyword, DSL vector
  - Errors: `ex-info` for unknown keyword/operator/type
- `packets`
  - Signature: `(packets opts)`
  - Returns: lazy seq of packet maps
  - Contract highlights:
    - source is exactly one of `:path` or `:device`
    - `:filter` accepts `string | keyword | vector | nil`
    - `:decode? true` adds `:decoded` or `:decode-error`
    - `:xform` is applied via `(sequence xform stream)`
  - Runtime notes:
    - inherits `capture->seq` default stop conditions (`:max`, `:max-time-ms`, `:idle-max-ms`)
    - applies `decode-ext/apply!` only when `:decoded` exists
- `write-pcap!`
  - Signature: `(write-pcap! packets out)`
  - Input: seq of `byte-array` or `{:bytes ... :sec ... :usec ...}` maps
  - Behavior: writes to `out`, throws `ex-info` on invalid output
- `list-devices`
  - Signature: `(list-devices)`
  - Returns: seq of `{:name "..." :desc "..."}` maps

### 2.2 `paclo.decode-ext`

- `register! [k f]`: register hook (same key overwrites and moves to tail)
- `unregister! [k]`: remove hook by key
- `installed []`: return hook keys in execution order
- `apply! [m]`: apply hooks conditionally
  - Guard: `m` is map, has `:decoded`, does not have `:decode-error`
  - Hook exceptions are swallowed
  - Non-map hook return values are ignored

### 2.3 Non-public boundary (v1.0)

- `paclo.pcap`, `paclo.parse`, `paclo.proto.*` are internal namespaces
- v1.0 public API surface is explicitly `paclo.core` + `paclo.decode-ext`

## 3. Official CLI contract draft

Target commands:

- `examples.pcap-filter`
- `examples.pcap-stats`
- `examples.flow-topn`
- `examples.dns-qps`
- `examples.dns-topn`

Shared exit codes (from `examples.common`):

- `1`: missing required args (usage)
- `2`: input PCAP not found
- `3`: enum validation error (`group`/`mode`/`metric`/`format`)
- `4`: invalid flag or numeric value

Shared output rules:

- primary data goes to stdout (`edn` / `jsonl` / `csv`)
- metadata and warnings go to stderr
- uncaught exceptions currently follow JVM exit behavior

## 4. BPF DSL freeze draft (`paclo.core/bpf`)

Logical forms:

- `[:and expr ...]`
- `[:or expr ...]`
- `[:not expr]`

Protocol forms:

- `:udp`, `:tcp`, `:icmp`, `:icmp6`, `:arp`
- `:ip`, `:ipv4`, `:ip6`, `:ipv6`
- `[:proto <keyword>]`

Address forms:

- `[:host "..."]`
- `[:src-host "..."]`
- `[:dst-host "..."]`
- `[:net "..."]`
- `[:src-net "..."]`
- `[:dst-net "..."]`

Port forms:

- `[:port N]`
- `[:src-port N]`
- `[:dst-port N]`
- `[:port-range A B]`
- `[:src-port-range A B]`
- `[:dst-port-range A B]`

Error behavior:

- unknown operator/type -> `ex-info`
- invalid numeric port conversion -> number parse error

## 5. Compatibility matrix (decision)

P3 target:

- JDK: 17 / 21
- Clojure: 1.12.x
- Babashka: 1.12.x
- OS: macOS / Linux (x86_64, arm64)

Implementation status (2026-02-23):

- `deps.edn` baseline is `1.12.1`
- required compatibility jobs: Linux/JDK21 and macOS-latest/JDK17
- arm64 job is enabled on `ubuntu-24.04-arm` and required

arm64 promotion criteria (locked on 2026-02-23):

- 14+ day window with success rate >= 95%
- rerun/flaky dependency < 5%
- test-code-caused failures fixed and merged within 72 hours
- arm64 duration <= 1.5x x86_64 for `clojure -M:test`, dns-ext smoke, perf-gate
- promotion procedure documented via compatibility matrix job changes
- release-priority exception was used to require arm64 before full 14-day window

## 6. Performance budget (decision)

Baseline:

- mid-50k synthetic PCAP (`decode?=true`): `879.9ms` (recorded on 2025-12-04)

v1.0 operational thresholds:

- hard fail: `<= 1.2s`
- warning: `> 1.0s`

Enforced via `clojure -M:perf-gate` in CI.

## 7. Breaking-change decisions (final)

- Decision A: official Clojure support is fixed to `1.12.x`
- Decision B: CLI exit codes remain `1/2/3/4` in v1.0
- Decision C: keep `clojure -M:run` by providing `paclo.core/-main`

## 8. Carry-over tasks for Phase I

- [x] Add API quick reference and compatibility matrix to README
- [x] Sync cljdoc API contract (`docs/cljdoc-api-contract.md`)
- [x] Add compatibility jobs (Linux/JDK21 + macOS/JDK17)
- [x] Add performance gate (mid-50k)
- [x] Define arm64 gating criteria
- [x] Promote arm64 job to required
- [x] Stabilize arm64 required flow around `pcap-loop-test`
- [x] Fix `pcap-loop-test` root cause and re-integrate into required unit tests
- [ ] Continue required-gate observations and tune thresholds/config as needed
- [x] Add CLI snapshot and exit-code tests
