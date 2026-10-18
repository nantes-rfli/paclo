# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

Changes after v1.4.0 belong here.

### Build

- Identify ordinary development/CI artifacts as `1.5.0-SNAPSHOT`, separately from
  published v1.4.0. SNAPSHOT POMs name the source commit as their SCM tag;
  distribution verification checks that identity alongside versions and hashes.
  This identifier does not assign a v1.5.0 release scope or date.

### Performance

- Index repeated DNS retired-key expiry in large states with immutable deadline
  buckets. Small initial states retain the existing scan path. Standard EDN
  state data, old snapshots, exact time, diagnostics and bounds stay compatible;
  the optional metadata index adds bounded storage and a rebuild after restore.
  See the [measured tradeoffs](dev/issue-37-retired-expiry-evaluation.md) (Issue #37).

## [1.4.0] - 2026-10-17

This release includes P01–P08 and merged stabilization, performance and Java
compatibility fixes; P09/P10 are excluded. The
[migration guide](docs/migration-from-1.3.md) explains Writer metadata precedence
and stricter validation, exact bounded DNS reports and explicit CLI failures.
See the [release notes](docs/release-notes-1.4.0.md) and
[acceptance checklist](dev/release-1.4.0-checklist.md) for scope and evidence.
Phase-specific exclusions below describe each change's scope; PCAPNG metadata
I/O is now provided separately by P08-E2/E3.

### Added

- `paclo.pcapng/write-pcapng!` synchronously writes ordered SHB/IDB/EPB/SPB and
  permitted opaque events, preserving mixed section byte orders/interfaces,
  exact uint64 ticks, resolution/offset, timestamp absence and ordered options.
- Explicit preserve (default), lossy drop/count and author modes validate metadata,
  references and exact/derived time without repair. The bounded writer publishes
  a closed sibling temp via exclusive atomic rename on supported Linux/macOS
  filesystems, refusing existing names and unsafe fallbacks. Primary failures and
  cleanup details survive; Classic `core/write-pcap!` is unchanged.

- P08-E2 review corrections: enforce the packet byte ceiling from fixed EPB/SPB
  headers before allocating/reading the remaining block body. Positive regression
  coverage confirms repeated IDB IPv4/IPv6 addresses retain order, owned octets
  and fixed lengths under both byte orders and all existing option ceilings.
- P08-E2: `paclo.pcapng/open-source` and `source-info` provide a bounded,
  synchronous, Closeable single-consumer PCAPNG event reduction. Ordered
  SHB/IDB/EPB/SPB and permitted opaque events retain section/interface identity,
  mixed byte order/LINKTYPE/snaplen, owned option octets and exact unsigned ticks,
  decimal/binary resolution, signed offsets and explicit timestamp absence.
  Integer microsecond projection preserves the existing packet shape; explicit
  nil DLT prevents unknown LINKTYPEs from defaulting to Ethernet. Checked resource
  ceilings, malformed/unsupported-input failures and deterministic termination
  accompany lifecycle/heap acceptance tests and runnable documentation. Existing
  native APIs and Classic writer behavior remain unchanged. PCAPNG output is E3.
- P08-D2: NULL (native DLT 0) and LOOP (108) IPv4/IPv6 full decode and numeric
  flow projection on Linux/macOS, after cross-endian installed-libpcap probes
  on Linux x64, macOS ARM64 and Linux ARM64. Shared framing reads AF at offset
  0 and IP at offset 4; NULL accepts a unique known AF under either order,
  LOOP requires big endian. AF 2 selects IPv4, 24/28/30 select IPv6; unknown AF
  and AF/version mismatch use distinct additive diagnostics. Full uses
  `:type :null` / `:loop`, `:address-family` and `:l3`; existing IP/L4, DNS/TLS,
  flow/window/DNS analysis and array ownership remain unchanged. No raw byte
  normalization, origin OS inference, full decode on the flow path or frame copy.
  Original container order is unavailable, so NULL/container consistency and
  original encoding cannot be guaranteed. Unmeasured OS DLT mappings remain
  unsupported; PCAPNG metadata/writing and live/NIC validation remain separate.
- P08-D1: Raw IP IPv4/IPv6 full decode and numeric flow projection for native
  DLT_RAW 12 on Linux/macOS. Bare IP starts at offset zero; the version nibble
  selects existing IP/L4 parsers, and full results use `{:type :raw-ip :l3 ...}`
  without synthetic link fields or a whole-frame copy. DNS/TLS extensions and
  P06/P07 analysis compose unchanged. Empty, invalid-version and truncated
  packets use structured diagnostics with absolute offsets; invalid versions
  never fall back to Ethernet. Savefile LINKTYPE_RAW 101 is not a packet DLT.
  Unverified-platform DLT mappings remain deferred.
- P08-C: shared Ethernet/VLAN, Linux SLL (DLT 113) and SLL2 (276) framing for
  full decode and numeric flow projection. Cooked IPv4/IPv6 reuse TCP/UDP/ICMP,
  fragment/extension and DNS/TLS parsers. Full maps use `:linux-sll`/`:linux-sll2`
  with protocol, packet/hardware types, bounded address and SLL2 reserved/interface
  index; Ethernet output is unchanged. The interface index is not PCAPNG metadata.
  Flow aggregates and time-window/DNS analysis accept cooked traffic. Short link
  headers report required 16/20 bytes, invalid address lengths report malformed
  fields, and unknown cooked protocols use additive `:unsupported-protocol`.
  No frame copy/conversion, registry, dependency, release or stats-schema change.
  Noninitial IPv6 flow fragments stop at their fragment header, matching full
  decode even when the next extension header is absent from that fragment.
  PCAPNG metadata/output remain unsupported.

- P08-B2: three-argument `core/write-pcap!` accepts explicit native `:linktype`
  and positive `:snaplen` (signed native int range). The existing two-argument
  form defaults to Ethernet (1)/65536. Single-DLT Classic PCAP preserves ordered
  bytes, microsecond timestamps and captured/original lengths; no suffix-based
  format selection, byte conversion or PCAPNG metadata/output support.

- P07-A: public `paclo.window` tumbling counts/captured bytes and `paclo.dns`
  packet-to-EDN normalization/UDP correlation. Pure immutable init/step/advance/
  finish APIs use integer microsecond event time, explicit monotonic watermarks,
  floor boundaries, lateness, timeout and required retention limits. Arithmetic
  promotes on overflow; capacity errors never evict. DNS reuses existing decode
  and explicit annotations, matches endpoint/version/ID/question keys, tracks
  earliest-query retries, classifies ambiguity/unmatched/negative RTT and bounds
  retired-key quarantine against immediate ID reuse/duplicate responses.
  Capture behavior is unchanged; CLI migration is described below.

- P06: public `paclo.flow/key`, `aggregate-rf`, and `top-n` for canonical numeric
  IPv4/IPv6 identity, unidirectional/bidirectional normalization, immutable exact
  packet/captured/wire totals, required cardinality bounds and deterministic ties.
  Invalid flows skip; eligible invalid lengths throw; counters promote on overflow.
  Full decode's legacy string-address flow descriptor remains compatible.
- Internal projection moved from `paclo.flow` to `paclo.flow.project`; supported
  core packet transformations remain unchanged. `flow-topn` delegates analysis
  to the library, retains display/format/async options and adds `--max-flows N`
  (default 100000). Formerly unbounded captures can now exceed this budget; set
  a larger explicit bound. Ties follow canonical order. Async cancellation stops
  the reader, drop counts are accurate and reader/aggregate exceptions propagate.

- P05: native `pcap_datalink` binding and integer DLT `:linktype` on raw packets
  across lazy reads, reductions/reports and managed capture. Acquire once after
  activation/open, fail without guessing Ethernet, and close on setup failure.
- Full/flow reject explicit unsupported or invalid link types before parsing,
  retaining metadata and adding `:unsupported-linktype` diagnostics. Full keeps
  raw bytes and skips extensions; flow omits bytes and includes linktype metadata.
  Missing linktype in standalone `packet-xf` retains legacy Ethernet behavior.
  Stats remain schema version 1; these decode failures use existing error counts.
  Real SLL/loopback fixtures and an executable raw-read example cover dispatch.
  P05 adds no decoders, conversion or PCAPNG support; P08-B2 writer options are
  described above.

- P04: canonical raw/full/flow packet data contracts and additive EDN
  `:diagnostics` with stable stage/reason fields and byte locations when known.
  Existing decoded values, `:decode-error` strings and statistics v1 are retained.
- Opt-in full-decode `:extension-error-mode :report` for isolated exception and
  non-map hook failures, ordered by zero-based execution index for explicit and
  global hooks. Default `:ignore` retains legacy outputs; invalid settings fail
  before source open. Three-argument `decode-ext/apply!` shares the hook runner.

- P03: ordered `:extensions` function vectors for full decode in `packet-xf`,
  `packets`, synchronous reductions/reports, and managed capture. Explicit
  selection retains duplicates and is independent of the global registry;
  `[]` disables extensions and omission preserves dynamic global hooks.
  Invalid configuration and raw/flow combinations fail early with `ex-info`.
- Public `paclo.proto.dns-ext/annotate-dns` and
  `paclo.proto.tls-ext/annotate-tls-sni` functions for direct use and independent
  fan-out branches. Existing registration and best-effort parsing remain intact.
- Two-argument `paclo.decode-ext/apply!` for supplied functions, sharing the
  existing decode eligibility, exception isolation and non-map result policy.

### Changed

- P01: align current public API documentation and examples with implemented
  behavior, separate historical records and verify maintained examples in CI.
  Complete the v1.3.0 → v1.4.0 migration guide for Writer and CLI changes.

- Issue #44: construct full-decode Ethernet/cooked address strings with direct
  primitive char-array stores, avoiding reflective writes. Shared framing,
  public packet/VLAN shapes, diagnostics and numeric flow projection are unchanged.
  Repeated CPU/allocation and native offline comparisons are recorded in
  `dev/issue-44-ethernet-performance.md`; no live-capture speed claim.

- P07-B: DNS RTT/QPS examples delegate to `paclo.dns`/`paclo.window`, use explicit
  DNS extensions and one shared sync/async reducer adapter. Event time is exact
  native microseconds; monotonic max-time minus `--reorder-us` drives expiry.
  New pending/retired/window/group/sample/qname limits bound analysis and reports.
  pairs retains only topN candidates; stats/qstats keep bounded exact samples.
  QPS max-buckets bounds finalized and empty-filled output; overflow now exits 5
  before stdout instead of silently truncating. Cancellation/drop reports carry
  incomplete metadata; source/reducer failures close and join the owning producer.
- RTT now uses strict question-aware correlation, earliest-query retries,
  expiry and retired-key quarantine. Missing questions, negative RTT and late or
  unmatched responses are diagnostic counts, never guessed pairs. This can change
  historical pair counts. Fix native timestamp keys and fractional average;
  async metadata no longer contaminates statistics. QPS remains packet counts,
  fixes negative/large timestamps and empty fill losing simultaneous groups,
  adds deterministic ties, groups client/server IPs by QR role instead of raw
  source/destination, and decodes Punycode in non-leading labels. Offline
  reports now read to EOF, removing inherited 100-packet/10-second capture caps.
- Measured DNS advance allocation improvement: remove only expired retired keys
  instead of reconstructing every live quarantine entry at each watermark;
  immutable snapshots, expiry boundaries and the public API remain unchanged.

### Fixed

- Compile Java bindings with `javac --release 17` on both supported JDKs.
  JDK 21-built distribution JARs now contain Java 17-compatible bytecode and
  cannot compile references to newer JDK APIs. CI runs the same packaged JAR
  in isolated JDK 17 and JDK 21 consumers, checking contents, POM and SHA-256.
  No packet processing or public API behavior changes.

- Managed capture serializes native break/close during concurrent stop/close,
  preventing a stop caller from using a freed handle. Close clears any packet
  offered during shutdown after the producer has finished.
- Documented the reproduced legacy lazy capture limitation: abandoning a full
  blocking queue can retain its producer/native source indefinitely, past
  count/time/predicate limits. No automatic abandonment detection or lazy API
  behavior change is introduced. Offline/live prefix examples use `with-open`
  managed capture; synchronous `reduced` is also a deterministic alternative.

- P08-B2: reject explicit invalid/mismatched packet DLTs, mixed-DLT sequences,
  caplen above snaplen and invalid/unknown options. Non-Ethernet maps previously
  mislabeled Ethernet by two-argument calls now require matching `{:linktype dlt}`.
  Maps/byte-arrays without framing metadata trust the caller's selected DLT.
- Native `pcap_dump_flush` now returns int through JNR and reports failures.
  Linux/macOS also inspect the C stream for earlier failed writes, even when
  flush succeeds. Writer cleanup always attempts flush and both closes without replacing the
  original error; native dead-handle/dumper open errors are observable. Failure
  may leave a partial file. Native void close cannot report OS close-only errors;
  flush is not a durability guarantee. Regression tests include all 28 P08-A
  fixtures and native Ethernet/SLL/SLL2/NULL/LOOP round trips.

- P08-B1: native `pcap_next_ex` failures now propagate across synchronous,
  lazy and managed reads instead of looking like EOF. `:pass` keeps the valid
  prefix and reports failed/error termination; stats v1 adds native reason,
  phase, return code and message while retaining class/message fields.
  Non-report callers can observe failures through `:on-error`.
- Failed offline/live/configured setup closes its native handle once, including
  BPF/netmask failures, without masking the original cause. Lazy terminal/error
  notification no longer blocks on a full packet queue. Legacy lazy abandonment
  remains an accepted limitation from Issue #40; managed capture supports close.

- P02: `write-pcap!` accepts read packet maps directly, preserving packet bytes,
  timestamps, captured lengths and original lengths, including truncated records.
  `:ts-sec`/`:ts-usec` takes precedence over legacy `:sec`/`:usec`; raw bytes,
  omitted timestamps and partial legacy pairs retain the current-time fallback.
- Reject invalid bytes, partial new timestamps, invalid selected timestamp values,
  inconsistent lengths and unsigned 32-bit overflow with `ex-info`. Complete
  legacy pairs containing `nil` or coercible non-integers now fail validation.
  P02 retains Ethernet output and the two-argument writer; P08-B2 adds explicit
  DLT options as described above. Source global
  headers and timestamp precision are not copied; older libpcap's post-2038
  timestamp interpretation remains a native limitation.

### Performance

- Avoid DNS expiry scans before the next possible deadline using one immutable
  integer hint; sort only expired queries. Strict matching, diagnostics, bounds,
  exact time, old EDN snapshots and CLI reports remain supported (Issue #37).
- Reuse stored keys when updating hash-map flow aggregates, reducing temporary
  allocation on revisited flows. Small maps and other caller-supplied map types
  retain the previous path; public API, immutable snapshots and exact counters
  are unchanged.
- Reduce temporary allocation in exact flow aggregation with single-key persistent
  map updates and indexed IPv6 word access. Public keys, exact counters, bounds
  and immutable reducer snapshots retain their existing contract (Issue #34).

## [1.3.0] - 2026-08-01

### Added

- Added `paclo.core/packet-xf` for composing compatible full decode or numeric
  flow projection with standard Clojure transducers.

- Added public `paclo.stream/fan-out`, `branch`, and `stats` for backend-neutral
  bounded distribution through reducible, seqable, closeable branches.

- Added branch-local blocking/dropping policies and schema-versioned data-only
  distribution, buffer, backpressure, lifecycle, and error statistics.

### Changed

- Unified packet transformation across lazy sequences, synchronous reduction,
  reduction reports, and managed captures through `packet-xf`.

- Added `:decode-mode :flow` support to `paclo.core/packets`.
- External exact-count live benchmarks now stop capture at the expected packet
  count instead of relying only on a duration timeout.

### Fixed

- Read macOS `timeval.tv_usec` using its 32-bit Darwin ABI width instead of
  including the adjacent struct padding in packet timestamps.

- Released the fan-out dispatcher's reference to the lazy source head so long
  bounded streams do not retain every realized tail.

## [1.2.0] - 2026-07-30

### Added

- Added an exact-count UDP generator and external expected-packet accounting
  for reproducible end-to-end real-NIC live-capture measurements.

- Added `paclo.core/reduce-packets-report` for synchronous results plus
  schema-versioned execution statistics and explicit stop reasons.

- Added single-consumer managed captures through `start-capture`,
  `capture-packets`, `stop-capture!`, and `capture-stats`.

### Changed

- Unified synchronous and managed capture reporting around data-only source,
  timing, packet, queue, libpcap, stop-reason, and error fields.

- Advanced the local development version to `1.2.0-SNAPSHOT`.

### Fixed

- Managed capture shutdown no longer depends on inserting a terminal marker
  into a full blocking queue; explicit close unblocks the producer and
  deterministically releases the libpcap handle.

## [1.1.0] - 2026-07-27

### Added

- Added a phase-1 offline/live performance runner with deterministic PCAP
  generation, isolated JVM scenarios, EDN/JSON results, and JVM metrics.

- Added internal portable `pcap_stats` counters and loopback-live load
  measurement.

- Added `paclo.core/reduce-packets` for synchronous transducer-aware reduction
  without the producer queue or an intermediate lazy sequence.

- Added opt-in numeric `:decode-mode :flow` projection to `reduce-packets`.
- Added opt-in live capture buffer and immediate-mode configuration using
  libpcap's create/activate API.

- Added live sender, libpcap, paclo queue, and consumer stage metrics with a
  0.1% sustainability classifier and per-scenario maximum passing result.

- Added direct, bounded-blocking, and bounded-dropping live benchmark
  comparisons plus an external-generator profile for real-NIC measurement.

- Added opt-in `:queue-mode :dropping` and final `:on-queue-stats` counters to
  the lazy packet sequence.

### Changed

- CI now runs a non-thresholded 50k performance smoke and uploads its results.
- Replaced hot-path address `format` calls with dedicated conversions, reducing
  compatible full-decode allocation without changing packet maps.

- Migrated `flow-topn` to the synchronous numeric flow projection and an
  internally mutable accumulator while preserving its EDN/JSONL output contract.

- Advanced performance result files to schema version 2 for staged live
  metrics.

- Hardened release publication with main/tag provenance checks, release gates,
  uploaded candidate artifacts, and a non-publishing manual dry-run.

### Fixed

- Preserved `nil` from truncated DNS and TLS byte readers instead of applying
  primitive return coercion to missing data.

- Made live queue high-water and backpressure metrics race-safe when consumers
  drain immediately or producers encounter a full bounded queue.

## [1.0.1] - 2026-02-23

### Added

- Added `.github/workflows/publish.yml` to publish tagged releases to Clojars (or manual dispatch), preparing cljdoc
  indexing.
- Added `:deps-deploy` alias (`slipset/deps-deploy`) for Maven/Clojars deployment.

### Changed

- `build.clj` now resolves version from `PACLO_VERSION` /tag context, writes Maven metadata (SCM/description/url), and
  adds a local `install` task.
- Switched publish/cljdoc coordinates from `io.github.nantes-rfli/paclo` to `org.clojars.nanto/paclo`.
- Added MIT license metadata to generated POM and added a repository `LICENSE` file.
- Rewrote user-facing docs in English and clarified README/docs structure for Clojars/cljdoc readers.
- Normalized docstrings/comments across source, examples, and tests for consistency.

## [1.0.0] - 2026-02-23

### Changed

- Promoted `v1.0.0-rc.1` to stable `v1.0.0`.
- Kept the v1 API/CLI/BPF contracts, compatibility matrix, and CI gates established during RC.

## [1.0.0-rc.1] - 2026-02-23

### Changed

- Added `:deps/prep-lib` (`build/javac`) to enable Java class preparation for git dependencies before use.
- Updated install/release docs to require `clojure -X:deps prep` for first-time git dependency setup.

## [1.0.0-rc] - 2026-02-23

### Added

- Added `docs/migration-0.4-to-1.0.md` with a migration checklist, compatibility policy, CLI exit-code contract, and
  deprecation timeline notes.
- Added `docs/release-v1-rc-checklist.md` to standardize `v1.0.0-rc` release gates and tagging steps.
- Added `.github/workflows/arm64-promotion-report.yml` to report arm64 required-gate promotion readiness (14-day window,
  success/rerun/duration thresholds).
- Added `dev/script/arm64_promotion_report.sh` to compute the same arm64 promotion metrics locally via `gh` API.

### Changed

- Roadmap progress for v1.0 Phase I is now tracked with concrete items (BPF error contract tests, `invalid :filter`
  contract test, migration guide draft).
- Docs index and README documentation links now include the 0.4 -> 1.0 migration guide.
- Added arm64 required-gate promotion criteria to the v1 freeze draft (success/flake/perf thresholds and promotion
  procedure).
- Updated README `deps.edn` install snippet from `v0.3.0` to `v0.4.0` tag/sha.
- Made `arm64-monitor` a required CI gate by removing `continue-on-error` (exception path without waiting 14-day
  observation window).
- Updated compatibility matrix macOS runner label to `macos-latest` (replacing unsupported `macos-13` configuration).
- Isolated Clojure deps cache keys by `runner.arch` to prevent x64/arm64 cache cross-restore in CI jobs.
- Stabilized arm64 required gate by excluding `paclo.pcap-loop-test` from the gating test regex and running it as a
  non-gating observation step.
- Re-integrated `paclo.pcap-loop-test` into arm64 required unit tests after removing reflection-based
  `PointerByReference` mutation in tests.
- Recorded `v1.0.0-rc` local gate execution results in the release checklist and updated P3 acceptance progress in
  ROADMAP.

### Tests

- Strengthened BPF error-contract tests to assert `ex-message` and `ex-data` for unknown proto/op and unsupported forms.
- Added explicit `core/packets` invalid-filter contract test (`ex-message` + `ex-data`).

## [0.4.0] - 2025-12-10

### Added

- DNS aggregation CLIs `examples.dns-topn` / `examples.dns-qps` (EDN/JSONL/CSV, async/drop/cancel, qname punycode
  normalization, SNI/ALPN aggregation, empty-bucket fill).
- Added four TLS sample PCAPs (`tls-sni-sample.pcap`, `tls-sni-alpn-sample.pcap` , `tls-sni-h3-sample.pcap` ,
  `tls-sni-alpn-h3mix-sample.pcap` ) and expanded smoke tests.
- Added DNS QPS benchmark reference to README/ROADMAP (dns-synth-small 10pkt, bucket=1000, decode?=true, ~16.2ms).
- CI: added dns-ext smoke (`examples.dns-topn`) and cljdoc CLI dry-run to the build job.
- CI: set coverage job to Temurin 17 with continue-on-error to mitigate cloverage native crashes.

### Fixed

- Added `--log-punycode-fail` to `dns-qps` , aligning README/help with implementation; punycode decode failures now log
  WARN to stderr.

### Notes

- Eastwood passes via `-M:eastwood:dns-ext` (+ data.xml); warnings limited to boxed-math/performance/reflection.
- nvd-clojure runs in GitHub Actions `Dependency Audit` using `secrets.NVD_API_TOKEN` ; to reproduce locally set
  `NVD_API_TOKEN` and run `clojure -M:nvd dev/nvd-clojure.edn "$(clojure -Spath -A:dev:dns-ext)"` .
- 2025-12-10: GitHub Actions "Dependency Audit" (nvd-clojure) completed with `NVD_API_TOKEN`, no critical CVEs.

## [0.3.0] - 2025-12-05

### Added

- TLS ClientHello SNI/ALPN decode extension (`paclo.proto.tls-ext`) and example `examples.tls-sni-scan` (EDN/JSONL).
- REPL pipeline benchmark sample numbers for small / mid (50k) / large (100k) synthetic PCAPs.
- Synthetic PCAP generator `make-synth-pcap` to reproduce benchmark inputs (count/caplen configurable).
- Property test to assert decode_ext isolates exceptions yet keeps later hooks running.
- Added decode_ext guard coverage for packets without `:decoded` or with `:decode-error` (hooks are skipped).
- Added JSONL metadata smoke test for `examples.pcap-filter`.
- Added opt-in `--async` support to `pcap-filter` / `flow-topn` / `pcap-stats` / `dns-rtt` (backpressure/drop/timeout
  demos).

### Docs

- `docs/extensions.md` stability notes for decode_ext hooks (map-only apply, exception isolation, API compatibility).
- Roadmap updated to reflect Phase B progress and outstanding tasks; mid-size REPL turnaround numbers added; proto-dns
  split draft added (`dev/proto-dns-split-plan.md`).
- README REPL turnaround section now lists small/mid/large pipeline-bench samples.
- Aligned examples docs/help text (`dns-summary` alias hint, `tls-sni-scan` formats/tips), including shared EDN/JSONL
  flags and `_` skip usage.
- Updated `docs/extensions.md` with v0.3 stability notes and explicit hook guard conditions.
- Added async opt-in examples and long-PCAP backpressure/drop observation steps to README (`pcap-filter` / `flow-topn` /
  `pcap-stats` / `dns-rtt` ) and synced ROADMAP core.async progress.

### Fixed

- `examples.dns-summary` help text now references the required `:dns-ext` alias.
- `examples.tls-sni-scan` accepts skipped optional args via `_` and emits consistent format errors.
- BPF arg `_` now correctly treated as "unset" in `examples.pcap-filter` / `flow-topn` / `pcap-stats` to match Usage
  tips.

## Versioning / SemVer

This project follows [SemVer](https://semver.org/).
Until **v1.0.0**, **minor versions may include breaking changes**.
Patch versions never do.

## [0.2.0] - 2025-08-24

### Added

- `:xform` transducer support in `core/packets`.
- BPF DSL extensions: `:proto` (`:ip/:ipv4/:ip6/:ipv6`), `:src-net/:dst-net`, `:port-range` variants.
- `core/list-devices` facade and minimal test.
- Golden PCAP round-trip tests and error propagation tests.

### Changed

- Documentation: added roadmap and README Quick Start.

### Fixed

- Stabilized AI_HANDOFF generation and primary links (ROADMAP added).
