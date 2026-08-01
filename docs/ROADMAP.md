# Paclo Roadmap

This roadmap tracks release objectives, acceptance criteria, and current progress.
It is intentionally concise and focuses on user-visible outcomes.

## North star

"Make PCAP processing feel native in Clojure data workflows (EDN/maps/seq/transducers)."

## Release timeline

- `v0.2` (completed): OSS baseline (`:xform`, BPF DSL expansion, minimal L2/L3/L4 decode, CI hardening)
- `v0.3` (completed, 2025-12-05): data-first UX improvements and decode extension stabilization
- `v0.4` (completed, 2025-12-10): DNS observability tooling (`dns-topn`, `dns-qps`, async behavior)
- `v1.0.0` (released, 2026-02-23): API freeze and stable release artifacts
- `v1.0.1` (released, 2026-02-23): documentation and publication pipeline polish
- `v1.1.0` (released, 2026-07-27): measured high-throughput paths and
  staged live-capture observability
- `v1.2.0` (released, 2026-07-30): controlled capture execution, synchronous
  reports, and managed single-consumer capture lifecycles
- `v1.3.0` (released, 2026-08-01): composable packet transforms and
  bounded, observable multi-consumer fan-out

## v1.0 completion status

The v1.0 release roadmap is complete.

Completed release artifacts:

- [x] `v1.0.0-rc` and `v1.0.0-rc.1` tags/releases
- [x] `v1.0.0` tag and GitHub Release (latest)
- [x] `v1.0.1` patch release for docs/publication follow-up
- [x] Clojars publish pipeline and release publication (`org.clojars.nanto/paclo`)
- [x] cljdoc publication confirmed (`CURRENT` page and successful build)
- [x] Migration guide (`docs/migration-0.4-to-1.0.md`)
- [x] Public API contract (`docs/cljdoc-api-contract.md`)
- [x] Compatibility matrix and performance gate integrated into CI

## Quality gates in place

- Required CI matrix for Linux/macOS and JDK 17/21
- arm64 CI job enabled as required gate
- Performance gate (`clojure -M:perf-gate`) with warn/fail thresholds
- Dependency audit (`nvd-clojure`) in GitHub Actions
- Lint/static checks (`eastwood`, `clj-kondo`) and regression tests

## Current focus (post-1.0)

`v1.0` is shipped; next work is maintenance and incremental improvements.

- [ ] Stabilize arm64 success rate against long observation windows
- [ ] Keep publish/release automation healthy (token rotation, workflow maintenance)
- [ ] Continue documentation polish for user-facing pages and examples
- [ ] Add optional integrations only as opt-in aliases (no heavy default dependencies)

## v1.1 release status

- [x] Reproducible offline and live measurement foundation
- [x] Public synchronous `reduce-packets` API with transducer fusion
- [x] Opt-in numeric flow projection and compatible full-decode optimization
- [x] `flow-topn` migration to the numeric fast path
- [x] Live direct/blocking/dropping comparison and staged drop metrics
- [x] v1.1 public API contract, changelog, and release metadata prepared
- [x] Publish `v1.1.0` to Clojars and verify cljdoc
- [x] Publish the `v1.1.0` GitHub Release

## v1.2 release status

- [x] Define a schema-versioned execution statistics contract
- [x] Add synchronous result-plus-statistics reduction
- [x] Add an opaque, Closeable managed capture handle
- [x] Add explicit idempotent stop and single-consumer packet delivery
- [x] Make shutdown independent of queue capacity
- [x] Add lifecycle, early-reduction, and full-queue regression tests
- [x] Add managed-capture performance scenarios
- [x] Run loopback and separate-host real-NIC acceptance probes
- [x] Complete static, compatibility, and packaging gates
- [x] Complete the publication dry-run
- [x] Publish `v1.2.0` to Clojars and verify cljdoc

The v1.2 scope intentionally excludes multiple consumers, pub/sub, dynamic
BPF replacement, pause/resume, borrowed buffers, batching, parallel decode,
mmap, and PCAPNG. These capabilities require separate evidence and contracts.

## v1.3 release status

- [x] Add one composable `packet-xf` transformation source of truth
- [x] Add backend-neutral `fan-out`, `branch`, and `stats` public functions
- [x] Keep every branch bounded with explicit blocking or dropping behavior
- [x] Make branch ownership, cancellation, and close semantics deterministic
- [x] Add schema-versioned per-branch and distribution statistics
- [x] Prove slow-branch isolation, bounded heap, and source-head release
- [x] Pass the Linux/macOS, JDK 17/21, arm64, lint, coverage, and package gates
- [x] Clear the historical live floor with a separate-JVM Linux probe
- [x] Complete the publication dry-run on the release commit
- [x] Publish `v1.3.0` to Clojars and verify cljdoc

The v1.3 public surface remains deliberately small. It does not expose the
core.async backend, dynamically add or remove branches, or make a branch
multi-consumer. Those choices preserve ordinary seq/reduce composition and
keep ownership and overload behavior explicit.

## Performance track

The performance track preserves the v1 data-first API and advances only when
the preceding measurement gate provides evidence for the next change.

1. [x] Establish reproducible offline and loopback-live baselines.
2. [x] Compare the queue/lazy-seq path with a synchronous reducing path.
3. [x] Add opt-in flow projection and reduce allocation.
4. [x] Profile the parser and adopt only evidence-backed compatible changes.
5. [x] Tune live capture buffers and report drop location.
6. [ ] Consider borrowed buffers, batching, parallel decode, or mmap only if the
   earlier phases do not meet the documented throughput targets.

North-star targets on the reference Mac are 1.5M pps raw read, 1M pps flow
projection, 200k pps compatible full decode, and a continuously improving
60-second live rate below 0.1% drop. Phase-1 measurements may revise these
targets when the reason and baseline are documented.

The first reference run reached all three offline targets: 1.58M pps raw,
1.02M pps flow projection, and 299k pps compatible full decode. Parser
profiling did not justify replacing the compatible parser with a second
offset-based implementation. Phase 5 therefore remains focused on sustained
live drop behavior; phase 6 stays conditional rather than becoming default
scope.

The first 60-second buffered-immediate `lo0` probe sustained approximately
369k processed pps with zero reported kernel or interface drops and about
67 MB peak heap. The local UDP generator, rather than capture, limited this
probe. Phase 5 added direct, bounded-blocking, and bounded-dropping comparison
profiles; sender, libpcap, queue, and consumer stage counters; a 0.1%
sustainability classifier; and an external-generator profile for real-NIC or
separate-host tests. Controlled overload now distinguishes queue drops from
blocking backpressure.

The first separate-host probe used an Ubuntu 24.04 wired sender and the Intel
Mac's Wi-Fi interface. It sustained 7,500 pps for 60 seconds at 0.002%
end-to-end loss with no observable Paclo drop. This validates the external
measurement path but remains network-path limited; a wired-to-wired run is
still needed to find the real-NIC capture maximum.

The v1.2 managed-capture probe reused that path. Raw and full-decode managed
captures each processed an exact 15,000-packet run at 1,000 pps, but repeated
15- and 60-second results varied substantially despite zero observable
kernel, interface, queue, consumer-gap, or decode drops. The 60-second runs
kept bounded queue depths and approximately 63-67 MB peak heap. This validates
the managed lifecycle and records the required real-NIC observation, while
confirming that the current wired-to-Wi-Fi path cannot provide a repeatable
end-to-end throughput floor.

The v1.3 bounded fan-out track adds `paclo.stream/fan-out`, `branch`, and
`stats` as a small backend-neutral public surface. Combined offline runs
validated two blocking consumers, slow-branch drop isolation, bounded heap,
and the 1,250 bytes/packet allocation ceiling. A Linux separate-JVM live gate
then realized approximately 400k pps: dual fan-out delivered 2,000,000 packets
to each branch at approximately 392k pkt/s, and slow-dropping delivered all
1,000,000 packets to the fast branch at approximately 384k pkt/s. Both runs
reported zero kernel and managed-queue drops. This clears the historical 369k
live floor; packaging and release checks remain the final v1.3 work.

Phase 6 remains a post-v1.1 conditional investigation. Borrowed buffers,
batching, parallel decode, and mmap should be attempted only when a measured
workload remains below target after the compatible Phase 1-5 paths.

## Notes

- Public user docs are maintained in English (`README.md`, `docs/README.md`, `docs/usage.md`, `docs/extensions.md`).
- Internal planning notes may exist separately and are not part of the public API contract.
