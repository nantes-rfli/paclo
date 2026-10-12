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

## Released milestones and historical evidence

- v1.0: stable API, publication, Clojars and cljdoc support; details in
  [v1.0 release record](archive/release-v1-rc-checklist.md).
- v1.1: synchronous reduction, flow projection and measurement foundation;
  details in [v1.1 release record](archive/release-v1.1.0-checklist.md).
- v1.2: managed capture, result statistics, explicit lifecycle and stop behavior;
  details in [v1.2 release record](archive/release-v1.2.0-checklist.md).
- v1.3: packet transformations and bounded multi-consumer fan-out;
  details in [v1.3 release record](archive/release-v1.3.0-checklist.md).

The canonical release-by-release change list is [CHANGELOG](../CHANGELOG.md).
Completed acceptance checks remain in the archived checklists, not in this live
roadmap. The current CI gates and developer procedures are documented in
[CONTRIBUTING.md](../CONTRIBUTING.md) and `.github/workflows/ci.yml`.

## Current priorities

The accepted next-development queue is maintained in
[`dev/codex-plan.md`](../dev/codex-plan.md), with dependencies and acceptance criteria.
It prioritizes faithful packet round trips, explicit extension composition, data
contracts, and reusable analysis. Release labels there are candidates. Developer
setup and verification are in [`CONTRIBUTING.md`](../CONTRIBUTING.md).

`v1.3.0` is shipped. P02 packet metadata preservation is implemented in
`[Unreleased]`, with CI and review tracked in the accepted plan. P03 is in progress;
acceptance still requires review and merge.

- [ ] Stabilize arm64 success rate against long observation windows
- [ ] Keep publish/release automation healthy (token rotation, workflow maintenance)
- [ ] Continue documentation polish for user-facing pages and examples
- [ ] Add optional integrations only as opt-in aliases (no heavy default dependencies)

## Performance direction

Paclo keeps its v1 data-first API and promotes optimizations only on measured
evidence. The offline measurement, synchronous reduction, numeric projection,
parser profiling and live queue observability phases have been completed.

Reference-Mac targets remain 1.5M pps raw, 1M pps numeric flow projection,
200k pps compatible full decode, and less than 0.1% drop over sustained
60-second live runs. These are targets, not cross-platform performance guarantees.

Borrowed buffers, batching, parallel decode and mmap remain conditional
investigations, not approved implementations. See the
[accepted development plan](../dev/codex-plan.md) for P10 dependencies and
[performance measurement](performance.md) for reproducible evaluation.
Historical measurements and the limits of each observation are preserved in
[performance evidence](archive/performance-results.md).

## Notes

- Public user docs are maintained in English (`README.md`, `docs/README.md`, `docs/usage.md`, `docs/extensions.md`).
- Internal planning notes may exist separately and are not part of the public API contract.
