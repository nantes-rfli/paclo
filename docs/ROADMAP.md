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

- `v1.4.0` (released, 2026-10-17): metadata-preserving capture I/O, explicit
  extensions/diagnostics, bounded Flow/Window/DNS analysis, multi-DLT decoding
  and metadata-aware PCAPNG read/write

## Released milestones and historical evidence

- v1.0: stable API, publication, Clojars and cljdoc support; details in
  [v1.0 release record](archive/release-v1-rc-checklist.md).
- v1.1: synchronous reduction, flow projection and measurement foundation;
  details in [v1.1 release record](archive/release-v1.1.0-checklist.md).
- v1.2: managed capture, result statistics, explicit lifecycle and stop behavior;
  details in [v1.2 release record](archive/release-v1.2.0-checklist.md).
- v1.3: packet transformations and bounded multi-consumer fan-out;
  details in [v1.3 release record](archive/release-v1.3.0-checklist.md).
- v1.4: packet preservation, bounded analysis and PCAPNG metadata;
  details in [v1.4 publication record](../dev/release-1.4.0-publication.md).

The canonical release-by-release change list is [CHANGELOG](../CHANGELOG.md).
Completed acceptance checks remain in the archived checklists, not in this live
roadmap. The current CI gates and developer procedures are documented in
[CONTRIBUTING.md](../CONTRIBUTING.md) and `.github/workflows/ci.yml`.

## Current priorities

The accepted next-development queue is maintained in
[`dev/codex-plan.md`](../dev/codex-plan.md), with dependencies and acceptance criteria.
P01–P08 are implemented and published in **v1.4.0 (2026-10-17)**, including
packet metadata preservation, explicit extensions, diagnostics, flow/window/DNS
analysis, Linux/macOS multi-DLT decoding and metadata-aware PCAPNG I/O.
Stabilization and measured flow/DNS/Ethernet improvements are also merged.
The plan assigns completed items to v1.4.0; older phase labels in historical
records do not imply separate releases. Developer setup and verification are in [`CONTRIBUTING.md`](../CONTRIBUTING.md).

`v1.4.0` is the published stable version, retaining approved Writer correctness/
validation and DNS bounded-report/failure policies. See the
[migration guide](migration-from-1.3.md), [release notes](release-notes-1.4.0.md)
and [publication record](../dev/release-1.4.0-publication.md) for actual release
artifacts and acceptance evidence.
Issues [#37](https://github.com/nantes-rfli/paclo/issues/37) and
[#44](https://github.com/nantes-rfli/paclo/issues/44) are closed after acceptance
of the measured DNS and Ethernet work. DNS PR #57 is included in v1.4.0;
[PR #66](https://github.com/nantes-rfli/paclo/pull/66) merged after publication
and remains unreleased. Its accepted memory/rebuild costs and missing long
production-PCAP/live-NIC evidence remain documented; closure does not establish
general production throughput. P09/P10 remain blocked on a concrete integration
need or measured workload shortfall.

Next development starts with **P11, an environment and tooling inventory**.
The P11–P17 candidates prioritize stable Clojure adoption, JDK/dependency health,
practical REPL workflows and interoperability with real PCAP/PCAPNG files while
preserving the v1 API and lightweight dependencies. JDK 25 compatibility and
Clojure 1.13 preparation require separate evidence and adoption decisions.
Detailed prerequisites, priority and acceptance criteria belong in the plan.
`v1.5.0` is a possible next release, with no committed feature set, release date
or version change from this planning update.

Continue long-window ARM64 observation, release automation maintenance and
documentation polish. Optional integrations and new abstractions require a
demonstrated workflow; performance changes require measurements.

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
