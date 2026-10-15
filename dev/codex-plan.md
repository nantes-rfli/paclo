# Accepted Paclo development plan

The user accepted this direction on 2026-10-11. Baseline: main at
`aaa3ec7bd3ac686c2e7ef85f1cf13c2245eb1978`, after v1.3.0.
This file is the persistent work queue for future Codex tasks.
Environment preparation does not implement the feature items below.

## Goal and decision rules

Make packets ordinary Clojure data that can be composed, preserved, inspected,
and replayed. Preserve the small public API and the current v1 contract.

- Separate pure transformations from capture, scheduling, clocks, output, and CLI policy.
- Use ordinary functions, maps, `comp`, reducers, and transducers before new abstractions.
- Keep state, ownership, time, overload, and termination explicit.
- Preserve existing keys and behavior; introduce compatible opt-in paths.
- Keep optional dependencies optional and optimize only against measured needs.

## Work queue

Statuses: `ready`, `blocked` (by the listed prerequisites), `in-progress`, `done`.
Release labels are planning candidates, not scheduled or approved publications.

| ID | Candidate | Task | Depends on | Status |
| --- | --- | --- | --- | --- |
| P01 | v1.3.x | Align public documentation with v1.3 behavior | — | done |
| P02 | v1.3.x or v1.4 | Preserve packet metadata through PCAP read/write | — | done |
| P03 | v1.4 | Explicit per-pipeline decode extensions | P01 | done |
| P04 | v1.4 | Packet/flow contracts and structured diagnostics | P02, P03 | done |
| P05 | v1.4 or later | Identify link types and report unsupported decoding | P04 | done |
| P06 | v1.5 | Reusable flow keys and aggregates | P04 | done |
| P07-A | v1.5 | Pure bounded time windows and DNS correlation | P03, P04, P06 | done |
| P07-B | v1.5 | DNS CLI migration and bounded reporting | P07-A | done |
| P08-A | Later | Capture capability inventory and fixture-backed scope | P05, P07-B | done |
| P08-B1 | Later | Native read failures and failed-open ownership | P08-A | done |
| P08-B2 | Later | Explicit single-DLT Classic PCAP writer | P08-B1 | done |
| P08-C | Later | Shared link framing and SLL/SLL2 full/flow decoding | P08-B2 | done |
| P08-D1 | Later | Raw IP IPv4/IPv6 full/flow decoding | P08-C | done |
| P08-D2 | Later | NULL/LOOP full/flow decoding after AF/endian probes | P08-D1 | done |
| P08-E1 | Later | Metadata-aware PCAPNG and exact timestamp contract design | P08-D2 | done |
| P08-E2 | Later | Bounded metadata-aware PCAPNG reader and exact input time | P08-E1 | in-progress |
| P08-E3 | Later | Explicit PCAPNG writer preservation and loss policies | P08-E2 | blocked |
| P09 | Later | Optional integrations and reducible-source investigation | Demonstrated use case | blocked |
| P10 | Conditional | Borrowed buffers, batching, parallel decode, or mmap | Measured target shortfall | blocked |

Default next task: **P08-E2 correction CI (#51/#52), then independent re-review of PR #50**.
E1 merged as `2e7e357` through PR #47; Issue #48's full Eastwood gate fix merged
as `008c93b` through PR #49. E2 starts from that main; E3 waits for E2.
P08-D2 merged through [PR #46](https://github.com/nantes-rfli/paclo/pull/46)
at `ccebcad`; P08-D1 merged through PR #45 at `0d06dd1`.
P08-C merged through [PR #43](https://github.com/nantes-rfli/paclo/pull/43)
at `9d83bb2` on 2026-10-14.
P08-B2 merged through [PR #42](https://github.com/nantes-rfli/paclo/pull/42)
at `4998ddc`. Its implementation and verification evidence remains in the work log.
P08-B1 merged through [PR #41](https://github.com/nantes-rfli/paclo/pull/41)
at `c729e19`. P08-A merged through PR #38 at `8663e69`.
Implement one reviewable item or a documented slice at a time. Update this
queue after completion; do not start all phases together.

## CI maintenance: Issue #48

Status: **done**, implementation, local checks and all 12 CI jobs pass on
[PR #49](https://github.com/nantes-rfli/paclo/pull/49), merged as `008c93b`.
This is a separate maintenance item
from the feature queue. Start: latest main `2e7e357` after PR #47 merged.
Compile Java/native prerequisites in the dedicated Eastwood job, fail on
reported analysis/linter errors, and require Eastwood in the `build` aggregate.
Preserve all lint roots/rules/excludes and existing quality/performance gates.
Four isolated JVM probes cover complete analysis, informational warnings,
evaluation failure and analysis failure with a dependent namespace unanalyzed.
Detailed commands, full namespace inventory and CI timing comparison are in
[the work log](work-log.md). This maintenance item is complete.
P08-E2/E3 and other feature implementation are outside this task.

## P01: Documentation and API discovery

Status: **done**. PR #17 was merged on 2026-10-11, documenting the
released v1.3 public API without creating new runtime behavior. Its eight
executable documentation examples are maintained by
`dev/script/verify_doc_examples.py`; PR #26 generalized their identification
and execution. Full verification evidence and any historical pending-merge
statements are retained in [the work log](work-log.md).

## P02: Faithful PCAP round trips

Status: **done**. [PR #29](https://github.com/nantes-rfli/paclo/pull/29)
was merged on 2026-10-12. Local checks and all implementation-commit CI jobs passed,
including Linux x64/JDK21, macOS ARM64/JDK17 and the Linux ARM64 monitor.
Evidence is tracked in [the work log](work-log.md); the final evidence-only
commit's checks are reported in the PR. Merge acceptance completes P02;
this status update does not establish a separate independent review.
P03 is now accepted; P04 is the current feature.

Released v1.3.0 reads emit `:ts-sec`/`:ts-usec`; its writer consumes `:sec`/`:usec`.
Passing a captured map directly to that writer replaces its time with wall-clock time.
That writer also constructs both lengths from the byte array, losing original `:len`
for truncated captures. These are distinct from later PCAPNG format support.

- Accept captured maps directly while keeping legacy timestamp inputs working.
- Specify precedence when both timestamp pairs occur, partial/invalid timestamps,
  and the retained current-time behavior for raw bytes without timestamps.
- Preserve captured bytes and original packet length; validate length consistency.
- Document the Ethernet/link-type boundary rather than promising all-format round trips.
- Assess compatibility before selecting a patch or minor release; do not rename existing keys.

Acceptance: real read/filter/write/read fixtures preserve timestamps, bytes, capture
length, and wire length. Include truncated records, zero timestamps, legacy inputs,
and conflicting metadata. Use packet-byte equality rather than Java-array identity.

## P03: Explicit extension composition

Status: **done**. [PR #30](https://github.com/nantes-rfli/paclo/pull/30)
was merged on 2026-10-12 at `e778895`. Its final CI run passed all 12 jobs,
including Linux x64/JDK21, macOS ARM64/JDK17 and Linux ARM64/JDK21.
Historical design and verification evidence is retained in [the work log](work-log.md).

At the P03 baseline, `packet-xf` consulted the process-wide hook registry while
processing packets. Registering a hook after constructing the same transducer
changed its output. DNS/TLS annotations were private and exposed via registration.

Add an explicit, ordered extension configuration to the transformation path and
publish supported ordinary annotation functions. Final option: `:extensions`;
public functions: `annotate-dns` and `annotate-tls-sni`. The pre-implementation
design note and final choices are recorded in the work log.

- An explicit vector selects exactly those functions; an empty vector selects none.
- Omission preserves the existing global registry behavior for v1 callers.
- Explicit selection must not merge in or re-read the global registry.
- Share the same semantics across `packet-xf`, packets, reduction, reports, and managed capture.
- Preserve ordering and define failure handling and full-decode/flow applicability.
- Existing `register!`, `unregister!`, and `apply!` behavior remains compatible.

Acceptance: independent simultaneous pipelines and fan-out branches cannot alter each
other's selected extensions; same input and configuration produce the same result
when supplied functions are pure. Test exceptions, non-map results, empty selection,
registration changes after construction, and legacy behavior.

## P04: Data contracts and diagnostics

Status: **done**. [PR #31](https://github.com/nantes-rfli/paclo/pull/31)
was merged on 2026-10-12 at `17d8bf1`. Implementation and verification evidence
is retained in the work log. P05 is accepted; P06 prerequisites are complete.

Document packet and flow key types, timestamp units, missing/unsupported values,
and metadata preservation. Use an additive contract; avoid requiring a heavy schema
library or per-packet validation on the hot path.

Keep `:decode-error` strings for compatibility and add structured diagnostic data
with stable stage/reason fields and location when available. Make extension failures
observable through an explicitly selected policy or report without changing legacy
exception isolation. Decide how diagnostic schema evolution relates to existing
schema-versioned execution statistics.

Document that byte arrays are mutable and references are shared across fan-out
branches. Treat published packet bytes as read-only; show copying before mutation.
Do not claim that putting an array in an immutable map makes the array immutable.

Acceptance: consumers can distinguish unsupported input, malformed data, and extension
failure without parsing prose. Diagnostics/stats intended as data can round-trip as EDN.
Test meaningful invariants with `test.check` and validate performance impact.

## P05: Link-type awareness

Status: **done**. [PR #32](https://github.com/nantes-rfli/paclo/pull/32)
implements native DLT metadata and safe Ethernet dispatch. Local verification
and all 12 implementation CI jobs passed, including the supported platform
matrix and ARM64 monitor. Evidence is tracked in the work log.
Merged on 2026-10-12 in main `7711170`.

Full and flow decoding at the baseline assume Ethernet. Surface the actual source link type
and dispatch or explicitly reject unsupported decoding, preserving raw capture access.
Define metadata placement and stats behavior across live/offline execution before
adding new native bindings or public keys.

Acceptance: Ethernet behavior is compatible; a non-Ethernet fixture cannot silently
appear to be a valid Ethernet decode. Use Linux cooked and loopback fixtures to select
the next supported types. Validate native calls on the existing platform matrix.

## P06: Reusable flow analysis

Status: **done**. PR #33 merged on 2026-10-12 at `0665c09`.
[PR #33](https://github.com/nantes-rfli/paclo/pull/33) contains the implementation.
Three public functions in
`paclo.flow` use a six-field numeric canonical key, immutable bounded aggregates
and deterministic Top-N. Projection moved to internal `paclo.flow.project`.
Full decode retains its legacy display descriptor; CLI delegates analysis,
adds --max-flows and preserves display formats. Tests include 650 property
cases, real PCAP processing paths and independent fan-out; all 16 executable
documentation examples pass, including the previous 14. Local performance gate
and clean JAR consumer pass. All 12 implementation CI jobs passed on `64b0df6`,
including Linux x64/JDK21, macOS ARM64/JDK17 and Linux ARM64/JDK21. Measurement evidence and limitations are in the
work log; persistent analysis costs more than the old unchecked mutable CLI.
P07 is split into P07-A (pure analysis) and P07-B (CLI migration).
Performance improvement remains tracked separately in issue #34.

Extract the useful behavior in `dev/examples/flow_topn.clj` into small supported
functions: unidirectional/bidirectional keys, counts/bytes, and result projection.
Keep formatting and CLI argument handling in examples. Choose a public namespace
deliberately; `paclo.flow` is currently internal.

Acceptance: vectors, offline packets, and managed streams reuse the same analysis;
results are ordinary data. Specify ordering, IPv4/IPv6, absent ports, and whether
bytes means captured or wire bytes. Define a cardinality limit or bounded variant
before recommending unbounded-duration aggregation. Confine optimized mutation.

## P07-A: Pure bounded time windows and DNS correlation

Status: **done**. PR #35 merged on 2026-10-12 at `2e15af7`. `paclo.window` and `paclo.dns` provide ordinary
immutable state transitions. [PR #35](https://github.com/nantes-rfli/paclo/pull/35)
passed all 12 implementation CI jobs on `902eef8`.
The [pre-implementation design](p07-a-design.md)
fixes event time, explicit watermarks, lateness, retries, ambiguity, quarantine,
expiry and required cardinality limits. Reuse existing DNS decode/annotation.
Validate determinism, EDN, immutable snapshots, bounded retention and actual
PCAP capture/reduction/fan-out paths. Do not migrate the existing DNS CLIs.

## P07-B: DNS CLI migration and bounded reporting

Status: **done**. PR #36 merged on 2026-10-14 at `8312d10`; all 12 implementation
CI jobs passed on `30cd06a`. The [CLI migration contract](p07-b-design.md)
and [work log](work-log.md) document strict DNS RTT correlation, packet QPS
windows, exact microseconds and max-event-time/reorder watermarks. CLI-only
report state is bounded: topN pairs, exact samples/qname groups, active windows/
groups and finalized/filled rows. Overflow fails before output. Sync/async
share packet steps and one source-owning delivery adapter; cancellation/drop
metadata never becomes analysis data. Corrected native RTT, average, empty fill,
source EOF limits and deterministic ties are documented with regression tests.
CI outcomes and platform/performance evidence are maintained on
[PR #36](https://github.com/nantes-rfli/paclo/pull/36). Performance issues #34 and #37
remain separate. P08-A now inventories native I/O without adding decoders.

## P08-A: Capture format and link-type investigation

Status: **done**. [PR #38](https://github.com/nantes-rfli/paclo/pull/38)
merged on 2026-10-14 at `8663e69`.
The [capability inventory and design](p08-a-capture-formats.md) separate code,
native specification and measured results. 28 deterministic fixtures and native
precision probes pass on Linux x64/libpcap 1.10.4, macOS ARM64/libpcap 1.10.1
and Linux ARM64/libpcap 1.10.4. All 12 implementation CI jobs passed on `43138ba`
after retrying an unassigned macOS runner; no gate changed. No new public API
or decoder was added. See the work log for initial failures and limitations.

## P08-B: Explicit and safe capture I/O subset

Status: B1 **done**, merged through [PR #41](https://github.com/nantes-rfli/paclo/pull/41)
at `c729e19`; B2 **done**, merged on
[PR #42](https://github.com/nantes-rfli/paclo/pull/42).
All 12 implementation CI jobs passed on `edc1c4e`, including Linux x64/JDK21,
macOS ARM64/JDK17 and Linux ARM64/JDK21. Native read errors now throw by default;
pass retains the valid prefix with failed/error stats and structured native
reason/phase/return code/message in schema v1. One setup owner closes failed
offline/live/configured opens exactly once without masking the cause (issue #39).
Lazy terminal/error notification lives outside the packet queue; abandonment
while blocked delivering packets remains issue #40. All 28 format fixtures and
ownership/callback/full-queue regression tests pass. Detailed local/CI evidence
is in the work log. No new decoder, writer behavior or version was added.

B2 implementation is complete in `c08fe6d`: the public three-argument writer
uses the existing internal writer and rejects known framing mismatches/invalid
options/snaplen excess. Valid two-argument Ethernet inputs remain compatible;
non-Ethernet maps require matching native DLT options. Shared cleanup preserves
primary failures; int flush status and Linux/macOS sticky stream-error inspection
report known output failures. Six native DLT round trips and all 28 fixtures,
405 local tests, 22 executable examples, Java quality, performance and isolated
JAR consumer checks pass. All 12 implementation CI jobs passed on `75c5906`, including Linux x64/JDK21,
macOS ARM64/JDK17 and Linux ARM64. Final evidence-head checks are maintained on
the PR; first-run lint configuration failure and correction are in the work log.
No gate/version change. SLL/SLL2 shared full/flow framing forms the next slice
in P08-C; PCAPNG metadata/writing and exact timestamps require separate
contracts. Issue #40 and performance issues #34/#37 remain outside B2.

## P08-C: Shared framing and Linux cooked decoding

Status: **done**, merged on 2026-10-14 at `9d83bb2` through
[PR #43](https://github.com/nantes-rfli/paclo/pull/43). Implementation `5d5e848`
and all local gates are complete. [CI run 38525529813](https://github.com/nantes-rfli/paclo/actions/runs/38525529813)
passed all 12 jobs, including Linux x64/JDK21, macOS ARM64/JDK17 and Linux ARM64.
Full/flow share packed framing, cooked IP/L4 parsers and diagnostics; raw arrays,
Ethernet shapes, extensions and P06/P07 composition are preserved. 28 original
and four new captures, 412 tests, 300 cooked property cases, 24 executable docs,
JAR consumer and unchanged quality/performance gates pass. See the
[performance comparison](p08-c-performance.md) for the measured Ethernet CPU cost
and allocation reductions, and [work log](work-log.md) for complete evidence.
Final evidence-head checks remain on PR #43. These offline checks do not imply
release, live/NIC throughput or unmeasured-platform validation.

- Share bounds-checked Ethernet/VLAN, SLL (DLT 113), SLL2 (DLT 276) framing in
  `paclo.linktype`; return packed L3 offset/protocol without a per-packet map on
  the flow path. Full decode builds link-specific fields separately.
- Reuse existing full IP/L4 parsers and numeric flow walkers; preserve Ethernet
  shapes, absent-DLT legacy behavior, ownership, metadata and explicit extensions.
- Add deterministic cooked IPv4/IPv6/protocol/fragment/malformed fixtures while
  retaining P08-A's 28 fixtures and P05 inputs. Cover all public execution paths,
  independent fan-out, flow aggregates and time-window/DNS composition.
- Document fields and diagnostic boundaries; retain 22 maintained examples and
  add runnable cooked samples. Measure Ethernet before/after and cooked decode
  throughput/allocation, with unchanged performance gates.
- Run focused/full/static/documentation/fixture/package/consumer checks, open an
  independent PR and inspect all CI jobs including the native platform matrix.
  Review/merge, releases, NULL/LOOP/Raw decoders, PCAPNG metadata/writer, exact
  timestamps, issue #40 and performance issues #34/#37 are outside this task.

## P08-D1: Raw IP full and flow decoding

Status: **done**, merged on 2026-10-14 at `0d06dd1` through
[PR #45](https://github.com/nantes-rfli/paclo/pull/45). Implementation `bc2e9a0`
starts from P08-C main `9d83bb2`. Local check passes 418 tests, 10 JUnit tests,
35 captures, 200 Raw property cases and all 26 executable examples. Package and
isolated JAR consumer pass. The [performance evidence](p08-d1-performance.md)
retains mixed and controlled single-DLT comparisons, negative variation and
unchanged allocations/gates. D2's [handoff](p08-d2-null-loop.md) is complete;
NULL/LOOP runtime probes/decoders remain unfinished. Implementation
[CI run 38543025204](https://github.com/nantes-rfli/paclo/actions/runs/38543025204)
passed all 12 jobs, including Linux x64/JDK21, macOS ARM64/JDK17 and Linux ARM64.
Final evidence-head checks are maintained on the PR. No release or merge here.

- Add bare IPv4/IPv6 framing at offset zero to `paclo.linktype`, using the version
  nibble and measured Linux/macOS native DLT_RAW 12; reject savefile code 101
  and guessed mappings on other systems. Use `{:type :raw-ip :l3 ...}`.
- Reuse full IP/L4 and fast numeric projection, with extensions, fragments,
  structured absolute diagnostics and all capture/analysis paths unchanged.
- Deterministic fixtures, property regressions, executable full/flow docs,
  Ethernet/cooked/Raw throughput and allocation, all existing gates, packaged
  consumer, independent PR and supported-platform CI are required.
- Keep the P08-C Ethernet full slowdown (4.9–9.8%) visible and track improvement
  in [issue #44](https://github.com/nantes-rfli/paclo/issues/44). Do not loosen
  performance gates or implement NULL/LOOP here.

## P08-D2: NULL/LOOP decoding

Status: **done**. [PR #46](https://github.com/nantes-rfli/paclo/pull/46)
merged at `ccebcad`; the implementation/verification history follows.
Probe-only `9e36c04` passed all 12 CI jobs on
[run 38577395767](https://github.com/nantes-rfli/paclo/actions/runs/38577395767)
before decoder edits. Linux x64/macOS ARM64/Linux ARM64 all return the stored
NULL/LOOP bytes unchanged across both Classic/PCAPNG container orders and all
IPv6 AFs; native DLT 0/108. [Measurement data](p08-d2-native-evidence.edn),
[final contract](p08-d2-null-loop.md) and [performance comparisons](p08-d2-performance.md)
separate measured results from source inference and remaining platform limits.
Shared framing at offset 4, truthful full wrappers and numeric projection are
implemented, with distinct unknown-AF/version mismatch diagnostics, unchanged
arrays and IP/L4/extension/analysis contracts. Local 428 tests, 10 JUnit, 47
fixtures, 500 new property cases, 28 executable docs, Java quality and isolated
JAR consumer pass. Final controlled comparisons retain negative Flow medians,
unchanged allocations and unchanged performance gates. Implementation `93e5cde`
passed all 12 jobs on [CI run 38582258137](https://github.com/nantes-rfli/paclo/actions/runs/38582258137),
including Linux x64, macOS ARM64 and Linux ARM64. Final evidence-head checks
are maintained on the PR. Review/merge subsequently completed; no release or
unrelated issue work was performed by the implementation task.
The completed native prerequisite establishes unchanged pseudoheaders; NULL
uses unique known AF interpretation in either order, LOOP strictly big endian.
Unmeasured OS mappings, live/NIC validation, PCAPNG metadata/writing, exact
precision and container-order inference remain outside this item.

## P08-E1: Metadata-aware PCAPNG and exact timestamp design

Status: **done**, merged as `2e7e357` through
[PR #47](https://github.com/nantes-rfli/paclo/pull/47). Design, deterministic
fixtures and characterization are complete in this task; no new public API or
production reader/writer is implemented. Baseline is D2 main `ccebcad`.
The [E1 contract and handoff](p08-e1-pcapng-contracts.md) is authoritative for
future PCAPNG event/descriptors, exact ticks/resolution/offset/absence,
Closeable single-consumer reduction, limits, failure and output loss policies.
P08-A remains historical native evidence; the v1 contract remains implemented
behavior. Ten additional captures and six Python wire/arithmetic tests run via
`paclo.pcapng-contract-design-test` in the unchanged platform suites. Actual
commands/results and platform limits are recorded in the work log.

## P08-E2: Bounded metadata-aware PCAPNG reader

Status: **in-progress** for review corrections and independent re-review on
[PR #50](https://github.com/nantes-rfli/paclo/pull/50).
Initial implementation from main `008c93b` passed all 12 CI jobs on Linux x64,
macOS ARM64 and Linux ARM64, but independent review requested
[multi-address IDB regression coverage (#51)](https://github.com/nantes-rfli/paclo/issues/51)
and [packet prefix preallocation enforcement (#52)](https://github.com/nantes-rfli/paclo/issues/52).
Both follow-ups are implemented with positive address-option coverage and packet
prefix validation; 18 focused tests / 1323 assertions, 449 full tests / 17070
assertions and local quality/doc/performance gates pass. Unchanged platform CI
and independent re-review remain pending; merge remains pending. Implementation follows the reviewed
[E2 steps and acceptance](p08-e1-pcapng-contracts.md#p08-e2-implementation-plan-and-acceptance):
checked file cursor, SHB/IDB/EPB/SPB, ordered owned option/opaque data, exact
integer time, Closeable IReduceInit source and bounded status. Existing native
APIs remain unchanged; prove lifecycle/limits with real fixtures and constrained
heap streaming. Public contract/changelog updates accompany actual behavior.
No writer, live metadata, issue #40 change or performance work in this item.

## P08-E3: PCAPNG writer

Status: **blocked** by E2. Implement the reviewed
[E3 steps and acceptance](p08-e1-pcapng-contracts.md#p08-e3-implementation-plan-and-acceptance):
ordered encoding, preserve/lossy/author policies, exact timestamp validation,
unknown/no-copy restrictions, semantic round trips and atomic path publication.
Prove failure cleanup and source ownership; preserve Classic write-pcap! behavior.
No byte-identical reproduction, append/stream output, release or merge authority.

## P08-P10: Evidence-driven expansion

- P08: first inventory what the installed libpcap already reads. Explicitly define
  supported PCAPNG blocks, multiple interfaces/link types, timestamp resolution,
  read versus write support, and metadata loss. Add support in fixture-backed slices.
- P09: add optional export/inspection integrations only for a concrete user workflow.
  Investigate an `IReduceInit` source only if existing reduction and stream branches
  leave a demonstrated composition gap; define reopen/single-use and close semantics.
- P10: retain current ownership and copying defaults. Investigate borrowed buffers,
  batching, parallel decode, or mmap only after profiling a workload below target.
  Prove lifetime, ordering, cancellation, allocation, and throughput before adoption.

Use the existing measurement runners. Current historical offline targets were met;
the wired-to-wired real-NIC ceiling remains separate from loopback evidence.

## Verification and handoff

When work is completed, update this queue's task status and dependency readiness.
Record detailed PR, test commands, outcomes, decisions, and remaining limitations
in [the development work log](work-log.md). A passed offline CI check does not
establish live capture or real-NIC performance.
