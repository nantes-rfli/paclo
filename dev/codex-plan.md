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
| P06 | v1.5 | Reusable flow keys and aggregates | P04 | in-progress |
| P07 | v1.5 | Bounded time windows and DNS request/response analysis | P03, P04, P06 | blocked |
| P08 | Later | Broader link-type and PCAPNG support | P05, concrete fixtures | blocked |
| P09 | Later | Optional integrations and reducible-source investigation | Demonstrated use case | blocked |
| P10 | Conditional | Borrowed buffers, batching, parallel decode, or mmap | Measured target shortfall | blocked |

Default next task: **P06 independent review and merge**. P05 was merged through
PR #32 on 2026-10-12. P07 awaits P06 acceptance; P08 still needs a
fixture-backed scope decision.
Implement one reviewable item or a documented slice at a time. Update this
queue after completion; do not start all phases together.

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

Status: **in-progress** (implementation, local verification and implementation CI complete;
independent review and merge remain required).
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
After P06 acceptance, the next feature is **P07**, bounded windows and DNS
correlation; those behaviors are not part of P06.

Extract the useful behavior in `dev/examples/flow_topn.clj` into small supported
functions: unidirectional/bidirectional keys, counts/bytes, and result projection.
Keep formatting and CLI argument handling in examples. Choose a public namespace
deliberately; `paclo.flow` is currently internal.

Acceptance: vectors, offline packets, and managed streams reuse the same analysis;
results are ordinary data. Specify ordering, IPv4/IPv6, absent ports, and whether
bytes means captured or wire bytes. Define a cardinality limit or bounded variant
before recommending unbounded-duration aggregation. Confine optimized mutation.

## P07: Time windows and DNS analysis

Build on the existing DNS QPS/RTT examples. Prefer a deterministic state transition,
for example `(step state event) -> {:state next-state :events [...]}`; names are a
design sketch. Supply time/expiration explicitly and keep clocks outside the pure core.

Specify event time versus processing time, out-of-order records, window closing,
DNS retransmissions/ID reuse, expiry, and outstanding-request/cardinality bounds.
Use a fresh state per reduction; do not share a stateful reducing function between consumers.

Acceptance: offline replay and live adapters agree for the same ordered events;
expiry and bounds are deterministic; long-running state remains bounded. CLI
examples become thin clients of these functions. Document approximate statistics
if exact quantiles or top-N would require unbounded memory.

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
