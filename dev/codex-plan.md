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
| P01 | v1.3.x | Align public documentation with v1.3 behavior | — | in-progress |
| P02 | v1.3.x or v1.4 | Preserve packet metadata through PCAP read/write | — | ready |
| P03 | v1.4 | Explicit per-pipeline decode extensions | P01 | blocked |
| P04 | v1.4 | Packet/flow contracts and structured diagnostics | P02, P03 | blocked |
| P05 | v1.4 or later | Identify link types and report unsupported decoding | P04 | blocked |
| P06 | v1.5 | Reusable flow keys and aggregates | P04 | blocked |
| P07 | v1.5 | Bounded time windows and DNS request/response analysis | P03, P04, P06 | blocked |
| P08 | Later | Broader link-type and PCAPNG support | P05, concrete fixtures | blocked |
| P09 | Later | Optional integrations and reducible-source investigation | Demonstrated use case | blocked |
| P10 | Conditional | Borrowed buffers, batching, parallel decode, or mmap | Measured target shortfall | blocked |

Default next task: **finish P01 review and verification in PR #17**, then P02.
Implement one reviewable item or a documented slice at a time. Update this
queue after completion; do not start all phases together.

## P01: Documentation and API discovery

Known baseline gaps:

- `core/packet-xf` exists but is absent from the README public API table and API contract.
- `docs/usage.md` says fan-out is unavailable despite the v1.3 public stream API.
- README's DNS quick check requires the nonexistent `paclo.dns.decode` namespace.

Document the selection among synchronous reduction, managed capture, and fan-out.
Explain that taking a prefix of a lazy sequence does not itself stop its source.
Show reliable early termination with reduction or explicit `with-open` ownership.
Document existing stop defaults and distinguish finite-file completion from limits.

Acceptance: examples execute; API docs agree; resource-owning examples close on
early termination. This item must not invent new runtime APIs.

Documentation submitted in [PR #17](https://github.com/nantes-rfli/paclo/pull/17)
on 2026-10-11. README, usage guide, API contract, and extension guide now
cover `packet-xf`, bounded fan-out, early closure, stop defaults, EOF, and
the existing writer limitations; the incorrect DNS namespace was corrected.
Static checks passed (code/API cross-reference, Markdown fence balance,
obsolete namespace and placeholder function scans). Example execution,
Markdown lint, and full tests have not been run locally from this chat
environment. Keep P01 in progress until the PR is reviewed, CI is checked,
and the example-execution acceptance is verified.

## P02: Faithful PCAP round trips

Baseline reads emit `:ts-sec`/`:ts-usec`; the writer consumes `:sec`/`:usec`.
Passing a captured map directly to the writer replaces its time with wall-clock time.
The writer also constructs both lengths from the byte array, losing original `:len`
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

Baseline `packet-xf` consults the process-wide hook registry while processing packets.
Registering a hook after constructing the same transducer changes its output.
DNS/TLS annotation functions are currently private and exposed through registration.

Add an explicit, ordered extension configuration to the transformation path and
publish supported ordinary annotation functions. Proposed option name: `:extensions`.
Finalize names in a short design note before freezing them.

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

Full and flow decoding currently assume Ethernet. Surface the actual source link type
and dispatch or explicitly reject unsupported decoding, preserving raw capture access.
Define metadata placement and stats behavior across live/offline execution before
adding new native bindings or public keys.

Acceptance: Ethernet behavior is compatible; a non-Ethernet fixture cannot silently
appear to be a valid Ethernet decode. Use Linux cooked and loopback fixtures to select
the next supported types. Validate native calls on the existing platform matrix.

## P06: Reusable flow analysis

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

## Verification record and handoff format

For each completed slice append:

```text
Item / slice:
Status and implementation commit or PR:
Contract decisions:
Commands and measured results:
Unverified platforms or blocked checks:
Next item:
```

Baseline investigation: 34 focused tests / 118 assertions passed on Linux/JDK 21.
Timestamp replacement and global-hook dependence were reproduced. That investigation
did not validate live capture or rerun historical performance measurements.
See `dev/codex-environment-validation.md` for preparation results.

Item / slice: P01 / public API and usage documentation
Status and implementation commit or PR: PR #17 (review and validation pending)
Contract decisions: Document only the shipped v1.3 API; no new runtime options;
  `packet-xf` is public and fan-out is separately owned; current writer
  metadata loss remains until P02.
Commands and measured results: GitHub source/API inspection and static
  documentation consistency checks passed; runtime examples, local lint,
  and tests were not executed in this chat environment.
Unverified platforms or blocked checks: Executable example acceptance,
  PR CI, local Markdown lint, live capture, macOS/arm64.
Next item: Finish P01 verification/review; then P02.
