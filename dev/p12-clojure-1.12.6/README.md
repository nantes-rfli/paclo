# P12: Clojure 1.12.6 adoption

Baseline: main `e05e0c67735be7b4b39a3730dfbe12ed2bd30945`, after reviewed
[PR #69](https://github.com/nantes-rfli/paclo/pull/69). Date: 2026-10-18 (Asia/Tokyo).
The supplied checkout was clean. This item adopts Clojure 1.12.6; it does not
assign a release scope/date to the retained `1.5.0-SNAPSHOT` identifier.

## Dependency and compatibility decision

| Coordinate | Before | After |
| --- | --- | --- |
| org.clojure/clojure | 1.12.1 | 1.12.6 |
| org.clojure/spec.alpha (transitive) | 0.5.238 | 0.5.238 |
| org.clojure/core.specs.alpha (transitive) | 0.4.74 | 0.4.74 |
| org.clojure/core.async | 1.6.681 | 1.6.681 |
| com.github.jnr/jnr-ffi | 2.2.14 | 2.2.14 |
| org.clojure/data.json | 2.5.0 | 2.5.0 |
| com.github.spotbugs/spotbugs-annotations | 4.8.6 | 4.8.6 |

The complete `clojure -Stree` results in [deps-before.txt](deps-before.txt) and
[deps-after.txt](deps-after.txt) differ only in the Clojure version. The separate
`dev/perf-merge/deps.edn` is aligned to 1.12.6; its data.json remains 2.5.0.
The exact distribution dependency allowlist changes only Clojure. The CLI and
isolated tools.build/development-tool dependency graphs retain their existing
selections; their bundled/transitive runtimes are not Paclo's production pin and
upgrading those tools belongs to separate work. Negative POM
controls reject the old Clojure version, unintended core.async/JNR upgrades and
changed dependency semantics; they assert that each mutation actually applies.
Historical release evidence, P11 findings and prior measurements retain their
original versions. No production source or public function signature changes.

Rechecked official [stable downloads](https://clojure.org/releases/downloads),
[versioned history](https://github.com/clojure/clojure/blob/clojure-1.12.6/changes.md)
and [upstream advisory](https://github.com/clojure/clojure/security/advisories/GHSA-q527-rxcp-97g8).
1.12.6 is the selected stable version and the advisory's explicit patched version.
The advisory concerns attacker-controlled Java object deserialization. Paclo's
production source has no ObjectInputStream/readObject path; this observation
does not establish downstream application safety or a complete dependency audit.
No exploit payload is run and no scanner success is inferred from this update.

Java object serialization changes for LazySeq, Iterate and FnLoaderThunk are
separate from Paclo's EDN persistence contract. No promise is made that serialized
runtime objects can be restored across Clojure versions. Existing flow/window/DNS
state data and old EDN snapshots remain the supported restoration path. Packet
byte arrays, capture/fan-out handles, functions and cached metadata are not added
to that contract. See the clarified [v1 contract](../../docs/cljdoc-api-contract.md).

Compiler/protocol paths are exercised by namespace loading, the full test suite,
cloverage instrumentation and Eastwood traversal. The relevant existing tests
include `reduce-test` (transducer completion and early reduced),
`managed-capture-test`, `capture-lifecycle-test`, `stream-impl-test` (lazy delivery,
full queues, exceptions, cancellation and deterministic close), `flow-test`,
`window-test` and `dns-test` (EDN restore/continuation and immutable snapshots),
and the PCAPNG tests (bounded I/O, eduction, completion, exact time and cleanup).
The initial cloverage run failed one DNS assertion that required all metadata
on the fresh empty retired map to be absent. Instrumentation adds source-location
metadata (`:line`, `:column`, `:end-line`, `:end-column`); the same failure was
reproduced with Clojure 1.12.1 and unchanged cloverage 1.2.4 (22 DNS tests,
387 assertions, one failure). This is an existing instrumentation-sensitive test,
not a Clojure 1.12.6 production behavior regression.

The correction tests the actual ownership invariant more directly: finishing an
annotated, indexed state must clear pending/retired entries and discard both the
expiry index and caller metadata. Incidental source locations are permitted.
No instrumentation exclusion, coverage threshold, production code or dependency
is changed. Normal and baseline instrumented DNS tests both pass after the correction
(22 tests, 390 assertions). The full candidate cloverage suite is rerun too.

## CI queue-test correction

The first final-head run for `df90816`
([macOS job](https://github.com/nantes-rfli/paclo/actions/runs/39089499187/job/117563237437))
failed `capture->seq-respects-queue-cap`: one of three synthetic packets arrived
and EOF/break was never reached. Its capture deadline was 50 ms. The native loop
correctly stops when that wall-clock deadline expires; cold native/JIT work or
scheduler delay can exhaust it before the remaining fake packets are read.

Injecting a 60 ms synthetic packet-read delay reproduces the exact three failures
on both Clojure 1.12.1 and 1.12.6. Keep that delay as a regression and give this
queue/EOF test a finite 10000 ms capture budget. Retain all original packet,
byte/order and EOF assertions, and additionally assert capacity 2, all three
enqueued, zero drops and observed maximum depth <=2. Both runtime probes then
pass all five assertions. This changes test input configuration, not the public
capture defaults, time-limit implementation, CI job timeout, performance budgets,
coverage gate or any deadline-specific test. Production source is unchanged.
The repeated local check/coverage/static suites pass; all final-head CI jobs
are rerun for the corrected commit.
Earlier successful consumer jobs are not relabeled as final-revision evidence.

## Local verification

Environment: macOS 15.4.1 x86_64, Temurin 21.0.12.1+1, CLI 1.12.5.1654,
system libpcap 1.10.1. Local clj-kondo 2026.05.25 and clojure-lsp
2026.05.05-12.58.26 differ from pinned CI; CI evidence is recorded separately.
JDK 17 is unavailable locally. Tests on other platforms require their CI jobs.

Local results: `check` passes JUnit 10/10, all 493 Clojure tests and native
smoke; the corrected full cloverage run passes 493 tests / 19,130 assertions
with 91.39% form / 95.46% line coverage. JaCoCo passes at 43.8% lines (25% gate).
SpotBugs, CheckStyle, kondo (zero warnings/errors), Eastwood (632 informational
warnings, zero exceptions), LSP clean-ns/format (no changes), all 36 maintained
examples and distribution/build-identity/release-guard tests pass. Markdown
network/cache and one new-log blank-line failure were corrected and rechecked;
failed attempts are recorded separately in [the work log](../work-log.md).
Final-head CI results, exact job URLs and same-JAR consumer identities are
recorded in [PR #70](https://github.com/nantes-rfli/paclo/pull/70) after completion, without a self-referential
commit claiming CI success for a different revision.

## Performance comparison

Run serially after the other CPU-heavy checks, from the repository root:

```bash
python3 dev/p12-clojure-1.12.6/compare.py --output /tmp/paclo-p12-comparison
```

The script resolves two classpaths and rejects any difference other than Clojure
1.12.1 versus 1.12.6. Both execute the unchanged `paclo.dev.perf-worker` in separate
JVMs with `-XX:-OmitStackTraceInFastThrow -Xms512m -Xmx512m`. A single deterministic
50,000-packet mixed 64-byte UDP/512-byte TCP PCAP is reused. Each worker runs five
warm-ups and seven measured repetitions. Runtime order is baseline, candidate,
candidate, baseline (ABBA); scenario order reverses in the second half.
The retained raw EDN includes runtime/native environment, counts, throughput,
allocation, CPU, heap and GC observations. Allocation is the existing runner's
thread-allocation estimate, not a retained-memory measurement. The original
mid-50k gate keeps warning 1000 ms / failure 1200 ms; no threshold changes.

Completed all 20 workers / 140 measured samples. Each sample reports exactly
50,000 packets / 14,400,000 captured bytes. The input hash is retained in
[dataset.sha256](dataset.sha256), source/flags in [manifest.json](manifest.json),
raw samples in [results.edn](results.edn) and pooled medians, ranges and individual
batch medians in [summary.json](summary.json). Each table cell pools 14 samples.

| Scenario | 1.12.1 packets/s | 1.12.6 packets/s | Change | Allocated bytes/packet | Change |
| --- | --- | --- | --- | --- | --- |
| flow-reduce | 166718 | 171694 | +3.0% | 6016.8 → 6000.0 | -0.3% |
| full-decode | 151219 | 153816 | +1.7% | 5524.2 → 5599.6 | +1.4% |
| full-reduce | 188657 | 189588 | +0.5% | 5448.9 → 5402.1 | -0.9% |
| raw-reduce | 953695 | 907254 | -4.9% | 1026.9 → 1026.1 | -0.1% |
| write-pipeline | 294395 | 304021 | +3.3% | 1621.6 → 1620.8 | -0.0% |

Raw reduction is 4.9% slower in this comparison, with nearly unchanged allocation;
both candidate batch medians are lower. Its measured ranges overlap (baseline
896,533–985,209 versus candidate 812,040–957,368 packets/s). Other paths range
from +0.5% to +3.3% throughput; full lazy decode allocation increases 1.4%.
These are observations on one host/input, not proof of equivalence or a general
speedup. No relative performance threshold is invented or relaxed to accept them.
The existing cold mid-50k gate passes at **635.9 ms**, below unchanged 1000 ms
warning / 1200 ms failure budgets. Existing CI covers all 27 offline scenarios.
Offline throughput does not validate live capture, real-NIC drops, long
production traces or other platforms.

## Local distribution evidence

`package`, `verify_distribution.py prepare` and isolated `consume --report`
all exit 0. The artifact retains `1.5.0-SNAPSHOT`, exact reviewed production
sources/dependencies and ten Java classes at major 61, with no preview classes.
Its JDK 21 consumer executes fixture I/O and public APIs using the packaged JAR
and `-Srepro` outside the checkout. The local JAR SHA-256 is
`e37dae1b723242d8c0052cbfba8bbe1c9297816648bca4587cf8b24cf60efa11`.
[Local provenance](local-provenance.json) and the
[local JDK 21 consumer](local-consumer-jdk21.json) identify baseline HEAD `e05e0c6`
and `source_dirty=true`: these local candidate bytes include the reviewed edits,
not an unmodified main build. Final clean-head CI builds a separate JAR once
and both supported runtime consumers must verify those same bytes; their hashes
and source identities belong to the PR's exact-head CI evidence.

## Scope limits and handoff

No CLI, optional/build/tool dependency, core.async or JNR upgrade; no weakened
quality/coverage/performance/CI gate; Java 17 bytecode/API baseline is retained.
No JDK 25/1.13 experiment, P14–P17 implementation, live/NIC claim, release/tag,
publication or merge. P13 is the next main item after P12's independent review
and merge; selecting it does not automatically declare JDK 25 support.
