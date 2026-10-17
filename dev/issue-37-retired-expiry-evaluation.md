# Issue #37: remaining retired-key expiry evaluation

Date: 2026-10-17 (Asia/Tokyo). This follow-up starts after published v1.4.0
and PR #57. It evaluates only actual retired-key expiry; the earlier
[DNS performance investigation](issue-37-dns-performance.md) remains the
record for projection, matching, reporting, windows, output and delivery.

## Scope and baseline

Issue [#37](https://github.com/nantes-rfli/paclo/issues/37) remains open and
non-blocking. Its completion criteria retain strict question-aware matching,
exact microseconds, diagnostics, finite cardinality, deterministic reporting,
EDN snapshots, bounded delivery and all existing quality/performance gates.
[PR #57](https://github.com/nantes-rfli/paclo/pull/57) merged as `e444b10`:
filter pending queries before sorting and use one conservative integer hint
to avoid scans before the earliest possible expiry. Those changes are retained.
The pre-#57 `452de98` and analytically incorrect legacy CLI are not comparators
in this follow-up. No repetition of the original CLI/decomposition study.

Fixed checkout: `14a92d513de1c26dd7cdc059434acd409343278d`.
Its DNS blob is `85d9fea2b46d9666165fe2cfdb414a3fc64b4ce6`, identical to the
published `v1.4.0` source. The [published API contract](../docs/cljdoc-api-contract.md#paclodns)
is the compatibility baseline. At an actual expiry, `advance` still traverses
every retired key to release due entries and recompute the lower bound.
Sequential sparse expiry therefore costs O(R) per watermark at R retained keys.
No-expiry advances remain O(1). Allocation is principally proportional to deleted
entries, rather than a newly rebuilt copy of the whole retained map.

## Candidates

All prototypes were measured in isolated JVMs from reproducible patches; the
final hybrid candidate is now implemented in the production namespace. They add
no option, dependency, scheduler or public selector.

- **Bucket index:** a persistent sorted map from exact quarantine deadlines to
  vectors of transaction keys. Retirement inserts one membership; advance visits
  only due buckets and dissociates their keys. Finish clears both collections.
- **Compact index:** singleton deadlines hold a transaction key directly;
  colliding deadlines hold a vector. A watermark reaching the greatest indexed
  deadline clears all retired keys at once. This addresses the first candidate's
  per-deadline vector cost and unnecessary O(R log R) index deletions on full
  release; the first candidate's full-release regression is not the final design.
- **Metadata index:** the compact index is attached as immutable metadata to the
  retired map. Normal EDN printing omits it, leaving exactly the ordinary data
  representation. A restored/old snapshot rebuilds the index when needed; the
  index is an optional, disposable acceleration structure, never authoritative
  transaction data. This avoids the explicit index's duplicated serialized keys
  and the corresponding duplicate restored key objects.
- **Hybrid metadata index (final candidate):** keep the previous scan path while
  no index exists and there are at most 1024 retired keys. Build the immutable
  index when that boundary is crossed; keep it until all retired entries are
  released, then discard it. This avoids indexing the small states where the
  always-indexed prototype adds update cost. The private cutoff is above the
  measured 1000-key regime, not a new public option, retention limit or quality
  threshold. It is not claimed to be the mathematically optimal crossover.

Membership is bounded by `:max-retired`; there are no stale heap entries,
callbacks, mutable caches or retained output history. Deadline comparisons retain
Clojure integer promotion. EDN restores the index as an ordinary map, so it is
converted to a sorted map at the next index operation. Old snapshots without an
index build it from their existing retired keys. The current hint's fast path
still avoids that work before a deadline. These rebuild costs are measured.

A sorted deadline index avoids requiring transaction keys themselves to be
orderable. A persistent heap would still duplicate one key membership and its
serialized representation, and adds heap maintenance code; it was not implemented
or claimed measured here. A published mutable queue would not meet the immutable snapshot contract.
Metadata intentionally trades index persistence for a one-time rebuild after
EDN restoration; restored sequential expiry is measured separately to expose
that cost as well as its amortization.

## Method and reproduction

Use the same macOS x86_64, Temurin 21.0.12.1, Clojure 1.12.1 and 512 MiB fixed
heap as the previous investigation. Run processes serially, without concurrent
builds, tests, lint or other measurements. Desktop activity, temperature and
frequency are uncontrolled; this is not a formal confidence interval.

The opt-in [follow-up runner](paclo/dev/dns_expiry_perf.clj) reuses the existing
`dns-perf` input generators, paired counter boundaries, five warmups and seven
alternating samples. Steady native PCAP uses two warmups and five samples.
Baseline DNS/window/CLI sources are loaded from the fixed post-#57 commit into
separate namespaces. The candidate patch is loaded into the process only;
shared native capture, decoding, reporting and adapters are unchanged.
Both API maps use Vars. Namespace-renamed baseline hint keys and the candidate
internal index are excluded from public-state equality. Every reference, warmup
and timed result compares complete pending/retired maps, events, reports and
execution counters after stopping counters. Candidate index membership is also
checked against its retired map outside timing. No timed samples are discarded.

Archived runner snapshots preserve the measurement-time versions. For future
reproduction, the current runner selects canonical main `17e2088`, whose complete
tree is identical to measured `14a92d5`; this avoids depending on the squashed
PR #65 head. Full history (or fetching the pinned main commit) is required.
The current runner also permits comparison against the accepted production source.
Final source changes after measurement are formatting/comments only.
The first bucket run predates the additional index-membership assertion and
header source hashes; its paired public-result checks are the same. Its retention
serialization uses the renamed baseline hint (21 extra characters). The final
compact runs canonicalize that hint for serialized-size comparison.

```bash
git show 17e2088:src/paclo/dns.clj > /tmp/paclo-dns-release.clj
patch -o /tmp/paclo-dns-index-hybrid.clj /tmp/paclo-dns-release.clj < dev/measurements/issue-37-final/hybrid-index.patch
clojure -J-Xms512m -J-Xmx512m -M:dev:dns-ext -m paclo.dev.dns-expiry-perf stress /tmp/paclo-dns-index-hybrid.clj
clojure -J-Xms512m -J-Xmx512m -M:dev:dns-ext -m paclo.dev.dns-expiry-perf stress /tmp/paclo-dns-index-hybrid.clj reverse
```

Use `updates`, `boundary`, `activation`, `retention`, `restored-retention`,
`active-restored-retention`, `ordinary`, `low-density`, `steady` and
`restored-stress` instead of `stress` for the other suites. `short` and
`ordinary-hot` use twenty warmups; load `/tmp/paclo-dns-release.clj` as the
candidate for their identical-code controls. Each invocation starts an
independent JVM. The second timed run reverses the initial pair order. Patches,
raw EDN and validated summaries are in
[the measurement manifest](measurements/issue-37-final/manifest.json).

Inputs reuse the existing deterministic generator:

- 10000/100000 retired keys, 1000 successive advances releasing one key each;
  the separate mixed control has 1000 pending/10000 retired and 100 expiries.
- Build retired states through actual query/response `step` calls at
  10/1000/10000/100000 keys, with equal or 1 us spaced deadlines. This measures
  the entire normalization/update path, not an isolated index insertion.
- Boundary advances at 10/10000/100000 keys: none, first exact deadline, full
  release, first expiry after EDN restoration, and a legacy snapshot missing
  both internal hint and index. Equal deadlines expire together.
- A restored-state stress variant performs the same 1000 advances after EDN
  print/read, measuring the rebuild and subsequent expiry together.
- Ordinary real native reads of generated PCAPs: 500 pairs/10 qnames and
  2000 pairs/2000 qnames, with 1 ms query spacing and default DNS options.
  Stats/report, sync/async capacity one, complete results and counters compared.
  A separate low-density native control uses 20000 pairs/2000 names spaced one
  second apart (5.56 hours of event time), retaining only about ten keys.
- Existing steady 40000-packet/20000-pair PCAP over 20 seconds of event time,
  default 5 s timeout + 5 s reuse. Assert all matches/samples and exactly 10000
  retired keys before finish. Offline replay runs without sleeping.

Counters include wall time, thread CPU, JVM process CPU, live-thread allocation,
GC count/time. Result/index validation runs after counters, but its temporary
allocation can affect later JVM-wide collections; no GC-pause reduction is
attributed to the candidate. These are not RSS/native memory or pause percentiles. Serial core
expiry has no short-lived producer; native async allocation may omit threads
ending between snapshots. Process CPU includes JIT and GC.
Retention separately forces GC and holds independent roots: ten roots at
1000/10000 entries and one at 100000. Restored retention holds five/one roots
created by actual EDN print/read; temporary serialization strings are not held.
Both are noisy live-heap estimates, not graph size or peak memory. EDN counts
are characters, not heap bytes. Pending-state retention is unchanged and only
rechecked in the first exploratory run.

## Results and decision

**Decision A: adopt the hybrid metadata index as an unreleased internal
optimization and submit an independent PR.** It resolves the measured repeated
large-retired-map scan without changing the public data, matching, errors,
expiry boundaries or retention limits. Published v1.4.0 remains unchanged.
Issue #37 stays open for independent review; this PR must not merge before review.

The final candidate has **55 distinct timed conditions repeated in independent
JVMs: 110 paired conditions / 1524 timed samples**. Its additional warmup
sensitivity suites add 16 pairs / 224 samples, and same-code controls another
16 pairs / 224 samples. Across all four candidates and controls, the existing
summarizer validates **340 pairs / 4720 timed samples**, all public results equal.
Exploratory candidates do not all have two full repetitions; final acceptance
uses the complete two-JVM hybrid comparison. No samples are discarded.

### Actual expiry and native high-density replay

Arrows are fixed post-#57 baseline → final candidate. MB means decimal megabytes;
512 MiB remains the fixed heap size. Units and complete sample dispersion are
retained in [summary JSONL](measurements/issue-37-final/summary.jsonl).
Allocation is per entire call, not retained heap.

| Condition (work per call) | ms, JVM 1 | ms, JVM 2 | Allocated MB/call, JVM 1 |
| --- | --- | --- | --- |
| 10000 retired, 1000 actual expiries | 126.128 → 2.782 | 161.066 → 3.684 | 2.282 → 5.849 |
| 100000 retired, 1000 actual expiries | 4075.426 → 1.915 | 4860.908 → 1.998 | 2.397 → 6.838 |
| 10000 EDN-restored, 1000 actual expiries | 169.949 → 8.899 | 177.217 → 10.766 | 2.255 → 11.560 |
| 100000 EDN-restored, 1000 actual expiries | 5172.527 → 112.836 | 4389.238 → 113.842 | 2.366 → 82.870 |
| 1000 pending/10000 retired, 100 pending expiries | 19.319 → 4.924 | 21.309 → 5.009 | 0.359 → 0.654 |
| Steady native stats sync, 40000 packets | 3107.548 → 1073.281 | 3481.707 → 1119.949 | 1481.373 → 1535.074 |
| Steady native stats async, 40000 packets | 3001.123 → 894.513 | 3359.139 → 994.357 | 1702.711 → 1755.945 |

The 100000-key repeated-expiry workload falls from 4.08/4.86 seconds to about
1.9/2.0 ms. Even when a standard EDN snapshot must rebuild its index, the same
1000 advances improve from 5.17/4.39 seconds to 113/114 ms. These are advances,
not packet-throughput claims. The generated native high-density PCAP improves
about 2.9–3.4×, with all 20000 matches, samples and delivery counts preserved.

### Normal work and controls

| Condition (work per call) | ms, JVM 1 | ms, JVM 2 | Allocated MB/call, JVM 1 |
| --- | --- | --- | --- |
| 1000 packets/10 names sync, 20 warmups | 55.395 → 53.775 | 46.987 → 45.890 | 36.626 → 36.539 |
| 1000 packets/10 names async, 20 warmups | 40.174 → 40.900 | 30.992 → 32.142 | 42.074 → 42.018 |
| 4000 packets/2000 names sync, 20 warmups | 132.117 → 132.884 | 129.799 → 125.159 | 146.453 → 147.445 |
| 4000 packets/2000 names async, 20 warmups | 108.784 → 113.802 | 111.069 → 113.000 | 168.395 → 169.417 |
| Low-density native sync, 40000 packets | 981.073 → 996.986 | 1013.120 → 1022.907 | 1464.775 → 1461.895 |
| Low-density native async, 40000 packets | 820.352 → 842.338 | 828.534 → 848.703 | 1685.091 → 1682.387 |

The longer-warmed ordinary PCAP medians change −3.6% to +4.6%; same-code native
controls change −5.4% to +5.5%. Low-density native processing costs about 1–3%
more elapsed time, with slightly lower allocated bytes. No ordinary/low-density
speedup or zero-overhead claim is made. These measured differences are acceptable
alongside the reproducible pathological-workload improvement.

The original five-warmup ordinary results are retained: one low-cardinality async
row rises 11.4% in JVM 2. Direct 1000-key spaced builds show +8.2%/+31.2% elapsed
time. Increasing warmups to twenty does not eliminate the short-build discrepancy:
+32.2%/+38.8% for the candidate, but +29.4%/+41.4% for **identical released code**
in the same namespace-loading arrangement. Tiny ten-key cases vary still more.
These controls expose measurement/loading/JIT sensitivity; they do not identify
its precise cause, and no subtraction of unrelated runs is used. They are not
sufficient to attribute those large short-batch percentages to the index.
The cutoff conservatively avoids index storage/tree updates in small initial
states; it is not derived by treating those noisy timings as a precise crossover.

### Updates, activation and snapshot rebuilds

| Condition (work per call) | ms, JVM 1 | ms, JVM 2 | Allocated MB/call, JVM 1 |
| --- | --- | --- | --- |
| Build 100000 retired, spaced deadlines (200000 events) | 1306.343 → 1402.909 | 1299.013 → 1435.792 | 2256.894 → 2354.918 |
| Build 100000 retired, equal deadlines (200000 events) | 1285.323 → 1292.582 | 1294.037 → 1338.851 | 2248.896 → 2266.692 |
| Cross 1024 → 1025 retained keys (2 events) | 0.096 → 1.440 | 0.082 → 1.947 | 0.030 → 0.531 |
| First exact expiry after restoring 100000 spaced keys | 4.938 → 138.897 | 5.022 → 106.065 | 0.010 → 76.723 |
| Release all 100000 spaced keys | 15.479 → 0.023 | 15.848 → 0.018 | 52.021 → 0.011 |

Index maintenance has a real cost: constructing a 100000-key spaced state takes
about 7–11% more elapsed time. Activation at 1025 keys adds a one-time tree build.
The index remains active as cardinality falls, until complete release/finish,
which avoids repeated creation near the cutoff. No new option or tuning API.

A snapshot with no index and 100000 spaced keys pays roughly 100 ms and about
77 MB of transient allocation on its first index-dependent operation, versus a
few milliseconds and roughly 10 KB for the old scan. Standard EDN deliberately
omits the cache, so frequent restore/single-step/checkpoint workflows can be
slower. This is an explicit limitation, not a compatible-performance guarantee.
The directly measured restored 1000-advance comparison above includes that build;
no amortization estimate is inferred by subtracting unrelated benchmarks.

### Retained memory and serialization

| State | Retired keys | Heap MB/root, JVM 1 | Heap MB/root, JVM 2 | Standard EDN chars/root |
| --- | --- | --- | --- | --- |
| Direct immutable roots | 10000 | 4.805 → 5.173 | 4.814 → 5.166 | 1737975 → 1737975 |
| Direct immutable roots | 100000 | 48.777 → 52.575 | 48.774 → 52.605 | 17566865 → 17566865 |
| Immediately after EDN read | 10000 | 5.029 → 5.037 | 5.024 → 5.024 | — |
| Immediately after EDN read | 100000 | 50.940 → 50.975 | 51.016 → 50.955 | — |
| After EDN read + first expiry | 9999 | 5.044 → 5.404 | 5.030 → 5.399 | — |
| After EDN read + first expiry | 99999 | 50.934 → 54.595 | 50.974 → 54.629 | — |

The large direct/activated states add roughly 7–8% retained heap, about
3.7–3.8 MB at 100000 keys. Standard EDN has the same character count, and an EDN
read alone has effectively identical retained memory. One first expiry removes
one key before the active-restored estimate; exact entry counts are checked.
At 1000 initial keys the final implementation retains no index. Small differences
between estimates are GC/JIT noise, not object-graph-size guarantees.

This improves the explicit compact-index alternative, which approximately doubles
standard EDN size (17566865 → 35133565 characters at 100000 keys) and restored heap
(about 51 → 102 MB). The initial vector-bucket alternative also adds avoidable
full-release work. Both are rejected. The always-indexed metadata experiment
removes serialization duplication, but the final small-state path avoids paying
for an index where a bounded scan is cheap.

### CPU, allocation and GC

| Condition, JVM 1 | Thread CPU ms/call | Process CPU ms/call | GC count/ms over all samples |
| --- | --- | --- | --- |
| 100000 retired, 1000 actual expiries | 4065.229 → 1.932 | 4067.138 → 1.951 | 0/0 → 0/0 |
| 100000 EDN-restored, 1000 actual expiries | 5061.216 → 111.985 | 5066.514 → 123.968 | 0/0 → 2/6 |
| Steady native stats sync, 40000 packets | 3095.288 → 1062.738 | 3150.115 → 1126.583 | 24/40 → 23/44 |
| Build 100000 retired, spaced deadlines (200000 events) | 1258.771 → 1347.385 | 1797.422 → 1899.812 | 72/321 → 67/368 |
| First exact expiry after restoring 100000 spaced keys | 4.957 → 138.546 | 4.953 → 138.911 | 0/0 → 1/4 |

CPU follows the major elapsed-time improvements. Sparse deletion allocates more
per actual expiry because persistent tree paths must be replaced; native steady
replay allocates about 3.6% more per packet. Rebuild allocation is substantial and
explicit above. GC totals include all samples (seven, or five for steady replay)
and surrounding JVM effects. They do not establish reduced GC pause percentiles
or native/RSS memory usage. No threshold or accuracy tradeoff is used to obtain
the improvement.

## Compatibility and verification

Prototype DNS tests ran in isolated JVMs with the legacy-state helper also
stripping cache metadata. The adopted tests retain that helper change and add
large indexed states: standard/explicit-metadata EDN, independent forks,
atomic capacity failures with exact errors, full release, promoting integer
time and earlier retries. A new 100-case property compares indexed, restored
and full-scan states after mixed transitions and verifies exactly one index
membership per retired key. Existing 900 property cases remain unchanged.
Focused source tests pass 22 tests / 387 assertions, including all 1000 generated
cases. State data keeps the six existing keys; no index is serialized by default.

```bash
bash dev/script/codex.sh test -n paclo.dns-test
clojure -M:dev -m paclo.dev.dns-perf-summary dev/measurements/issue-37-final/hybrid-stress-1.edn
```

No suitable long representative production PCAP is available. PR #57 already
records the small bundled and 38-packet Wireshark traces, which cannot exercise
large retained sets. Replaying another tiny trace does not answer this question.
The generated steady PCAP is a native-I/O control, not proof of production
resolver distributions, sustained live throughput, wall-clock soak or NIC rate.
No other-platform performance or live-capture claim follows from this work.

## Local acceptance and review handoff

- Focused DNS: 22 tests / 387 assertions, including 1000 generated cases.
- Full `check`: 493 Clojure tests / 19125 assertions, ten JUnit tests and native smoke.
- Kondo: zero errors/warnings; Eastwood: all 115 namespaces, zero exceptions.
  Namespace/format dry-runs pass. The lint wrapper's Markdown stage initially
  failed on sandbox npm DNS access. The same pinned Markdown tool, rerun with
  network access after two formatting fixes, passes all 49 Markdown files.
- All 36 executable documentation examples and local links pass.
- SpotBugs, CheckStyle and JaCoCo pass; Java coverage 43.8%, unchanged gate 25%.
- Existing 50000-packet decode gate: 446.4 ms; thresholds remain 1000/1200 ms.
- Package/inventory and isolated JAR-only JDK 21 consumer pass. Local JDK 17 is
  unavailable; committed same-JAR JDK 17/21 CI consumers remain required.
- Workflow, dependencies, build configuration and all 14 CI jobs are unchanged.
  Final-head remote CI and the independent PR URL are recorded in the PR description.

Implementation starts from reviewed main `17e2088`; its tree is identical to the
fixed measurement checkout `14a92d5`. Final code differs from the measured hybrid
patch only in whitespace/comments. Reproduction patches, exact runner snapshots,
checksums and all raw/control records are in the measurement manifest. The work
log retains commands, successful results and the resolved tool/network failures.

The pathological scan justifies this bounded internal optimization. Ordinary
work incurs measured small costs, and large EDN-restored states pay a real build
cost; both must remain visible to reviewers. Keep Issue #37 open through review,
with closure decided against these acceptance results and the disclosed absence
of representative long production traces. No automatic issue closure, merge,
release, P09/P10 work or broad production throughput claim accompanies this PR.
