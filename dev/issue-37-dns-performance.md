# Issue #37: bounded DNS analysis performance

Investigation date: 2026-10-17 (Asia/Tokyo). Fixed correct baseline:
`452de98cf6d1a604e5823e80dc1cf5edadfe4b67`, after merged PRs #55/#56.
Those flow optimizations are retained without changes. Issue #34 remains closed;
Issue #44, P09/P10, release and merge work are outside this PR.

## Method and reproduction

macOS x86_64, Temurin JDK 21.0.12.1, Clojure 1.12.1, system libpcap;
Clojure CLI 1.12.5.1654. Measurements run serially, without concurrent builds,
tests or lint. The supplied checkout is used; no additional worktree.

The original runner remains unchanged:

```bash
clojure -M:dev:dns-ext -m paclo.dev.dns-cli-perf
mkdir -p /tmp/paclo-dns-legacy
git show 2e15af7:dev/examples/dns_rtt.clj > /tmp/paclo-dns-legacy/dns_rtt.clj
git show 2e15af7:dev/examples/dns_qps.clj > /tmp/paclo-dns-legacy/dns_qps.clj
clojure -M:dev:dns-ext -m paclo.dev.dns-cli-perf /tmp/paclo-dns-legacy
```

See [P07-B's method](p07-b-performance.md). Legacy reads the same 1000 packets,
but computes nil RTTs and lacks equivalent strict/exact/bounded analysis.
Its timing is context, never an optimization target or correctness comparator.
Raw results: [main CLI](measurements/issue-37/main-cli.edn),
[legacy CLI](measurements/issue-37/legacy-cli.edn).

The new opt-in runner loads baseline DNS/window/CLI sources from `git show
452de98:<path>` into separate namespaces. Shared capture, decoder, extension,
serializer and delivery code is identical. No production selector or dependency
is added. Every warmup and timed pair compares complete returned states/events,
reports and delivery counters after stopping counters; only the new internal
scalar hint is excluded from equality. No samples are discarded.

```bash
clojure -J-Xms512m -J-Xmx512m -M:dev:dns-ext -m paclo.dev.dns-perf expiry final
clojure -J-Xms512m -J-Xmx512m -M:dev:dns-ext -m paclo.dev.dns-perf pipeline final
clojure -J-Xms512m -J-Xmx512m -M:dev:dns-ext -m paclo.dev.dns-perf window final
clojure -J-Xms512m -J-Xmx512m -M:dev:dns-ext -m paclo.dev.dns-perf anomalies final
clojure -J-Xms512m -J-Xmx512m -M:dev:dns-ext -m paclo.dev.dns-perf large final
clojure -J-Xms512m -J-Xmx512m -M:dev:dns-ext -m paclo.dev.dns-perf stress final
clojure -J-Xms512m -J-Xmx512m -M:dev:dns-ext -m paclo.dev.dns-perf steady final
clojure -J-Xms512m -J-Xmx512m -M:dev:dns-ext -m paclo.dev.dns-perf retention final
```

Repeat timed suites in independent JVMs, passing `reverse` after `final` in the
second invocation to reverse initial baseline/candidate order. The tiny trace
suite retains the same initial order in both repetitions; it supports result
equivalence, without an attributable performance claim. Each condition
has one baseline reference run, five warmups per implementation and seven
alternating measured samples. JVM startup is excluded; even the original CLI
runner invokes complete `-main` calls within a warmed JVM.
A separate same-main `dispatch` control compares baseline namespace Vars with
dereferenced function values, since the baseline API map stores Vars and the
candidate map stores functions. This calling overhead is not credited as a DNS
optimization. Main/main conditions (native capture, projection, serialization, delivery) expose
noise and overhead; they are not credited as implementation improvements.

Each sample records wall time, current-thread CPU, JVM process CPU, GC collection
count/time and live-thread allocated-byte deltas. Current-thread CPU excludes
async producer work; process CPU includes producer, GC and JIT. Live-thread
allocation can miss threads that terminate between snapshots, and includes
small measurement overhead. Process CPU and submillisecond differences need
caution. GC counters are JVM-wide totals, not pause percentiles or attribution.
Production source blob at final measurement:
`85d9fea2b46d9666165fe2cfdb414a3fc64b4ce6`.
The summary validates paired sample counts, equal results and input units,
then emits medians, throughput, CPU/unit, allocation/unit, GC and dispersion:

```bash
clojure -M:dev -m paclo.dev.dns-perf-summary dev/measurements/issue-37/pipeline-1.edn
```

Retention is a separate forced-GC heap-delta experiment holding independent
complete roots; it is an estimate, not an object graph measurement or RSS peak.
Ten roots are held at 1000/10000 keys, one at 100000 keys to leave room for
full EDN serialization/restoration in the same 512 MiB JVM. EDN character
counts are serialized size, not heap bytes. No CLI peak counter
is described as retained memory.

## Inputs and scope

- Original 500-question/1000-packet generated PCAP, 100 us RTT, complete CLI
  including EDN/stderr formatting to a null Writer, sync/async capacity one.
- Expiry: 10/1000/10000 pending or retired keys; deadlines all equal or spaced
  by 1 us. Twenty no-expiry advances, one/few expired or all expired in a jump,
  and 1000 successive advances expiring one key at a time. The `few` label
  means the first deadline: one expiry for spaced deadlines, the entire burst
  for all-equal deadlines. A separate 100000-key
  no-expiry case reaches the default pending/retired limits.
- Stress: 1000 successive actual retired expiries at 10000/100000 retained
  keys; mixed 1000 pending/10000 retired with 100 successive pending expiries.
- Pipeline: 500 pairs/10 qnames and 2000 pairs/2000 qnames, 1 ms query spacing;
  exact pairs/stats/qstats, replay of all six QPS groups, native QPS sync/async
  for rcode/qname/client/server, capacity one, projection/correlation/report-only
  and adapter-only measurements.
- Long offline PCAP: 20000 pairs, 2000 qnames, one-second query spacing, 100 us
  RTT; about 5.56 hours of event time, read as fast as possible without sleeping.
  This measures finite offline processing, not a 5.56-hour JVM soak or NIC rate.
- Steady high-density PCAP: another 20000 pairs/40000 packets over 20 seconds,
  2000 qnames, 1 ms spacing, default 5 s timeout plus 5 s reuse delay. The
  second half passes the quarantine horizon with actual expiry and up to 10000
  retired keys. Stats sync/async uses two warmups and five samples per JVM
  (each warmup already processes 40000 packets). Assert all 20000 pairs,
  10000 retired keys and 20000 samples before finish.
- Anomalies: timeouts, retries including earlier queries, quarantined ID reuse,
  unmatched, negative and late input, with reorder 0 and 300 us. Complete
  diagnostics and correct report results must agree.
- Window advance: 10/1000/10000 active windows, both native sorted states and
  EDN-restored states, none/one/all ready; measured separately from QPS replay.
- EDN/JSONL/CSV: twenty serializations of the same finalized QPS rows to a null
  Writer. Disk, terminal rendering and network output are excluded.

External real trace: Wireshark's [SampleCaptures](https://wiki.wireshark.org/SampleCaptures)
links [dns.cap](https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures/dns.cap)
as various DNS lookups. It contains 38 UDP DNS packets, 14 qnames and 19
strictly matched transactions over about 279 seconds of event time, with no
analysis diagnostics (13 noerror, six nxdomain). Downloaded 2026-10-17,
4338 bytes, SHA-256
`041eeb6f98bb398f1ee8b09651b5b5a84f6a62639f95bf226f9e7b77355d9f28`.
It is fetched outside the repository and is not redistributed. Reproduce:

```bash
curl --fail --location https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures/dns.cap -o /tmp/wireshark-dns.cap
clojure -J-Xms512m -J-Xmx512m -M:dev:dns-ext -m paclo.dev.dns-perf trace /tmp/wireshark-dns.cap
```

The existing four-packet `dns-sample.pcap` is also measured. These small traces
exercise actual lookup bytes/timings; neither establishes representative
production/resolver traffic distributions or large real-world cardinality.
No suitable long production PCAP was available. Generated long/high-cardinality
inputs complement rather than replace that missing evidence.

## Candidate decisions

1. Filter pending entries before sorting. Adopt: no-expiry/few-expiry advances
   avoid sorting live queries, while expired deadline/key ordering is identical.
2. Add one conservative `:paclo.dns/next-expiry-us` integer (nil if empty).
   Adopt based on the paired results below: updates can lower it, removals may
   leave it early, and advance scans only when it is reached. A stale early
   value costs an extra scan, never misses expiry. Old EDN snapshots without
   the hint scan once before installing it. It survives EDN and immutable forks.
3. The first hint prototype returned a new `[aggregate minimum]` vector for
   each scanned key. Reject that allocation. Final scan uses a local volatile
   scalar; only its integer value and persistent collections escape. It keeps
   P07-B's existing retired map and only dissociates expired entries.
4. During retired scans, a known live minimum is already above the watermark.
   Keys at least that large need no second comparison or volatile write. Adopt
   this small short-circuit after the initial scalar implementation exposed
   increased cost on sequential retired expiry. Two isolated scan-method
   comparisons motivate it; full API comparisons below support acceptance.
   A pure minimum accumulator with a local volatile retained-map holder was
   also measured, but adds an extra holder and has noisier full-deletion costs;
   reject it in favor of the smaller change.
5. Do not add a per-key expiry index. The one-integer hint addresses the
   measured no-expiry cost without duplicate key membership, comparator/EDN
   restoration rules or a new retention budget. Repeated sparse actual expiry
   still scans; results below quantify the remaining limit. A full index needs
   separate evidence of necessity and update/retention benefit.
6. Leave window, matching, IP validation, reporting, serialization and delivery
   implementations unchanged. Their measured costs remain visible. This PR
   does not bypass normalization or replace exact samples with approximation.

Exploratory raw results are retained as well: scan-before-sort and the allocating
hint prototype. The `initial/` directory retains the complete first scalar
implementation (`802b23940d749d2dfb85717e90f15b4b18ea57d0`); the
[volatile-minimum patch](measurements/issue-37/volatile-minimum.patch) reproduces
it from final source. `scan-method-*` compares two isolated scan algorithms;
`scan-accumulator-*` compares the initial scan with the rejected retained-map
holder variant. Their baseline is the scalar scan, not main. Reproduce with
the `scan` and `accumulator` suites in two JVMs. The [scan patch](measurements/issue-37/scan-before-sort.patch)
applies to baseline DNS source; the [allocating scan patch](measurements/issue-37/allocating-hint.patch)
applies to final DNS source. Run the same `expiry` suite after each patch to
reproduce those candidate algorithms. The first exploratory scan header mistakenly abbreviates the
baseline as `452de98a`; its loader actually used `452de98` as above. That first
runner's CPU values also include snapshot overhead; use its elapsed/allocation
results only. CPU boundaries were corrected before the hint and final runs.

## Results and remaining costs

The final summarizer validates **354 paired conditions / 4940 timed samples**, all complete results equal. No
samples are discarded. Raw records and summaries are in the
[measurement index](measurements/issue-37/manifest.edn) and
[summary JSONL](measurements/issue-37/summary.jsonl). Numbers
below are medians; arrows mean fixed correct main → accepted candidate.

### Complete CLI, including output

The unchanged original runner uses 1000 packets/500 qnames, three warmups/five calls, default JVM heap selection
and null output. This table is separate from the 512 MiB paired analysis experiments. CLI process startup is
excluded. Old source uses current capture/decode dependencies and returns analytically different results.

| CLI | Legacy ms | Main ms | Candidate ms, JVM 1 / 2 | Allocated MB, main → candidate 1 / 2 |
| --- | --- | --- | --- | --- |
| rtt-pairs sync | 50.45 | 114.38 | 134.11 / 143.75 | 44.85 → 43.68 / 43.31 |
| rtt-qstats sync | 48.92 | 76.20 | 88.26 / 87.67 | 41.58 → 40.29 / 39.85 |
| qps sync | 41.16 | 52.07 | 68.48 / 69.78 | 26.46 → 26.48 / 26.06 |
| rtt-pairs async | 50.67 | 67.43 | 102.30 / 99.53 | 52.40 → 51.85 / 50.84 |
| rtt-qstats async | 54.61 | 52.45 | 61.40 / 84.28 | 47.25 → 45.92 / 45.45 |
| qps async | 49.74 | 40.95 | 60.93 / 70.93 | 32.15 → 32.08 / 31.64 |

These standalone CLI invocations are not alternating baseline/candidate pairs. Their times include more warmup/JIT
variation; use the paired results for adoption. QPS is unchanged and has no attributed speedup. Original heap-pool
peaks include garbage and are not retained-memory measurements.

### Native capture, decode, analysis and report, excluding output

Each invocation opens/closes the real generated PCAP, runs the shared adapter and produces the entire exact report.
Low cardinality is 500 pairs/10 qnames; high is 2000 pairs/2000 qnames. Output serialization and JVM startup are
excluded. Throughput uses all delivered packets, not pairs.

| Condition | ms JVM 1 | ms JVM 2 | Throughput change 1 / 2 | B/packet JVM 1 |
| --- | --- | --- | --- | --- |
| 1000 pkts/10 names, pairs sync | 44.876 → 38.816 | 47.605 → 41.523 | +15.6% / +14.6% | 46260 → 45242 |
| 1000 pkts/10 names, pairs async | 45.069 → 40.955 | 38.033 → 31.577 | +10.0% / +20.4% | 51839 → 50760 |
| 1000 pkts/10 names, stats sync | 40.384 → 30.690 | 37.529 → 30.613 | +31.6% / +22.6% | 37396 → 36352 |
| 1000 pkts/10 names, stats async | 38.630 → 23.795 | 29.731 → 22.129 | +62.3% / +34.4% | 42955 → 41825 |
| 1000 pkts/10 names, qstats sync | 42.415 → 38.577 | 36.075 → 29.631 | +9.9% / +21.7% | 38150 → 37107 |
| 1000 pkts/10 names, qstats async | 40.329 → 30.910 | 30.412 → 22.648 | +30.5% / +34.3% | 43711 → 42585 |
| 4000 pkts/2000 names, pairs sync | 366.514 → 197.885 | 242.605 → 137.030 | +85.2% / +77.0% | 46615 → 45622 |
| 4000 pkts/2000 names, pairs async | 278.349 → 148.468 | 242.450 → 116.673 | +87.5% / +107.8% | 52287 → 51133 |
| 4000 pkts/2000 names, stats sync | 323.293 → 157.689 | 217.780 → 106.889 | +105.0% / +103.7% | 37433 → 36389 |
| 4000 pkts/2000 names, stats async | 229.563 → 93.652 | 212.220 → 84.587 | +145.1% / +150.9% | 43114 → 41837 |
| 4000 pkts/2000 names, qstats sync | 351.205 → 166.060 | 220.154 → 114.464 | +111.5% / +92.3% | 39970 → 38926 |
| 4000 pkts/2000 names, qstats async | 301.170 → 135.823 | 244.860 → 118.840 | +121.7% / +106.0% | 45632 → 44400 |

The 4000-packet stats condition improves about 2.0× sync and 2.5× async in both JVMs. Allocation falls much less
than elapsed/CPU time: the main benefit is avoiding repeated retired-map work. Required event
validation/normalization, decoder allocation and bounded reporting remain.

The long low-density PCAP spans 5.56 hours of event time but keeps few active retired keys. The steady-density PCAP
spans 20 seconds and passes the default 10-second quarantine horizon, retaining 10000 keys at EOF. Both return all
20000 matches.

| 40000-packet condition | ms JVM 1 | ms JVM 2 | Throughput change 1 / 2 |
| --- | --- | --- | --- |
| 5.56 h, pairs sync | 1411.594 → 1388.680 | 1676.020 → 1633.829 | +1.7% / +2.6% |
| 5.56 h, pairs async | 1292.271 → 1338.300 | 1341.308 → 1294.771 | -3.4% / +3.6% |
| 5.56 h, stats sync | 1127.443 → 1092.488 | 1230.223 → 1211.088 | +3.2% / +1.6% |
| 5.56 h, stats async | 1073.839 → 1018.676 | 998.730 → 975.960 | +5.4% / +2.3% |
| 5.56 h, qstats sync | 1465.521 → 1413.380 | 1264.711 → 1269.703 | +3.7% / -0.4% |
| 5.56 h, qstats async | 1095.258 → 1059.193 | 1063.477 → 1036.461 | +3.4% / +2.6% |
| 20 s high density, stats sync | 6935.316 → 3632.461 | 7523.102 → 3789.840 | +90.9% / +98.5% |
| 20 s high density, stats async | 7385.801 → 3392.742 | 7228.854 → 3535.492 | +117.7% / +104.5% |

Small changes in the low-density trace are noisy and are not a universal speedup claim. Default-horizon
high-density stats improves 90.9–117.7% across both deliveries/JVMs, with complete counts and bounded retained
state asserted.

### Expiry

Here units are advances, not packets. `none` repeats twenty advances; first/all are one advance; sequential/stress
rows perform the stated number. For dense deadlines, the first deadline expires the whole burst. Allocation is
total per measured call, not retained bytes.

| Condition | ms JVM 1 | ms JVM 2 | Allocated MB/call JVM 1 |
| --- | --- | --- | --- |
| 10000 pending, no expiry (20) | 2215.101 → 0.021 | 1909.979 → 0.020 | 2043.626 → 0.021 |
| 10000 pending, first expiry | 187.835 → 2.425 | 94.396 → 0.905 | 102.191 → 0.012 |
| 10000 pending, all spaced | 137.442 → 144.069 | 106.723 → 112.200 | 117.969 → 117.870 |
| 10000 pending, simultaneous burst | 111.012 → 112.137 | 179.943 → 189.280 | 117.968 → 118.828 |
| 10000 retired, no expiry (20) | 15.982 → 0.030 | 5.801 → 0.016 | 0.036 → 0.020 |
| 10000 retired, first expiry | 0.477 → 0.902 | 0.761 → 1.307 | 0.010 → 0.010 |
| 10000 retired, full release | 1.966 → 2.839 | 2.265 → 3.394 | 4.110 → 4.110 |
| 1000 pending, 1000 sequential advances | 2914.644 → 38.069 | 4156.550 → 47.410 | 3434.835 → 3.347 |
| 1000 retired, 1000 sequential advances | 10.173 → 12.329 | 13.880 → 15.774 | 1.933 → 2.149 |
| 100000 pending, no expiry | 1332.527 → 0.016 | 1986.817 → 0.035 | 1100.601 → 0.009 |
| 100000 retired, no expiry | 4.855 → 0.017 | 8.043 → 0.027 | 0.010 → 0.009 |
| 1000 pending/10000 retired, 100 advances | 828.428 → 25.051 | 688.667 → 21.164 | 596.194 → 0.359 |
| 10000 retired, 1000 actual expiries | 140.570 → 228.050 | 142.797 → 171.924 | 2.066 → 2.282 |
| 100000 retired, 1000 actual expiries | 4796.216 → 5671.220 | 4439.946 → 5077.766 | 2.180 → 2.396 |

No-expiry work is constant with the hint; a few pending expiries avoid sorting live queries. Mixed expiry improves
strongly. **Sequential actual retired expiry remains slower than main**: throughput falls 16.9–38.4% at 10000 keys
and 12.6–15.4% at 100000. The initial scalar implementation was worse; the accepted short-circuit reduces
recalculation work but does not remove its O(retired) scan. Full bursts also have temporary sorted-entry/output
allocation; no across-the-board expiry allocation improvement is claimed.

This tradeoff is explicit. A per-key index could address repeated actual expiry but needs evidence for its
update/retention cost and representative production demand. The present improvement does not solve every
large-retired workload. **Leave Issue #37 closure to independent review; this PR does not use `Fixes #37`.**

### Processing costs, CPU, GC and controls

Representative 4000-packet decomposition, JVM 1. These are separate direct measurements, not additive accounting or
subtraction of unrelated runs. Full decode includes DNS annotation. Correlation validates normalized events again,
as required by the public API. Report-update rows consume 2000 matches and exclude final quantile/report
projection. Output rows serialize 2000 finalized QPS rows twenty times.

| Phase | ms/call main → candidate | Process CPU µs/unit | Allocated B/unit | GC count/ms across 7 samples |
| --- | --- | --- | --- | --- |
| Native raw capture | 2.837 → 2.768 | 0.98 → 1.28 | 559 → 559 | 0/0 → 0/0 |
| Native full + DNS annotation | 51.855 → 48.309 | 12.65 → 11.94 | 13597 → 13597 | 1/6 → 1/7 |
| DNS packet → event | 33.984 → 37.830 | 8.69 → 9.23 | 10688 → 10688 | 1/8 → 1/8 |
| Correlation without advance | 57.842 → 49.542 | 13.98 → 12.23 | 11130 → 11094 | 1/8 → 0/0 |
| Correlation with advance | 179.531 → 37.444 | 44.42 → 9.33 | 12250 → 11254 | 0/0 → 2/5 |
| RTT pairs update (per match) | 37.090 → 38.309 | 18.72 → 18.87 | 20309 → 20411 | 0/0 → 2/3 |
| RTT stats update (per match) | 2.908 → 2.791 | 1.66 → 1.64 | 1927 → 1927 | 0/0 → 0/0 |
| RTT qstats update (per match) | 5.139 → 4.895 | 2.52 → 2.44 | 3830 → 3830 | 0/0 → 0/0 |
| QPS qname replay | 58.357 → 59.668 | 14.53 → 14.88 | 12085 → 12085 | 1/1 → 1/1 |
| Delivery only sync | 0.124 → 0.123 | 0.03 → 0.03 | 113 → 113 | 0/0 → 0/0 |
| Delivery only async | 39.400 → 39.026 | 12.70 → 12.57 | 4610 → 4610 | 0/0 → 1/1 |
| EDN output (per row) | 101.965 → 104.385 | 2.54 → 2.60 | 1854 → 1854 | 0/0 → 3/3 |
| JSONL output (per row) | 37.659 → 37.286 | 0.94 → 0.93 | 1450 → 1450 | 2/1 → 1/1 |
| CSV output (per row) | 40.372 → 41.077 | 1.01 → 1.04 | 1771 → 1771 | 0/0 → 3/4 |

Repeated expiry scans account for the large time difference; projection, mandatory validation, Top-N maintenance
and serialization still cost CPU/allocation. Pairs sorts at most topN candidates; exact stats/qstats retain bounded
samples and sort during reporting. These paths are deliberately unchanged. Heap allocation is not native/off-heap
allocation. GC totals vary with surrounding garbage/JIT; no GC-pause percentile or consistent collection-count
reduction is claimed.

Identical-code controls range -29.9% to +22.3% throughput; the same-main Var/function dispatch control ranges -1.7%
to +0.9% with effectively identical allocation. No small change in these controls is credited to the
implementation. Unchanged QPS replay/native conditions range -23.4% to +24.1%; complete six-group results agree.
Window-only native/EDN-restored none/first/all comparisons remain in the raw summary; window code is unchanged.

The real Wireshark trace has 19 matches/38 packets and no diagnostics in both implementations and deliveries; all
six QPS group reports agree. Its timing changes range -29.9% to +20.0%, so no real-trace throughput benefit is
established by this tiny input. The bundled four-packet trace also agrees exactly.

Temperature, CPU frequency and unrelated desktop activity were not controlled. Dispersion/min/max are preserved in
summary JSONL; two independent JVM repetitions do not establish formal confidence intervals or universal bounds. No
production long trace, sustained wall-clock soak, live/NIC, other-platform performance, RSS peak or native
allocation claim is made.

## State and compatibility checks

The hint adds at most one integer per state, independent of pending/retired
cardinality. Its bit width follows the existing arbitrary-precision time
contract; this is not an independent byte-memory limit. It refers to no packet, event, collection, clock or
external cache.
There is no index membership to become stale or grow beyond the existing bounds.
It can be too early, never too late: new queries and earlier retries take the
minimum; consumed/expired queries cannot raise it without a full scan. The scan
recomputes the minimum of live pending and retired deadlines, and retiring
expired queries incorporates their future quarantine deadlines. Reaching an
obsolete early hint is safe and measurable extra work.

Tests compare every generated transition with a simple full-scan expiry oracle,
including atomic max-pending/max-retired failures, old snapshots with the hint
removed, EDN restoration, deterministic expiry ties, independent forks, negative
and arbitrary-precision integer time. Existing CLI fixtures/properties continue
to cover exact RTT, samples/qname/rows/windows/groups limits, output order and
formats, sync/async cancellation, drops, errors and cleanup.

The retained-state experiment measures complete independently built pending and
retired roots, so string/key costs dominate. A small negative heap delta or a
few bytes/key difference is measurement noise; no per-key memory reduction is
claimed. Finish clears the hint and both DNS collections. Core API functions,
options, errors, matching and diagnostic event shapes remain unchanged.

| Retained state | Roots | Estimated heap bytes main → candidate | EDN characters per root main → candidate |
| --- | --- | --- | --- |
| 1000 pending | 10 | 7765992 → 8289712 | 399610 → 399645 |
| 1000 retired | 10 | 4960000 → 4960176 | 171940 → 171975 |
| 10000 pending | 10 | 81517296 → 81581672 | 4044610 → 4044645 |
| 10000 retired | 10 | 48068240 → 48124952 | 1737940 → 1737975 |
| 100000 pending | 1 | 82829296 → 82720832 | 40922390 → 40922425 |
| 100000 retired | 1 | 48770056 → 48790968 | 17566830 → 17566865 |

Every retention root round-trips as EDN. The extra serialized hint is 35
characters for these inputs, independent of key count. No retained mutable
object or unbounded additional collection is introduced.

## Verification and delivery

- `bash dev/script/codex.sh doctor`: JDK/Clojure/native libpcap available;
  actual offline native read succeeds.
- Focused DNS tests: 19 tests / 298 assertions, including the existing 600
  and new 300 property cases; three successful invocations during refinement.
- `bash dev/script/codex.sh check`: 487 Clojure tests / 18648 assertions,
  10 JUnit tests and native four-packet smoke, exit 0.
- `bash dev/script/codex.sh perf`: 50k full-decode gate 501.8 ms,
  unchanged warning/failure thresholds 1000/1200 ms, exit 0.
- `python3 dev/script/verify_doc_examples.py`: all 34 examples, exit 0.
- `python3 dev/script/verify_doc_links.py`: all maintained local links/anchors, exit 0.
- Documentation parser regressions: 15 tests; link regressions: nine tests.
  The latter initially fails on macOS's `/var` temporary-directory alias;
  `TMPDIR=/private/tmp python3 -m unittest discover -s dev/script -p 'test_verify_doc_links.py'`
  passes using a canonical root. No checker or test is changed.
- `python3 dev/script/test_eastwood_runner.py`: all four real exit-status
  probes, including deliberate aborted analysis, pass. Full lint analyzes
  108 namespaces with 551 informational warnings and zero exceptions.
- `bash dev/script/codex.sh package`: distributable JAR built, exit 0.
  An independent `-Srepro` project whose only direct dependency is the local
  JAR loads all production/DNS extension/native binding resources via `jar:`.
  Exact fixture RTTs, EDN/legacy state, independent capacity-one fan-out,
  BigInt retry/quarantine, authored PCAPNG read/decode and window composition
  all pass. Run `prepare` after packaging to restore development test classes.
- `clojure -M:spotbugs`, `clojure -M:checkstyle`, `clojure -M:jacoco`,
  `JACOCO_MIN_LINE=0.25 clojure -M:jacoco-gate`: all exit 0; Java line
  coverage 43.8%, existing threshold 25.0%.

The consumer project must live outside the checkout, with this `deps.edn`
(replace the absolute artifact path for the local checkout):

```clojure
{:deps {org.clojars.nanto/paclo {:local/root "/absolute/checkout/target/paclo-1.3.0-SNAPSHOT.jar"}}}
```

From that directory, run:

```bash
clojure -Srepro -M -i /absolute/checkout/dev/paclo/dev/dns_jar_consumer.clj -e '(paclo.dev.dns-jar-consumer/-main "/absolute/checkout")'
```

`bash dev/script/codex.sh lint` completes with exit 0: kondo has zero
warnings/errors, all 108 Eastwood namespaces complete without exceptions,
namespace/format dry-runs have no changes, and all 40 Markdown files pass.
`git diff --check` and final local links pass. No gate or analysis scope is
relaxed. The unchanged twelve-job GitHub Actions workflow is checked on the PR;
its run link and final-head status are recorded there and in the work log.

[PR #57](https://github.com/nantes-rfli/paclo/pull/57) is open for independent
review. Implementation head `f507d42` passes
[all twelve CI jobs](https://github.com/nantes-rfli/paclo/actions/runs/38944789749):
build checks, documentation, Linux/JDK21 and macOS ARM64/JDK17 compatibility,
Linux ARM64 monitor, all three performance measurements, performance/build
aggregates, Eastwood and coverage. The actual cloverage step succeeds, despite
the pre-existing continue-on-error setting. Eastwood analyzes all 108 namespaces,
551 informational warnings and zero exceptions; deliberate failure probes pass.
CI full-decode gate is 749.3 ms with the same 1000/1200 ms thresholds. Tests
pass on every platform (487 tests; assertion counts include platform-specific
native checks). A final documentation-only verification commit is checked again;
its final-head run is linked in the PR. No merge or Issue closure is performed.
