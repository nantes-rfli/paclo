# Issue #34: exact flow aggregation performance

Baseline: main `e069657824ff2cdaf61af1210073b194bebff805`, after PR #54.
The public flow implementation is unchanged from P06. This investigation does
not implement issues #37/#44 or P09/P10. No dependency, quality gate, threshold,
release version, capture ownership or public API is changed.

## Reproduction

Environment: Intel Core i7-8700B 3.20 GHz, Macmini8,1, 6 physical / 12 logical
cores, 32 GiB RAM; macOS 15.4.1 x86_64, Temurin 21.0.12.1, Clojure 1.12.1.
JVM/environment metadata is also emitted by the runner. The measured production
source has git blob `faec3910fe0efc81a088ed8a27aca2931b38f014`; the runner reports
baseline HEAD because the optimization was measured before its implementation
commit. All performance commands
run serially, without concurrent tests, lint, packaging or other benchmarks.

First reproduce the original P06 experiment without changing its runner:

```bash
clojure -M:dev -m paclo.dev.flow-perf 7711170
```

That experiment uses three warmups/five measurements, 100000 IPv4/UDP packets,
10/10000 flows, both directions, current-thread allocation and amplified retained
heap. It compares the actual old CLI loaded from git with the public API.
Fixture SHA-256: DNS
`f1c22ca607df4124c939f363f8fc8d6348715d3cecb9174e52413b08931449e2`;
SLL2 `75d395935bb0844f223884f6f652fe07d4a2d1ca0450b140a1cf97f7f411f8fb`.
The old CLI has unchecked mutable two-counter state; it is background context,
not an equivalent replacement for exact immutable bounded aggregation.

For the new paired experiment:

```bash
clojure -J-Xms512m -J-Xmx512m -M:dev \
  -m paclo.dev.flow-aggregate-perf e069657
```

Run it twice in independent JVMs. Both implementations load into separate
namespaces in the same JVM. Ten warmups per implementation precede nine
measurements; baseline/current order alternates each round. Each sample reduces
100000 packets. The report retains raw elapsed/CPU/allocation/GC measurements,
summary counts, flow counts and full-result equality checks. Baseline may also
be an explicitly selected trusted source file for isolated candidate comparisons.

- Synthetic IPv4/IPv6 UDP, 10/10000 flows, unidir/bidir; caplen 64, wire length 84.
  Bidir reverses every other pass over the flow set, exercising both orders while
  retaining exactly the selected cardinality. IPv6 uses signed high words and
  unsigned endpoint comparison. The limit equals the synthetic cardinality.
- Actual DNS Ethernet and mixed IPv4/IPv6/malformed SLL2 PCAP fixtures, replayed
  as projected packets and as raw packet bytes through `packet-xf` plus aggregate.
  Fixture opens occur outside these replay timings. Invalid records remain in
  the input and their skipped summary counts are checked against baseline.
- A 100000-record Classic PCAP made by repeating the actual DNS fixture bytes,
  with synchronous native read, flow decode and aggregation inside each timing.
  Both implementations read the same temporary file; generation is untimed and
  the file is removed afterward. This measures offline file processing, not NICs.
- Allocation is current-thread `ThreadMXBean` bytes. CPU is current-thread CPU
  nanoseconds/packet (this synchronous pipeline runs on that thread). GC count
  and milliseconds are JVM-wide deltas, summed over the nine measured samples.
- Retained heap is a separate amplified experiment: about 100000 flow entries
  across independent persistent results, each reducing the small seed once.
  Inputs remain strongly reachable across two full-GC readings; shared input
  addresses/vectors are excluded. Results are used after the second reading.
  Native rows use the same projected seed for this experiment. These noisy heap
  deltas are neither peak memory nor a capture/CLI memory ceiling.

Optional second argument selects scenario-name substrings (`ipv4`, `ipv6`,
`projected`, `decode`) or `native`. Profiling is separate from timed comparisons:

```bash
clojure -J-Xms512m -J-Xmx512m -M:dev \
  -m paclo.dev.flow-aggregate-perf e069657 profile-baseline /private/tmp/flow-before.jfr
clojure -J-Xms512m -J-Xmx512m -M:dev \
  -m paclo.dev.flow-aggregate-perf e069657 profile-current /private/tmp/flow-after.jfr
```

The stack-profile workload is 10 million IPv6 packets / 10000 flows / bidir,
after warmup. JFR also includes input construction and the short warmup phase.
A separate sampler records Java stacks about every 2 ms. Stack sampling
perturbs execution and is biased toward observable safepoints; its occupancy
counts explain mechanisms, not precise CPU percentages. JFR allocation samples
are weighted estimates, not the timed allocation counter. The initial empty-configuration
JFR recording produced no ExecutionSample events. The final runner explicitly
sets a 10 ms execution-sampling period and records 827 baseline / 615 current
samples; JFR hot-method and allocation views are included in the measurement
data alongside portable stacks and unprofiled ThreadMXBean CPU measurements.

## Baseline and investigation

The fresh original-runner reproduction gives approximately 1.052M / 0.947M pps
at 10 flows (unidir/bidir) and 0.641M / 0.663M at 10000; allocation is
1662.1 / 1662.1 / 1938.6 / 1939.6 B/packet. P06 recorded 0.531M / 0.589M /
0.468M / 0.461M and 2054.1 / 2054.1 / 2330.6 / 2331.6 B/packet. Source inspection
finds no intervening public aggregate implementation change. JIT warmup, call
site shape, heap and host variation matter: historical timing/allocation numbers
are not an optimization baseline. The unchanged-source paired control agrees
on allocation in every scenario, with low-single-digit timing differences.

The initial allocation profile finds object arrays, ArraySeq, map entries,
array-map sequences, HAMT node arrays, persistent maps and boxed Longs. Stack
sampling of baseline IPv6 aggregation finds most occupancy inside aggregation,
with additional IPv6 validation and unsigned address normalization work.

Final JFR hot-method samples put array-map lookup, HAMT lookup, generic numeric
comparison and validation among baseline leaders. RT.first accounts for 3.02%
of baseline samples and 0.98% current; sequence-next/traversal and variadic assoc
leave the current top-25 list. Current samples emphasize map lookup, hashing,
equality and indexed word reads. Small sample counts and setup/warmup inclusion
limit precision; these are observed sample shares, not a complete CPU budget.

Final paired profile recordings support the same mechanisms. JFR's allocation
by-site view attributes 13.65% of baseline weighted allocation to ArraySeq.create,
11.99% to PersistentVector.chunkedSeq, 7.42% to ArraySeq.next and 8.41% to the
three-argument RestFn dispatch site. These sites disappear from the current top
allocation list (RestFn remains at 0.04%). HAMT node copies, map entries and
persistent map copies then dominate. These are shares of separate perturbed
recordings, not throughput or absolute-allocation ratios. Portable stack profiles
contain 6343 baseline / 3812 current snapshots; baseline RT.next/first/seqFrom
frames are prominent, while the current top frames emphasize hashing and map
updates. Raw stack counts are retained in the measurement data.

Source and compiled bytecode explain the specific costs:

- Canonical key maps are built once per packet, then hashed/looked up in the
  flow map. Persistent array-map hashing traverses entries; high cardinality
  additionally updates HAMT nodes. These costs remain. Literal maps already use
  `RT.mapUniqueKeys`; a bespoke fixed-map macro would duplicate that facility.
- Two-pair `assoc` calls for outer state and summary use the variadic path,
  allocating argument arrays/sequences in addition to persistent map copies.
  Single-key calls avoid that overhead while performing the same map updates.
- IPv6 has exactly two validated vector words. `every?`, `first` and `second`
  introduce sequence traversal for validation and endpoint comparison. Guarded
  indexed reads preserve signed-word validation and unsigned address order.
- Exact `inc'`/`+'` update five counters per eligible packet (three flow totals,
  seen and aggregated), retaining Long boxing and generic numeric dispatch.
  JFR attributes 6.41% of baseline allocation to Long.valueOf and 2.90% of hot
  samples to Numbers.category; neither observation isolates counter-only cost.
  Overflow is uncommon in these timings and separately tested through and beyond
  2^100. Removing promotion
  or switching to unchecked arrays is not a compatible optimization.
- The flow limit is checked only when the lookup finds no previous entry. Map
  count is constant-time; no full scan or per-update cardinality counter exists.
  Keep the check, including arbitrary-precision limit values and error data.

## Candidate decisions

| Candidate | Measured outcome | Decision |
| --- | --- | --- |
| Split three-argument numeric bounds into binary comparisons | Microprobe saves allocation, but warmed aggregation allocation is unchanged; timing varies in both directions | Reject; whole-operation benefit not established |
| Merge validation and key construction to reuse six lookups | IPv4 unidir +3.8%, bidir -5.4% in initial pair; allocation unchanged | Reject; inconsistent benefit |
| Single-key persistent `assoc` calls | IPv4 +8.6–14.5% in initial pairs; 304 fewer B/packet at both cardinalities/directions | Adopt; small local change, same maps/metadata/snapshots |
| Indexed IPv6 validation/comparison, on top of preceding candidate | Versus assoc-only: +4.2–14.8%; 352 fewer B/packet unidir, 432 bidir | Adopt; avoids demonstrated sequence work |
| Private mutable aggregate/transient retained between reducer steps | Would invalidate already published intermediate state, forks, completion identity or reducer reuse | Reject before implementation; the contract requires persistent steps |
| Fresh fixed-map construction for state/summary | Must preserve caller metadata and unrelated entries; literal keys already use mapUniqueKeys | Reject before implementation; added special cases without evidence |

The adopted code keeps the original validating key path, exact counters, limit,
error text/data, arbitrary-precision semantics and immutable map result. All
0/1/2 reducer arities and the three public functions remain unchanged.

## Results

### Synthetic aggregation

Within each cell, values are baseline → current. CPU is thread ns/packet.

| Input | Direction | pps, repetition 1 | pps, repetition 2 | Gain 1 / 2 | B/packet, repetition 2 | CPU, repetition 2 |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| ipv4-10 | unidir | 1,007,431 → 1,139,799 | 1,066,712 → 1,195,025 | +13.1% / +12.0% | 1638.1 → 1334.1 | 913 → 832 |
| ipv4-10 | bidir | 908,337 → 1,005,865 | 1,050,365 → 1,161,330 | +10.7% / +10.6% | 2022.2 → 1718.2 | 943 → 853 |
| ipv4-10000 | unidir | 617,654 → 646,819 | 803,720 → 863,517 | +4.7% / +7.4% | 2263.0 → 1959.0 | 1228 → 1154 |
| ipv4-10000 | bidir | 603,113 → 649,656 | 796,654 → 870,324 | +7.7% / +9.2% | 2265.6 → 1961.6 | 1252 → 1148 |
| ipv6-10 | unidir | 540,075 → 663,164 | 807,148 → 1,006,637 | +22.8% / +24.7% | 2479.7 → 1711.7 | 1227 → 983 |
| ipv6-10 | bidir | 654,929 → 886,146 | 751,745 → 1,001,855 | +35.3% / +33.3% | 2566.2 → 1718.2 | 1318 → 995 |
| ipv6-10000 | unidir | 581,920 → 697,729 | 632,607 → 758,689 | +19.9% / +19.9% | 2727.2 → 1959.2 | 1558 → 1312 |
| ipv6-10000 | bidir | 536,120 → 634,391 | 598,523 → 738,493 | +18.3% / +23.4% | 2811.0 → 1963.0 | 1647 → 1350 |

### PCAP workloads

Within each cell, values are baseline → current. CPU is thread ns/packet.

| Input | Direction | pps, repetition 1 | pps, repetition 2 | Gain 1 / 2 | B/packet, repetition 2 | CPU, repetition 2 |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| dns-sample-projected | unidir | 870,664 → 941,686 | 1,031,013 → 1,075,960 | +8.2% / +4.4% | 2335.8 → 2031.8 | 966 → 921 |
| dns-sample-projected | bidir | 922,775 → 1,035,503 | 1,050,758 → 1,134,254 | +12.2% / +7.9% | 1903.9 → 1599.9 | 929 → 864 |
| dns-sample-decode | unidir | 427,012 → 485,955 | 729,613 → 766,943 | +13.8% / +5.1% | 2567.8 → 2263.8 | 1358 → 1295 |
| dns-sample-decode | bidir | 746,818 → 779,179 | 837,111 → 865,832 | +4.3% / +3.4% | 2135.9 → 1831.9 | 1192 → 1148 |
| cooked/sll2-projected | unidir | 1,054,671 → 1,222,705 | 1,294,433 → 1,560,883 | +15.9% / +20.6% | 1479.6 → 1102.0 | 763 → 636 |
| cooked/sll2-projected | bidir | 1,127,479 → 1,408,676 | 1,251,845 → 1,540,775 | +24.9% / +23.1% | 1534.1 → 1092.0 | 789 → 640 |
| cooked/sll2-decode | unidir | 142,646 → 146,003 | 147,859 → 151,827 | +2.4% / +2.7% | 4657.3 → 4279.8 | 6724 → 6542 |
| cooked/sll2-decode | bidir | 133,013 → 138,574 | 145,461 → 149,980 | +4.2% / +3.1% | 4711.8 → 4269.7 | 6820 → 6623 |
| dns-native-replay | unidir | 396,091 → 398,192 | 512,313 → 551,201 | +0.5% / +7.6% | 3063.8 → 2759.8 | 1940 → 1802 |
| dns-native-replay | bidir | 414,148 → 362,974 | 545,878 → 582,649 | -12.4% / +6.7% | 2631.9 → 2327.9 | 1817 → 1705 |

### Retention and GC

Repetition 2; retained bytes/flow are separate full-GC heap estimates. GC cells
are total count / milliseconds across nine timed samples, excluding forced GCs.

| Input | Direction | Retained B/flow, before → after | GC before | GC after |
| --- | --- | ---: | ---: | ---: |
| ipv4-10 | unidir | 200.9 → 206.1 | 4 / 8 | 4 / 12 |
| ipv4-10 | bidir | 206.3 → 206.1 | 6 / 5 | 4 / 6 |
| ipv4-10000 | unidir | 190.8 → 190.8 | 7 / 12 | 5 / 7 |
| ipv4-10000 | bidir | 189.9 → 189.9 | 6 / 9 | 6 / 7 |
| ipv6-10 | unidir | 198.1 → 198.1 | 6 / 5 | 6 / 4 |
| ipv6-10 | bidir | 206.3 → 206.1 | 7 / 4 | 5 / 4 |
| ipv6-10000 | unidir | 190.6 → 190.6 | 9 / 12 | 4 / 6 |
| ipv6-10000 | bidir | 190.6 → 190.6 | 9 / 13 | 4 / 6 |
| dns-sample-projected | unidir | 235.4 → 235.4 | 5 / 5 | 7 / 3 |
| dns-sample-projected | bidir | 318.7 → 318.7 | 5 / 5 | 5 / 3 |
| dns-sample-decode | unidir | 307.4 → 307.4 | 5 / 5 | 9 / 5 |
| dns-sample-decode | bidir | 390.9 → 390.7 | 5 / 3 | 6 / 5 |
| cooked/sll2-projected | unidir | 228.1 → 228.1 | 5 / 5 | 3 / 3 |
| cooked/sll2-projected | bidir | 231.0 → 230.8 | 5 / 4 | 3 / 3 |
| cooked/sll2-decode | unidir | 363.5 → 364.9 | 13 / 9 | 12 / 8 |
| cooked/sll2-decode | bidir | 366.6 → 367.4 | 13 / 9 | 13 / 8 |
| dns-native-replay | unidir | 235.4 → 235.4 | 9 / 6 | 7 / 5 |
| dns-native-replay | bidir | 318.7 → 318.7 | 9 / 6 | 5 / 5 |

Across both repetitions, synthetic aggregation improves **4.7–35.3%** in every
scenario. IPv4 saves 304 B/packet; IPv6 saves 624–848 B/packet, depending on
direction and JIT compilation. Thread CPU decreases in all synthetic pairs.
Absolute allocations differ between independent JVMs (including the unchanged
baseline), so the within-JVM differences are the comparison, not pooled absolute
values. The individual nine samples and equality/count results are in the
[measurement data](issue-34-flow-measurements.edn).

Projected fixture aggregation improves consistently. Native DNS unidir changes
+0.5% / +7.6%; bidir changes **-12.4% / +6.7%**. Thus native end-to-end throughput
improvement is **not established**; the aggregate allocation saving is present
in both repetitions. The first native bidir CPU change is 2352 → 2401 ns/packet,
whereas the second is 1817 → 1705. Preserve the negative result rather than
ascribing it entirely to scheduling or claiming a universal pipeline gain.

Retained state shape is unchanged. High-cardinality synthetic estimates agree
at about 190 B/flow. Low-cardinality estimates are roughly 198–206 B/flow, with
a repeated ~5 B/flow first-scenario delta; these full-GC estimates include JVM
noise and do not establish a retained-memory reduction. GC usually falls with
allocation, but neither counts nor milliseconds improve monotonically (for
example repetition-1 IPv6 bidir has 7 → 8 collections and high-cardinality
bidir has 12 → 14 ms). No GC-latency guarantee is inferred.

## Verification

Local `check` passes ten JUnit tests and 480 Clojure tests / 17858 assertions,
including all 650 P06 property cases and added snapshot/fork, promoted-counter
and IPv6 boundary regressions. Full lint, 34 executable documentation examples,
local links, diff whitespace, package and the isolated JAR consumer pass.
The unchanged full-decode performance gate passes 896.7 ms (1000/1200 ms budgets).

Implementation `c4f2a27` on [PR #55](https://github.com/nantes-rfli/paclo/pull/55)
passes [all 12 CI jobs](https://github.com/nantes-rfli/paclo/actions/runs/38738630317),
including Linux x64/JDK21, macOS ARM64/JDK17, Linux ARM64, the pinned linters,
documentation, Java quality/coverage and all 27 merged performance scenarios.
These platforms validate correctness, not the local benchmark speedups.
Detailed commands, initial failed tooling/format checks and their corrections
are preserved in [the work log](work-log.md#issue-34--exact-flow-aggregation-performance-2026-10-15).
Independent review and merge remain outstanding.

## Remaining limits

These are local offline measurements on one runtime/hardware combination.
Tiny checked-in capture fixtures are replayed to amplify costs; they do not
represent the diversity or cardinality distribution of a production trace.
Native replay retains low flow cardinality. Live capture, NIC drops, other
platform performance, larger heap behavior and sustained production load are
unmeasured. Platform CI verifies correctness, not these local speedups.

Map-key hashing/equality, immutable node/map copies and exact boxed counters
remain substantial costs, especially at high cardinality. This change does not
add caches, mutable accumulators, alternate backends, borrowed buffers, parallel
execution or faster Top-N sorting. Broader work still requires a concrete target
and equivalent correctness/ownership evidence.
