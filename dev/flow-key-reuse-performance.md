# Existing flow key reuse: paired performance evidence

Baseline: latest main `6095c7fa8b1c2ec982064860d0b08c7e5bd931f4`, after
PR #55; Issue #34 is closed. This is a separately requested follow-up.
Prior research in `/private/tmp/paclo-flow-study-20261015` informed the candidate;
its timing numbers are not measurements of this implementation.

## Design and compatibility

Only `aggregate-rf` lookup/update changes. For `PersistentHashMap`, standard
`find` retrieves the existing entry and standard `key`/`val` supply the saved key
and counters. `assoc` uses that saved key on hits and the newly generated key on
misses. Other map types retain `get` and the generated key. Initialization,
completion, validation, exact arithmetic, cardinality checks, exceptions and
persistent state/summary updates are unchanged.

The concrete type check is deliberately narrow. There is no assumption about
cardinality thresholds in production, no access to HAMT nodes or fields, and no
new abstraction or public implementation choice. Clojure's pinned implementation
uses key identity to short-circuit equality in hash-map updates; array-map lookup
has different costs. An unconditional `find` would add entry allocation on small
maps without the same benefit. Caller-supplied sorted maps therefore keep their
existing comparator and update path. If a different map implementation is used,
correctness falls back to the original operations.

Source references: Clojure 1.12.1
[PersistentHashMap](https://github.com/clojure/clojure/blob/clojure-1.12.1/src/jvm/clojure/lang/PersistentHashMap.java),
[PersistentArrayMap](https://github.com/clojure/clojure/blob/clojure-1.12.1/src/jvm/clojure/lang/PersistentArrayMap.java)
and [APersistentMap](https://github.com/clojure/clojure/blob/clojure-1.12.1/src/jvm/clojure/lang/APersistentMap.java).
Both HAMT traversals remain. The generated key still needs hashing; hash caching
already existed. The benefit is avoiding a second deep key comparison and its
temporary objects. Public values remain ordinary immutable maps and exact
integers; no mutable accumulator, hidden cache, custom key or API is introduced.

## Measurement protocol

Intel Core i7-8700B / Macmini8,1, 6 physical / 12 logical cores, 32 GiB;
macOS 15.4.1 x86_64, Temurin 21.0.12.1, Clojure 1.12.1, libpcap 1.10.1.
Each independent JVM uses `-Xms512m -Xmx512m`. The existing
`paclo.dev.flow-aggregate-perf` runner performs ten warmups per implementation,
then nine samples per implementation with alternating order, each processing
100000 packets. No tests, lint, compilation, packaging or other benchmark runs
concurrently. Unrelated host load cannot be eliminated.

Complete results are checked before sampling and after every sample, outside all
timing, CPU, allocation and GC counter intervals. Replay preserves invalid SLL2
records and compares the complete skipped/aggregated summary as well as flows.
All byte inputs are shared read-only. Drops are zero for these synchronous
offline reductions; this is not kernel-drop or live-capture evidence.

- Synthetic IPv4/IPv6 UDP, unidir/bidir, 7/8/9/10/10000 flows. Bidir reverses
  endpoints on alternating passes over the seed; direction/cardinality remain
  fixed. The limit equals seed cardinality.
- 25000/50000/75000 distinct seeds cycled through 100000 packets exercise
  75/50/25% revisits. 100000 seeds are all-new. These are controlled input patterns,
  not observed production distributions.
- The IPv4 hot-set case routes nine out of ten inputs to 100 hot flows; the
  remaining inputs cycle through 9900 cold flows. This deterministic skew tests
  sensitivity to locality without claiming a measured real-world distribution.
- DNS Ethernet and mixed IPv4/IPv6/malformed SLL2 fixtures run as projected replay
  and raw-byte decode plus aggregate. Fixture reads are outside replay timing.
- Native rows repeat actual DNS/SLL2 fixture records into a 100000-record PCAP
  with matching DLT 1/276. The same temporary file feeds both implementations;
  timed work includes native open/read, decode, aggregate and close. File
  generation/deletion is untimed. These small repeated fixtures are not a large
  operational trace, cold-disk benchmark or CLI formatting/serialization test.
- Throughput is packets/second from median elapsed time. CPU is current-thread
  CPU ns/packet, and allocation is current-thread ThreadMXBean B/packet. GC count
  and milliseconds are JVM-wide deltas summed over nine measured samples.
- Retained B/flow is a separate amplified full-GC heap-difference experiment over
  independent results, reducing each seed once and excluding shared input data.
  About 100000 entries are retained, with at least two results (200000 entries
  for all-new). Hot-set/native rows use projected seeds, not their timed input
  distribution. This noisy estimate is not RSS, peak memory or a hard limit;
  no retained-state reduction or GC latency improvement is expected.

Measured production blob: `13fa5acd21ad03dda2bcf50f3d9ca0466d04f35c`.
Runner blob: `0e977854c914c81cb78baceda1860a6209f6871c`.
Fixture SHA-256: DNS
`f1c22ca607df4124c939f363f8fc8d6348715d3cecb9174e52413b08931449e2`;
SLL2 `75d395935bb0844f223884f6f652fe07d4a2d1ca0450b140a1cf97f7f411f8fb`.

## Reproduction

Run serially from the repository root after `bash dev/script/codex.sh doctor`:

```bash
clojure -J-Xms512m -J-Xmx512m -M:dev \
  -m paclo.dev.flow-aggregate-perf \
  6095c7fa8b1c2ec982064860d0b08c7e5bd931f4 key-reuse
```

The second independent JVM swaps namespace roles by loading main into
`paclo.flow` and passing the saved candidate source as the baseline argument.
Its output labels are reversed when summarizing: `:baseline` is the candidate,
`:current` is main. Save candidate source before loading main, then run this in
a fresh JVM with the same flags and `-M:dev`:

```clojure
(require '[clojure.java.shell :as shell]
         '[paclo.dev.flow-aggregate-perf :as bench])
(spit "/private/tmp/paclo-key-reuse-candidate.clj" (slurp "src/paclo/flow.clj"))
(load-string (:out (shell/sh "git" "show"
                            "6095c7fa8b1c2ec982064860d0b08c7e5bd931f4:src/paclo/flow.clj")))
(bench/-main "/private/tmp/paclo-key-reuse-candidate.clj" "key-reuse")
```

A separate same-source control compiles main in both namespaces and focuses on
small-map/all-new conditions. In another fresh JVM, use the same require and
load-string above (without saving or using candidate source), followed by:

```clojure
(let [scenario-var (ns-resolve 'paclo.dev.flow-aggregate-perf 'scenarios)
      scenarios @scenario-var
      native-var (ns-resolve 'paclo.dev.flow-aggregate-perf 'compare-native)]
  (with-redefs-fn
    {scenario-var
     (fn [_]
       (filter #(contains? #{"ipv4-7" "ipv4-8" "ipv6-7" "ipv6-8"
                             "ipv4-100000" "ipv6-100000"} (:name %))
               (scenarios true)))
     native-var (fn [& _])}
    #(bench/-main "6095c7fa8b1c2ec982064860d0b08c7e5bd931f4" "key-reuse")))
```

The companion CSV normalizes namespace roles and retains all timed samples,
CPU/allocation/GC counters, dispersion, retained estimates and actual input/flow
counts for both repetitions and control. Environment headers and original EDN
outputs are also saved with the local evidence archive. For `run=control`,
CSV candidate columns denote the second independently compiled copy of main,
not the optimized implementation.

## Results and decision

Adopt the small implementation; all local delivery gates below pass. The two
independent JVMs complete 50 paired conditions each; the separate main/main
control completes 12 pairs. All 2016 timed samples have full-result equality,
100000 seen packets and successful retained-result/reachability checks.
Detailed [CSV evidence](flow-key-reuse-measurements.csv) includes every sample.

- Repeated 9/10/10000-flow aggregates improve **7.1–21.1%** across both IP versions
  and directions in both JVMs. The reproducible key-reuse allocation reduction
  is **352 B/packet** at 9/10 flows and **316.8 B/packet** at 10000 flows.
- JVM 2 additionally allocates 24 B/packet less on IPv6 even at 7/8 flows and
  all-new inputs, where key reuse cannot explain it. Do not attribute that extra
  difference to reuse. Raw JVM 2 differences reach 376 B/packet; table/CSV retain
  them. The same-source control has equal allocation in all twelve conditions.
  Namespace/JIT/call-site effects still limit attribution of small differences.
- 7/8-flow throughput varies **-4.7% to +3.6%**, all-new **-2.6% to +4.9%**.
  Main/main control varies **-3.4% to +5.4%** with unchanged allocation. The
  small-map negative extrema do not repeat in JVM 2; no clear large regression
  is established. This does not prove zero overhead for every caller map.
- Controlled 25/50/75% revisit cases vary **-0.6% to +11.3%**. Allocation savings
  scale with visits (88/176/264 B/packet before the JVM 2 IPv6 offset). At 25%
  revisits, one IPv6 bidir comparison is -0.6%; sparse revisits are not promised
  a useful speedup. The synthetic hot set improves **12.2–16.1%** and saves
  about 316.7 B/packet.
- DNS projection/decode has no allocation reduction. Throughput varies
  **-1.1% to +8.7%** / **-2.0% to +4.5%**, respectively. Its small flow map takes
  the fallback; do not attribute positive timing alone to key reuse.
- SLL2 projection improves **10.2–16.8%**, decode replay **2.0–4.7%**; both save
  **203 B/packet**, averaged across valid/revisited and invalid fixture records.
- Native DNS varies **-1.8% to +3.1%**, unchanged allocation: no repeatable
  end-to-end gain is claimed. Native SLL2 improves **0.7–3.1%** and saves
  203 B/packet; the timing benefit is small relative to the aggregate-only gain.
- Retained-state estimates differ by approximately **-5.3 to +5.3 B/flow** with
  the same published representation. This is full-GC measurement noise, not a
  memory reduction. Measured GC count increases in 28/100 comparisons and GC
  milliseconds in 40/100 despite lower allocation in the target cases. No GC
  latency guarantee is supported. All unfavorable results remain in the CSV.

Ten warmups and alternating order reduce bias, but two JVM repetitions and nine
samples do not establish formal statistical significance or universal bounds.
Individual timings include GC/outliers; the CSV retains sample min/max and CV.
For example, JVM 1 IPv4/75000/bidir main and JVM 2 SLL2 decode/unidir main
have elapsed-time CV around 54%; medians retain all nine samples without trimming.
No operational trace was available; no conclusion is made for real NIC/live
capture, other CPUs/OS/JDK performance, cold storage, peak/RSS or long-run GC
pause distributions. The benefit and low implementation cost justify adoption;
the fixed quality/performance gates remain unchanged.

### Throughput, CPU and allocation

Both columns compare this task's latest-main baseline and candidate. Timing
percentages are independently computed within each JVM. The absolute JVM 2
values must not be mixed with JVM 1 or historical research values.

| Input | Direction | kpps main → candidate (JVM 2) | Throughput change JVM 1 / 2 | CPU ns/packet (JVM 2) | Allocation B/packet (JVM 2) |
| --- | --- | --- | --- | --- | --- |
| ipv4-7 | unidir | 804.6 → 810.3 | -0.5% / +0.7% | 1240 → 1226 | 1639.7 → 1639.7 |
| ipv4-7 | bidir | 702.8 → 705.1 | -1.5% / +0.3% | 1419 → 1416 | 2023.7 → 2023.7 |
| ipv4-8 | unidir | 780.3 → 781.4 | -4.7% / +0.1% | 1269 → 1270 | 1743.7 → 1743.7 |
| ipv4-8 | bidir | 628.9 → 620.6 | -4.7% / -1.3% | 1587 → 1600 | 2191.7 → 2191.7 |
| ipv4-9 | unidir | 890.4 → 1070.6 | +16.8% / +20.2% | 1110 → 916 | 1703.7 → 1351.7 |
| ipv4-9 | bidir | 838.1 → 986.1 | +16.4% / +17.7% | 1191 → 1012 | 1703.7 → 1351.7 |
| ipv4-10 | unidir | 872.9 → 1019.7 | +14.4% / +16.8% | 1135 → 969 | 1718.0 → 1366.1 |
| ipv4-10 | bidir | 809.1 → 932.8 | +19.0% / +15.3% | 1218 → 1042 | 1718.1 → 1366.1 |
| ipv4-10000 | unidir | 524.1 → 561.4 | +13.9% / +7.1% | 1886 → 1768 | 1959.0 → 1642.2 |
| ipv4-10000 | bidir | 511.7 → 557.4 | +11.8% / +8.9% | 1934 → 1764 | 1961.5 → 1644.7 |
| ipv4-25000 | unidir | 541.1 → 579.1 | +9.6% / +7.0% | 1806 → 1682 | 1929.1 → 1665.1 |
| ipv4-25000 | bidir | 502.9 → 537.2 | +8.0% / +6.8% | 1965 → 1811 | 1942.9 → 1678.9 |
| ipv4-50000 | unidir | 553.5 → 594.5 | +11.3% / +7.4% | 1771 → 1644 | 1750.3 → 1574.3 |
| ipv4-50000 | bidir | 524.0 → 548.6 | +8.5% / +4.7% | 1846 → 1816 | 1766.9 → 1590.9 |
| ipv4-75000 | unidir | 625.4 → 630.3 | +6.3% / +0.8% | 1597 → 1539 | 1560.6 → 1472.6 |
| ipv4-75000 | bidir | 572.7 → 593.3 | +5.1% / +3.6% | 1707 → 1668 | 1581.0 → 1493.0 |
| ipv4-100000 | unidir | 652.7 → 635.8 | +4.1% / -2.6% | 1516 → 1531 | 1371.7 → 1371.7 |
| ipv4-100000 | bidir | 651.5 → 666.2 | +1.3% / +2.3% | 1498 → 1488 | 1397.4 → 1397.4 |
| ipv6-7 | unidir | 647.3 → 670.8 | -0.6% / +3.6% | 1536 → 1480 | 1663.7 → 1639.7 |
| ipv6-7 | bidir | 560.2 → 573.0 | -1.1% / +2.3% | 1779 → 1735 | 2047.7 → 2023.7 |
| ipv6-8 | unidir | 603.9 → 619.7 | -1.2% / +2.6% | 1639 → 1597 | 1767.7 → 1743.7 |
| ipv6-8 | bidir | 535.0 → 548.9 | +1.5% / +2.6% | 1860 → 1810 | 2215.7 → 2191.7 |
| ipv6-9 | unidir | 769.1 → 928.7 | +12.8% / +20.8% | 1295 → 1071 | 1727.7 → 1351.7 |
| ipv6-9 | bidir | 654.6 → 792.9 | +13.0% / +21.1% | 1495 → 1259 | 1735.7 → 1359.7 |
| ipv6-10 | unidir | 683.2 → 811.2 | +14.8% / +18.7% | 1451 → 1221 | 1735.6 → 1359.7 |
| ipv6-10 | bidir | 670.8 → 780.9 | +15.0% / +16.4% | 1480 → 1259 | 1742.1 → 1366.1 |
| ipv6-10000 | unidir | 466.9 → 521.3 | +7.1% / +11.7% | 2137 → 1911 | 1983.1 → 1642.3 |
| ipv6-10000 | bidir | 458.9 → 513.7 | +8.9% / +11.9% | 2174 → 1938 | 1986.9 → 1646.1 |
| ipv6-25000 | unidir | 459.5 → 510.0 | +8.8% / +11.0% | 2170 → 1940 | 1953.8 → 1665.8 |
| ipv6-25000 | bidir | 439.1 → 475.0 | +10.3% / +8.2% | 2275 → 2076 | 1965.5 → 1677.5 |
| ipv6-50000 | unidir | 502.9 → 543.5 | +4.3% / +8.1% | 1947 → 1805 | 1774.3 → 1574.3 |
| ipv6-50000 | bidir | 473.1 → 514.2 | +6.1% / +8.7% | 2065 → 1936 | 1790.3 → 1590.3 |
| ipv6-75000 | unidir | 560.3 → 583.6 | +6.6% / +4.2% | 1783 → 1695 | 1584.9 → 1472.9 |
| ipv6-75000 | bidir | 540.4 → 577.6 | -0.6% / +6.9% | 1793 → 1701 | 1604.8 → 1492.8 |
| ipv6-100000 | unidir | 618.8 → 648.9 | -2.3% / +4.9% | 1587 → 1509 | 1396.1 → 1372.1 |
| ipv6-100000 | bidir | 573.1 → 588.7 | +0.2% / +2.7% | 1713 → 1643 | 1420.8 → 1396.8 |
| ipv4-hotset | unidir | 682.7 → 789.1 | +13.1% / +15.6% | 1455 → 1256 | 1944.3 → 1627.6 |
| ipv4-hotset | bidir | 650.5 → 755.5 | +12.2% / +16.1% | 1511 → 1302 | 1948.3 → 1631.6 |
| dns-sample-projected | unidir | 826.9 → 885.7 | +8.7% / +7.1% | 1196 → 1111 | 1343.8 → 1343.8 |
| dns-sample-projected | bidir | 891.8 → 939.8 | -1.1% / +5.4% | 1120 → 1054 | 1119.9 → 1119.9 |
| dns-sample-decode | unidir | 597.4 → 624.5 | -0.6% / +4.5% | 1668 → 1584 | 1575.8 → 1575.8 |
| dns-sample-decode | bidir | 668.7 → 694.9 | -2.0% / +3.9% | 1491 → 1436 | 1351.9 → 1351.9 |
| sll2-projected | unidir | 1106.2 → 1277.6 | +10.2% / +15.5% | 889 → 778 | 1102.0 → 899.0 |
| sll2-projected | bidir | 1114.6 → 1301.6 | +12.7% / +16.8% | 892 → 767 | 1091.9 → 888.9 |
| sll2-decode | unidir | 78.5 → 82.2 | +2.9% / +4.7% | 12689 → 12122 | 4575.7 → 4372.7 |
| sll2-decode | bidir | 85.0 → 87.7 | +2.0% / +3.2% | 11716 → 11333 | 4565.6 → 4362.6 |
| dns-native-replay | unidir | 418.0 → 430.8 | +2.9% / +3.1% | 2371 → 2305 | 2071.8 → 2071.8 |
| dns-native-replay | bidir | 442.4 → 454.2 | -1.8% / +2.7% | 2240 → 2192 | 1847.9 → 1847.9 |
| sll2-native-replay | unidir | 85.8 → 87.9 | +3.1% / +2.4% | 11608 → 11335 | 5531.1 → 5328.1 |
| sll2-native-replay | bidir | 106.5 → 107.9 | +0.7% / +1.3% | 9371 → 9251 | 5521.0 → 5318.0 |

### Retention and GC

Retention is the separate seed-state estimate above; GC sums only measured
intervals and excludes the forced GC used by retained-memory experiments.

| Input | Direction | Retained B/flow (JVM 2) | GC count/ms main → candidate (JVM 1) | GC count/ms main → candidate (JVM 2) |
| --- | --- | --- | --- | --- |
| ipv4-7 | unidir | 203.1 → 197.8 | 4/4 → 5/6 | 5/8 → 4/4 |
| ipv4-7 | bidir | 203.1 → 203.1 | 6/5 → 5/7 | 5/8 → 6/7 |
| ipv4-8 | unidir | 199.7 → 199.7 | 6/5 → 4/3 | 4/5 → 6/7 |
| ipv4-8 | bidir | 199.7 → 199.7 | 6/5 → 6/4 | 6/12 → 6/6 |
| ipv4-9 | unidir | 200.6 → 200.6 | 4/3 → 4/4 | 4/6 → 4/5 |
| ipv4-9 | bidir | 200.6 → 200.6 | 6/9 → 3/5 | 6/15 → 3/4 |
| ipv4-10 | unidir | 206.1 → 206.1 | 5/5 → 4/2 | 5/4 → 4/7 |
| ipv4-10 | bidir | 206.1 → 206.1 | 5/8 → 4/5 | 6/13 → 3/12 |
| ipv4-10000 | unidir | 190.8 → 190.8 | 5/11 → 5/8 | 6/12 → 5/16 |
| ipv4-10000 | bidir | 189.9 → 189.9 | 5/12 → 5/9 | 6/16 → 5/22 |
| ipv4-25000 | unidir | 207.7 → 207.7 | 7/17 → 5/12 | 5/26 → 7/32 |
| ipv4-25000 | bidir | 208.5 → 208.5 | 6/17 → 6/18 | 6/34 → 5/25 |
| ipv4-50000 | unidir | 203.2 → 203.2 | 6/16 → 4/16 | 4/31 → 5/29 |
| ipv4-50000 | bidir | 203.2 → 203.2 | 4/19 → 6/17 | 8/46 → 1/8 |
| ipv4-75000 | unidir | 197.2 → 197.2 | 4/20 → 4/11 | 4/19 → 4/31 |
| ipv4-75000 | bidir | 197.2 → 197.2 | 3/29 → 5/24 | 7/54 → 3/20 |
| ipv4-100000 | unidir | 194.0 → 194.0 | 3/12 → 3/12 | 3/23 → 3/18 |
| ipv4-100000 | bidir | 194.1 → 194.1 | 4/13 → 5/25 | 5/38 → 4/22 |
| ipv6-7 | unidir | 203.1 → 203.1 | 7/7 → 7/3 | 5/5 → 4/4 |
| ipv6-7 | bidir | 203.1 → 208.3 | 9/6 → 10/9 | 4/4 → 7/9 |
| ipv6-8 | unidir | 199.7 → 199.7 | 6/5 → 9/5 | 4/3 → 5/8 |
| ipv6-8 | bidir | 199.7 → 199.7 | 10/5 → 11/11 | 6/6 → 7/7 |
| ipv6-9 | unidir | 200.6 → 200.6 | 4/3 → 4/3 | 6/8 → 3/4 |
| ipv6-9 | bidir | 209.5 → 209.5 | 6/8 → 3/6 | 5/9 → 4/12 |
| ipv6-10 | unidir | 198.1 → 198.1 | 4/3 → 5/4 | 5/6 → 4/4 |
| ipv6-10 | bidir | 206.1 → 206.1 | 5/10 → 4/5 | 4/7 → 5/14 |
| ipv6-10000 | unidir | 190.6 → 190.6 | 5/7 → 5/9 | 6/14 → 4/11 |
| ipv6-10000 | bidir | 190.6 → 190.6 | 5/7 → 5/11 | 5/13 → 5/15 |
| ipv6-25000 | unidir | 208.6 → 208.6 | 7/19 → 4/10 | 5/28 → 3/14 |
| ipv6-25000 | bidir | 208.3 → 208.3 | 6/19 → 6/17 | 6/29 → 6/28 |
| ipv6-50000 | unidir | 203.2 → 203.2 | 6/16 → 4/17 | 7/48 → 3/14 |
| ipv6-50000 | bidir | 203.4 → 203.2 | 4/20 → 6/16 | 6/29 → 3/21 |
| ipv6-75000 | unidir | 197.3 → 197.3 | 4/19 → 4/12 | 2/8 → 6/35 |
| ipv6-75000 | bidir | 197.3 → 197.3 | 3/15 → 5/24 | 6/45 → 3/25 |
| ipv6-100000 | unidir | 194.1 → 194.1 | 3/12 → 3/14 | 4/22 → 5/34 |
| ipv6-100000 | bidir | 194.1 → 194.1 | 4/14 → 4/15 | 4/23 → 4/29 |
| ipv4-hotset | unidir | 190.8 → 190.8 | 6/7 → 5/5 | 4/8 → 5/10 |
| ipv4-hotset | bidir | 189.9 → 189.9 | 6/9 → 4/8 | 5/13 → 5/14 |
| dns-sample-projected | unidir | 235.4 → 235.4 | 7/7 → 5/3 | 3/5 → 4/6 |
| dns-sample-projected | bidir | 318.7 → 318.7 | 4/2 → 5/5 | 3/4 → 3/5 |
| dns-sample-decode | unidir | 307.4 → 307.4 | 7/5 → 6/5 | 4/6 → 5/7 |
| dns-sample-decode | bidir | 390.7 → 390.7 | 6/6 → 4/2 | 3/6 → 4/4 |
| sll2-projected | unidir | 228.1 → 228.1 | 4/4 → 2/2 | 4/5 → 2/3 |
| sll2-projected | bidir | 230.8 → 230.8 | 3/3 → 3/2 | 3/4 → 2/4 |
| sll2-decode | unidir | 364.8 → 363.7 | 12/8 → 12/8 | 13/17 → 12/14 |
| sll2-decode | bidir | 366.9 → 366.2 | 12/8 → 11/7 | 13/13 → 12/15 |
| dns-native-replay | unidir | 235.4 → 235.4 | 9/5 → 6/6 | 6/6 → 6/8 |
| dns-native-replay | bidir | 318.7 → 318.7 | 4/3 → 9/6 | 4/6 → 6/6 |
| sll2-native-replay | unidir | 228.1 → 228.1 | 14/10 → 15/12 | 16/19 → 15/15 |
| sll2-native-replay | bidir | 230.8 → 230.8 | 16/17 → 14/15 | 15/11 → 15/10 |

## Delivery validation

| Command | Result |
| --- | --- |
| `bash dev/script/codex.sh doctor` | Pass; JDK 21/Clojure 1.12.1, actual four-packet native read |
| `bash dev/script/codex.sh test -n paclo.flow-test` | Pass; 19 tests / 821 assertions, 750 property cases |
| `bash dev/script/codex.sh check` | Pass; 484 tests / 18553 assertions, JUnit 10/10, native smoke |
| `bash dev/script/codex.sh lint` | Pass; kondo clean, 106 Eastwood namespaces / zero exceptions, lsp clean/format, 39 Markdown files |
| `clojure -M:spotbugs`, `clojure -M:checkstyle` | Pass |
| `clojure -M:jacoco`, `clojure -M:jacoco-gate` | Pass; 43.8% against unchanged 25% line gate |
| `python3 dev/script/verify_doc_examples.py` | Pass; all 34 examples |
| `python3 dev/script/verify_doc_links.py`, `git diff --check` | Pass |
| `bash dev/script/codex.sh perf` | Pass; 630.2 ms, unchanged warning/failure 1000/1200 ms |
| `bash dev/script/codex.sh package` | Pass; unchanged snapshot version; expected JAR resources and exact measured flow source |
| Independent `clojure -Srepro -M consumer.clj` | Pass; JAR-only classpath/resource origins, real DNS, exact counters, hash-map forks/EDN, PCAPNG/window composition |
| `bash dev/script/codex.sh prepare` | Pass; restored Java tests after packaging |

Local tools are clj-kondo 2026.05.25 and clojure-lsp 2026.05.05-12.58.26.
CI pins remain clj-kondo 2025.10.23 and clojure-lsp 2025.11.28-12.47.43.
Implementation `3d37a8890a55cb97296bbb6d974ec24c203cee54` on
[PR #56](https://github.com/nantes-rfli/paclo/pull/56) passes **all 12 CI jobs** on
[run 38908188042](https://github.com/nantes-rfli/paclo/actions/runs/38908188042).
Linux x64/JDK21 and Linux ARM64 pass 484 tests / 18559 assertions; macOS
ARM64/JDK17 passes 484 / 18553. Actual OS/architecture checks pass. Java quality
passes at 43.8% / 25%; existing performance gate is 769.9 ms / 1200 ms;
all 34 executable examples, cljdoc loading, 27 merged performance scenarios,
pinned kondo/lsp and Eastwood (zero exceptions) pass. Final evidence-head checks
are maintained on the PR. No gate, runner matrix, warning policy or threshold
has been changed. This task does not merge
or release; independent review remains the next step after successful checks.
