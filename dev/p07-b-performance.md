# P07-B offline CLI measurements

Measured on 2026-10-13, macOS x86_64, Temurin JDK 21.0.12.1, Clojure 1.12.1.
Baseline CLI source is main `2e15af7`; final source is the P07-B PR.

## Method

Runner: `clojure -M:dev:dns-ext -m paclo.dev.dns-cli-perf`. For the baseline,
extract `dev/examples/dns_rtt.clj` and `dns_qps.clj` from `2e15af7` into an
external temporary directory, then pass that directory as the runner argument.
The runner generates the same real PCAP: 500 distinct questions, 1000 UDP DNS
packets, query/response separated by 100 us, all inside one one-second window.
Three full-workload warmups, five measured complete CLI invocations per scenario;
EDN goes to a null Writer, so formatting/serialization are included. Async uses
buffer mode, capacity one, no timeout or drops. Final comparison JVMs run serially
with no concurrent test/documentation workload.

The old QPS inherited a 100-packet limit. Normalize only legacy source capture
options to read all 1000 packets with an overflow-safe duration; leave its
analysis, retention and output untouched. Without that normalization its timing
would measure only one tenth of the input. Old RTT uses missing timestamp keys
and computes nil RTT; its qstats does not perform equivalent correct quantiles.
These compare input/workflow costs, not equivalent analytical correctness.

Allocation sums live Java thread allocated-byte deltas, including async source
threads, using ThreadMXBean. Warmups reduce missing/new-thread variation, but
thread lifecycle/JIT effects remain. Heap-pool peak-used counters are coarse
process measurements that include garbage and prior scenarios; they are not
retained-size measurements. Times are medians; allocation is decimal MB per
1000-packet invocation, not a platform-independent target.

## Complete CLI comparison

| Scenario | Delivery | Old ms | Final ms | Old allocated MB | Final allocated MB | Final packets/s |
| --- | --- | --- | --- | --- | --- | --- |
| rtt-pairs | sync | 31.58 | 102.17 | 18.06 | 45.23 | 9787 |
| rtt-pairs | async | 32.95 | 60.04 | 18.80 | 52.63 | 16656 |
| rtt-qstats | sync | 29.15 | 73.74 | 19.54 | 41.84 | 13561 |
| rtt-qstats | async | 31.94 | 60.24 | 20.23 | 47.53 | 16602 |
| qps | sync | 21.90 | 54.50 | 16.77 | 26.76 | 18348 |
| qps | async | 28.91 | 37.68 | 17.45 | 32.43 | 26537 |

The new CLI adds strict correlation, integer samples, exact quantiles, finite
retention and watermark/diagnostic handling. It costs more than the old unchecked
analysis; no universal throughput improvement is claimed. Quarantine still has
an O(retired keys) scan per watermark. Large cardinalities need further measured
index work, without weakening the pure API or reuse policy. P06 issue #34 remains
separate and unchanged.

## Measured retired-map improvement

An initial P07-B implementation rebuilt every live retired key at each advance,
even when none expired. `reduce-kv` now removes only expired keys from the existing
persistent map. This preserves immutable snapshots, mixed expiry and EDN behavior.
For the same workload, allocation changes were:

| RTT scenario | Before optimization MB | Final MB |
| --- | --- | --- |
| rtt-pairs sync | 68.26 | 45.23 |
| rtt-pairs async | 75.84 | 52.63 |
| rtt-qstats sync | 64.86 | 41.84 |
| rtt-qstats async | 70.76 | 47.53 |

## Retained state and output

Before EOF, final pairs holds 50 candidates for 500 matches, no RTT sample
history, zero pending and 500 retired keys. qstats holds 500 integer samples in
500 qname groups, zero pending and 500 retired keys. QPS holds one window and
500 window/group pairs; no finalized rows yet. After finish DNS clears pending/
retired, QPS clears active windows and holds 500 finalized output rows. The old
RTT holds all 500 pair maps (plus async metadata); the old QPS map holds 500
bucket/group entries and only truncates after accumulation. Those old states
lack retention budgets; their entry counts follow the inspected old reducer.

The final runner measures retained EDN character counts, separately for report
and core state: pairs 6387/85947, qstats 27297/85947, QPS 425/25070 before finish.
These are serialized sizes, not heap bytes. They expose the quarantine cost as
well as bounded report retention. Capacity/property tests independently check
candidate/sample/window/group/output limits and explicit overflow failures.

Output-only measurement serializes 500 finalized QPS rows 100 times after three
warmups. The final run took 136.54 ms total (about 1.37 ms/report). This excludes
capture/aggregation and includes EDN string construction with a null Writer.

Heap-pool peak-used ranges (old / final, decimal MB) across the five runs:

- rtt-pairs sync: 36.5–187.5 / 70.0–187.4.
- rtt-pairs async: 116.6–187.9 / 103.4–227.0.
- rtt-qstats sync: 44.7–187.5 / 69.7–187.2.
- rtt-qstats async: 112.2–196.1 / 82.9–230.1.
- qps sync: 128.6–187.9 / 53.1–225.1.
- qps async: 66.3–133.5 / 57.5–276.1.

These peaks are deliberately not described as retained memory or a stable
memory improvement. Entry bounds, raw packet exclusion and post-finish release
are the memory contract. This finite 500-group workload does not establish
100000-group throughput, long-run heap/GC behavior, live capture, real NICs or
other platforms. The unchanged default full-decode performance gate passed at
634.2 ms and, after the role-group follow-up, 879.7 ms for 50000 packets/74 bytes
(warning 1000, failure 1200); it does not
exercise CLI analysis. No performance or coverage threshold was relaxed.
