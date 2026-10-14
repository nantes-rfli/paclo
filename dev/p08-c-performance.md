# P08-C framing performance evidence

Baseline: main `4998ddc` (P08-B2). Implementation: the P08-C sources committed
with this report. Local macOS 15.4.1 x86_64, JDK 21.0.12.1, Clojure 1.12.1,
libpcap 1.10.1. No live/NIC, IPv6 performance or analysis-aggregate claim.

## Method

Run `clojure -M:dev -m paclo.dev.framing-perf 4998ddc` with other verification
processes finished. Two independent JVM runs are retained as
[run 1](p08-c-framing-performance-1.edn) and
[run 2](p08-c-framing-performance-2.edn). The runner loads unchanged baseline
linktype/parse/project/core sources from Git under renamed namespaces in the
same JVM, warms every variant five times, and alternates their order over seven
50,000-packet samples. Reported throughput and current-thread allocation are
medians, using the JDK ThreadMXBean allocation counter. No warm-up/sample outcome
is selected or discarded. All checksums agree and drops are zero.

Input uses the existing deterministic IPv4 UDP-64 and TCP-512 Ethernet generator;
cooked inputs retain identical IP/L4 bytes under actual 16/20-byte headers.
Only packet-xf is timed (explicit empty extensions for full decode). Input arrays
and repeated packet vectors are built before measurement, snapshots before warmup.
Full results retain array identity; post-run bytes equal snapshots. Source review
confirms no whole-frame clone or synthesized Ethernet header. Existing full L4
payload copies remain. This does not measure native capture copying, GC retention,
DNS/TLS extension cost, stream scheduling or P06/P07 aggregation.

## Ethernet comparison

Ranges below cover both JVM medians. Negative changes are measured throughput
reductions; these are not statistical confidence intervals.

| Input | Mode | Baseline kpps | Current kpps | Change | Allocation bytes/packet, baseline → current |
| --- | --- | --- | --- | --- | --- |
| UDP-64 | full | 345.7–347.1 | 319.1–330.1 | -7.7–-4.9% | 3512 → 3096 |
| UDP-64 | flow | 3703.7–3913.2 | 3284.3–3885.4 | -11.3–-0.7% | 280 → 280 |
| TCP-512 | full | 264.1–283.7 | 241.8–255.9 | -9.8–-8.4% | 5544 → 5128 |
| TCP-512 | flow | 3430.3–3683.0 | 3281.7–3706.9 | -4.3–0.6% | 280 → 280 |

Full decode allocates 416 fewer bytes/packet (11.8% UDP / 7.5% TCP). Flow remains
280 bytes/packet for every DLT. Ethernet UDP flow varies from -11.3% to -0.7%
across these runs; TCP flow varies from -4.3% to +0.6%. Full decode retains a
measurable throughput cost after the shared framing/link construction refactor.
It is not claimed faster or performance-equivalent. The unchanged end-to-end
50,000-packet gate passes at 514.7 ms (warning 1000 / failure 1200 ms).

Initial experiments exposed redundant validation/lookups, boxed cooked DLT
comparison and an extra fast-path packing call. Keep an Ethernet-first DLT guard,
reuse the packet's DLT object, compare other DLTs through a constant set, use
primitive framing results and inline hot Ethernet packing. This removes the
observed extra 24 bytes for DLT 276. Full link construction reuses its parser-local
ByteBuffer for addresses; it allocates no second buffer or link-intermediate map.
No thresholds, workflows or performance issues #34/#37 were changed.

## Cooked decode results

These are throughput/allocation measurements of the new capability, not a speedup
comparison to the old unsupported-input error path.

| Input | Mode | DLT | Current kpps (two runs) | Allocation bytes/packet |
| --- | --- | --- | --- | --- |
| UDP-64 | full | 113 | 392.3–440.4 | 2992 |
| UDP-64 | full | 276 | 346.9–365.5 | 3400 |
| UDP-64 | flow | 113 | 4050.6–4073.6 | 280 |
| UDP-64 | flow | 276 | 3736.9–3744.0 | 280 |
| TCP-512 | full | 113 | 305.4–305.6 | 5024 |
| TCP-512 | full | 276 | 271.4–276.4 | 5432 |
| TCP-512 | flow | 113 | 3458.3–3979.4 | 280 |
| TCP-512 | flow | 276 | 3526.7–3657.2 | 280 |
