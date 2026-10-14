# P08-D1 Raw IP performance evidence

Baseline: P08-C main `9d83bb2`. Current: the D1 sources committed with this
report. Local macOS 15.4.1 x86_64, Temurin 21.0.12.1, Clojure 1.12.1, libpcap
1.10.1. No live/NIC, IPv6-throughput or analysis-aggregate claim.

## Method and limits

Run `clojure -M:dev -m paclo.dev.framing-perf 9d83bb2 DLT` for DLTs 1, 113,
276 and 12, with other verification processes finished. The existing runner now
accepts an optional native DLT filter, preserving its original mixed-DLT mode.
Each capture handle has a single DLT; the filtered method compares baseline and
current under the same framing input mix. Raw runs measure only current behavior.
Two complete rounds comprise **eight independent JVMs**: [round 1](p08-d1-framing-performance-1.edn)
and [round 2](p08-d1-framing-performance-2.edn). Each has its own runtime header.

Each JVM loads baseline linktype/parse/project/core under renamed namespaces;
warms each variant five times and alternates order over seven 50,000-packet
samples. Throughput and current-thread allocation are medians from ThreadMXBean.
Every final sample contributes; no selected/discarded sample. Ranges span the two
matching JVM medians, not confidence intervals. JIT decisions can change full
allocation between JVMs; compare matching baseline/current per run.

The unfiltered measurements for the same final runtime sources are also retained:
[mixed run 1](p08-d1-mixed-framing-performance-1.edn) and
[mixed run 2](p08-d1-mixed-framing-performance-2.edn). Their baseline sees three
DLTs while current sees four, so their framing profiles differ. Some flow medians
were lower (SLL UDP down 4.4–9.8%, Ethernet TCP -5.3% to +3.3%). This motivated
controlled single-DLT measurements; it does not justify discarding those results
or claiming regression-free behavior on all hosts.

Inputs use the existing deterministic IPv4 UDP-64 and TCP-512 Ethernet generator,
with the same IP/L4 bytes under SLL/SLL2 headers or no header for Raw IP. Arrays,
packet vectors and snapshots are built before timing. Only packet-xf is timed;
full uses explicit empty extensions. For each DLT, baseline/current checksums
agree (different header sizes correctly give different captured-byte sums).
All drops are zero, full retains input array identity and all snapshots match.
This excludes native copying, retained heap, DNS/TLS extensions, stream scheduling
and P06/P07 analysis cost. Existing full L4 payload copies remain; source review
confirms no whole-frame clone, fabricated Ethernet frame or extra flow/link map.

Initial implementation experiments used an extra max in shared bounds checks and
an OS-conditioned set Var for all non-Ethernet DLTs. One intermediate version
showed 6.7–9.4% lower Ethernet UDP flow medians. Keep existing Ethernet/cooked
checks first and consult the OS guard only for DLT 12; define minimum framing
bytes directly (Raw needs one version byte). Raw version validation lives in a
small helper so it does not expand the shared payload method with failure data.
Intermediate source versions are not final results; no P08-C slowdown repair or
unrelated optimization is included. Timing variation alone does not prove which
JIT/code-layout decision caused an observed difference.

## Existing-link comparison

Throughput is kpps. Allocation is bytes/packet, rounded; baseline → current
ranges cover both final runs, with matching allocation in each run.

| Input | Mode | DLT | Baseline kpps | Current kpps | Change across runs | Allocation baseline → current |
| --- | --- | --- | --- | --- | --- | --- |
| UDP-64 | full | 1 | 347.9–356.6 | 354.7–356.0 | -0.5–+2.3% | 3224–3264 → 3224–3264 |
| UDP-64 | full | 113 | 422.4–453.8 | 432.0–450.4 | -0.8–+2.3% | 2952–3160 → 2952–3160 |
| UDP-64 | full | 276 | 378.5–391.9 | 383.0–384.3 | -1.9–+1.2% | 3320–3568 → 3320–3568 |
| UDP-64 | flow | 1 | 3224.0–3709.9 | 3394.2–3986.2 | +5.3–+7.4% | 280 → 280 |
| UDP-64 | flow | 113 | 4198.2–4201.7 | 4189.4–4256.1 | -0.3–+1.4% | 280 → 280 |
| UDP-64 | flow | 276 | 3673.2–3821.7 | 3800.6–4028.2 | -0.6–+9.7% | 280 → 280 |
| TCP-512 | full | 1 | 270.4–271.2 | 264.8–273.0 | -2.1–+0.7% | 5160–5240 → 5160–5240 |
| TCP-512 | full | 113 | 325.2–328.0 | 323.9–324.2 | -1.3–-0.3% | 4944–5136 → 4944–5136 |
| TCP-512 | full | 276 | 289.4–291.4 | 282.8–292.0 | -3.0–+0.9% | 5312–5544 → 5312–5544 |
| TCP-512 | flow | 1 | 3785.6–3889.0 | 3772.2–3885.2 | -3.0–+2.6% | 280 → 280 |
| TCP-512 | flow | 113 | 4203.5–4288.8 | 4273.9–4417.1 | +1.7–+3.0% | 280 → 280 |
| TCP-512 | flow | 276 | 3937.8–3976.0 | 3839.7–4103.5 | -3.4–+4.2% | 280 → 280 |

The [P08-C report](p08-c-performance.md) remains the evidence for the original
Ethernet full throughput loss of 4.9–9.8% versus P08-B2. Improvement is tracked
separately in [issue #44](https://github.com/nantes-rfli/paclo/issues/44).
These D1 measurements compare against C, not B2; they do not erase that loss.
Flow allocation remains 280 bytes/packet for every DLT. No existing-link
allocation increase is measured. Throughput variation is disclosed in every row;
these local medians alone do not establish performance equivalence on all hosts.

## Raw IP capability

This measures new supported decoding, not a speedup against unsupported errors.

| Input | Mode | Raw frame bytes | Current kpps | Allocation bytes/packet |
| --- | --- | --- | --- | --- |
| UDP-64 | full | 50 | 573.6–594.8 | 2960–3000 |
| UDP-64 | flow | 50 | 4046.4–4117.7 | 280 |
| TCP-512 | full | 498 | 390.0–405.4 | 4896–4976 |
| TCP-512 | flow | 498 | 4074.3–4320.7 | 280 |

Final `bash dev/script/codex.sh perf`: **574.0 ms**, against unchanged 1000 ms
warning / 1200 ms failure budgets. No performance gate, CI scenario, workflow,
version or analysis issue #34/#37 was changed. Supported-platform CI remains
separate evidence: [implementation run 38543025204](https://github.com/nantes-rfli/paclo/actions/runs/38543025204)
passed all 12 jobs, with its unchanged 50k gate at **722.9 ms** and all 27 quick
scenarios merged. CI and local times are separate observations. Offline
transformation measurements do not validate live/NIC capture or performance
on unmeasured systems.
