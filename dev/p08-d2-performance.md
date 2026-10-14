# P08-D2 NULL/LOOP performance evidence

Baseline: merged D1 main `0d06dd1`. Current: final runtime sources committed with
this report. Local macOS 15.4.1 x86_64, Temurin 21.0.12.1, Clojure 1.12.1,
libpcap 1.10.1. These are transformation measurements, without live/NIC, native
copying, IPv6 throughput, extension or aggregate-performance claims.

## Method and limits

The existing runner now accepts NULL/LOOP, preserving single-DLT and mixed modes.
Run `clojure -M:dev -m paclo.dev.framing-perf 0d06dd1 DLT` for 1/113/276/12/0/108.
Two final rounds comprise 12 independent JVMs, with other checks finished:
[round 1](p08-d2-framing-performance-1.edn) and
[round 2](p08-d2-framing-performance-2.edn). Every JVM prints its runtime header.
Each loads baseline namespaces, warms every variant five times and alternates
order over seven 50,000-packet samples. ThreadMXBean provides current-thread
allocation; throughput and allocation are medians of all seven samples. Ranges
span two matching JVM medians, not confidence intervals. No final sample or JVM
was dropped. Full allocations can differ across JVMs due to JIT decisions;
matching baseline/current allocations agree within every final JVM.

IPv4 UDP-64 and TCP-512 use the same IP/L4 bytes under six link headers. NULL
uses little-endian AF 2, LOOP big-endian AF 2, both with offset 4. Inputs and
snapshots precede timing; full has explicit empty extensions. Every variant
successfully processes 50,000 packets per sample, errors/drops zero; matching
baseline/current checksums agree, all snapshots stay unchanged, and full retains
array identity. Flow's existing 280 bytes/packet is unchanged for all six DLTs.
Existing full payload copies remain; no whole-frame copy or link/full map is
added on flow. NULL/LOOP baseline decoding was unsupported, so their capability
is measured only for current, not as a speedup against error handling.

## Existing-link comparisons

Throughput is kpps; allocations are rounded bytes/packet. Change ranges use
paired D1/D2 medians in each JVM, not ratios of unrelated range endpoints.

| Input | Mode | DLT | D1 kpps | D2 kpps | Matching change | Allocation D1 → D2 bytes/packet |
| --- | --- | --- | --- | --- | --- | --- |
| UDP-64 | full | 1 | 270.4–288.7 | 289.3–295.0 | 2.2–7.0% | 3096–3224 → 3096–3224 |
| UDP-64 | full | 113 | 366.2–390.5 | 361.8–378.6 | -3.0–-1.2% | 3120–3160 → 3120–3160 |
| UDP-64 | full | 276 | 301.4–367.9 | 320.3–365.3 | -0.7–6.3% | 3488–3568 → 3488–3568 |
| UDP-64 | full | 12 | 474.8–538.7 | 499.0–609.1 | 5.1–13.1% | 2792–3000 → 2792–3000 |
| UDP-64 | flow | 1 | 2777.4–3057.1 | 2678.3–2793.1 | -8.6–-3.6% | 280 → 280 |
| UDP-64 | flow | 113 | 3313.5–3931.2 | 3312.0–3641.4 | -15.8–9.9% | 280 → 280 |
| UDP-64 | flow | 276 | 3745.7–3781.3 | 3189.8–4222.3 | -14.8–11.7% | 280 → 280 |
| UDP-64 | flow | 12 | 3451.9–4278.6 | 3459.5–4400.1 | 0.2–2.8% | 280 → 280 |
| TCP-512 | full | 1 | 219.5–220.5 | 221.7–226.8 | 1.0–2.9% | 5128–5160 → 5128–5160 |
| TCP-512 | full | 113 | 257.1–288.2 | 260.9–278.5 | -3.3–1.5% | 5056–5136 → 5056–5136 |
| TCP-512 | full | 276 | 235.6–282.4 | 233.2–287.7 | -1.0–1.9% | 5424–5544 → 5424–5544 |
| TCP-512 | full | 12 | 326.0–414.3 | 320.6–407.9 | -1.7–-1.5% | 4784–4976 → 4784–4976 |
| TCP-512 | flow | 1 | 3389.8–3670.8 | 3062.4–3481.5 | -16.6–2.7% | 280 → 280 |
| TCP-512 | flow | 113 | 3484.1–3573.9 | 3732.2–4078.3 | 4.4–17.1% | 280 → 280 |
| TCP-512 | flow | 276 | 3408.9–3890.0 | 3575.0–4034.7 | 3.7–4.9% | 280 → 280 |
| TCP-512 | flow | 12 | 3262.1–4433.4 | 3948.3–4356.1 | -1.7–21.0% | 280 → 280 |

Ethernet UDP flow is 3.6–8.6% lower in both final JVMs; one TCP flow median is
16.6% lower, the other 2.7% higher. Cooked UDP flow spans -15.8% to positive
changes; Raw full TCP is 1.5–1.7% lower. These are disclosed throughput concerns,
not a claim of universal performance equivalence. No existing-link allocation
increase is measured. Successful existing-link branches still do their original
bounds/framing work; new AF/version work is confined to DLT 0/108. Expanded
shared dispatch can change JIT/inlining profiles, but this experiment does not
identify a particular compiler cause. Absolute baseline throughput also varied
across independent JVMs; historical D1 Mac numbers are not interchangeable with
these matched comparisons.

The original P08-C Ethernet full slowdown versus B2 remains independently
tracked in [issue #44](https://github.com/nantes-rfli/paclo/issues/44). This report
compares to D1, not B2, and does not claim to resolve it. Issues #34/#37/#40/#44
and all thresholds remain unchanged.

## New NULL/LOOP capability

| Input | Mode | DLT | D2 kpps | Allocation bytes/packet |
| --- | --- | --- | --- | --- |
| UDP-64 | full | 0 | 435.0–448.5 | 2840 |
| UDP-64 | full | 108 | 452.9–475.3 | 2840–3008 |
| UDP-64 | flow | 0 | 2738.1–3531.7 | 280 |
| UDP-64 | flow | 108 | 3441.8–3465.6 | 280 |
| TCP-512 | full | 0 | 316.5–339.9 | 4872 |
| TCP-512 | full | 108 | 304.8–337.6 | 4872–4984 |
| TCP-512 | flow | 0 | 2674.3–3145.5 | 280 |
| TCP-512 | flow | 108 | 2850.7–3034.3 | 280 |

NULL/LOOP add unsigned AF reads, known-family membership, and version consistency
checks compared with bare IP. NULL can additionally reverse AF bytes; LOOP
accepts only network order. Full also reads AF for its truthful three-field
wrapper. This is necessary validation work; unknown AF is never inferred from
version alone. Flow allocates no new framing/detail map. Separate single-DLT
JVMs are not paired allocation/CPU controls between different link types, so
cross-DLT rows alone do not quantify the marginal cost of one AF operation.

## Initial implementation and final adjustment

Both [initial round 1](p08-d2-initial-framing-performance-1.edn) and
[initial round 2](p08-d2-initial-framing-performance-2.edn) are retained, with the
[exact runtime source delta against D1](p08-d2-initial-decoder.patch). The runner
and methodology are the same. Initial flow lows included Raw UDP -37.2%, SLL2
TCP -28.1% and Ethernet TCP -25.6%, with unchanged allocations and substantial
between-JVM variation. These results were not discarded from the record.

The final source restores Raw's direct equality check rather than adding set
membership on that path, isolates new-only minimum-size handling, and moves
short-header prose selection to an error-path helper. Existing successful bounds
branches stay compact; framing semantics and tests are unchanged. Final Raw UDP
flow pairs are +0.2%/+2.8%, but other negative medians remain as reported above.
This is an evidence-motivated limitation of D2 overhead, not proof of a JIT cause
or a general optimization of the existing decoder.

Final `bash dev/script/codex.sh perf`: **573.5 ms**, unchanged 1000 ms warning /
1200 ms failure budgets. The earlier source passed at 732.1 ms; both observations
are retained, not treated as a causal speedup. Native platform CI and its existing
quick scenarios are separate observations, recorded in the work log and PR.

Implementation `93e5cde` [CI run 38582258137](https://github.com/nantes-rfli/paclo/actions/runs/38582258137)
passed all 12 jobs, including the three native environments, 28 docs and all 27
existing quick performance scenarios. Its unchanged gate measured **501.8 ms**
on Linux x64. CI and local times are separate observations, not a causal speedup.
Final evidence-head checks are maintained on PR #46.
