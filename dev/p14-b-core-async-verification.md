# P14-B: core.async update and asynchronous compatibility

Status: implementation is in [PR #76](https://github.com/nantes-rfli/paclo/pull/76).
Implementation and required verification are complete; independent review,
including the measured performance trade-off, is pending. P14 remains unfinished.

## Selection and scope

Started from latest main `4a113c60184128df442f3fa152ebf0390cedc6a5`.
[PR #75](https://github.com/nantes-rfli/paclo/pull/75) merged on 2026-10-18 at
12:00:29 UTC (21:00:29 Asia/Tokyo). The supplied checkout was clean.

On 2026-10-18, the [official core.async repository](https://github.com/clojure/core.async)
identifies 1.9.865 as its latest release.
[Maven Central metadata](https://repo.maven.apache.org/maven2/org/clojure/core.async/maven-metadata.xml) also lists
1.10 prereleases, including 1.10.874-alpha3; these are not stable candidates.
Select 1.9.865 rather than a prerelease. Keep Clojure 1.12.6, JNR-FFI 2.3.3,
`1.5.0-SNAPSHOT`, CLI and all direct development-tool versions unchanged.
No core.async.flow migration, release, tag or publication is included.

## Resolved production graph

| Dependency | Before | After |
| --- | --- | --- |
| core.async | 1.6.681 | 1.9.865 |
| tools.analyzer.jvm | 1.2.3 | 1.3.3 |
| tools.analyzer | 1.1.1 | 1.2.0 |
| core.memoize | 1.0.253 | 1.1.266 |
| core.cache | 1.0.225 | 1.1.234 |
| data.priority-map | 1.1.0 | 1.2.0 |
| tools.reader | 1.3.6 | 1.5.0 |

Both analyzer graphs request ASM 9.2, which loses ordinary version selection to
JNR's ASM 9.10.1. JNR/jffi/native/assembler and all selected ASM versions remain
unchanged. Independent consumers now require the exact seven async JARs and
record their SHA-256 hashes as well as the existing native graph. Old/missing/
duplicate async JARs fail the gate; negative controls cover those failures.

## Internal compatibility and contracts

`src/paclo/stream/impl.clj` is the only production core.async caller. It owns
fixed channels and a stateless, shared `(fn-handler callback false)`, calling
`impl/put!` and `impl/take!` before falling back to `>!!` and `<!!`.
The released 1.6.681 and 1.9.865 `fn-handler` implementations have identical
Lock/Handler behavior: always active, nonblockable, lock ID zero and a stable
commit callback. The protocols source only adds `Capacity`; the ReadPort,
WritePort, Handler and Buffer signatures used here remain unchanged.
See [versioned handler source](https://github.com/clojure/core.async/blob/v1.9.865/src/main/clojure/clojure/core/async.clj)
and [protocols](https://github.com/clojure/core.async/blob/v1.9.865/src/main/clojure/clojure/core/async/impl/protocols.clj).
Paclo keeps its own future dispatcher and blocking consumer ownership.

No production runtime change was necessary. Regression tests check repeated
empty/full operations with the shared immediate handler: failed immediate
operations must not register pending puts/takes or consume later values.
Additional tests exercise concurrent runtimes with capacity-one buffers and
repeated nil/false values, deterministic dropping and abandonment accounting,
and closing an actually blocked branch while its sibling receives every value.
The full existing lifecycle suite retains early reduced, consumer/source error,
source cancellation, close timeout, callback error, idempotence and monotonic/
bounded statistics checks. Existing managed native-capture tests exercise real
PCAP fixtures and exception cleanup. Distribution consumers additionally check
nil/false delivery through capacity-one public branches on every runtime.

The retention probe generates unchunked large byte arrays on demand, uses two
blocking branches plus an unconsumed dropping branch, verifies order and exact
terminal counter conservation, then closes 50 saturated runtimes. Sampled weak
payload references must clear while all completed/abandoned handles stay alive.
A smaller probe is part of the ordinary Clojure suite; the separate bounded-heap
run records stress evidence. These checks do not promise a byte limit on values:
queue capacity continues to bound value count and packet arrays remain shared.

## Verification

Local macOS x64 Temurin21.0.12.1+1 / Clojure1.12.6 / libpcap1.10.1:

- `bash dev/script/codex.sh doctor`, `prepare`, focused stream tests and `check`
  pass:498 Clojure tests /19,669 assertions,13 JUnit tests, offline smoke.
  The same23 focused tests /707 assertions pass under both async versions.
- clj-kondo:zero warnings/errors. Eastwood completes all namespaces with648
  informational warnings (including12 boxed-arithmetic warnings in the new
  probe) and zero exceptions. All four runner exit-status controls pass.
- LSP namespace cleanup and final formatting dry-runs pass. The initial format
  difference was one indentation space in the new regression; corrected.
- SpotBugs, CheckStyle and JaCoCo pass;80.8% exceeds the unchanged25% threshold.
- All40 documentation examples and16 parser controls pass; Markdown lint and
  local links/anchors pass. Distribution negative controls:16 tests pass.
- The unchanged mid50k decode performance gate passes at514.1ms against its
  existing1000ms warning /1200ms failure limits.
- Actual JDK25.0.4.1+1 source compilation,13 JUnit tests,498 Clojure tests /
  19,669 assertions, native/BPF/interface smoke and dependency inventory pass.
  JDK25 logs retain default native-access warnings without suppression.

Initial sandbox dependency resolution failed on Maven-cache permissions;
preparation succeeded with normal cache/network access. Markdown lint likewise
needed npm network/cache access. These failed attempts are not passing checks.
The installed hook's `clj` entrypoint requires unavailable rlwrap; after separate
successful wrapper tests and LSP checks, its documented SKIP_TESTS/SKIP_FMT flags
were used while retaining hook Markdown and kondo checks. No hook is edited.

No existing CI job, required gate, threshold or support guard is changed.

## Performance comparison and adoption trade-off

Use the unchanged `paclo.dev.stream-combined-bench` on the same macOS x64/JDK21
machine with200000 generated64-byte UDP packets in an actual Classic PCAP,
three warmups and five measurements per scenario in each independent JVM.
Capture/branch capacities are4096; the idle dropping branch has64 slots.
Production source is identical between versions. Initial reports record base
HEAD `4a113c6`; the after runs use the uncommitted dependency update later
committed as `da7a8c7`. The filenames, commands and before/after dependency
trees identify that difference; the base SHA alone does not. Reports include runtime/commit,
CPU, allocation, heap peak, GC and complete capture/stream counters.
[Before1](p14-b-evidence/before-1.edn), [before2](p14-b-evidence/before-2.edn),
[after1](p14-b-evidence/after-1.edn), [after2](p14-b-evidence/after-2.edn) and the
[summary](p14-b-evidence/comparison-summary.edn) retain every run.

Reproduce each variant in a fresh JVM, repeating twice:

```bash
clojure -Sdeps '{:deps {org.clojure/core.async {:mvn/version "1.6.681"}}}' -M:dev -m paclo.dev.stream-combined-bench --count 200000 --warmups 3 --runs 5 --output /tmp/old.edn
clojure -M:dev -m paclo.dev.stream-combined-bench --count 200000 --warmups 3 --runs 5 --output /tmp/new.edn
```

Run diagnostic controls separately with `clojure -M:dev dev/p14-b-evidence/callback-diagnostic.clj.txt default /tmp/control.edn`,
selecting `legacy-adapter` or `legacy-dispatch` instead of `default`.

| Scenario | Old pps, JVM1 / JVM2 | New pps, JVM1 / JVM2 | Throughput change |
| --- | --- | --- | --- |
| Managed control | 443527 /403170 | 461212 /385800 | +4.0% /−4.3% |
| Managed dual blocking | 409631 /386138 | 266400 /273354 | −35.0% /−29.2% |
| Managed fast plus idle dropping | 481943 /469472 | 401492 /400904 | −16.7% /−14.6% |

Dual allocation rises1051→1227 and993→1234 bytes/packet; dropping rises836→923
and835→916. Control stays about645 bytes/packet. Dual CPU rises1.33→1.69s
and1.36→1.69s per200000 packets. Both blocking consumers receive every packet;
fast/drop runs always deliver200000 to fast and64 to slow with199936 drops.
No capture drops or errors occur; all buffers stay within configured capacities.

This is a material measured regression in these scenarios despite the existing
performance gate passing. Do not claim a speedup or equivalence. Allocation
snapshots cover live JVM threads and can be affected by JIT/scheduling; they
are not exact per-class allocation profiles. A third old-version recheck and
callback controls examine repeatability; the third new-version combined run
is retained but excluded because it overlapped JDK25 source-check startup.
The clean third old-version recheck reaches473099pps /996B per packet in the
dual scenario. A later isolated1.9.865 control reaches303834pps /1256B.
A diagnostic that strips the new channel callback metadata adapter reaches
372756pps /1051B; additionally using an eight-thread fixed callback executor
reaches422678pps /1012B. All run three warmups/five measurements with exact
200000-value counts. See the [diagnostic source](p14-b-evidence/callback-diagnostic.clj.txt),
[raw control](p14-b-evidence/callback-default.edn),
[adapter control](p14-b-evidence/callback-adapter.edn),
[dispatch control](p14-b-evidence/callback-dispatch.edn) and
[summary](p14-b-evidence/diagnostic-summary.edn).

Upstream1.9.865 adds `on-caller` completion metadata and `appm` callback wrappers;
these controls support partial attribution to that adapter/scheduling change,
not a complete per-class allocation explanation. Removing metadata also changes
callback scheduling, so this is not an isolated wrapper-allocation experiment.
No default callback/executor override or workaround ships in this PR.
Reviewer acceptance must include this measured cost; further optimization or
upstream investigation needs its own justified measurement, preserving the
existing delivery/termination contracts.

## Bounded-heap load and retention

The JDK21 probe passes with `-Xmx256m`,8000000 unchunked64KiB payloads
(524288000000 generated payload bytes) over87.8seconds and50 additional
saturated-close cycles. Both blocking branches receive all8000000 values in
order; the four-slot idle branch drops7999996. All terminal conservation and
capacity checks pass. All8050 sampled payload weak references clear while the
completed/abandoned handles remain strongly reachable. The metric summing JVM
heap-pool peaks is126923064bytes; allocated bytes are537271812288 with5848GCs
and4026ms GC time. This metric is not peak RSS or an exact retained-heap size.
See the [raw long probe](p14-b-evidence/retention-long-jdk21.edn) and
[initial2000000-value probe](p14-b-evidence/retention-jdk21.edn).

Reproduce with `clojure -J-Xmx256m -M:dev -m paclo.dev.stream-retention 8000000 65536 /tmp/retention.edn`.
JDK17.0.20.1,21.0.12.1 and25.0.4.1 also each pass the2000000-value/64KiB
probe in22.3,22.6 and22.1seconds respectively, with2050/2050 sampled payloads
released on every runtime. See the [cross-JDK summary](p14-b-evidence/retention-summary.edn).
The ordinary suite runs a smaller2000-value/16KiB regression including the50
abandon cycles. This finite synthetic stress does not establish indefinite
production-trace memory behavior or live capture performance.

## CI and distribution

Implementation `da7a8c7` passes all16 jobs in
[CI39127114926](https://github.com/nantes-rfli/paclo/actions/runs/39127114926):
Linux x64/JDK21, macOS ARM64/JDK17, Linux ARM64, JDK25 source, independent same-JAR
17/21/25 consumers,25 debug/deny, quality/coverage/static/documentation and all
three performance shards plus the27-scenario merger. No workflow is changed.
[Job conclusions](p14-b-evidence/ci-implementation-result.json) preserve status.

The clean CI JDK21 producer uses PR merge ref `7b7a91ea08b77a48d6bf52da22cd99f7955de33c`;
JAR SHA256 `9dfdf2294d2fb4310bb76eda901e33738495c12e12e6a6aacc88f539b85fd745`.
All three independent consumers verify that identical hash and the exact seven
async JAR hashes. See [producer provenance](p14-b-evidence/provenance-ci-jdk21.json),
[17](p14-b-evidence/consumer-jdk17-linux-x64.json),
[21](p14-b-evidence/consumer-jdk21-linux-x64.json),
[25](p14-b-evidence/consumer-jdk25-linux-x64.json),
[25 debug](p14-b-evidence/consumer-jdk25-native-access-linux-x64.json) and
[25 deny](p14-b-evidence/consumer-jdk25-unsafe-deny-linux-x64.json).
The default logs retain native-access warnings; debug and Unsafe denial pass.
The local JDK21 package and strict JAR inventory/Java17 class-file/POM/source
inspection also pass. Its SHA256 is
`94f54fc37690fb7640ff84b2795bb0cb87917368a170ed5d6537116a329be792`;
source is `da7a8c7`, with `source_dirty:true` because evidence/docs were edited.
The [local provenance](p14-b-evidence/provenance-local-jdk21.json) records this
separately from the clean CI artifact. That identical local JAR passes fresh
checkout-independent [17](p14-b-evidence/consumer-local-jdk17.json),
[21](p14-b-evidence/consumer-local-jdk21.json),
[25](p14-b-evidence/consumer-local-jdk25.json),
[25 debug](p14-b-evidence/consumer-local-jdk25-debug.json) and
[25 deny](p14-b-evidence/consumer-local-jdk25-deny.json) runs, each with seven
resolved async hashes and unchanged native graph. Default warnings are retained.
Final evidence-only head CI is recorded in the PR before handoff.

Unverified: representative production traces, live NIC traffic, live capture
throughput/drop rates, JDK 25 on all supported OS/CPU combinations, Windows and
32-bit. JDK 17/21 remain formally supported; JDK 25 remains an experiment.
