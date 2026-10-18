# P14-B: core.async update and asynchronous compatibility

Status: implementation and verification in progress; independent review and
merge are separate. P14 as a whole remains unfinished.

## Selection and scope

Started from latest main `4a113c60184128df442f3fa152ebf0390cedc6a5`.
[PR #75](https://github.com/nantes-rfli/paclo/pull/75) merged on 2026-10-18 at
12:00:29 UTC (21:00:29 Asia/Tokyo). The supplied checkout was clean.

On 2026-10-18, the [official core.async repository](https://github.com/clojure/core.async)
identifies 1.9.865 as its latest release. Maven Central metadata also lists
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

Local and CI results will be recorded after the required commands complete.
No existing CI job, required gate, threshold or support guard is changed.

Unverified: representative production traces, live NIC traffic, live capture
throughput/drop rates, JDK 25 on all supported OS/CPU combinations, Windows and
32-bit. JDK 17/21 remain formally supported; JDK 25 remains an experiment.
