# P14-A: JNR-FFI update and native compatibility

## Scope and upstream selection

Start: main `4a86d666be839e89480bd02d5772dbc5cf87cdb8`, after independently
reviewed [P13 PR #73](https://github.com/nantes-rfli/paclo/pull/73) merged at
2026-10-18 09:58:37 UTC. Its final head `ee74766` passed all16 CI jobs in
[run39113609011](https://github.com/nantes-rfli/paclo/actions/runs/39113609011).
[P11](p11-environment-inventory.md) and [P13](p13-jdk25-verification.md) are
historical baselines, not evidence that this candidate passes.

Rechecked official sources on2026-10-18 (Asia/Tokyo):

- [Maven Central metadata](https://repo.maven.apache.org/maven2/com/github/jnr/jnr-ffi/maven-metadata.xml)
  names **2.3.3** as latest/release, lastUpdated20260915181839.
- The [published POM](https://repo.maven.apache.org/maven2/com/github/jnr/jnr-ffi/2.3.3/jnr-ffi-2.3.3.pom)
  and [official tag POM](https://github.com/jnr/jnr-ffi/blob/2.3.3/pom.xml)
  identify2.3.3, jffi1.4.3 and ASM9.10.1. The
  [GitHub Releases page](https://github.com/jnr/jnr-ffi/releases) still labels
  2.3.2 latest; publication metadata and the tag establish the newer stable artifact.

Only JNR-FFI changes in the production declarations:2.2.14 →2.3.3.
Clojure1.12.6, core.async1.6.681, all other production/tool versions,
`--release 17 -Xlint:all -Werror -proc:none`, `1.5.0-SNAPSHOT`, public APIs,
artifact inventory and quality/performance thresholds remain unchanged.
Formal support remains JDK17/21. This does not decide formal JDK25 support.

Actual `clojure -Stree` selects jffi1.4.3 **both Java and native classifier**,
ASM/commons/analysis/tree/util9.10.1, jnr-a64asm1.0.0 and jnr-x86asm1.0.2.
core.async's analyzer still requests ASM9.2, which loses ordinary version
selection to9.10.1; core.async/analyzer declarations are not upgraded.
The independent consumer checks this selected graph and records each JAR SHA256.
Negative controls reject stale native classifiers, mixed ASM versions, missing
and duplicate entries, as well as the existing wrong direct-POM dependencies.
No production transitive overrides are introduced.

## Local native and distribution evidence

Host: macOS15.4.1, Darwin24.4.0, Intel Core i7-8700B3.20GHz, x86_64.
Clojure CLI1.12.5.1654; Clojure library1.12.6. Actual Temurin runtimes:
17.0.20.1+1,21.0.12.1+1-LTS,25.0.4.1+1-LTS. JDK17/25 are the official,
checksum-verified archives provisioned by P13 under `/tmp/paclo-p13/jdks`;
[P13 archive identities](p13-evidence/jdk-archives.json) apply to those files.

JDK21 produces one JAR and the checkout-independent consumers17/21/25 all pass,
including both25 diagnostic reruns. Local JAR SHA256:
`918f9da3e2275a367c5bfff69a4cec59369e68eda7a64d37314857b47fda5f79`.
Source provenance is the main SHA above with `source_dirty:true` for this update;
all ten Java classes are major61. The same JAR is verified before/after each
consumer, with `-Srepro` in fresh external temporary projects. No source recompilation
or user dependencies supply Paclo. Cached success does not prove cold setup.

Each consumer actually loads **libpcap1.10.1**, with
`dladdr(pcap_lib_version)` identifying `/usr/lib/libpcap.A.dylib` (system/dyld
cache), logical JNR name `libpcap.dylib`. Pointers and C-long are8 bytes.
No Homebrew library or standalone system library hash is claimed.

Existing real-fixture coverage includes physical PCAP headers/bytes/time through
native EOF; struct layouts; successful/no-match/invalid BPF; failed open;
interface enumeration/free; native and Classic writer metadata/precision,
truncated/malformed reads, writer flush/errors and repeated close. Independent
consumers cover six native DLT round trips, rich PCAPNG known-semantics read/write,
early-reduced cleanup, DNS/TLS/Flow/window and bounded capture/fan-out shutdown.
The full suite additionally exercises exceptional/abandoned/full-queue ownership.
No production binding change or duplicate native regression test is needed.
Existing JUnit ABI tests now also run in the supported macOS ARM64 and Linux
ARM64 source jobs, alongside their unchanged Clojure suites. Those jobs print
CPU and actual loaded native library identities.

## JDK25 warnings: measured conditions

| Graph | Default options | Native access + Unsafe debug | Native access + Unsafe deny |
| --- | --- | --- | --- |
| P13 JNR2.2.14/jffi1.3.11 | Pass; native-access and Unsafe.putLong warnings | Pass; Unsafe stacks in jffi registration/read/write | Fail; UnsupportedOperationException putLong in registration |
| P14-A JNR2.3.3/jffi1.4.3, macOS x64 and Linux x64 CI | Pass; native-access warning only | Pass; no Unsafe warning/stack observed | Pass; full same-JAR consumer |

Default startup applies no suppression or native-access option. It still reports
`System.load` from `com.kenai.jffi.internal.StubLoader` in the unnamed module.
The diagnostic options are explicitly
`--enable-native-access=ALL-UNNAMED --sun-misc-unsafe-memory-access=debug`
or the same native permission with `--sun-misc-unsafe-memory-access=deny`.
Native permission removes its corresponding warning only in diagnostic runs.

The [official jffi1.4.3 source artifact](https://repo.maven.apache.org/maven2/com/github/jnr/jffi/1.4.3/jffi-1.4.3-sources.jar),
`com/kenai/jffi/MemoryIO.java:isUnsafeAvailable`, returns false when the Java
major version is at least23; `newMemoryIO` then chooses the JNI native implementation.
The actual local JDK25 `MemoryIO/getInstance` class is
`com.kenai.jffi.MemoryIO$NativeImpl64` (see the retained diagnostic log).
This explains the measured change; warning removal was not assumed beforehand.
It is not an FFM migration or proof of compatibility with future native restrictions.
[Issue #74](https://github.com/nantes-rfli/paclo/issues/74) remains the review context.
Unsafe-denial success is not required for this update's acceptance and does not
expand the formal support promise. Unfiltered local default/debug/deny logs and
JSON are retained separately in `/tmp/paclo-p14-a`; CI uploads them separately.

## Verification checkpoint and limits

Commands, completed checks and CI results are maintained in [the work log](work-log.md).
Local checks are complete: JDK21 full check and JDK25 source experiment each
pass JUnit13/13 and493 Clojure tests/19,130 assertions with zero failures/errors,
including native/BPF/interface checks. All40 maintained documentation examples,
clj-kondo (zero warnings/errors), Eastwood (636 informational warnings, zero
exceptions), LSP namespace/format dry-runs, Markdown54 files and local links pass.
SpotBugs, CheckStyle and JaCoCo80.8% pass with the unchanged25% threshold.
The unchanged JDK21 mid-50k gate passes before/after at849.1/777.1ms
(warn1000/fail1200). These are single cold gates with no separate warm-up,
allocation/drop instrumentation or statistical throughput-improvement claim.
Source, test fixtures, CPU and runtime stay fixed for this coarse comparison.

Machine-readable local [producer](p14-a-evidence/provenance-jdk21-macos-x64.json),
consumers [17](p14-a-evidence/consumer-jdk17-macos-x64.json),
[21](p14-a-evidence/consumer-jdk21-macos-x64.json),
[25](p14-a-evidence/consumer-jdk25-macos-x64.json),
[debug](p14-a-evidence/consumer-jdk25-debug-macos-x64.json),
[deny](p14-a-evidence/consumer-jdk25-deny-macos-x64.json),
[source25](p14-a-evidence/source-jdk25-macos-x64.json)/
[steps](p14-a-evidence/source-jdk25-macos-steps.json) and
[actual memory implementation](p14-a-evidence/jffi-memory-jdk25-macos-x64.log)
retain exact identities and conditions.

Implementation [PR #75](https://github.com/nantes-rfli/paclo/pull/75),
head `c0fd760`, runs in
[CI39124535933](https://github.com/nantes-rfli/paclo/actions/runs/39124535933).
Its required Linux x64 JDK25 source job passes JUnit13/13 and493 Clojure tests /
19,136 assertions (six existing Linux-specific assertions), compilation/native
checks and dependency inventory. Exact Temurin25.0.4.1+1-LTS, Linux kernel
6.17.0-1022-azure, loaded `/lib/x86_64-linux-gnu/libpcap.so.1.10.4`, libpcap1.10.4
with TPACKET_V3 and8-byte pointer/C-long are in the separate
[Linux source report](p14-a-evidence/source-jdk25-linux-x64.json)/
[steps](p14-a-evidence/source-jdk25-linux-steps.json).
All16 implementation CI jobs pass, including the required build aggregate,
40 documented examples, existing supported-platform/ARM64 jobs, every analyzer/
coverage/lint gate and all three performance shards/merger. The CI JDK21
mid-50k gate passes at827.1ms against the same1000/1200ms budgets.

The CI producer uses clean PR merge ref `59020db917798efd04bcfc50d35b684ea20be308`;
its JAR SHA256 is
`3097d9c215ae832635d4d80c9d356b55fa64f2e093a31a24266ea0335293ba7d`.
This single artifact passes independent17/21/25 consumers plus25 debug/deny.
Default25 has only the native-access warning; debug/deny have no Unsafe warning
and denial exits0. Separate CI [producer](p14-a-evidence/provenance-ci-jdk21.json),
[17](p14-a-evidence/consumer-jdk17-linux-x64.json),
[21](p14-a-evidence/consumer-jdk21-linux-x64.json),
[25](p14-a-evidence/consumer-jdk25-linux-x64.json),
[debug](p14-a-evidence/consumer-jdk25-debug-linux-x64.json),
[deny](p14-a-evidence/consumer-jdk25-deny-linux-x64.json) and
[job conclusions](p14-a-evidence/ci-implementation-result.json) retain identity.
Local and CI producer hashes are intentionally distinct.

Native source CI records these additional CPU/platform conditions; all use
JNR2.3.3/jffi1.4.3 and8-byte pointers/C-long. Full log
[identity excerpts](p14-a-evidence/ci-platform-identity-excerpts.log) retain exact
JVM/OS/CPU/library details; original unfiltered logs remain in Actions.

| Source job | CPU | Actual OS/JDK | Loaded libpcap |
| --- | --- | --- | --- |
| Linux x64 supported | AMD EPYC7763 | Linux6.17.0-1022-azure, Temurin21.0.12.1+1-LTS | 1.10.4 TPACKET_V3, /lib/x86_64-linux-gnu/libpcap.so.1.10.4 |
| Linux x64 experiment | AMD EPYC9V74 | Ubuntu24.04/Linux6.17.0-1022-azure, Temurin25.0.4.1+1-LTS | Same1.10.4 image; native/dev packages1.10.4-4.1ubuntu3.1 |
| macOS ARM64 supported | Apple M1 (Virtual) | macOS26.6.2, Temurin17.0.20.1+1 | 1.10.1, /usr/lib/libpcap.A.dylib |
| Linux ARM64 supported | Neoverse-N2 | Linux6.17.0-1022-azure, Temurin21.0.12.1+1-LTS | 1.10.4 TPACKET_V3, /lib/aarch64-linux-gnu/libpcap.so.1.10.4 |

P14-A implementation/compatibility verification is complete; independent review
is pending on PR75. The final evidence commit changes records only; final-head
CI is checked and recorded in the PR separately before handoff.

Unverified: live NIC capture/traffic/drop statistics, long production workloads,
JDK25 ARM64, other OS/JVM vendors, JDK25 analyzers/coverage/performance, Windows,
32-bit and future JDKs. Offline results are not operational throughput claims.
Existing JDK21 analyzer/coverage/performance gates remain required; no gate or
support guard is weakened. P14's other updates require separate selection.
