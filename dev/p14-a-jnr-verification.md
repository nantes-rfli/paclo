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
| P14-A JNR2.3.3/jffi1.4.3, local macOS x64 | Pass; native-access warning only | Pass; no Unsafe warning/stack observed | Pass; full same-JAR consumer |

Default startup applies no suppression or native-access option. It still reports
`System.load` from `com.kenai.jffi.internal.StubLoader` in the unnamed module.
The diagnostic options are explicitly
`--enable-native-access=ALL-UNNAMED --sun-misc-unsafe-memory-access=debug`
or the same native permission with `--sun-misc-unsafe-memory-access=deny`.
Native permission removes its corresponding warning only in diagnostic runs.

The [official jffi1.4.3 source artifact](https://repo.maven.apache.org/maven2/com/github/jnr/jffi/1.4.3/jffi-1.4.3-sources.jar),
`com/kenai/jffi/MemoryIO.java:isUnsafeAvailable`, returns false when the Java
major version is at least23; `newMemoryIO` then chooses the JNI native implementation.
This explains the measured change; warning removal was not assumed beforehand.
It is not an FFM migration or proof of compatibility with future native restrictions.
[Issue #74](https://github.com/nantes-rfli/paclo/issues/74) remains the review context.
Unsafe-denial success is not required for this update's acceptance and does not
expand the formal support promise. Unfiltered local default/debug/deny logs and
JSON are retained separately in `/tmp/paclo-p14-a`; CI uploads them separately.

## Verification checkpoint and limits

Commands, completed checks and CI results are maintained in [the work log](work-log.md).
At this checkpoint prepare, package, graph resolution, all five local independent
consumers and15 Python distribution regression tests pass. Source25, full21,
quality/lint/docs/performance and CI completion are still being collected.
No pending check counts as passed. Final PR-head CI evidence belongs in the PR.

Unverified: live NIC capture/traffic/drop statistics, long production workloads,
JDK25 ARM64, other OS/JVM vendors, JDK25 analyzers/coverage/performance, Windows,
32-bit and future JDKs. Offline results are not operational throughput claims.
Existing JDK21 analyzer/coverage/performance gates remain required; no gate or
support guard is weakened. P14's other updates require separate selection.
