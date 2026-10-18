# P13: JDK 25 compatibility verification

## Scope and decision

Started from main `e2a5eb11617aa5e364da340672424fac284d0251` after
[P15 PR #71](https://github.com/nantes-rfli/paclo/pull/71) merged at
2026-10-18 08:10:36 UTC. No production source, public API, dependency, release
version, Java compilation option or support guard changes are included.

The current graph works under default JDK 25 on the measured macOS x64 host,
including the JDK 21-built distribution and a separate source build/test run.
Keep JDK 17/21 formally supported. JDK 25 remains an explicitly tested experiment:
Linux x64 CI results are recorded below; other OS/CPU/vendor combinations and
live capture require separate evidence before extending formal support.
Existing JDK 21 analyzer, coverage and performance gates remain mandatory.
A successful runtime experiment does not validate those tools under JDK 25.

## Local environment and artifact identity

All local results are from 2026-10-18 (Asia/Tokyo): macOS 15.4.1, Darwin 24.4.0
`xnu-11417.101.15~117/RELEASE_X86_64`, Intel Core i7-8700B at 3.20 GHz,
`x86_64`. Clojure library 1.12.6; CLI 1.12.5.1654. The repository CI keeps
CLI 1.11.1.1435 for the new experiment. JNR-FFI 2.2.14 resolves jffi Java/native
1.3.11; production dependencies are unchanged.

| Role | Actual Eclipse Adoptium Temurin runtime | Result |
| --- | --- | --- |
| Producer | 21.0.12.1+1-LTS | Built `1.5.0-SNAPSHOT` once, all ten binding classes major 61 |
| Independent consumer | 17.0.20.1+1 | Passed |
| Independent consumer | 21.0.12.1+1-LTS | Passed |
| Independent consumer | 25.0.4.1+1-LTS | Passed, default JVM options; warnings retained |
| Source build/test | 25.0.4.1+1-LTS | Passed: JUnit 13/13, Clojure 493 tests / 19,130 assertions |

The **same** producer JAR SHA-256 for all three consumers is
`1acc1ee887dfcf9f9ac2ad18ceabad0267c14f20fa4826d7e066493e774aa015`.
Its POM SCM/source commit is the main commit above. Provenance records
`source_dirty: true` because development harness edits were present; packaged
production source bytes still match the unchanged main implementation.
No JDK 25-built JAR is substituted for the JDK 21 candidate.

Each consumer uses a fresh temporary project outside the checkout, `-Srepro`,
only the supplied JAR/harness/fixtures and fixed production dependencies. It
checks every source/binding origin and both pre/post hashes. No repository
classes, user deps or source recompilation supply the library. Shared Maven
cache availability is not evidence of a cold dependency download.
JDK 17/25 archives were downloaded to `/tmp/paclo-p13/jdks` from the official
Adoptium API/release URLs and checked against their SHA-256. The installed
`openjdk@25` alias actually launched 26.0.2.1 and was excluded before testing.
The source runner verifies the actual specification version is 25.

All three JVMs load **libpcap 1.10.1**, with `dladdr(pcap_lib_version)` reporting
`/usr/lib/libpcap.A.dylib` (macOS system/dyld shared cache). JNR's logical loader
name is `libpcap.dylib`; it does not identify Homebrew/tcpdump's separate library.
Pointer and C-long sizes are both eight bytes. OS build identifies this system
library installation; a standalone library-file hash is not claimed.

Machine-readable [producer provenance](p13-evidence/provenance-jdk21.json),
[JDK archives](p13-evidence/jdk-archives.json), independent
[JDK 17](p13-evidence/consumer-jdk17-macos-x64.json),
[JDK 21](p13-evidence/consumer-jdk21-macos-x64.json),
[JDK 25](p13-evidence/consumer-jdk25-macos-x64.json) reports and
[source runtime](p13-evidence/source-jdk25-macos-x64.json)/
[source commands](p13-evidence/source-jdk25-steps.json) retain exact identities.

## Executed checks

`bash dev/script/codex.sh doctor` passes on supported JDK 21 with an actual
four-packet/438-byte offline native read. JDK 25 verification uses direct
commands rather than widening `environment-check`'s deliberate 17/21 guard.

After `bash dev/script/codex.sh package` under JDK 21:

```bash
python3 dev/script/verify_distribution.py prepare target/paclo-1.5.0-SNAPSHOT.jar /tmp/paclo-p13/distribution-final
```

With each selected JDK's `JAVA_HOME` and `bin` first on `PATH`, invoke the
bundle's verifier (the following is the JDK 25 example):

```bash
python3 /tmp/paclo-p13/distribution-final/verify_distribution.py consume /tmp/paclo-p13/distribution-final --report /tmp/paclo-p13/consumer25-final.json
python3 dev/script/verify_jdk25.py /tmp/paclo-p13/source25-final
```

All steps exit 0. The source runner executes `build/javac`, `build/javac-test`,
`build/junit`, the full Clojure suite, direct native smoke and `-Stree`.
`--release 17 -Xlint:all -Werror -proc:none` and JUnit `--fail-if-no-tests` remain
unchanged. Native regression tests compare every physical fixture record's time,
lengths and bytes to JNR reads through EOF; exercise the real BPF structure,
compile/set/filter, invalid syntax, failed open and repeated close. Existing
JUnit struct/stat tests remain included. No tests are skipped.

Each independent consumer checks successful/no-match/invalid BPF, failed open,
interface enumeration/free, native load, idempotent close, six DLT full/flow
projections and Classic PCAP exact metadata/bytes round trips, DNS annotation/
correlation, TLS, Flow/window state, rich PCAPNG known-semantics round trip,
PCAPNG EOF/early-reduced close and bounded managed capture/fan-out shutdown.
The full source suite additionally exercises malformed native reads, truncated
records, timestamp precedence, writer publication/error cleanup, exceptions,
full queues, abandonment and repeated close. Offline stats tests check layout
and mocked lifecycle; live NIC statistics are not validated.

Initial harness compilation exposed explicit `close()` inside Java
try-with-resources as an `-Xlint:try` warning. The final tests use explicit
try/finally ownership for double-close checks; warning/error flags are unchanged.
The first failed run is not counted as a pass.

## Native-access and Unsafe diagnostics

Default startup succeeds with two distinct JDK 25 warnings:

- Restricted `System.load` called by `com.kenai.jffi.internal.StubLoader` in
  the unnamed module from jffi 1.3.11. This is the native-access warning described
  by [JEP 472](https://openjdk.org/jeps/472).
- Terminally deprecated `sun.misc.Unsafe.putLong` called by
  `com.kenai.jffi.UnsafeMemoryIO$UnsafeMemoryIO64`. This is the memory-access
  warning described by [JEP 498](https://openjdk.org/jeps/498).

A separate full consumer run with
`--enable-native-access=ALL-UNNAMED --sun-misc-unsafe-memory-access=debug`
succeeds and preserves Unsafe stack traces. Its first call chain is
`UnsafeMemoryIO64.putAddress` → `NativeMethods.register` →
`AbstractX86StubCompiler.attach` → `AsmLibraryLoader` → `PcapLibrary.<clinit>`.
Further memory reads/writes also use Unsafe. Native access permission removes
its corresponding warning, while Unsafe debug still reports its own calls.
This is diagnostic attribution, not blanket warning suppression or a replacement
for the default successful run.

With native access enabled but `--sun-misc-unsafe-memory-access=deny`, the same
JAR fails with `UnsupportedOperationException: putLong` during jffi registration,
before ordinary packet processing. This intentionally restrictive diagnostic is
not the JDK 25 default. It establishes a real future-compatibility constraint:
P14 must evaluate the JNR/jffi graph and repeat native/ABI tests; this task does
not upgrade JNR or assume an upgrade eliminates Unsafe. No all-platform or
future-JDK guarantee follows from the default success.

Local unfiltered logs remain in `/tmp/paclo-p13` (`consumer25-final.log`,
`consumer25-debug-final.log`, `consumer25-deny.log`, `source25-final/*.log`).
CI uploads default/debug consumer logs, JSON and source logs, including failures.

## CI and remaining acceptance

The required `build` aggregate retains every old dependency and additionally
requires `jdk25-source`. The existing no-checkout consumer matrix retains 17/21
and adds 25, all downloading the single JDK 21 artifact. The 25 source job uses
Ubuntu 24.04 x64/Temurin 25, pinned existing CLI, installed libpcap, direct
compilation/JUnit/Clojure/native commands and unfiltered logs. Reports include
exact JVM, OS/architecture, dependency versions and loaded libpcap image/version;
the job records the installed native package builds. Failures remain fatal.

Final-head CI results and the P13 PR link will be recorded after execution.
The JDK 17/21 local full check and unchanged quality gates are recorded in the
work log as they complete. No skipped/blocked check counts as success.

Unverified: JDK 25 Linux ARM64, macOS ARM64, Windows/other OSes, other JDK vendors,
live capture privileges/traffic, NIC/drop statistics, long-running production
workloads, performance targets under 25, and analyzer/coverage-tool operation
under 25. Existing platform CI on JDK 17/21 remains separate evidence.
