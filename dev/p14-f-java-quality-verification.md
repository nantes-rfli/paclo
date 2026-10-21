# P14-F: SpotBugs and JaCoCo verification

Selected on2026-10-21 (Asia/Tokyo) from fetched main `204d72c` after PR83 merged.
Scope: SpotBugs/annotations4.8.6 ->4.10.5 and JaCoCo agent/CLI0.8.12 ->0.8.15.
Clojure1.12.6, core.async1.6.681, JNR-FFI2.3.3, CLI1.12.5.1664,
tools.build0.10.14,1.5.0-SNAPSHOT and Java `--release 17` remain fixed.
CheckStyle10.18.0 and JUnit Platform1.10.2 remain fixed. No public API changes.

## Same-class before/after comparison

Local platform: macOS x86_64, Temurin21.0.12.1+1, libpcap1.10.1,
CLI1.12.5.1664. Initial doctor used installed CLI1.12.5.1654; all subsequent
checks explicitly selected the existing checksum-verified1664 installation.
Only JDK21 is available locally; supported17 and experimental25 require CI.

Ran original runners first, then changed only dependency pins and ran the same
runners against the same compiled Java17 bindings. Original XML reports and
resolved trees are preserved in [p14-f-evidence](p14-f-evidence).

| Measurement | Old | New, original runner | Final runner |
| --- | --- | --- | --- |
| SpotBugs analyzed classes | 10 | 10 | 10 |
| Findings | 1 EI_EXPOSE_REP | 1 EI_EXPOSE_REP | 1 EI_EXPOSE_REP |
| Analysis errors / missing classes | 0 / 0 | 0 / 0 | 0 / 0 |
| JaCoCo instruction covered / total | 228 / 283 | 228 / 283 | 228 / 283 |
| Branch covered / total | 19 / 26 | 19 / 26 | 19 / 26 |
| Line covered / total | 59 / 73 (80.82%) | 59 / 73 (80.82%) | 59 / 73 (80.82%) |
| Complexity covered / total | 28 / 37 | 28 / 37 | 28 / 37 |
| Method covered / total | 22 / 24 | 22 / 24 | 22 / 24 |
| Class covered / total | 7 / 9 | 7 / 9 | 7 / 9 |

SpotBugs counts include interfaces; JaCoCo reports classes with executable code.
No denominator change or new production finding is observed. The line threshold
remains25%; empty reports no longer qualify as100%. The report-level counter is
used once, avoiding duplicate class/package/sourcefile counters.

## Detection and native ownership review

The finding is `PcapHandle.pointer()` returning its owned `jnr.ffi.Pointer`.
This intentional public binding accessor supplies the pointer to native libpcap
calls. A defensive Java pointer copy would not copy/own a native `pcap_t` safely.
The established single-owner close contract remains; this is a documented API
exposure, not a newly discovered leak. Keep the finding visible and informational
under the existing policy, without adding any suppression or weakening a rule.

Reviewed `PcapHandle`/`BpfProgram` idempotent close, successful and failed offline
open, `compileFilter`/`freeFilter`, device-list ownership and the borrowed
`pcap_dump_file` stream contract. Existing real-native JUnit tests exercise failed
open, valid open/read/EOF, BPF compile/install/free and repeated close. Static
analysis cannot establish arbitrary native lifetime correctness, race safety or
live capture validity. Existing best-effort close behavior is not redesigned.

The XML exclusion file stays empty. Existing URF suppressions on BPF/native
struct fields retain their ABI purpose: JNR/native access is not an ordinary Java
read. No lambda is present in those suppression scopes, so4.10.5's method/lambda
suppression change does not broaden them.

Core plugin descriptors contain497 ->518 pattern IDs:25 added and4 removed,
listed in [detectors.json](p14-f-evidence/detectors.json). These are capability
inventories, not25 new Paclo findings. Added patterns include non-atomic shared
operations, unsafe synchronization, lock ownership, substring misuse and useless
suppressions. A real Java17 probe produces zero findings with4.8.6 and two with
4.10.5: `DMI_MISLEADING_SUBSTRING` for `StringBuilder.substring(0)` and
`RV_RETURN_VALUE_IGNORED_NO_SIDE_EFFECT` for discarded `Arrays.copyOf` output.
Both have concrete source causes, retained as positive controls in the regression
suite; [comparison](p14-f-evidence/detector-probe.json) records actual exits0/1.

Versioned upstream rationale: [SpotBugs4.10.5 changes](https://github.com/spotbugs/spotbugs/blob/4.10.5/CHANGELOG.md)
and [JaCoCo release history](https://www.jacoco.org/jacoco/trunk/doc/changes.html).
JaCoCo0.8.12 supports Java22 and experimentally23;0.8.15 supports through26,
including25. Paclo retains formal17/21 support and the25 experiment.

## Resolved dependency changes

Production changes only annotations4.8.6 ->4.10.5; its jsr3053.0.2 dependency
stays fixed. The direct dependency, generated POM and distribution verifier agree.
No analyzer/coverage implementation enters the production dependency graph.

SpotBugs alias graph changes (see full before/after trees):

| Artifact family | Old selected | New selected |
| --- | --- | --- |
| ASM (all five modules) | 9.10.1 (JNR mediation over analyzer9.7) | 9.11 (analyzer mediation over JNR9.10.1) |
| BCEL | 6.9.0 | 6.13.0 |
| commons-lang3 / commons-text | 3.14.0 / 1.10.0 | 3.21.0 / 1.15.0 |
| dom4j / jaxen | 2.1.4 / 2.0.0 | 2.2.0 / 2.0.6 |
| gson / error_prone_annotations | 2.11.0 / 2.27.0 | 2.14.0 / 2.48.0 |
| slf4j-api / log4j api+core | 2.0.13 / 2.23.1 | 2.0.20 / 2.26.1 |
| Saxon-HE / xmlresolver (+data) | 12.4 / 5.2.2 | 12.10 / 5.3.3 |
| commons-io / jspecify | absent | 2.22.0 / 1.0.1 |
| httpclient5 / httpcore5(+h2) / commons-codec | 5.1.3 / 5.1.3 / 1.15 | removed from this graph |

jcip-annotations1.0-1 remains. ASM9.11 is confined to the analyzer alias;
production and JaCoCo resolve JNR's ASM9.10.1. JaCoCo agent/runtime, CLI, core and
report align at0.8.15; its POM moves ASM9.7 ->9.10.1, already selected through
JNR before this update. args4j2.0.28 remains. These graph comparisons are not a
new NVD audit or a blanket security claim.

## Failure behavior and CI coverage

SpotBugs now requests `-exitcode`: findings bit1 remains informational, missing
classes bit2 and analysis errors bit4 fail, including combined flags. It validates
the newly generated nonempty XML and clears old output before resolving the
classpath. A launcher exit1 without a valid new report also fails. Subprocess
classpath failures propagate from both Java quality entry points.

JaCoCo clears old exec/XML first, uses `append=false`, instruments `paclo.jnr.*`,
and requires JUnit `--fail-if-no-tests`. Instrumenting just bindings avoids
unnecessary framework instrumentation; measured binding counters are unchanged.
Test/report subprocess failures propagate.
Actual old/new failure comparison is retained in
[failure-comparison.json](p14-f-evidence/failure-comparison.json): missing-class
SpotBugs exits0 ->1; empty-report gate exits0 ->1. Corrupt XML and below-threshold
coverage remain failures, with additional malformed-counter controls. The XML reader closes deterministically;
missing, malformed, empty, negative, duplicate or nonnumeric LINE counters fail.
Thresholds below0.25, above1.0 and non-finite values fail.

Regression controls execute real command entry points in disposable projects:
resolution/launcher/test/report errors, all SpotBugs error-flag combinations,
real missing-class analysis, real positive detections, real zero-test JUnit,
real corrupt JaCoCo exec data,25% boundary and corrupt/empty coverage reports.
CI keeps16 jobs. Existing21 build-checks and supported17/21 compatibility jobs
plus experimental25 source job now measure bindings and retain reports. A separate
probe compiles with each actual JDK (class61/65/69), instruments it and checks
covered LINE/BRANCH counters, proving format support beyond running release17
classes on a newer VM. Local actual21 probe passes (major65).

## Verification results and remaining work

Local doctor/prepare/check and Java quality commands pass. Full check:13 JUnit
and494 Clojure tests/19,137 assertions, zero failures/errors, offline smoke passes.
All11 new quality regressions,16 doc-parser tests,15 distribution regressions,
6 existing build-toolchain regressions, all40 executable documentation examples
and P16 (5 tests/377 assertions) pass. A contended local performance invocation
fails at1484.1ms; retain that observation. After competing verification JVMs exit,
the same unchanged gate passes at719.6ms (warn1000/fail1200). Full lint initially
rejects the final logging helper's indentation; format only that file and rerun.
Final lint/package/consumer and16-job CI are pending; independent review remains
required. Local reports are under /tmp/paclo-p14f; committed evidence records
portable comparison data, with final CI evidence added after execution.

Remaining P14 candidates require separate selection: hold core.async PR76 behind
Issue77; evaluate data.json2.5.2 only with JSON round-trip/diagnostic evidence;
defer optional data.csv1.1.1 (parent-only change), test.check1.1.3 until meaningful
property/shrink verification and deps-deploy0.2.5 until isolated release-tool
review. Keep CheckStyle10.18.0/JUnit5 generation; no major migration is selected.
Cloverage1.2.4/Eastwood1.4.3 remain unchanged. No P17/P09/P10, live performance,
release, tag, publication or merge is authorized by this work.

Reproduction commands (from repository root, reference CLI selected):

```bash
bash dev/script/codex.sh doctor
bash dev/script/codex.sh prepare
bash dev/script/codex.sh check
bash dev/script/codex.sh lint
clojure -M:spotbugs
clojure -M:checkstyle
clojure -M:jacoco
JACOCO_MIN_LINE=0.25 clojure -M:jacoco-gate
python3 -B -m unittest discover -s dev/script -p 'test_java_quality.py'
python3 -B -m unittest discover -s dev/script -p 'test_build_toolchain.py'
python3 -B -m unittest discover -s dev/script -p 'test_verify_distribution.py'
python3 -B -m unittest discover -s dev/script -p 'test_verify_doc_examples.py'
python3 dev/script/verify_doc_examples.py
python3 dev/script/verify_interop.py /tmp/paclo-p14f/interop
python3 dev/script/verify_java_quality_runtime.py /tmp/paclo-p14f/runtime21
bash dev/script/codex.sh perf
bash dev/script/codex.sh package
python3 dev/script/verify_distribution.py prepare target/paclo-1.5.0-SNAPSHOT.jar /tmp/paclo-p14f/distribution
python3 dev/script/verify_distribution.py consume /tmp/paclo-p14f/distribution --report /tmp/paclo-p14f/consumer-jdk21.json
```

Evidence directories above must be fresh. Packaging runs after all consumers of
`target/classes` finish. Original comparisons used old pins at main204d72c,
followed by new pins before modifying runner source. The positive detector probe
source is reproduced by `test_new_detector_and_improved_ignored_copy_detection`.
[Tool JAR hashes](p14-f-evidence/tool-jars.json) identify the actual old/new binaries.
