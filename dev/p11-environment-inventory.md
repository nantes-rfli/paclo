# P11: Environment, dependency and compatibility inventory

## Executive summary

Checked on **2026-10-18 (Asia/Tokyo)**, consolidating upstream evidence at 09:50.
Repository baseline: latest fetched main
`97873f79eb5360d47b59692127e760e4ea1ec188`. This is an investigation and handoff;
no dependency, source, CI, build setting, release version or support policy changes here.

Recommended order:

1. Independently correct development-artifact identity. CI currently packages
   unreleased main as `1.4.0`, while local builds default to `1.4.0-SNAPSHOT`.
   Propose `1.5.0-SNAPSHOT` as a development identifier, subject to a separate
   maintenance PR; this assigns neither a v1.5.0 feature set nor a release date.
2. Evaluate Clojure **1.12.6** in P12 while holding other production dependencies
   fixed. It includes correctness fixes and a security hardening change relevant
   to applications deserializing untrusted Java objects. A historical clean NVD
   report does not establish absence of current advisories.
3. Select small P14 slices for audit/tool reliability, then core.async and JNR
   independently. Preserve a diagnostic run of the existing graph on JDK 25;
   a JNR update is not an assumed prerequisite or proof of JDK 25 support.
4. After P12, run P13's JDK 25 experiment using the same JDK 21-built JAR as
   the JDK 17/21 consumers. Decide formal support separately. Retain Java 17
   bytecode, supported-platform tests, quality budgets and performance gates.
5. Select P15/P16 independently after P11 review. Keep P17 conditional on P12
   and an explicit need/maturity decision; Clojure 1.13 remains an alpha series.

The main CI baseline passes all 14 jobs. Local evidence is narrower: macOS
x86_64, Temurin 21.0.12.1, Clojure 1.12.1, CLI 1.12.5.1654 and an offline native
read of four packets/438 bytes. JDK 17/25 are unavailable locally. No candidate
runtime/library has been installed or executed. No live/NIC or performance
claim is added.

## Evidence and release boundaries

Evidence labels used below:

- **Repository**: inspected configuration/source at the baseline above.
- **Executed**: command actually run in this task, with local scope.
- **Remote CI**: inspected GitHub run/job/step conclusions for an exact commit.
- **Upstream**: official release notes, tags, published POMs or registry metadata;
  version availability does not prove Paclo compatibility.
- **Recommendation**: proposed work, acceptance conditions or inferred risk.

Read [AGENTS](../AGENTS.md), [CONTRIBUTING](../CONTRIBUTING.md), the
[v1 API contract](../docs/cljdoc-api-contract.md), [accepted plan](codex-plan.md),
[roadmap](../docs/ROADMAP.md), [deps.edn](../deps.edn), [build.clj](../build.clj),
all four `.github/workflows/` files and the actual distribution/native code.
The linked local files refer to this checkout; the
[baseline tree](https://github.com/nantes-rfli/paclo/tree/97873f79eb5360d47b59692127e760e4ea1ec188)
preserves their immutable versions.

[PR #67](https://github.com/nantes-rfli/paclo/pull/67) merged at
2026-10-18 00:41:22 UTC as `97873f7`. P01–P08 are done and published;
P09/P10 remain blocked, rather than completed. P11–P17 definitions and their
acceptance criteria remain the authority for subsequent work.

[Published v1.4.0](https://github.com/nantes-rfli/paclo/releases/tag/v1.4.0)
resolves to `74a17b0`, published 2026-10-17. The
[publication record](release-1.4.0-publication.md) owns deployed hashes and
JDK 17/21 published-byte evidence. Main additionally contains documentation
PR #65 (`17e2088`), the unreleased DNS expiry optimization
[PR #66](https://github.com/nantes-rfli/paclo/pull/66) (`443bc66`), and planning
PR #67. `git log v1.4.0..HEAD` and the actual diff confirm this boundary.
`deps.edn`, `build.clj` and workflows have no changes across that range.
Publication evidence must not be relabeled as evidence for unreleased DNS code.

## Current environment

| Layer | Repository / CI selection | Executed local observation | Interpretation |
| --- | --- | --- | --- |
| Clojure library | `org.clojure/clojure` 1.12.1 | doctor and `clojure -Stree`: 1.12.1 | Library selection is independent of CLI version |
| Clojure CLI | CI mostly 1.11.1.1435; source compatibility, ARM64 and Publish use `latest` | 1.12.5.1654 | CI is not uniformly pinned; floating jobs need exact-version evidence |
| JDK | Temurin 21 build; 17/21 runtime support | Temurin 21.0.12.1+1, javac 21.0.12.1 | Local JDK inventory also has unsupported 13.0.2; no local 17 or 25 |
| Java bytecode / APIs | `--release 17 -Xlint:all -Werror -proc:none` shared by jar/javac/javac-test/prep | doctor compiled existing bindings | Class major <=61, no preview classes; runtime 25 does not imply target 25 |
| OS / CPU | Linux x64, macOS ARM64, Linux ARM64 CI | macOS 15.4.1 / x86_64 | Local x86_64 process evidence is additional and narrower than CI |
| Native libpcap | Linux installs OS `libpcap-dev`; macOS uses system library; no pinned native package version | Paclo's `.pcap_lib_version`: **1.10.1** | Record the library actually loaded, not only a package-manager version |
| tcpdump | No pinned default dependency | `tcpdump --version`: 4.99.7, linked libpcap 1.11.0 | This is a different libpcap from Paclo's; not native-binding validation |
| clj-kondo | CI + Linux installer: 2025.10.23 | 2026.05.25 | Local lint cannot be substituted for the pinned CI tool |
| clojure-lsp | CI + installer: 2025.11.28-12.47.43 | 2026.05.05-12.58.26; bundled kondo 2026.04.16-SNAPSHOT | Standalone and bundled kondo differ |
| Markdown / runtime | markdownlint-cli2 0.18.1 via npx; Node not pinned by workflow | Node 24.8.0, npm 11.6.0 | Network/cold-cache setup remains relevant |
| Other tools | babashka floating master installer in build-checks; Python 3 and shell from runner | No babashka compatibility experiment | Moving runner images/installers reduce reproducibility |

The separate [performance merger deps](perf-merge/deps.edn) also pin Clojure
1.12.1 and data.json 2.5.0. A future intentional library change must decide
whether to align these pins; silently leaving two baselines obscures evidence.

## Production and optional dependency comparison

All current versions below come from `deps.edn`. Candidates are upstream
observations on the check date, not tested replacements. For every candidate,
review the resolved transitive graph and fresh security evidence; absence of a
specific advisory in a row is not a clean security scan.

| Coordinate / scope | Current | Stable or candidate observed upstream | Changes, compatibility/security risk and recommendation |
| --- | --- | --- | --- |
| `org.clojure/clojure` / production | 1.12.1 | **1.12.6**, 2026-09-02, [downloads](https://clojure.org/releases/downloads), [versioned changes](https://github.com/clojure/clojure/blob/clojure-1.12.6/changes.md) | LazySeq visibility, compiler, reify metadata and gen-class fixes; serialization restrictions. Prioritize P12 for correctness/security, with unchanged public contracts |
| `org.clojure/core.async` / production | 1.6.681 | **1.9.865**, 2026-03-19, [official history](https://github.com/clojure/core.async#releases-and-dependency-information) | Inactive alt retention fix, executor/callback dispatch changes, io-thread virtual threads when available, datafy. Paclo uses impl protocols and reusable fn-handler: high lifecycle risk; own P14 PR, no new flow framework |
| `com.github.jnr/jnr-ffi` / production | 2.2.14 | **2.3.2**, 2026-09-15, [release](https://github.com/jnr/jnr-ffi/releases/tag/2.3.2) | Aligned multibyte string terminator scan; intervening ABI/platform/dependency changes. Native memory/loader and generated-bytecode risk; separate platform-tested P14 PR |
| `org.clojure/data.json` / production | 2.5.0 | **2.5.2**, [history](https://github.com/clojure/data.json#change-log) | Repeated-read EOF fix, control-character diagnostics, parent/Clojure updates. Low urgency; check JSON CLI/report round trips, numeric types and diagnostic changes before adoption |
| `com.github.spotbugs/spotbugs-annotations` / production | 4.8.6 | **4.10.5**, [versioned changes](https://github.com/spotbugs/spotbugs/blob/4.10.5/CHANGELOG.md) | Method/constructor suppression also covers lambdas. Align deliberately with analyzer candidate; annotations still appear in published POM, so package checks required; no removal/re-scope proposed here |
| `org.clojure/data.csv` / optional `:csv` | 1.1.0 | **1.1.1**, 2025-12-30, [history](https://github.com/clojure/data.csv#change-log) | Parent POM update; no identified Paclo behavior need. Keep optional and defer; verify quoting/newlines and reader lifetime if changed |

Executed `clojure -Stree` shows Clojure's spec.alpha 0.5.238 and core.specs.alpha
0.4.74, core.async's tools.analyzer.jvm 1.2.3 / tools.reader 1.3.6, JNR's jffi
1.3.11 (Java and native classifier), ASM modules 9.2 and jsr305 3.0.2 through
SpotBugs annotations. Do not add direct overrides merely to make versions newer.

Upstream core.async 1.9.865's
[published POM](https://repo.maven.apache.org/maven2/org/clojure/core.async/1.9.865/core.async-1.9.865.pom)
selects tools.analyzer.jvm 1.3.3. JNR 2.3.2's
[published POM](https://repo.maven.apache.org/maven2/com/github/jnr/jnr-ffi/2.3.2/jnr-ffi-2.3.2.pom)
selects ASM 9.10.1 and **jffi 1.4.0**. Although
[jffi 1.4.1](https://github.com/jnr/jffi/releases/tag/jffi-1.4.1) exists with a
native boot-path fix, updating JNR does not automatically select it. Dependency
mediation across analyzer/JNR/ASM must be checked in the actual proposed graph.
Newer ASM is a reason to investigate, not evidence that current JNR fails on 25.

## Development, build, test and audit dependencies

| Coordinate / aliases | Current | Upstream comparison | Need, risks and acceptance focus |
| --- | --- | --- | --- |
| `io.github.cognitect-labs/test-runner` / `:test` | v0.5.1, SHA dfb30dd | [v0.5.1 tag](https://github.com/cognitect-labs/test-runner/tree/v0.5.1) remains latest listed tag | Keep; no update benefit identified. Preserve namespace discovery, nonzero failure exit and test counts |
| `org.clojure/test.check` / `:test`, `:coverage`, `:eastwood` | 1.1.1 | **1.1.3**, [changes](https://github.com/clojure/test.check/blob/master/CHANGELOG.markdown) | 1.1.2 reduces shrink-int allocation; 1.1.3 updates parent/Clojure. Low urgency; retain property cases, seeds and shrinking, align all three aliases |
| `io.github.clojure/tools.build` / `:build` | 0.10.5 | **0.10.14**, 2026-05-28, [changelog](https://github.com/clojure/tools.build/blob/master/CHANGELOG.md) | tools.deps/Clojure refresh, process buffering fix, SOURCE_DATE_EPOCH support for build.properties. Build/POM/provenance risk; own PR and same-JAR checks, not a runtime upgrade |
| `slipset/deps-deploy` / `:deps-deploy` | 0.2.2 | **0.2.5**, [registry](https://clojars.org/api/artifacts/slipset/deps-deploy), [source](https://github.com/slipset/deps-deploy/blob/master/deps.edn) | Maven/settings/tools.deps.edn and pomegranate changes. Published version confirmed; repository CHANGELOG is stale template text, so no complete versioned delta established. Defer until a separate release-tool review; dry-run/local tests only, no publication |
| `nvd-clojure/nvd-clojure` / `:nvd` | 5.2.0 | **5.3.0**, [changes](https://github.com/rm-hull/nvd-clojure/blob/master/CHANGELOG.md) | DependencyCheck 12.1.6 → 12.2.0 and non-JAR scanning. Security-tool health merits early P14 evaluation; upstream recommends tool isolation; preserve scan target and failure threshold |
| `cloverage/cloverage` / `:coverage` | 1.2.4 | **1.2.4**, [registry](https://clojars.org/api/artifacts/cloverage/cloverage) | Keep; no newer stable identified. Instrumentation/compiler sensitivity remains; actual Run cloverage result must be inspected despite informational CI policy |
| `jonase/eastwood` / `:eastwood` | 1.4.3 | **1.4.3**, [upstream](https://github.com/jonase/eastwood), [registry](https://clojars.org/api/artifacts/jonase/eastwood) | Keep; compiler/analyzer compatibility must be tested for P12/P17. Preserve full namespace traversal and exception exit behavior |
| `org.clojure/data.xml` / `:eastwood`, `:jacoco-gate` | 0.2.0-alpha8 | Stable **0.0.8**; current preview **0.2.0-alpha11**, [README](https://github.com/clojure/data.xml), [changes](https://github.com/clojure/data.xml/blob/master/CHANGES.md) | alpha9/10 parent/Clojure/reflection changes; alpha11 adds end-event information. Neither alpha11 adoption nor downgrade to 0.0.8 is automatic; keep until report-parser need is established, preserve XML namespace/coverage behavior |
| `com.github.spotbugs/spotbugs` / `:spotbugs` | 4.8.6 | **4.10.5**, 2026-10-12 publication, [release](https://github.com/spotbugs/spotbugs/releases/tag/4.10.5) | Reflection tracking and false-positive/negative fixes affect findings. Review findings and transitive parser security; pair with annotations deliberately, keep existing analyzer failure gate |
| `com.puppycrawl.tools/checkstyle` / `:checkstyle` | 10.18.0 | **14.3.0**, [release](https://github.com/checkstyle/checkstyle/releases/tag/checkstyle-14.3.0), [requirements](https://checkstyle.org/#JRE_and_JDK) | 14.3 modularizes artifact; rule/config and minimum-runtime changes. 13/14 need JRE 21, 11/12 need 17, 10 needs 11. Latest would stop local checkstyle on supported JDK 17; defer or explicitly retain a JDK17-capable line with an exact reviewed candidate |
| `org.jacoco/org.jacoco.agent$runtime` / `:jacoco` | 0.8.12 | **0.8.15**, [release](https://github.com/jacoco/jacoco/releases/tag/v0.8.15) | Newer class-file support and reporting fixes. Update together with CLI if instrumenting JDK25; latest not mandatory solely for current Java17-target bindings |
| `org.jacoco/org.jacoco.cli` / `:jacoco` | 0.8.12 | **0.8.15**; **0.8.14** first officially supports Java25, [release](https://github.com/jacoco/jacoco/releases/tag/v0.8.14) | Do not assume 0.8.12 understands JDK25 classes. Preserve 25% gate and inspect denominator/report changes; JDK21 coverage can remain while runtime-only 25 experiment proceeds |
| `org.junit.platform/junit-platform-console-standalone` / `:junit` | 1.10.2 | Latest framework **6.1.3**, Platform **6.1.3**, [release](https://github.com/junit-team/junit-framework/releases/tag/r6.1.3) | Major migration, not a 1.x patch. CLI/engine/JDK requirements need a dedicated review. Keep current for initial P12/P13; preserve ten Java tests and --fail-if-no-tests, including JaCoCo runner integration |
| `nrepl/nrepl` / optional `:nrepl` | 1.5.1 | **1.8.0**, [release](https://github.com/nrepl/nrepl/releases/tag/v1.8.0) | Session/classloader/stdin fixes, URL/TLS client changes; removes compatibility helper, minimum Clojure1.10. P15 may expose a need; keep localhost binding, test editor/session close, do not expose remote code execution service |
| `cider/cider-nrepl` / optional `:nrepl` | 0.58.0 | **0.63.1**, [release](https://github.com/clojure-emacs/cider-nrepl/releases/tag/v0.63.1) | Latest patch updates completion dependency; accumulated middleware/editor changes require a paired nREPL/client test. Defer to concrete P15 workflow, keep out of published POM |

Aliases `:dev`, `:run`, `:dns-ext`, `:perf-gate`, `:perf`, `:perf-generator` and
`:perf-worker` add paths/options, not dependencies. Optional DNS source is also
copied into the distribution JAR by `build/jar`; optional paths are not all
equivalent to optional Maven libraries. Test.check and data.xml repetitions must
be handled coherently without expanding the default production graph.

## Clojure and CLI compatibility assessment

The [stable downloads page](https://clojure.org/releases/downloads) identifies
1.12.6, rather than Maven's `release` field (which can name an alpha).
[CLI releases](https://clojure.org/releases/tools) identify **1.12.5.1664**
(2026-07-27): shared Maven session concurrency and deps.edn error-reporting fixes.
1.12.5.1654 added 429 retry handling and requires Java11+ for S3 downloads.
CLI adoption belongs to an independent P14 tool PR: test `-M`, `-T:build`,
prep-lib, Git dependency resolution, `-Srepro` consumers, cold caches and proxies.
Installing a CLI whose prefix includes 1.12.5 does not select that library in Paclo.

The [1.12.6 versioned history](https://github.com/clojure/clojure/blob/clojure-1.12.6/changes.md)
records cumulative changes since 1.12.1: LazySeq visibility/serialization,
Iterate serialization rejection, nested compiler sites, reify metadata,
constantly allocation, gen-class default methods and FnLoaderThunk serialization
rejection. Paclo's lazy reductions, reify-based resources, macro-generated
array maps and protocol dispatch warrant tests; no new API/macro syntax is
needed for adoption. Transformation completion arities, early `reduced`, exact
timestamps, metadata, EDN rehydration and deterministic close must remain intact.

[GHSA-q527-rxcp-97g8](https://github.com/clojure/clojure/security/advisories/GHSA-q527-rxcp-97g8)
is an upstream high-severity Java deserialization advisory. Its listed affected
range includes 1.12.1; its mitigation recommends >=1.12.6. The metadata leaves
1.12.5 outside the stated affected range but does not list it as patched; choose
the explicitly patched version. Exposure requires attacker-controlled Java
objects reaching ObjectInputStream with permissive class filtering. Repository
search found no ObjectInputStream/readObject use in Paclo source, Java, examples
or tests; this is not proof about downstream applications. PCAP parsing is a
different path. Java serialization of affected Clojure internals can break on
upgrade; Paclo's documented data/EDN contract does not promise that facility.

Upstream [Clojure 1.13.0-alpha9](https://clojure.org/news/2026/10/09/clojure-1-13-alpha9)
(2026-10-09) is announced; Maven metadata also lists it. It is not stable.
[Alpha5 notes](https://clojure.org/news/2026/07/21/clojure-1-13-alpha5) move the
runtime/bytecode baseline to Java17. The
[development history](https://clojure.org/releases/devchangelog) also changes
keyword array-map growth, transient metadata propagation and destructuring;
alpha9 already removes a directive introduced earlier. P17 should test
`fixed-array-map` in `src/paclo/flow/project.clj`, map equality/EDN rather than
iteration order, reify/protocols, compiler/analyzer tooling and allocation.
Do not infer performance improvement from upstream map changes or replace the
existing implementation without measurements. The environment doctor currently
requires Clojure1.12 and JDK17/21, so alpha experiments need isolated commands;
a guard failure is not evidence of library incompatibility.

## JDK and native integration

JDK17/21 support has both source-built and packaged evidence; see CI below.
`build/jar` packages Clojure sources and Java17-target native bindings, not an
AOT compiler-generated application or bundled libpcap. Java class compatibility
does not establish native ABI compatibility or downstream dependency support.

JDK25 is an **untested candidate in this task**. JDK major changes and floating
patch installations require the exact vendor/build, OS, CPU and loaded libpcap
version in future reports. Specific risks from official sources:

- [JEP472](https://openjdk.org/jeps/472): JNI native loading/linking warnings
  introduced in JDK24 and a future restriction path. JNR uses jffi JNI; inspect
  the actual caller/module and test default startup first. A separately recorded
  launch with `--enable-native-access=ALL-UNNAMED` may be appropriate for classpath
  code. Do not add that option globally or suppress all warnings as acceptance.
- [JEP498](https://openjdk.org/jeps/498): Unsafe memory-access warnings and future
  removal/restriction. Capture call sites from JNR/jffi/analyzers; do not assume
  a newer JNR has eliminated them. A deny/debug experiment is diagnostic, separate
  from ordinary-runtime support. No FFM backend is proposed.
- ASM, instrumenters and analyzers have class-version limits distinct from the
  JVM's ability to load Java17 bytecode. JNR-generated classes, JaCoCo on runtime
  classes, and static analyzers each need their own evidence. Keep current
  JDK21 quality gates while diagnosing 25; do not count skipped coverage as passed.
- Native functions use pointer/struct/timeval layouts, C-long/time_t sizes and
  platform AF values. Check BPF compilation, offline EOF/error/failed-open cleanup,
  PCAP writing/truncation/timestamp precedence, interface enumeration and stats.
  Test Linux x64/ARM64 and macOS ARM64; default-provider atomic PCAPNG publication
  and cleanup are separate filesystem contracts. Neither tests on a local x86_64 JVM
  nor a working library load validates those other platforms.

Paclo's native libpcap is **1.10.1** locally even though tcpdump reports 1.11.0.
Upstream's [1.11.0 tagged history](https://github.com/the-tcpdump-group/libpcap/blob/libpcap-1.11.0/CHANGES)
dates that release to 2026-09-13; the official website source still advertises
1.10.7. Treat 1.11.0 as the newer tagged candidate and 1.10.7 as the maintenance
comparison, documenting the website mismatch. The
[1.10.7 history](https://github.com/the-tcpdump-group/libpcap/blob/libpcap-1.10.7/CHANGES)
includes BPF interpreter/bounds/division and RPCAP security fixes. OS vendors
may backport fixes: the version string alone does not determine exposure.
P14/P16 should record OS package/security advisories and loaded library path/build;
JNR upgrades do not update the native libpcap supplied by the OS. Do not replace
the macOS system library in this inventory or treat tcpdump's library as Paclo's.

### Minimal future JDK25 CI experiment

After P12, add **one Linux x64/JDK25 distribution-consumer matrix entry** to the
existing bundle download, hash check, isolated execution and report upload.
Retain producer JDK21 and both mandatory 17/21 consumers. The added matrix entry
would be included in the existing `build` dependency, without changing its
success condition; formal support still requires a separate decision.

In the same scoped P13 experiment, a source-test job/entry should compile with
the existing `--release 17`, run Clojure tests, JUnit and DNS/native fixtures on
25. The minimal consumer addition alone does **not** satisfy full P13 acceptance.
Run direct build/test commands initially: `doctor`, `smoke` and therefore wrapper
`check` deliberately reject 25 in `environment-check`. Do not broaden the support
guard merely to make the experiment green. Record an equivalent offline smoke
through the consumer harness; any experimental harness/guard accommodation must
be explicitly reviewed and must preserve 17/21 verification.

## CI and development-tool gates

Repository workflow inventory (no changes proposed as part of P11):

| Job / workflow | Runtime, OS and CPU | Gate / limitation |
| --- | --- | --- |
| `build-checks` | Ubuntu latest x64 / JDK21 | One JAR, distribution verifier + tests, JUnit, native smoke, SpotBugs, CheckStyle, JaCoCo >=25%, performance 1000ms warn/1200ms fail, DNS CLI exit status, LSP dry-runs, kondo, Markdown |
| `documentation-checks` | Ubuntu latest x64 / 21 | Link/example checker unit tests, actual maintained examples, namespace load via cljdoc 0.0.1315-c9e9a7e (workflow-only dependency) |
| `compatibility-matrix` | Ubuntu latest x64 / 21; macOS latest ARM64 / 17 | Explicit OS/arch assertions, separate source builds, Clojure suite, DNS smoke; these are not same-JAR comparisons |
| `distribution-consumer` | Ubuntu latest x64 / 17 and 21 | No checkout or Java recompilation; both download identical JDK21 bundle, verify hashes, use temporary project/-Srepro and save runtime identity |
| `performance-measurement` + `performance-results` | Three Ubuntu x64 / 21 shards, then merger | Serial workers per dataset, exactly 27 scenarios, validated merged artifacts; does not establish live throughput |
| `eastwood-lint` | Ubuntu x64 / 21 | Runner exit-status tests and complete traversal; warnings informational, linter/analysis exceptions fatal |
| `build` aggregate | Ubuntu x64 | Requires success of all seven listed dependencies, including both consumer entries; `if: always()` prevents skipped failures becoming success |
| `arm64-monitor` | Ubuntu 24.04 ARM64 / 21 | Source build, Clojure suite, DNS smoke; separate from aggregate needs |
| `coverage` | Ubuntu x64 / 17 | cloverage; job and command continue-on-error, outside aggregate. Report actual command outcome, not only job success |
| `Dependency Audit` | Ubuntu x64 / 21, scheduled Monday + manual | Separate from PR CI; scans default `clojure -Spath`, CVSS >=7 fails, cache validity168h; does not cover every optional/dev alias or native OS library |
| `Arm64 Promotion Report` | Scheduled/manual report | Observation window/success/rerun/duration; optional enforce defaults false. Not proof of long-window workload performance |
| `Publish` | Ubuntu x64 / 21; CLI latest | Tag/manual guards, release metadata, Clojure/performance subset, JAR inspection; manual defaults dry-run. Does not replace complete CI/platform acceptance |

**Remote CI baseline:** [run39083684502](https://github.com/nantes-rfli/paclo/actions/runs/39083684502)
on main `97873f7`: all **14 jobs success**, including Linux ARM64 and the actual
`Run cloverage` step. Inspected all job conclusions and failure steps. This is
baseline evidence, not the final-head P11 PR result; final-head results belong
in that PR description. The branch API reports main **unprotected**, with no
required-status contexts configured. `build` is the intended workflow quality
gate, not an enforced branch rule. Retain all existing jobs and independent
review; adding repository protection is only a separate governance suggestion.

The latest [Dependency Audit run39017436182](https://github.com/nantes-rfli/paclo/actions/runs/39017436182)
is successful at release commit `74a17b0`, not current main. The
[saved audit summary](release-1.4.0-evidence/release-audit-summary.json) records
23 dependencies, zero NVD findings/suppressions, engine12.1.6 and 2026-10-17
database timestamps; OSS Index was disabled for missing credentials. This does
not contradict the Java-deserialization advisory: an NVD-only scan is limited
by its data sources/matching. No fresh NVD scan or blanket security clearance
is claimed here. Tool/optional transitive dependencies and OS libpcap need a
separate audit scope, without silently changing the production scan target.

| External tool | Pinned/current vs upstream candidate | Recommended P14 treatment |
| --- | --- | --- |
| clj-kondo | CI2025.10.23 vs **2026.08.04**, [release](https://github.com/clj-kondo/clj-kondo/releases/tag/v2026.08.04) | Hook arity fixes and accumulated lint changes; test existing config/hooks/source roots, review new findings individually; align installer/checksums/CI/docs |
| clojure-lsp | CI2025.11.28-12.47.43 vs **2026.10.15-11.42.38**, [release](https://github.com/clojure-lsp/clojure-lsp/releases/tag/2026.10.15-11.42.38) | Cache isolation/refactoring fixes; bundled kondo revision differs from standalone stable. Run clean-ns/format dry-runs, review diff before accepting formatting; no broad autoformat in a runtime PR |
| Eastwood | 1.4.3 vs 1.4.3 | Keep full traversal/exception gate; run runner regression test after compiler/tool changes |
| Clojure CLI | CI1.11.1.1435 / latest vs stable1.12.5.1664 | Choose a tested pin in a separate PR across scripts/consumers/Publish; record CLI version even where floating remains |
| Markdown, Python, babashka, Actions | Markdown0.18.1 pinned, other installers/runner images float; Actions checkout/setup-java/cache/upload/download use v4, setup-clojure13.0, LSP setupv1, github-scriptv7 | No version update justified here. Propose explicit Node/tool installation and Actions SHA pinning only as separate reproducibility/security work, with runtime/architecture and artifact-transfer validation |

## Development artifact identity: independent maintenance proposal

Repository facts:

- `build.clj` precedence is `PACLO_VERSION`, then matching `GITHUB_REF_NAME` tag,
  then fallback `1.4.0-SNAPSHOT`. Environment override can therefore supersede a tag.
- `build-checks` forces `PACLO_VERSION=1.4.0`; its prepare command passes
  `target/paclo-1.4.0.jar --version 1.4.0`. Source-matrix/ARM64/coverage builds
  instead use the fallback. The same run can produce differently named artifacts.
- The distribution verifier default is `1.4.0-SNAPSHOT`, with a hardcoded exact
  production dependency map. It records commit, dirty state, build JVM and hashes;
  consumers do not fetch Paclo from Clojars. This protects run-local byte identity
  but does not make the version label correct.
- Publish derives explicit version from input/tag, checks release metadata/source,
  and deploys only on authorized tag/non-dry-run paths. Ordinary PR CI does not
  overwrite Clojars. Existing snapshot naming is a provenance/cache/consumer
  confusion risk, not evidence of a redeployment of v1.4.0.

Recommendation for one small maintenance PR before candidate build comparisons:

1. Agree the next development coordinate. Preferred proposal: `1.5.0-SNAPSHOT`;
   `1.4.1-SNAPSHOT` remains an alternative only if maintainers choose a patch
   development line. Neither is set by P11. A later release-scope decision may
   select a different final release version.
2. Align build fallback, CI override (or remove redundant override), expected JAR
   path and explicit verifier version, verifier CLI default, distribution tests
   with embedded versions and maintained local packaging command examples.
   Search active references, separating historical release evidence and fixed
   consumer/hash reports, which must retain their original identities.
3. Retain group/artifact, source/class inventory, bytecode maximum, dependency
   assertions, same-bundle consumers, hashes/provenance and build aggregate.
   Artifact labels should carry the development version/run identity where useful.
   Never install an unreleased candidate as the published 1.4.0 coordinate.
4. Review Publish guards: SNAPSHOT development must not imply automatic snapshot
   deployment or a fabricated `v...-SNAPSHOT` release tag. The generated POM
   currently sets SCM tag to `v<version>` even for snapshots; propose using the
   actual source commit for snapshot SCM provenance while retaining real release
   tags. Test explicit release input/tag precedence and failure on metadata mismatch
   without creating tags, dispatching Publish or uploading to a Maven repository.

Acceptance: one JDK21-built development JAR/POM/properties all name the agreed
SNAPSHOT; prepare/17/21 consumers and negative identity/hash tests pass; clean
consumer cannot confuse it with Clojars1.4.0; release metadata/tag validation is
preserved. `PACLO_VERSION=1.4.0` is no longer used for ordinary main/PR builds.
No release version assignment, distribution, tag or publication occurs in P11.

## Recommended PR slices and acceptance

Every implementation slice requires separate review. Keep old public keys,
error strings, byte ownership, deterministic cleanup, bounded queues, legacy
extension registration, single-consumer contracts and optional dependency scope.
Public behavior changes require API docs/changelog; no such change occurs here.

| Order / independent PR | Plan impact and rationale | Verification and acceptance |
| --- | --- | --- |
| 1. Development SNAPSHOT identity | Maintenance proposal above; artifact integrity before comparing upgrades | Package once, inspect JAR/POM/properties/provenance, distribution-verifier tests including rejection cases, clean same-JAR17/21 consumers, release-guard tests and full CI; never deploy |
| 2. Clojure1.12.6 | P12; correctness and explicit security mitigation before feature adoption | Hold core.async/JNR fixed; prepare/check, executable docs, all static gates, unchanged perf gate plus comparable measurements, package and same-JAR17/21, Linux/macOS/ARM64 CI. Update verifier's exact dependency expectations with review and retain rejection of unintended POM changes |
| 3a. Audit reliability and scope | P14; evaluate nvd5.3.0/tool isolation and advisory/native coverage | Preserve default scan, CVSS7 threshold, database/report timestamps, no suppressions added to hide findings; demonstrate alias isolation and selected optional/tool graphs separately. Credentials/network failure is incomplete, not clean |
| 3b. CLI + tools.build | Separate tool/build slice, or split CLI and build if regressions require attribution | Cold/warm dependency setup, Git SHA resolution, prep-lib, javac17 API baseline, process exit/output, JAR contents/POM/provenance and -Srepro same-bundle consumers; keep all package gates |
| 3c. core.async1.9.865 | P14; internal protocol coupling and retention fixes justify isolated evaluation | Stream/fan-out regression tests for nil/false, drops/backpressure, ordering, full-queue close, exception/abandon/repeated close, blocked producer release, counters and bounded retention; repeat on17/21, full check/static/docs/perf/distribution. Do not adopt core.async.flow |
| 3d. JNR2.3.2 | P14; native/ASM changes need attribution independent of async | Resolved jffi/ASM graph, Java/JUnit/native real fixtures, BPF success/failure, struct layouts, failed-open cleanup, writer precision/errors, same-JAR17/21 and supported OS/CPU CI. Record native library version/path; preserve evidence of warnings/failures |
| 3e. Lint/analysis/coverage | P14; use need-specific kondo/LSP/SpotBugs/JaCoCo slices; keep Eastwood/cloverage initially | Pinned binary checksums on supported installer architecture, identical source coverage, no unexplained formatting diff; runner failure tests, zero analyzer exceptions, no weaker rules or budgets, unchanged25% Java gate; test17 local-tool contract before raising tool JDK minimum |
| 4. JDK25 experiment | P13 after P12; may run before a JNR change to identify actual failure | Same JDK21 bundle on17/21/25 plus separate25 source/JUnit/native tests, default and justified native options recorded, exact OS/CPU/JDK/libpcap, explicit coverage-tool limits. All existing jobs pass; no automatic formal support claim |
| 5a. Practical REPL examples | P15 after P11; no need to wait for P12 | PCAP read/write, Flow and DNS with existing APIs, fixtures/expected output, with-open/reduced/close behavior, localhost nREPL only if needed; register and execute doc-example markers. No framework or API addition |
| 5b. External capture interoperability | P16 after P11; native library observations strengthen need | Versioned tcpdump/dumpcap/Wireshark-generated redistributable files or generation commands; Linux/macOS and DLT/timestamp/interface/options/malformed matrix; compare native reader against metadata-aware PCAPNG separately, assert documented preserve/loss/atomic behavior and long-run bounds |
| 6. Low-urgency library patches | P14 selected individually: JSON/CSV/test.check; release tooling separately | JSON output/diagnostics, CSV escaping/lifetime, reproducible property runs, POM scope and same-JAR consumers for production changes; no extra dependency merely to enumerate outdated versions |
| Conditional. Clojure1.13 experiment | P17 only after P12 plus need/maturity decision | Isolated prerelease revision, tool/analyzer compatibility, map/transducer/metadata/lifecycle/EDN properties, JDK17/21 distribution checks and measured allocation/performance; wait for stable release and explicit adoption approval for production |

P12 is the next main plan item after P11 review; P13 remains dependent on P12.
P14–P16 become selectable after P11, independently, not automatically started.
The proposed SNAPSHOT maintenance slice is a newly documented follow-up, not an
extra implementation silently added to P12–P17. P09/P10 stay blocked. No v1.5.0
scope/date, new backend selector, dependency scanner package or pipeline DSL is approved.

## Verification performed and remaining uncertainty

Executed on the supplied checkout, initially clean; branch based on latest main:

- `bash dev/script/codex.sh doctor`: exit0 before and after switching baseline;
  existing Java compilation, Clojure1.12.1/JDK21, four-packet/438-byte real offline read.
- `clojure -Stree`, CLI/JDK/lint/Node version commands and native
  `.pcap_lib_version` call: current observations above. No candidate resolution,
  installation, upgrade, throughput measurement or full local runtime suite.
- Markdown lint, local-link checks, diff/scope/plan consistency results and
  final delivery are recorded in [work-log](work-log.md); final-head normal CI
  and unresolved review issues are recorded in the P11 PR description.

Remaining risks and evidence limits:

- JDK25 and Clojure1.12.6/1.13, core.async/JNR and other candidates are not executed
  here. Official release availability and newer ASM/JaCoCo support are not Paclo results.
- Local JDK17 unavailable; local JDK13 is outside support. Windows, 32-bit,
  BSD, other JVM vendors, big-endian and non-default filesystem providers are
  not validated by this inventory. Existing support scope is unchanged.
- Source-built macOS/ARM64 CI is distinct from packaged Linux consumers;
  same-JAR macOS/ARM64 coverage is a possible later verification improvement.
- Current Linux native package versions/paths and exact floating CLI/runner-image
  revisions need future per-run recording; package names alone cannot establish
  ABI/security parity with the local macOS system library.
- Clojure advisories, native vendor backports and optional/dev graph vulnerabilities
  need ongoing assessment. Latest NVD success covers its recorded graph/time only.
  No new NVD/OSS Index scan was run, and no missing credential is treated as a pass.
- deps-deploy's versioned change history is incomplete; do not infer a verified
  release-tool migration from registry freshness. data.xml's newer release is a
  preview, despite the older stable version's name.
- No live capture, real-NIC loss/throughput, representative long production PCAP,
  or fresh long-window ARM64 observation. Prior accepted DNS memory/rebuild costs
  and Ethernet/Flow performance limits remain in their original evidence.
- New findings are proposals only: native-version/path provenance, broader advisory
  coverage, floating-tool pinning, snapshot SCM identity and branch protection.
  They require independent selection/review; no automatic implementation follows.

All upstream URLs in this document were read on 2026-10-18. Official GitHub
Releases/README/history, Maven Central POMs and Clojars artifact APIs were preferred
to third-party version lists. Missing/404 histories were replaced by working
official sources where possible; the deps-deploy and libpcap source discrepancies
are retained explicitly. Recheck candidate availability and security information
at the beginning of each subsequent implementation PR.
