# P14-C: Clojure CLI and tools.build

## Scope and decision

Started from fetched main `c6209da7ea5fcdad03ac6a33ae9ddb4b30d203a6`, after
P16 PR78 merged. Adopt Clojure CLI **1.12.5.1664** and tools.build **0.10.14**.
This is a build/development change; production Clojure1.12.6, JNR-FFI2.3.3,
core.async1.6.681, development1.5.0-SNAPSHOT and `--release 17` stay fixed.
Published v1.4.0 artifacts, tags and evidence remain unchanged.

Upstream checked on 2026-10-19 (Asia/Tokyo):

- [Official CLI releases](https://clojure.org/releases/tools) identify
  1.12.5.1664 as stable, including Maven-session and deps.edn-error fixes.
- [tools.build v0.10.14](https://github.com/clojure/tools.build/tree/v0.10.14)
  and the [published Central POM](https://repo.maven.apache.org/maven2/io/github/clojure/tools.build/0.10.14/tools.build-0.10.14.pom)
  confirm the exact candidate. The tag's changelog still starts at 0.10.13;
  release availability is confirmed by the tag/POM and real resolution, not an
  invented 0.10.14 changelog entry.
- The [versioned changelog](https://github.com/clojure/tools.build/blob/v0.10.14/CHANGELOG.md)
  records intervening process-buffering and SOURCE_DATE_EPOCH improvements.
  The resolved 0.10.14 implementation was inspected and exercised.

## Version inventory and selection

| Surface | Before | After / policy |
| --- | --- | --- |
| CI build/docs/performance/merger/Eastwood/coverage | CLI1.11.1.1435 | CLI1.12.5.1664 official versioned Linux installer |
| Source Linux/macOS and ARM64 | CLI latest | CLI1.12.5.1664 via existing setup-clojure action |
| Same-JAR consumers17/21/25 and JDK25 source | CLI1.11.1.1435 | CLI1.12.5.1664 via existing action |
| Publish tag/manual/dry-run | CLI latest | Same tested CLI1.12.5.1664 pin; guards unchanged |
| Scheduled/manual Dependency Audit | CLI1.11.1.1435 | CLI1.12.5.1664; scan scope, CVSS gate, credentials and NVD tooling unchanged |
| Local machine at start | CLI1.12.5.1654 | Verified CLI1.12.5.1664 under `/tmp/paclo-cli-1.12.5.1664`; existing installation untouched |
| Managed image described by previous docs | CLI1.11.1.1435 | Image not modified; optional prefix installer and explicit PATH select the reference CLI |
| Build alias | tools.build0.10.5 | tools.build0.10.14; separate tool graph |

No active old/floating CLI selection remains. Historical environment/release/
benchmark evidence retains the version actually measured. Runner images,
babashka's existing floating installer, Action revisions and OS-native packages
retain their existing policy because they are separate P14 work. No kondo/LSP,
SpotBugs/JaCoCo/JUnit/NVD or production-library update is bundled here.

CI retains all16 jobs, aggregate dependencies, thresholds and optional-coverage
semantics. Main/Publish cache keys now include the CLI version, preventing restoration of an
old archive containing `~/.clojure`. Only Maven/Git download caches are saved;
CLI/user/tool configuration is excluded. The initial new-key run is intentionally
cold; subsequent runs can reuse artifacts without importing user aliases/config.
Consumers retain their existing Maven-only `distribution-deps-...-v1` keys;
audit retains its artifact/NVD-data key. Neither contains CLI configuration, so
invalidating these caches is unnecessary and would needlessly refresh the NVD DB.
The initial run confirms cold source/build/docs caches and successful warm
consumer/merger caches; a dedicated probe also tests cold and forced warm setup.
The optional local installer uses the official archive and its versioned
installer's SHA256 `77dd6868948074adcc93e83a796f8e8f15a1a92bcb1b9002d715fd2210e476f3`.
It supports Linux/macOS without GNU-sed assumptions or root, and refuses an
existing installation prefix. Managed activation remains optional.

## Resolution, prep and subprocess behavior

`verify_toolchain_resolution.py` runs outside the checkout with new Maven/Git
caches, copied real deps.edn, fresh CLJ_CONFIG and `-Srepro`. Both first and
forced warm resolution exercise production/test Maven dependencies, the existing
test-runner Git tag plus full SHA `dfb30dd6605cb6c0efc275e1df1736f6e90d4d73`,
and the separate tools.build graph. Warm runs reject new download/clone messages.
An unresolvable user dependency proves that top-level `-Srepro` excludes user
deps. The prep phase uses empty CLJ_CONFIG: prep launches a child CLI without
inheriting the parent's `-Srepro`. This is a CLI lifecycle/configuration boundary,
not a Paclo API change. Prep compiles the genuine Java bindings; class major61
and a separate consumer import establish Java17 output and usability.

Consumers explicitly select library Clojure1.12.6. The CLI's default library
1.12.5 otherwise takes precedence over a transitive Clojure dependency. The
existing distribution consumer already uses explicit production dependencies;
the new prep probe follows the same policy. tools.build's own tool JVM uses its
separate dependency graph, which does not enter Paclo's POM/default runtime graph.

Failure injection exposed an existing wrapper defect: `b/process` returns
`{:exit ...}`; returning that map from a task does not fail `-T:build`. A private
checked wrapper now throws on nonzero child status for SpotBugs, CheckStyle,
JaCoCo/gate, Javadoc and JUnit. Classpath lookup uses the same checked operation.
Analyzer output remains inherited; subprocess/command/exit details are retained
in exception data. Tests inject child/classpath/JUnit-launcher failure and
verify nonzero outer CLI exit. Failed Java compilation also fails javac,
javac-test and jar; a post-Java17 API is rejected under every shared compile task.
No quality gate is weakened; direct CI analyzer invocations remain unchanged.

## Reproducibility and provenance

Repeated `pom` with `SOURCE_DATE_EPOCH=946684800` produces identical POM and
properties bytes and a fixed 2000-01-01 UTC comment. The properties date text
still uses JVM locale (Japanese names locally, English on Linux CI). JAR entry
timestamps, manifest build-JDK metadata and source identity are separate inputs:
SOURCE_DATE_EPOCH alone does not promise byte-identical JAR archives or
cross-locale/cross-JDK reproduction. Distribution validation continues to hash
one actual JAR and exercise exactly those bytes on17/21/25.

Existing exact source/class inventory, Java17 class checks, Maven coordinates,
dependencies, SNAPSHOT full-commit SCM and dirty-state reports, release-tag SCM,
external/embedded POM consistency and negative/hash controls remain active.
Provenance and each consumer report additionally record the CLI version used.
PACLO_VERSION/tag/default precedence and all Publish authorization, current-main,
tag ancestry, version, metadata, credentials and dry-run guards remain unchanged.
Regression tests exercise those shell guards without dispatching Publish,
creating tags or deploying/installing published coordinates.

## Executed verification

Local: macOS x86_64, Temurin21.0.12.1+1, CLI1.12.5.1664, Paclo Clojure1.12.6,
system libpcap1.10.1. Commands/results and final CI evidence are recorded in
[the work log](work-log.md#p14-c-clojure-cli-and-toolsbuild).

Local verification passes doctor, prepare, check (13 JUnit,493 Clojure tests /
19,130 assertions,smoke), lint, all build tasks (including isolated SNAPSHOT
install), package, negative distribution/Publish controls,40 executable docs,
P16 (377 assertions),80.8% JaCoCo against25% and the unchanged946.9ms/1200ms
performance gate. The packaged JDK21 consumer passes and records CLI1.12.5.1664.
The local lint binaries are kondo2026.05.25 and LSP2026.05.05-12.58.26; CI retains
its existing pinned versions. Python3.15.0 / Node24.8.0 were used locally.

Two actual clean/package rebuilds with the fixed epoch have identical entry
payloads but23 different ZIP-entry timestamps. Their SHA256 values are
`1cdf86ea259fc7753e4d62b7e6f8c1c2dea4b12fa6686d3e9aedbd791fad5933` and
`084d530a5064864b345e9518c7eb04074e9cc44cc7ff676ca8ccac9917a83d5a`.
The separate normally built JDK21 consumer bundle hashes to
`6c07209ac6b431840eca601f81a3ec37541a56643114dd2c7f12276049dc5ee6`,
source6435bda,clean tracked tree. These are development builds, not v1.4.0 bytes.

Implementation6435bda passes **all16 jobs** in
[CI39256292560](https://github.com/nantes-rfli/paclo/actions/runs/39256292560).
Every job and actual step (including cloverage) succeeds. Linux x64/JDK21,
macOS ARM64/JDK17 and Linux ARM64/JDK21 each pass P16's32 valid/4 malformed
inputs,45 outputs and5 tests/377 assertions. The source suites retain493 tests
(19,136 assertions on Linux,19,130 on macOS), and JDK25 source verification passes.
CI retains pinned kondo/LSP,638 informational Eastwood warnings/zero exceptions,
40 executed docs,80.8%/25% JaCoCo,702.3ms/1200ms performance gate, all27 measured
performance scenarios/merger and successful Clojure coverage execution.

All five17/21/25 default/debug/deny consumer reports pass with CLI1.12.5.1664,
identical JAR SHA256
`2a4a46eef82d3063322a95fa2e9b46653e297119882c171ceb380f1e4f11195b`,
clean CI merge-ref source/SCM `6942c884607ff5a794f537218a1fe137dee7bb58`.
The [CI summary](p14-c-ci-evidence.json) retains all16 conclusions, producer/
consumer identities, interop/native/tool evidence and cold/warm timings.
Complete logs and generated fixtures remain Actions artifacts. Both the main
implementation run and the final evidence/probe-head run are linked on
[PR #80](https://github.com/nantes-rfli/paclo/pull/80); the PR records final-head
results without recursively creating another evidence-only commit.

The final follow-up makes prep and its consumer explicitly reuse the isolated
Maven cache instead of defaulting to the user cache. Its complete local probe
passes: cold Maven/Git6.693s and build4.412s; forced warm2.581s/2.145s;
prep15.818s and consumer4.378s. Proxy/CA/Maven settings remain inherited.

## Remaining boundaries

No local JDK17/25 is installed; their execution evidence comes from CI.
No live capture/NIC throughput, Windows, other untested JVM/OS/CPU or filesystem
support is inferred from offline tests. The audit workflow's CLI pin is checked
statically; no credential-dependent NVD scan is claimed. Publish is not executed,
and no tag/publication/merge occurs. P14 remains unfinished: P14-B/Issue77 and
other development tools are separate work. P17 and P09/P10 are untouched.
