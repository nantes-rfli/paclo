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
semantics. Cache keys now include the CLI version, preventing restoration of an
old archive containing `~/.clojure`. Only Maven/Git download caches are saved;
CLI/user/tool configuration is excluded. The initial new-key run is intentionally
cold; subsequent runs can reuse artifacts without importing user aliases/config.
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

Implementation verification is in progress. Remote CI must establish all16
job conclusions, same-JAR17/21/25, Linux/macOS/ARM64, P16 interoperability,
documentation, static analysis, coverage and unchanged performance gates.

## Remaining boundaries

No local JDK17/25 is installed; their execution evidence comes from CI.
No live capture/NIC throughput, Windows, other untested JVM/OS/CPU or filesystem
support is inferred from offline tests. The audit workflow's CLI pin is checked
statically; no credential-dependent NVD scan is claimed. Publish is not executed,
and no tag/publication/merge occurs. P14 remains unfinished: P14-B/Issue77 and
other development tools are separate work. P17 and P09/P10 are untouched.
