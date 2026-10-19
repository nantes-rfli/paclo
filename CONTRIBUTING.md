# Developing Paclo

Start with [AGENTS.md](AGENTS.md) and the [accepted development plan](dev/codex-plan.md).
The public compatibility baseline is [the v1 API contract](docs/cljdoc-api-contract.md).
Future API sketches in the plan are not available in the current release.

## Environment

Use Linux or macOS, JDK 21 (JDK 17 is also supported), Clojure CLI **1.12.5.1664**, and
libpcap. `deps.edn` selects the Clojure library version; the CLI version is separate.
The current development library baseline is Clojure 1.12.6; the separate
`-T:build` tool uses tools.build **0.10.14** and its own tool dependencies.
No application server, database, capture privileges, or publication
credentials are needed for ordinary offline development.

On another machine, install a supported JDK and the
[official Clojure CLI](https://clojure.org/guides/install_clojure).
To reproduce the CI CLI on Linux/macOS without changing a system installation,
use the optional checksum-verified installer with a new absolute prefix:

```bash
bash dev/script/setup-clojure-cli.sh /tmp/paclo-clojure-cli
export PATH="/tmp/paclo-clojure-cli/bin:$PATH"
clojure -Sdescribe
```

The installer needs curl, tar and Python 3; it refuses an existing prefix and
does not require root. After managed-environment activation, put the selected
CLI first on PATH if the activation script selects an older image CLI.
`doctor` prints the reference version and the actual CLI identity; it does not
silently replace an installed toolchain. Other CLI versions remain unverified
until tested. CI (including 17/21/25, ARM64, consumers, coverage and Publish) and
Dependency Audit all pin 1.12.5.1664. Publish uses the tested pin for both tag
and manual dry-run paths; all authorization/version/source guards still apply.
Main CI and Publish share Maven/Git download caches under CLI-specific keys;
user CLI/tool configuration is excluded. The first run under the new key must
download dependencies again; later runs can reuse those exact artifacts.
The independent consumers retain their Maven-only cache keys, and audit retains
its Maven/Git/NVD data cache: these contain artifacts/data independent of CLI
configuration and are verified or refreshed by their existing checks.

On Debian/Ubuntu, the native prerequisite is `libpcap-dev`; macOS supplies libpcap.
Static checks additionally need `clj-kondo`, `clojure-lsp`, and Node.js/npm (`npx`).
For Linux x86_64, `bash dev/script/codex.sh tools` installs checksum-verified
clj-kondo 2025.10.23 and clojure-lsp 2025.11.28-12.47.43 into ignored `.dev-tools/bin`.
The wrapper automatically selects them. The same versions are pinned in CI.
The installer requires `curl` and Python 3; it does not need root.
On other platforms install those versions using their upstream distributions.
Do not upgrade application dependencies just to provision tooling.

From the repository root:

```bash
bash dev/script/codex.sh doctor
bash dev/script/codex.sh prepare
bash dev/script/codex.sh check
```

The script switches to the repository root. In managed cloud environments, it
automatically sources `/workspace/.paclo-env/activate.sh` when available. This
refreshes the current proxy and CA configuration and selects writable caches.
It does not assume that a previous task's shell or processes survive.

`PACLO_ENV_ACTIVATE=/path/to/activate.sh` selects another activation script;
`PACLO_ENV_ACTIVATE=''` uses the current shell environment without activation.
When invoking `clojure` directly in the managed environment, source the activation
script in **each new shell** first. The wrapper's environment changes do not
propagate back to its parent shell.

The managed image's installer is `/workspace/.paclo-env/install.sh`; use it only
to restore missing tooling in that image. Its companion `start.md` describes
image-specific setup. These files are infrastructure, not required repository
files. Other machines use their normally installed toolchain.

## Daily commands

| Command after `bash dev/script/codex.sh` | Purpose |
| --- | --- |
| `doctor` | Compile bindings; check supported runtimes and a real offline libpcap read |
| `prepare` | Resolve development/test dependencies and compile Java bindings and tests |
| `tools` | Install pinned lint binaries locally on Linux x86_64 |
| `test -n paclo.reduce-test` | Compile bindings and run a selected test namespace |
| `test` | Compile bindings and run all Clojure tests |
| `java-test` | Compile and run JUnit with failure on zero discovered tests |
| `smoke` | Check fixture decoding, current writer behavior, and DNS annotation |
| `check` | Compile, run JUnit and all Clojure tests, then run the smoke check |
| `lint` | Run static checks and formatting checks without applying fixes |
| `perf` | Run the existing offline performance gate |
| `package` | Build the distributable JAR |
| `repl` | Start a terminal REPL with dev and DNS extension paths |

The wrapper forwards arguments only for `test`; unsupported commands or arguments
fail rather than silently ignoring them. `doctor` reports missing optional lint
tools, and `lint` fails if they are missing. `doctor` and `prepare` may download
uncached Maven/Git dependencies; neither installs system packages.

`package` calls the existing `build/jar`, which deletes and recreates `target/`.
Save useful measurement reports elsewhere first, and rebuild Java tests afterward.
Do not run packaging concurrently with tests, compilation, or performance work.

Some existing CLI/test processes wait for Clojure worker threads before exiting.
Wait for a successful exit, not just a reassuring output line. The standalone
environment smoke command calls `shutdown-agents` when complete.

## Verification by change

Maintained documentation examples carry `<!-- paclo-doc-test: <id> -->` markers
immediately before their code fences. The executable-example checker discovers
these in the root README and current `docs/` pages (excluding `docs/archive/`).
Register each new ID, its language, and its result check in
`dev/script/verify_doc_examples.py`; unknown, missing, or duplicate IDs fail.
Run `python3 -m unittest discover -s dev/script -p 'test_verify_doc_examples.py'`
for the parser and, after compiling Java, run
`python3 dev/script/verify_doc_examples.py` for the actual offline examples.

| Change | Required local evidence |
| --- | --- |
| Docs only | Markdown lint; execute changed examples where applicable |
| Development scripts | Shell syntax, help/error paths, and affected real commands |
| Clojure behavior | Focused regression tests, then `check` and relevant static checks |
| Java/native I/O | `check`, SpotBugs, CheckStyle, JaCoCo; supported-platform CI |
| Decode/reduction/stream hot paths | Above checks plus existing performance comparisons |
| Packaging/dependencies | `package`, JAR contents and clean-consumer validation |

Java quality commands are `clojure -T:build spotbugs`, `checkstyle`, `jacoco`,
and `jacoco-gate`; use the existing CI coverage threshold when reproducing CI.
Build subprocess failures propagate as nonzero CLI exits, including classpath
resolution and JUnit. Run `python3 -B -m unittest discover -s dev/script -p
'test_build_toolchain.py'` for failure-injection, Java 17 API and fixed POM-date checks.
Run `python3 dev/script/verify_toolchain_resolution.py /tmp/paclo-toolchain-resolution`
with a fresh output folder for independent cold/warm Maven/Git resolution and
`prep-lib` compilation. It uses temporary caches/configuration, preserving user
caches. Prep launches a child CLI without inheriting `-Srepro`, so the probe
uses an empty `CLJ_CONFIG` for that phase.
`SOURCE_DATE_EPOCH` (integer epoch seconds) fixes the generated POM properties
comment date. It does not fix JAR entry timestamps, JVM locale or build-JDK
manifest metadata; byte-identical JARs across rebuilds are not promised.
Full pipeline and compatibility checks remain defined in `.github/workflows/ci.yml`.
Keep CI and local checks aligned as the development wrapper evolves.

The required `build` aggregate includes the dedicated Eastwood job. Both CI
and local `lint` compile the Java bindings before analyzing all existing source,
development, DNS extension and test roots. Eastwood warnings remain informational;
analysis/linter exceptions (including aborted traversal with unanalyzed namespaces)
fail the command. Run `python3 dev/script/test_eastwood_runner.py` to verify the
actual runner exit status for complete analysis, warnings and deliberate failures.

For new behavior, select tests based on the contract being changed:

- Packet metadata: real PCAP round trips, including truncated records and timestamp precedence.
- Extensions: execution order, explicit empty selection, concurrent independent pipelines,
  failure policy, and legacy registration behavior.
- Lifecycles: early `reduced`, exceptions, full queues, idempotent close, and abandoned values.
- Analysis: deterministic replay, expiration, cardinality limits, and live/offline parity.

Performance measurements need the input, commit, runtime, platform, warm-up,
allocation, and drop counters. Cloud timings are not directly comparable to the
reference Mac. See [performance measurement](docs/performance.md). Live and real-NIC
experiments are separate from `check`; document the selected interface and traffic
scope, and do not infer capture throughput from a generator-limited run.

## External capture interoperability

After `bash dev/script/codex.sh prepare`, run
`python3 dev/script/verify_interop.py /tmp/paclo-interop` with a fresh output
folder. The gate requires `text2pcap`, `editcap`, `mergecap`, `tshark`, `capinfos`
and `tcpdump` on PATH; missing tools fail rather than skip. It opens only files,
requires no capture privileges and uses synthetic RFC 5737 addresses. Keep the
output folder for commands, tool versions, native/JVM identity, generated inputs,
Writer outputs, wire-oracle assertions and normalization evidence.

CI installs Ubuntu's `tshark`/`wireshark-common` and `tcpdump` packages from the
runner's configured Ubuntu repositories alongside existing libpcap-dev. macOS
fetches/checksums the signed upstream app through Homebrew's `wireshark-app`
cask definition and extracts only `Wireshark.app` from the read-only disk image
to the runner's temporary folder (no package/capture-helper install). It verifies
the app signature, uses its CLI directory on PATH, and uses the OS tcpdump. Versions are intentionally
those of these distributions, not claimed identical across OSes: package identity
is printed during installation and each execution saves full `--version` output.
The [P16 report](dev/p16-interop-verification.md) identifies actual tested versions.
No daemon, privileged capture helper, live interface or runtime dependency is added.
The existing Linux x64/JDK21, macOS ARM64/JDK17 and Linux ARM64/JDK21 jobs run this
gate and upload `p16-interop-*` artifacts. The build aggregate also requires the
ARM64 monitor so an interoperability failure there cannot pass the aggregate.

## Network and credentials

Use the supplied proxy and CA trust. Do not disable TLS checks, alter inherited
credentials, or dump environment variables. Dependencies may need Maven Central,
GitHub, and (for optional tooling) Clojars. Markdown lint uses the npm registry.
If an allowed-host policy blocks a dependency, record the host and command and use
the environment configuration workflow; cached success does not prove cold setup.

Ordinary development does not require `CLOJARS_PASSWORD` or `NVD_API_TOKEN`.
Publication and dependency-audit workflows manage their own credentials. If the
CLI's GitHub authentication is unavailable, use the connected GitHub tools when
available; do not start an interactive login or copy tokens into the repository.

## Dependency security audit

Use Python 3.11+, the pinned CLI 1.12.5.1664 and JDK 21, then run from the repository root:

```bash
python3 -B -m unittest discover -s dev/script -p 'test_dependency_audit.py'
python3 dev/script/dependency_audit.py /tmp/paclo-audit-production --refresh
```

The evidence folder must be new. Set `NVD_API_TOKEN` through the environment;
never put credentials in EDN or commit reports containing credentials. The
separate `dev/audit/deps.edn` project pins nvd-clojure 5.3.0. Both classpaths use
`-Srepro`: the root default dependencies are the production target, while the
helper's dependencies run the scanner. User aliases/deps are excluded. The
removed `:nvd` alias must not be used. This follows the
[upstream isolation guidance](https://github.com/rm-hull/nvd-clojure#clojure-cli).

The runner records classpaths, resolved dependency trees, JAR paths/selected
versions/SHA256 hashes, commands/statuses, JVM/CLI, source identity, effective
configuration, actual scanner/engine versions and original reports. Source
folders/classes remain excluded, as before; the scanner receives only the
resolved absolute JAR paths recorded in `scanner-input-classpath.log`.
The default `.dev-tools/nvd-data/12.2.0` cache is explicit and ignored; select
another location with `--data-directory`. `--resolve-only` verifies inventories
without an NVD scan and records `resolved-only`, never an audit pass.

Success requires scanner exit0, a current JSON report covering every production
JAR hash, no analysis exceptions/suppressions, engine 12.2.0, NVD Last Checked
within 24 hours and Last Modified within 7 days (with 5 minutes of clock tolerance).
`--refresh` forces an NVD check in this execution (validity 0); CI always uses it.
Normal local cached mode has a 24-hour validity window. Automatic updates remain enabled;
cache mtimes do not establish freshness. CVSS v2/v3/v4 base scores >=7.0 fail,
including exactly 7.0; invalid/unscored findings require triage and cannot pass.
The original tool's nonzero exit always fails too; logged errors and known
remote/update/analysis failure warnings cannot pass with a cached report. No suppressions are added.
NVD fetch/auth/analysis failure or missing/malformed output is incomplete.

The weekly Monday 03:00 UTC and manual workflow scans production only, restores
a versioned database cache, forces a new NVD check, verifies metadata and always uploads evidence even
on failure. A missing 12.2.0 database can be seeded from the old 12.1.6 Maven
cache: both published engines use directory schema 11.0/data.version 5.5. Only
the database is copied; the source is preserved, and refresh/report validation
still determines success. Cold imports get 120 minutes (observed 250k/410k records
in 45 minutes); other commands get 10 minutes, with a 135-minute job limit.
Command stages and incomplete evidence are saved before process launch.
OSS Index is disabled by nvd-clojure without its separate credentials;
when configured, inspect scanner logs for that service's actual outcome. Neither
state establishes broader advisory coverage. Optional `:csv`, test/dev/build and
scanner graphs are outside this production audit. Any future audit of those
scopes needs separately named inputs, evidence and results. OS libpcap/native
advisories and CPE matching limits remain separate. See the
[P14-D evidence and limits](dev/p14-d-dependency-audit-verification.md).

## Documentation verification

For documentation-only changes, run Markdown lint and the local-link checker:
`dev/script/mdlint.sh` and `python3 dev/script/verify_doc_links.py`. The link
checker includes archived Markdown and validates local paths and heading anchors;
it deliberately does not make network requests or validate external URLs.
Run `python3 -m unittest discover -s dev/script -p 'test_verify_doc_links.py'`
when modifying its parsing logic. Current runnable code examples are checked
separately; archived examples are not executed by the maintained-example gate.

## Release preparation

Use the [P01–P08 readiness audit](dev/release-readiness-p06-p08.md) for current
compatibility decisions and acceptance conditions. Archived release checklists
are historical evidence. Publication is a separate authorized task: a `v*` tag
push triggers Clojars deployment, while manual Publish defaults to a non-publishing
dry run and requires current main. Dry-run accepts an explicitly unreleased
version heading; publishing still requires a real dated changelog section.
The Publish workflow runs only a subset of CI; require the complete CI results separately,
including Linux ARM64, before approving a release.

## Distribution compatibility

`build/jar`, `build/javac` (including `:deps/prep-lib`) and `build/javac-test`
share `--release 17 -Xlint:all -Werror -proc:none`. The release option checks both
class-file compatibility and the Java 17 API baseline even when compiling on JDK 21.
CI uses the build tasks directly; a failed package build cannot fall back to
an unconfigured `javac` invocation.

Build the candidate once with JDK 21, then prepare a separate consumer bundle:

```bash
bash dev/script/codex.sh package
python3 dev/script/verify_distribution.py prepare target/paclo-1.5.0-SNAPSHOT.jar /tmp/paclo-distribution
python3 dev/script/verify_distribution.py consume /tmp/paclo-distribution --report /tmp/consumer-jdk21.json
```

Ordinary main/PR builds and the verifier default to `1.5.0-SNAPSHOT`. This is a
development identifier, not a v1.5.0 release scope or date. `PACLO_VERSION` takes
precedence over a GitHub tag ref (`GITHUB_REF_TYPE=tag`, `GITHUB_REF_NAME=v...`);
other refs use the development default. Non-SNAPSHOT versions retain `v<version>`
in the POM SCM tag. SNAPSHOT builds require Git HEAD and record its full commit
SHA instead of inventing a release tag. Uncommitted edits are reported separately
by `source_dirty` in distribution provenance; a commit SHA alone does not identify
those edits. Neither ordinary CI nor local packaging publishes artifacts.

Run the build identity regression with
`python3 -B -m unittest discover -s dev/script -p 'test_build_identity.py'`.
It generates POMs in `target/maven` without installing or publishing artifacts.

Use a fresh output directory for `prepare`; it checks all class-file versions,
the exact production source/binding inventory and existing Maven coordinates/
dependencies plus SCM identity, and records the source commit, tracked-file dirty
state, build JVM and hashes.
Test fixtures and the consumer harness are outside the JAR. Set `--version` to
the existing candidate version when using `PACLO_VERSION`, as Publish does.
Switch only the runtime to JDK 17 and invoke `consume` on the **same bundle**;
do not rebuild. Each consumer verifies hashes before execution and writes a
runtime/commit/JAR identity report after success. `-Srepro` and a temporary project
keep repository roots, user deps and recompiled bindings out of the classpath.

CI uploads the JDK 21 JAR once from `build-checks`; three jobs without checkout
download it on JDK 17/21/25. All must succeed in the required `build` aggregate.
The bundle's `provenance.json` and consumer reports and unfiltered warning logs are Actions artifacts.
Publish performs the same package inspection and saves provenance; CI remains
the full cross-runtime gate. No workflow dispatch or publication is needed to
validate a pull request.

## JDK 25 compatibility experiment

JDK 17/21 remain the supported baseline. P13 adds a required Linux x64 JDK 25
experiment, retaining the JDK 21 producer, Java `--release 17`, Clojure 1.12.6,
production dependencies and all existing quality/performance gates. It does not
establish support for every JDK 25 OS/CPU or live capture configuration.

Select an actual JDK 25 through `JAVA_HOME` and `PATH`, then run:

```bash
python3 dev/script/verify_jdk25.py /tmp/paclo-jdk25-source
python3 dev/script/verify_distribution.py consume /tmp/paclo-distribution --report /tmp/consumer-jdk25.json
python3 dev/script/verify_distribution.py consume /tmp/paclo-distribution --report /tmp/consumer-jdk25-debug.json --java-option=--enable-native-access=ALL-UNNAMED --java-option=--sun-misc-unsafe-memory-access=debug
```

Use a fresh source-report directory and the **same JDK 21-built bundle** used by
17/21. The source script runs compilation, JUnit (including native ABI fixtures),
the full Clojure suite, BPF/interface smoke and dependency inventory directly;
`doctor`/`smoke` retain their deliberate supported-JDK guard. Full PCAP/PCAPNG,
DNS and lifecycle smoke also runs in each independent distribution consumer.
Reports include exact JVM/OS/architecture, libpcap version and JNR-loaded paths.
No warning suppression is applied in the default run. The separate native-access/
Unsafe debug run attributes call sites; it is not a replacement acceptance run.
The existing JDK 21 SpotBugs, CheckStyle, JaCoCo and performance checks remain
mandatory; P13 does not claim JDK 25 analyzer/coverage compatibility.
See the [P13 evidence and support decision](dev/p13-jdk25-verification.md).

P14-A updates JNR-FFI to 2.3.3. Independent consumers additionally require
jffi Java/native 1.4.3, ASM 9.10.1 and the existing assembler versions, recording
JAR hashes after actual resolution. A mismatched/missing native classifier or
mixed ASM graph fails verification. The CI JDK 25 consumer separately records
`--enable-native-access=ALL-UNNAMED --sun-misc-unsafe-memory-access=deny`.
Success under denial is diagnostic evidence, not a formal support requirement;
only the previously attributed jffi `UnsupportedOperationException: putLong`
is accepted as a known diagnostic failure, with its original status/log retained.
Default startup and the debug consumer must still succeed. See the
[P14-A native compatibility report](dev/p14-a-jnr-verification.md).

## Handoff

Update the relevant task status and dependencies in `dev/codex-plan.md`.
Write the implementation commit/PR, actual commands and results, decisions,
unverified environments, and next task in [dev/work-log.md](dev/work-log.md).
Keep unfinished items visibly unfinished. Review version assignment against
compatibility before calling an item a patch release; release labels in the
plan are candidates.
