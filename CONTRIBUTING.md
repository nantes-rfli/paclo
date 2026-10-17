# Developing Paclo

Start with [AGENTS.md](AGENTS.md) and the [accepted development plan](dev/codex-plan.md).
The public compatibility baseline is [the v1 API contract](docs/cljdoc-api-contract.md).
Future API sketches in the plan are not available in the current release.

## Environment

Use Linux or macOS, JDK 21 (JDK 17 is also supported), the Clojure CLI, and
libpcap. `deps.edn` selects the Clojure library version; the CLI version is separate.
The managed cloud environment currently supplies JDK 21, CLI 1.11.1.1435,
and libpcap. No application server, database, capture privileges, or publication
credentials are needed for ordinary offline development.

On another machine, install a supported JDK and the
[official Clojure CLI](https://clojure.org/guides/install_clojure).
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
dry run and requires current main plus a dated changelog section. The Publish
workflow runs only a subset of CI; require the complete CI results separately,
including Linux ARM64, before approving a release.

## Handoff

Update the relevant task status and dependencies in `dev/codex-plan.md`.
Write the implementation commit/PR, actual commands and results, decisions,
unverified environments, and next task in [dev/work-log.md](dev/work-log.md).
Keep unfinished items visibly unfinished. Review version assignment against
compatibility before calling an item a patch release; release labels in the
plan are candidates.
