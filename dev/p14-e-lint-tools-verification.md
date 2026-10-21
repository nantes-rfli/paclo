# P14-E: clj-kondo and clojure-lsp verification

## Selection and scope

Selected on2026-10-21 (Asia/Tokyo) from fetched main `42d2123`, including merged
P14-D PR82. The checkout was clean. P14-B PR76 remains held by Issue77;
core.async1.6.681 is retained. No P17/P09/P10 work, release, tag, publication or
merge is included.

The official GitHub release API was rechecked at execution time:

- [clj-kondo v2026.10.20](https://github.com/clj-kondo/clj-kondo/releases/tag/v2026.10.20),
  published2026-10-20T08:23:48Z, non-prerelease and latest. This supersedes P11's
  2026.08.04 candidate. It includes Java25 class analysis, hook resolution/arity
  corrections, type narrowing and map argument checks. Adopt after verification.
- [clojure-lsp2026.10.15-11.42.38](https://github.com/clojure-lsp/clojure-lsp/releases/tag/2026.10.15-11.42.38),
  published2026-10-15T12:28:14Z, non-prerelease and latest. Adopt after verification.
  Native `--version` reports bundled kondo2026.08.05-SNAPSHOT (`c50ca52`), distinct
  from the standalone stable analyzer. No runtime Clojure/JDK change follows.

The web index's `/latest` redirect was stale for both repositories; direct
`https://api.github.com/repos/{owner}/{repo}/releases/latest` responses and
release asset digests established the actual candidates. Neither tool required
reverting to an older version in the local evaluation.

Clojure1.12.6, JNR-FFI2.3.3, core.async1.6.681, CLI1.12.5.1664,
tools.build0.10.14 and1.5.0-SNAPSHOT remain fixed. JDK17/21 support and the JDK25
experiment remain unchanged. No SpotBugs, CheckStyle, JaCoCo, JUnit, Eastwood,
cloverage, API or performance threshold is changed.

## Native distribution pins

`dev/script/setup-lint-tools.sh` is now the single CI/local source of versions,
asset URLs and SHA-256 pins. All are official release ZIP asset digests. The
installer hashes the downloaded archive before reading its named binary and
atomically replaces that binary only after successful verification/extraction.
A failed install exits nonzero; an already installed first tool may remain if
the second download fails. This is per-binary atomicity, not a two-tool transaction.

| Platform | clj-kondo2026.10.20 archive SHA-256 | clojure-lsp2026.10.15-11.42.38 archive SHA-256 |
| --- | --- | --- |
| Linux amd64 | `cfc093e177d0e4619ae7bf9d5acd8f0ea43e7bb18dae9d64c1fa9fbcd3832681` | `d68acf630465cec9d3685fd958f914d9228d90a07222edd301f1a4740b8e8b76` |
| Linux aarch64 | `8231f5a039dfa4d6c255a25ad3c1286a6a1679cd706ddbee646a6cbed4ba684c` | `232ac0cd191070a3b7b5532135ec9f97217b82324de7e97da0b1bf81353a3c94` |
| macOS amd64 | `4c3caabc03108d2fc9b1860ae6a140af67c791115e6c1e8eeadc7e943bf49c0f` | `468c261b48a7276c79cb92a82ddfce5474bc563ba6673df30cabf17a7f239ef3` |
| macOS aarch64 | `675c2e508c71afe774cfa402f7959a6580a82f15c15dc935502489ff88133815` | `84df57e51e27f4ecf20d0cd65aab3296e2ebf28dbaacca4fe216b6cf20485716` |

Kondo assets are `clj-kondo-2026.10.20-<platform>.zip` under tagv2026.10.20;
LSP assets are `clojure-lsp-native-<platform>.zip` under tag2026.10.15-11.42.38.
Old macOS amd64 comparison downloads were also hashed: kondo2025.10.23
`b6876f9311f2998cce0df226adf4792eacf287cfeba9bd067f44d56650956970`,
LSP2025.11.28-12.47.43
`d819a2556df02e50288ab142763d36791adb243792c4a95b3fcbab08ba2d7793`.
Their versions report old bundled kondo2025.10.24-SNAPSHOT for LSP.

## Coverage and before/after findings

Compare standalone tools over identical `src test dev extensions/dns/src build.clj`
with `--cache false`. The old CI command omitted the DNS extension, the old
local wrapper included DNS but omitted build.clj, and LSP's explicit source
paths omitted DNS. Shared wrappers now cover all these Clojure roots. LSP keeps
src-java for project analysis and explicitly checks deps.edn/
dev/nvd-clojure.edn formatting. No cached dependency analysis substitutes for
source traversal. Existing four resource-macro `:lint-as` mappings are unchanged;
there are no project hook files or broad exclusion rules to migrate.

| Analysis | Old pins, original source | New pins, original source | New pins, corrected source |
| --- | --- | --- | --- |
| Standalone kondo | 0 errors/0 warnings | 4 errors/2 warnings/2 infos | 0 errors/0 warnings/2 infos |
| LSP clean-ns | Nothing to clear | Nothing to clear | Verification below |
| LSP format | Nothing to format | Only changed negative-test hint alignment | Verification below |

Individual triage:

- Three positive-integer/map type errors in cooked, Raw IP and NULL/LOOP
  composition tests: `flow/top-n` takes an options map. Clojure's map
  destructuring had silently used defaultn10 for the numeric argument100.
  Correct to `{:n 100}` so tests exercise their intended call. Public API is unchanged.
- The negative-natural-integer error in flow-test deliberately passes `{:n -1}`
  to verify the existing ExceptionInfo contract. Keep the assertion with one
  form-scoped `:type-mismatch` hint and an explanatory comment. No global rule
  or source exclusion is changed.
- Two always-true conditions in DNS `u16`: `u8` returns primitive long and
  cannot successfully return nil. Replace nested `when-let` with `let`, retaining
  primitive return hints and invalid-read exceptions. New regression verifies
  zero QTYPE/QCLASS and unchanged original-packet identity for truncated words.
  No public annotation/error behavior changes.
- Two informational redundant-coercion findings remain visible in
  `dev/paclo/dev/perf.clj` and `test/paclo/diagnostics_test.clj`. They are harmless
  existing explicit primitive conversions. Leave performance code and numeric
  test intent intact; no severity or linter setting is changed.
- Formatter differences are limited to alignment of the new targeted hint;
  no bulk formatting or unrelated source cleanup is applied.

The original kondo findings were captured before code changes. Old LSP checks
ran with expanded DNS source coverage. The first new LSP formatting pass overlapped
the addition of the deliberate negative-test hint, so its diff is an edit
alignment result, not evidence of an upstream formatter regression.

## Failure contracts and verification

`test_lint_tools.py` runs real installed analyzers on temporary projects. It
checks resource macro bindings, unresolved symbols, unsupported reader syntax,
malformed kondo/LSP EDN, clean dry checks, formatting differences without writes,
parser exceptions for both LSP commands and unsupported formatter arguments.
Missing required binaries fail these tests rather than skip them.

An actual malformed kondo config reproduced `WARNING: error while reading ...`
followed by0 errors/0 warnings and exit0. The kondo wrapper now preserves nonzero
pipeline status and fails on tool-level `WARNING:` output. Ordinary source
warning/error exits remain unchanged. Formatting validates tracked analyzer EDN
before executing LSP. Installer tests use isolated synthetic ZIPs and process
shims for all four platform selections, repeated atomic replacements, tampering,
missing ZIP members, download failures and unsupported architectures. They do
not claim execution of a foreign binary.

Local platform: macOS x86_64, Temurin21.0.12.1, system libpcap1.10.1;
CLI1.12.5.1664 installed with the existing verified installer under a temporary
prefix. The initial doctor used the host CLI1.12.5.1654; all acceptance commands
are rerun with the reference CLI. Logs and downloaded archives are under
`/tmp/paclo-p14-e` and are not committed.

| Command/evidence | Result |
| --- | --- |
| `bash dev/script/codex.sh doctor` | Exit0; CLI1.12.5.1664, four-packet/438-byte native offline read |
| `bash dev/script/codex.sh prepare` | Exit0 |
| `bash dev/script/codex.sh check` | Exit0;13 JUnit tests,494 Clojure tests/19,137 assertions and offline smoke |
| Native installer on macOS x64 | Exit0; both official archive digests match and versions execute |
| Installer regression controls | Five tests pass; synthetic platform selection is separate from native CI |
| Analyzer and installer negative controls |15 tests pass, including real syntax/config/clean-ns/format failures |
| `package`, distribution prepare and JDK21 consume | Exit0; local JAR `8d29ed992318c95ec262a3b0ca73676fd591a8a65cb1f88297fcba2116dd8043`, source42d2123, source_dirty=true |
| Documentation parser and executable examples |16 parser tests and all40 examples pass |
| Local P16 offline interoperability | Exit0;5 tests/377 assertions, Wireshark4.6.8 and tcpdump4.99.7; Paclo system libpcap1.10.1 |
| Existing build-toolchain controls | Six tests pass after replay with network access for isolated Maven resolution |
| Full lint and final CI | In progress; final results follow |

CI retains all16 jobs. The build-checks job now uses the shared verified installer
and regression controls; existing compatibility jobs additionally execute native
kondo/LSP checks on Linux x64/JDK21, macOS ARM64/JDK17 and Linux ARM64/JDK21.
Their original unit tests, P16, performance, distribution and aggregate conditions
remain required. Remote results and final-head identity must be recorded before
claiming those platforms verified.

## Limits

Local JDK17/25 and ARM64 are unavailable. CI must establish those existing matrix
conditions, all40 documentation examples, P16 and same-JAR17/21/25 distribution
results; local x64 tests alone do not validate them. Live capture, real NIC
throughput, other JVM vendors/OSes, Windows and32-bit environments are unverified.
The tooling update neither expands formal JDK support nor resolves PR76/Issue77.
Independent review remains required; no merge is performed.
