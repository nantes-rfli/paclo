# Codex environment preparation

> Historical environment snapshot before P01. The current task queue is in
> [dev/codex-plan.md](../codex-plan.md); P01 has since been completed.

Preparation date: 2026-10-11 (Asia/Tokyo).
Application baseline: `aaa3ec7bd3ac686c2e7ef85f1cf13c2245eb1978`.
This record distinguishes executed checks from historical release evidence.

## Available environment

- Linux x86_64, OpenJDK/Javac 21.0.12.1, Clojure CLI 1.11.1.1435.
- Project Clojure 1.12.1 and native libpcap available through the managed activation script.
- Existing writable Maven/Git caches; no service or privileged capture needed for offline work.
- Repository-local lint installer pins clj-kondo 2025.10.23 and clojure-lsp 2025.11.28-12.47.43.
- Markdown lint is pinned to markdownlint-cli2 0.18.1.

## Executed checks

| Command / check | Result |
| --- | --- |
| `bash dev/script/codex.sh doctor` | Supported runtime; native offline read, 4 packets / 438 bytes |
| `bash dev/script/codex.sh prepare` | Dependency preparation and Java compilation succeeded |
| `bash dev/script/codex.sh check` | JUnit: 8 passed; Clojure: 273 tests / 1,020 assertions, zero failures/errors |
| Offline smoke within `check` | Decode, timestamp-adapted writer round trip, and DNS annotation passed |
| Shell syntax and command dispatch | Valid syntax; unknown command and unexpected arguments exit 2 |
| `bash dev/script/codex.sh tools` | Pinned native lint binaries downloaded, checksums verified, versions executed |
| `bash dev/script/codex.sh test -n paclo.packet-xf-test` | Argument forwarding verified; 8 tests / 17 assertions passed |
| clj-kondo over `src test dev extensions/dns/src` | Zero errors and warnings |
| clojure-lsp `clean-ns --dry` and `format --dry` | Nothing to change |
| Markdown lint | 18 maintained documentation files, zero errors |
| `bash dev/script/codex.sh package` | JAR built; core, stream, DNS extension, and native binding entries present |
| `git diff --check` and new documentation links | Passed |

The writer smoke uses the current explicit timestamp adapter. It does not claim
that plan item P02 is already fixed or that truncated metadata is preserved.

## Known environment limitation

`bash dev/script/codex.sh lint` correctly exits unsuccessfully at Eastwood dependency
resolution: `jonase/eastwood:1.4.3` cannot be downloaded from `repo.clojars.org`
(HTTP 403 under the current allowed-host policy). clj-kondo passed before that
step; namespace/format and Markdown checks were run separately and passed.

To enable the complete local lint command, add **repo.clojars.org** to this managed
environment's allowed hosts through the environment configuration UI, then rerun
`bash dev/script/codex.sh lint`. The session exposes environment inspection but no
configuration-write tool, so this preparation does not claim to have changed that
policy. No application secrets are needed. The existing Eastwood CI job remains
the remote check; its result must be inspected on the PR.

## Scope and next task

This change prepares development instructions, an executable entry point, pinned
lint installation, CI coverage of the entry point, and the accepted work queue.
No packet API implementation or release version changes are included.

Next task: **P01** in [codex-plan.md](../codex-plan.md).
Live capture, real-NIC performance, macOS/arm64, audit, and publication are separate
checks and are not established by this environment validation.
