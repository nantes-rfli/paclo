# Development work log

This is the retained execution and verification record for completed development
slices. Current approved task priorities and unimplemented API proposals belong
in [the accepted development plan](codex-plan.md). Historical statements below
remain evidence of their original time, not a description of current CI or PR state.

## P01 and its baseline investigation

PR [#17](https://github.com/nantes-rfli/paclo/pull/17) is **merged**.
The historical P01 record below was written before that merge; its phrase
"merge pending" describes the earlier snapshot, not the current repository state.
PR [#26](https://github.com/nantes-rfli/paclo/pull/26) subsequently generalized
the executable documentation verifier and was merged before this reorganization.

### Original P01 plan and verification notes

## P01: Documentation and API discovery

Known baseline gaps:

- `core/packet-xf` exists but is absent from the README public API table and API contract.
- `docs/usage.md` says fan-out is unavailable despite the v1.3 public stream API.
- README's DNS quick check requires the nonexistent `paclo.dns.decode` namespace.

Document the selection among synchronous reduction, managed capture, and fan-out.
Explain that taking a prefix of a lazy sequence does not itself stop its source.
Show reliable early termination with reduction or explicit `with-open` ownership.
Document existing stop defaults and distinguish finite-file completion from limits.

Acceptance: examples execute; API docs agree; resource-owning examples close on
early termination. This item must not invent new runtime APIs.

Documentation and verification are in [PR #17](https://github.com/nantes-rfli/paclo/pull/17)
on 2026-10-11. README, usage guide, API contract, and extension guide now
cover `packet-xf`, bounded fan-out, early closure, stop defaults, EOF, and
the existing writer limitations; the incorrect DNS namespace was corrected.
Long-running live examples now explicitly raise the idle limit.

The new Linux GitHub Actions documentation step passed in
[CI run 38143766864](https://github.com/nantes-rfli/paclo/actions/runs/38143766864).
Reproduce after compiling Java bindings:
`python3 dev/script/verify_doc_examples.py`.
Result: 8 selected maintained code examples executed successfully against
the bundled offline PCAP fixture, with assertions for packet count, flow
results, early `reduced`, fan-out delivery and DNS namespace registration.
The script extracts exact examples from maintained documents and runs the
corresponding Clojure CLI commands; stdout includes the expanded commands
and per-example PASS reports. Previous PR CI passed; at the time of this
record, the additional full-workflow run was still running after the
documentation step had succeeded. No live capture, real-NIC performance,
or managed Codex environment execution is claimed. P01 acceptance is met;
P03 is unblocked. Merge/review remains a separate gate.

### Original verification record and handoff

#### Verification record and handoff format

For each completed slice append:

```text
Item / slice:
Status and implementation commit or PR:
Contract decisions:
Commands and measured results:
Unverified platforms or blocked checks:
Next item:
```

Baseline investigation: 34 focused tests / 118 assertions passed on Linux/JDK 21.
Timestamp replacement and global-hook dependence were reproduced. That investigation
did not validate live capture or rerun historical performance measurements.
See `dev/codex-environment-validation.md` for preparation results.

Item / slice: P01 / public API and usage documentation
Status and implementation commit or PR: Done, PR #17 (merge pending)
Contract decisions: Document only the shipped v1.3 API; no new runtime options;
  `packet-xf` is public and fan-out is separately owned; current writer
  metadata loss remains until P02. Long-lived live examples have explicit
  idle timeouts rather than inheriting the default 3000 ms.
Commands and measured results: `python3 dev/script/verify_doc_examples.py`
  passed in CI run 38143766864: 8 of 8 extracted documented examples
  succeeded, including actual PCAP read and multi-branch fan-out; previous
  PR CI and static documentation checks passed. Additional full CI still
  running when this record was written.
Unverified platforms or blocked checks: Live capture/real NIC not claimed;
  this chat's container could not run native examples. The GitHub Actions
  execution is the P01 runnable-example evidence.
Next item: P02; P03 is unblocked/ready.

## Recording future changes

For each merged slice, record the task ID, PR or commit, behavioral contract
decisions, commands and outcomes, blocked or unverified checks, and the next
available item. Keep the task status itself in [the plan](codex-plan.md).

## Issue #18: fan-out close-test scheduling race (2026-10-12)

Item / slice: Maintenance / Issue [#18](https://github.com/nantes-rfli/paclo/issues/18)
Status and implementation commit or PR: [PR #28](https://github.com/nantes-rfli/paclo/pull/28), awaiting CI and review.
Contract decisions: Keep the stream runtime unchanged. A full queue alone
  does not guarantee that a blocking put has returned and its
  `:blocked-events` counter was updated. The bounded/idempotent close test
  now checks terminal states and buffer accounting; a separate test
  synchronizes on the blocking-put fallback before checking backpressure
  after the queued values are consumed.
Commands and measured results: Static delimiter-balance and diff checks only.
  Focused Clojure test repeats, `bash dev/script/codex.sh check`, and CI
  results were not available in this execution environment (no Clojure CLI
  and no outbound repository/dependency-server access).
Unverified platforms or blocked checks: Linux/macOS/JDK compatibility and
  repeated scheduling runs remain to be confirmed by GitHub Actions or a
  configured Clojure development environment.
Next item: Verify PR #28 CI and repeated focused runs before merging;
  P02 remains the next approved feature item.

## 2026-10-12 — P02 packet metadata round trips

Status: **in-progress**, pending required PR CI and review. No merge or release
is authorized by this task. This change implements only P02; P03 and all other
queue items retain their existing states.

Baseline and protection:

- The supplied checkout was clean on local `main` at `f0bc162`, with one local
  commit and 57 upstream commits of divergence. Preserved that branch and its
  commit; created `codex/p02-pcap-round-trips` from latest `origin/main`
  `e2ce4e3` (PR #28). No unrelated changes were included.
- Read current agent/contribution instructions, accepted P02 plan, public API
  contract, writer/reader, native header helpers, fixtures, tests and CI.
  The initial doctor attempt on the stale checkout found no wrapper; after
  switching to current main, doctor passed against real system libpcap.
- Before editing: `bash dev/script/codex.sh test -n paclo.pcap-unit-test`
  passed (48 tests / 101 assertions), and `test -n paclo.pcap-bytes-test`
  passed (1 test / 7 assertions).

Implemented contract:

- Keep `(write-pcap! packets out)` and Ethernet output. Prefer complete
  `:ts-sec`/`:ts-usec`; reject partial new pairs; otherwise use complete legacy
  `:sec`/`:usec`, or current time for missing pairs/partial legacy pairs/raw bytes.
  Check key presence so zero is retained and complete `nil` pairs are rejected.
  Validate only the selected pair: seconds `0..4294967295`, usec `0..999999`,
  integer types only. Legacy numeric coercion and complete nil fallback were
  incidental old behavior; explicit invalid complete inputs now fail as requested.
- Validate byte-array inputs; derive captured length from bytes, require supplied
  `:caplen` to match, retain original `:len` (default captured length), and require
  integer uint32 lengths with original length at least captured length. Only after
  validation, use unchecked int conversion to retain uint32 field bits.
- Keep existing resource-finally ownership, with exception cleanup regression
  tests. Write Linux int64 and Darwin int32 microseconds plus deterministic padding
  consistently with existing `PcapHeader.java`; no native binding rewrite.
- Add `metadata-roundtrip.pcap`, built by the independent Python struct generator
  `test/resources/make_metadata_fixture.py`, with full Ethernet records, a 42-byte
  capture of a 1500-byte packet, and original length `4294967295`. Real BPF and
  Clojure filter/read/write/read tests verify ordered records and byte contents.
  An independent binary parser verifies both fixture and serialized output headers,
  including uint32 seconds and lengths, so shared reader/writer errors cannot pass.
- Update maintained writer docs/docstrings, Unreleased notes and readiness smoke;
  preserve archived history. Register the runnable round-trip example as a ninth
  documentation check while retaining all eight required IDs.

Compatibility finding:

- An independently constructed record with seconds `4294967295` was returned as
  `:ts-sec -1` by this machine's macOS system libpcap. Current upstream
  [libpcap source](https://github.com/the-tcpdump-group/libpcap/blob/master/sf-pcap.c)
  defines unsigned savefile seconds, but older native readers sign-extend them.
  Do not silently change Paclo reader timestamps in P02. Document the post-2038
  native limitation; negative native seconds fail writer validation. The round-trip
  fixture uses seconds up to `2147483647` and verifies large unsigned original
  length end-to-end. A separate serialized-file test verifies max uint32 seconds.
  Review this limitation and stricter invalid-input rejection before deciding
  patch versus minor release. No version, tag or Clojars change was made.

Local evidence (macOS x86_64, Temurin JDK 21.0.12.1, Clojure CLI 1.12.5.1654,
project Clojure 1.12.1, system libpcap):

- `bash dev/script/codex.sh doctor`: PASS; real offline read, 4 packets / 438 bytes;
  clj-kondo, clojure-lsp and npx available.
- Focused final regressions: unit 49 tests / 103 assertions; bytes 5 / 87;
  new `paclo.pcap-roundtrip-test` 4 / 68; all passed.
- `bash dev/script/codex.sh check`: PASS; JUnit 8 tests, Clojure 287 tests /
  1211 assertions, offline writer/DNS smoke; final type-hint cleanup recheck also passed.
- `clojure -M:perf-gate`: PASS, existing 50k/74-byte gate 421.7 ms versus
  1000 ms warning / 1200 ms failure budgets. One local run is gate evidence,
  not a comparative performance improvement or regression claim.
- `python3 dev/script/verify_doc_examples.py`: PASS, 9 real offline examples.
- Parser tests: `python3 -m unittest discover -s dev/script
  -p 'test_verify_doc_examples.py'`: PASS, 13 tests.
- `python3 dev/script/verify_doc_links.py` and `git diff --check`: PASS.
- `dev/script/mdlint.sh`: PASS, 27 files / 0 errors after allowed network retry.
  Initial sandbox run failed with npm registry DNS `ENOTFOUND`; do not count it
  as success. `bash dev/script/codex.sh lint` passed kondo (0 errors/warnings),
  Eastwood and format/namespace checks but initially failed at the same npm step;
  the complete final command passed with network access (58 existing Eastwood
  warnings, no exceptions, no changes required by namespace/format checks).

CI/review and scope:

- Existing required `build` aggregates build checks, documentation, performance
  shards/results and compatibility matrix (Linux x64/JDK21 and macOS ARM64/JDK17).
  Linux ARM64 is a separate existing monitoring job, not a required aggregate
  dependency. Keep these jobs, quality thresholds and performance gates unchanged.
- PR creation/check results will be recorded below. Supported-platform CI,
  independent review, and live capture are not validated by the local offline run.
  No PCAPNG, additional/dynamic link types, source global-header/snaplen/precision
  preservation, borrowed buffers, parallel decoding or new public API is included.
- Next work is P02 CI and review; do not start P03 as part of this PR.

Commit-hook environment note: the existing `.githooks/pre-commit` invokes `clj`,
which requires missing `rlwrap` on this host. The first commit attempt aborted.
Use a temporary PATH shim delegating noninteractive `clj` to the installed
`clojure` CLI to execute the same hook checks; no hook or project tooling change.

PR and CI evidence:

- Implementation commit: `0a33a54133995c39b570e0eae787322766cc37f4`.
  [PR #29](https://github.com/nantes-rfli/paclo/pull/29) is open for review,
  attached to this chat, and not merged. The commit hook completed all its
  tests, formatting, Markdown and kondo checks using the temporary CLI shim.
- [Actions run 38202555953](https://github.com/nantes-rfli/paclo/actions/runs/38202555953)
  passed all 12 jobs on the implementation commit: required aggregate `build`,
  build/Java quality gates, documentation, Linux x64/JDK21 compatibility,
  macOS ARM64/JDK17 compatibility, three performance shards plus results,
  Linux ARM64 monitor, Eastwood and coverage. No failing/skipped job was observed.
- This evidence-recording commit changes only the plan/log. Its final-head CI
  is checked through the PR after pushing; implementation evidence above remains
  tied explicitly to the tested source commit rather than claiming a later SHA.
- Independent review is still absent (reviews list empty). P02 remains
  **in-progress** until review acceptance; next work is reviewing PR #29 and
  choosing a compatible release version. Do not merge or publish during this task.

## 2026-10-12: Merged branch cleanup

The user requested branch cleanup, expecting 26 deletions. GitHub had 27
branches: `main` and 26 completed PR branches. All 26 branch heads matched
exactly the final head SHA of a merged PR targeting `main`; no open PR used
any candidate. Some PRs used squash merges, so commit ancestry alone was
not sufficient evidence. Deleted these 26 remote branches and pruned their
remote-tracking refs. Retained all three local branches and the current
checkout, including the unique local `main` commit `f0bc162`.

Verification and commands:

- Initial `git status --short --untracked-files=all`: clean.
- `bash dev/script/codex.sh doctor`: PASS; real offline libpcap read,
  4 packets / 438 bytes; optional lint tools available.
- `git ls-remote --heads origin`, `git fetch --prune origin`, and
  `gh pr list --state all` with head SHAs: verified 26 deletion candidates.
  Initial sandbox network attempts failed DNS/connectivity; network-enabled
  retries passed.
- `git push --atomic` with one exact-SHA `--force-with-lease` and deletion
  refspec per branch: PASS, all 26 deleted in one transaction.
- Final `git fetch --prune origin`: PASS. Final `git ls-remote --heads origin`
  returned only `main` at `653414b9eb41a380df6262c1d79751af9b127f6d`.
- PR #29 was merged at 2026-10-12 04:22:44 UTC. Updated the plan to mark
  P02 accepted/done and P03 as the next unfinished item. No new independent
  review, live-capture, platform, or performance validation is claimed.

Documentation verification: `python3 dev/script/verify_doc_links.py` and
`git diff --check` passed. Markdown lint initially found one extra blank line
in this entry; removed it. Final `dev/script/mdlint.sh` passed (27 files,
0 errors) with network access. The initial sandbox lint attempt failed with
`ENOTFOUND registry.npmjs.org`; it is not counted as a passing check.
No source behavior, release version, publication, or PR merge was changed
by this cleanup task.

## 2026-10-12: Local branch cleanup

The user also authorized cleanup of the three local branches after review.
The unique local `main` commit `f0bc162` contains an obsolete v1.1 planning
draft, with no runtime code. Saved all three old branch heads and complete
history in `.dev-tools/branch-backups/20261012-local-cleanup.bundle` before
changing refs; `git bundle verify` passed. Saved the existing uncommitted
documentation diff alongside it as `20261012-uncommitted-docs.patch`.

- Initial status: only the previous plan/log edits were uncommitted.
- `bash dev/script/codex.sh doctor`: PASS, offline read 4 packets / 438 bytes.
- `git fetch --prune origin`: PASS; current worktree HEAD and `origin/main`
  had identical committed trees. `fix/hbh-udp` was an ancestor of `origin/main`.
- `git switch --detach origin/main`, `git branch -f main origin/main`, then
  `git switch main`: PASS; preserved the uncommitted plan/log edits.
- `git branch -d fix/hbh-udp` and `git branch -D codex/p02-pcap-round-trips`:
  PASS. P02 was already squash-merged as PR #29; its tree matched current main.
- Initial sandbox ref/index writes were denied; network-enabled/unsandboxed
  retries passed. No failed attempt is counted as a successful operation.
- Final local branch: only `main`, tracking `origin/main`, at `653414b`.
  No feature, release, or remote branch was changed during this local cleanup.
  Next feature remains P03; retained documentation edits are uncommitted.
- Verification: `git rev-list --left-right --count main...origin/main`
  returned `0 0`; `git diff --check` and the local Markdown link checker passed.
  Initial Markdown lint found an extra blank line before this entry; corrected it.
  Rerun passed (2 files, 0 errors).

## 2026-10-12: Commit branch-cleanup records

The user authorized committing the remaining plan/log changes. This commit
records remote and local branch cleanup, P02 merge acceptance, and P03 as
the next unfinished feature; it introduces no runtime changes.

- Initial status: only `dev/codex-plan.md` and `dev/work-log.md` modified.
- `bash dev/script/codex.sh doctor`: PASS, offline read 4 packets / 438 bytes.
- `dev/script/mdlint.sh`: PASS, 27 files / 0 errors.
  `python3 dev/script/verify_doc_links.py` and `git diff --check`: PASS.
  No runnable documentation examples changed.
- Commit command: `SKIP_TESTS=1 SKIP_FMT=1 SKIP_KONDO=1 git commit
  -m "docs: record branch cleanup and P02 completion"`. The existing hook's
  documented optional flags omit runtime tests and Clojure formatting/lint
  for this documentation-only change; its Markdown lint remains enabled.
- Scope: local commit only. No push, PR, release, or P03 implementation.

## 2026-10-12 — P03 design and implementation

Started from clean main `c13916b`, equal to fetched `origin/main`, containing
P02 merge `653414b` (PR #29). `bash dev/script/codex.sh doctor` passed on
macOS x86_64, Temurin JDK 21.0.12.1, Clojure 1.12.1 / CLI 1.12.5.1654;
native offline PCAP read and all optional lint tools were available.

Design decisions made before adding the API:

- `:extensions` is a vector whose elements satisfy `fn?`; validate configuration
  at pipeline construction, using key presence to distinguish omission from nil.
  Explicit configuration requires `:decode? true`; raw and flow modes reject it
  before opening a capture. Existing decode-mode exclusions remain unchanged.
- Omission keeps the dynamic process-wide registry. Explicit vectors select only
  their functions, including duplicates, in order; `[]` selects none. The vector
  is retained in the transform and never combined with the registry.
- Publish the existing `annotate-dns` and `annotate-tls-sni` functions directly;
  existing registration installs those same functions. Preserve best-effort parsing.
- Share failure isolation via an additive `decode-ext/apply!` arity accepting
  packet plus functions; core validates configuration once, outside packet execution.
  Map results feed the next function; exceptions and non-map results preserve
  the preceding map and later functions continue. Eligibility remains presence
  of `:decoded` and absence of `:decode-error`, as in the existing hook contract.
- Keep `packet-pipeline-xf` as the shared path for all capture models, with
  decode, selected extensions, then user `:xform`. Preserve stats and ownership.
  Structured extension diagnostics remain P04 work.

P03 remains in-progress until review and merge; no release or merge is authorized.

Implementation and offline regression evidence:

- Added construction-time vector/function validation and full-decode restriction
  to the shared core path; explicit selection bypasses the registry. Added the
  `apply!` arity to share eligibility and failure isolation, with no new stats.
  Published existing DNS/TLS functions and kept registration using those functions.
- `bash dev/script/codex.sh test -n` passed for `paclo.decode-ext-test`
  (6 tests / 22 assertions), `paclo.packet-xf-test` (8 / 17),
  `paclo.dns-ext-test` (8 / 18), `paclo.tls-ext-test` (11 / 20).
  Final `paclo.explicit-extensions-test` passed 10 tests / 134 assertions,
  including 100 generated ordered-composition/failure/determinism cases.
- DNS and TLS real PCAPs agree across direct `packet-xf`, lazy `packets`,
  synchronous reduction, reduction report, and managed capture. Tests compare
  all nested byte-array contents and decoded data, capture timestamps/lengths,
  ordering before user transforms, annotations and EOF/reduced report behavior.
  Concurrent fan-out uses finite input, capacity-one blocking branches and a
  promise to coordinate consumers with registration changes; no sleeps. It
  verifies different DNS/TLS selections, no global hook calls and unchanged bytes.
- Corrected an existing DNS hook test's cleanup key to the actual DNS namespace
  so its registration does not leak into subsequent compatibility tests.
- `bash dev/script/codex.sh check` passed: JUnit 8 tests, Clojure 297 tests /
  1348 assertions, zero failures/errors, offline native smoke. The final focused
  test run additionally covers the last reduced-report regression added afterward.
- `python3 dev/script/verify_doc_links.py` passed.
  `python3 -m unittest discover -s dev/script -p 'test_verify_doc_examples.py'`
  passed all 13 parser tests. `python3 dev/script/verify_doc_examples.py` passed
  all 12 real-PCAP examples: the original nine plus three P03 examples. Added
  the P02 ID to the mandatory preservation set and preloaded the DNS/TLS aliases
  alongside existing core/stream aliases for compiled expression checks.
- Initial focused lint found the generated property-test symbol needed the same
  declaration used by existing `defspec` tests; fixed without weakening checks.
  Initial document execution exposed missing preloaded aliases; fixed and reran
  every example. Corrected one new local anchor and one Markdown line length.
- Direct Markdown lint passed all 27 documents after fixes. Sandboxed npm
  access initially failed resolving registry.npmjs.org (and offline cache mode
  was incomplete); the authorized network-enabled run succeeded. Final complete
  `bash dev/script/codex.sh lint` passed: kondo zero errors/warnings,
  Eastwood 60 warnings / zero exceptions, and no namespace/format changes. Local tools are clj-kondo 2026.05.25 and
  clojure-lsp 2026.05.05-12.58.26; CI uses its unchanged pinned 2025 versions.

Performance evidence (offline only):

- `bash dev/script/codex.sh perf` passed: 50,000 packets / 74-byte frames,
  560.8 ms versus unchanged 1000 ms warning / 1200 ms failure budgets.
- Used existing `perf-data/ensure-dataset!` with `perf-spec/traffic-cases` to
  generate identical 50,000-packet UDP-64, TCP-512 and mixed PCAPs. For each
  case, ran `clojure -M:perf-worker --mode offline --scenario <full-decode|full-reduce>
  --path /private/tmp/paclo-p03-<case>.pcap --count 50000 --warmups 1 --runs 3`
  serially before runtime edits and after, without concurrent checks. Baseline
  is `c13916b`; revised measurements are the uncommitted P03 implementation.
  Initial attempts used unsupported offline `--scenarios` and the wrong
  traffic-case namespace; these failed and were corrected before measurement.
- Same macOS 15.4.1 x86_64 host, Temurin JDK 21.0.12.1, Clojure 1.12.1,
  libpcap 1.10.1, one warm-up and three measured runs per separate worker JVM.
  Every revised run processed 50,000 packets with zero decode errors. Lazy
  captures used default blocking queues; the worker reports no queue-drop
  counters for offline runs. Reducers have no producer queue.

| Case / scenario | Before pps | After pps | Change | Before alloc B/packet | After alloc B/packet | Change |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| mixed-full-decode | 141288.3 | 128389.0 | -9.1% | 5966.4 | 5974.2 | +0.1% |
| mixed-full-reduce | 160967.9 | 149250.1 | -7.3% | 5692.6 | 5861.3 | +3.0% |
| tcp-512-full-decode | 101681.8 | 105438.0 | +3.7% | 7240.5 | 7335.1 | +1.3% |
| tcp-512-full-reduce | 113240.1 | 108326.4 | -4.3% | 6966.3 | 7137.7 | +2.5% |
| udp-64-full-decode | 112314.3 | 133004.2 | +18.4% | 4761.1 | 4728.1 | -0.7% |
| udp-64-full-reduce | 169015.6 | 154807.9 | -8.4% | 4571.7 | 4658.1 | +1.9% |

These short runs show noisy throughput (-9.1% to +18.4%) and median allocation
changes of -0.7% to +3.0%; they do not establish a stable speedup or regression,
nor live/real-NIC throughput. Reports remain in `/private/tmp/paclo-p03-baseline`
and `/private/tmp/paclo-p03-revised`; packaging will not remove them.

Packaging and delivery preparation:

- After all tests, lint and performance workers exited, ran
  `bash dev/script/codex.sh package`: passed (unchanged snapshot version).
  `jar tf target/paclo-1.3.0-SNAPSHOT.jar` confirmed core, decode-ext, DNS and TLS
  namespaces. No packaging or tests ran concurrently.
- Created `/private/tmp/paclo-p03-consumer/deps.edn` with empty `:paths` and only
  the local JAR dependency; ran `clojure -Srepro -M check.clj` there. Passed
  `:p03-clean-jar-consumer-ok`, requiring both public annotation functions,
  verifying their resources load from `jar:file:` URLs, and checking actual
  DNS/TLS PCAP annotations through explicit synchronous reductions. No DNS
  source path or development alias was supplied to the consumer.
- `git diff --check` and local Markdown links passed after final edits.
- Implementation commit uses the repository hook's documented `SKIP_TESTS=1`,
  `SKIP_FMT=1`, `SKIP_KONDO=1` flags because those checks already passed above;
  the hook's Markdown lint remains enabled for the final log/doc changes.
- Existing workflow jobs and quality thresholds are unchanged. GitHub main has
  no branch-protection status configuration (API returned HTTP 404); the existing
  CI `build` aggregate and platform jobs remain the verification target.
- CI and PR URL will be recorded after creation. Independent review, live capture,
  real-NIC throughput and other unlisted platforms remain unverified. P03 stays
  in-progress pending review/merge; P04 remains blocked and is the next feature
  after acceptance. No merge, tag, version update, release or artifact publication.

PR and CI evidence:

- Implementation commit: `57b299822d21f7165f105f1ddc45fb2884237841`.
  Branch: `codex/p03-explicit-extensions`, pushed to origin.
  Created [PR #30](https://github.com/nantes-rfli/paclo/pull/30) against main
  with the final API/design, backward compatibility, annotations, independence,
  execution-model/fan-out checks, failure policy, performance and limitations.
- [Implementation CI run 38207019415](https://github.com/nantes-rfli/paclo/actions/runs/38207019415):
  **all 12 jobs passed**. `build-checks`, `documentation-checks`, three performance
  shards, `performance-results`, both `compatibility-matrix` jobs and the `build`
  aggregate passed. Separate `arm64-monitor`, `eastwood-lint` and optional
  `coverage` also passed. CI includes unchanged SpotBugs, CheckStyle, JaCoCo
  threshold, pinned lint tools, cljdoc namespace load and performance checks.
- Downloaded both compatibility job logs with `gh run view --job ... --log`:
  Linux x64/JDK21 and macOS ARM64/JDK17 each ran the final **298 tests /
  1353 assertions**, zero failures/errors, including P03's added namespace.
  Linux ARM64/JDK21 monitor also completed successfully. No workflow or quality
  gate changes were made to obtain these results.
- `gh pr view 30` confirms OPEN, no reviews and clean merge state. This confirms
  review readiness, not independent review or acceptance. Do not mark P03 done
  before review/merge; P04 remains blocked. Live capture and real-NIC performance
  remain unverified.
- This follow-up commit changes only the accepted plan and verification log.
  Its checks are tracked in PR #30; the completed implementation-run results
  above refer specifically to `57b2998`, not to an untested later SHA.

## P04 — design and baseline (2026-10-12)

- Clean supplied checkout; doctor passed on macOS x86_64 / Temurin 21.
  Fetched main and started `codex/p04-data-diagnostics` at `e778895`.
  GitHub confirms PR #30 merged at 2026-10-12 05:26:12 UTC; its final
  [CI run 38207387923](https://github.com/nantes-rfli/paclo/actions/runs/38207387923)
  passed all 12 jobs, including Linux x64, macOS ARM64 and Linux ARM64.
  Historical P03 evidence above is retained. P04 remains in-progress until merge.
- Canonical raw/full/flow contracts live in docs/cljdoc-api-contract.md.
  Capture metadata remains unchanged; flow includes present nil metadata fields
  and omits bytes/decoded. Published arrays remain mutable shared references.
- Add top-level `:diagnostics`, a vector of EDN maps, only on observed issues.
  Required stable keywords: `:stage` (:decode, :flow, :extension) and `:reason`
  (:short-frame, :truncated-header, :malformed-packet, :unsupported-ethertype,
  :extension-exception, :extension-non-map, :unexpected-failure).
  Locations use absolute frame byte offsets and required/available byte counts;
  omit location where unavailable. Unknown failures are unexpected-failure.
- Parser checks classify at the source, preserving legacy message text and decoded
  values. Internal map metadata carries nonfatal parser diagnostics to the facade;
  no diagnostic vector is allocated on normal success. Unknown L4 protocol alone
  is a best-effort unknown-l4 value, not a formal failure; unknown Ethernet input
  is unsupported, and known incomplete headers are truncated.
- Opt-in `:extension-error-mode :report` appends failures with zero-based execution
  index for explicit and global hooks. Default ignore retains prior outputs.
  Keep apply!'s one/two argument calls and share its hook runner with a third
  policy arity (nil extension selection means current global registry in that
  arity only). No registry keys or arbitrary exception data enter diagnostics.
  Reporting never adopts failed results and subsequent hooks still execute.
- Capture `:error-mode` is independent. Reject policy options without literal
  `:decode? true` and invalid modes before source acquisition.
- Statistics schema v1 and decode-error counters are unchanged. Diagnostics are
  packet data; reducers may accumulate them. EDN compatibility applies to
  diagnostics, not byte arrays in whole packets. No new dependency/schema validator,
  buffer copying, per-packet stack traces or link-type support is introduced.

P04 implementation and verification:

- Added classifications at header checks and the existing flow exceptions, without
  regex/message parsing. Partial UDP/VLAN/IPv6 data retains its previous shape;
  internal parser metadata carries nonfatal findings to top-level packet diagnostics.
  Errors with no established classification use unexpected-failure.
- Kept the normal extension path's vector reduction after initial measurements
  exposed an avoidable sequence allocation; report mode alone tracks indices.
  Shared apply-hook isolates both modes. Added primitive hints on header guards
  and advances to avoid boxing/reflection introduced by classification helpers.
- Added `paclo.diagnostics-test`: real DNS/TLS/metadata PCAPs and a temporary
  real PCAP containing IPv6, short Ethernet/IPv4/IPv6 and unknown Ethernet input
  agree across all five public paths. Tests cover raw types/units/truncation,
  missing/preserved metadata, numeric IPv4/IPv6, missing fragment/non-TCP ports,
  partial UDP/VLAN/IPv6 chains, malformed versions/options, unknown L3/L4,
  unexpected errors, explicit/global hook failures, continuation/order/indices,
  early validation, reducer/xform ordering, shared read-only fan-out arrays,
  unchanged v1 counts and EDN round trips. Two properties run 200 random framed
  inputs and 100 extension compositions. No timing sleeps or new dependencies.
- Focused command covering all four requested namespaces plus diagnostics:
  `bash dev/script/codex.sh test -n paclo.packet-xf-test -n paclo.flow-test
  -n paclo.decode-ext-test -n paclo.decode-ext-prop-test -n paclo.diagnostics-test`
  passed 35 tests / 327 assertions after type-hint cleanup. Diagnostics alone
  passed 11 tests / 266 assertions. Final delivery checks follow below.
- The existing flow-error equality test now includes the additive diagnostic;
  every original metadata field and the exact `bad flow` error string is retained.
- Compared against the P03 parser from a temporary `git archive e778895` source
  snapshot, using 1,000 seeded arbitrary inputs and 258 UDP/TCP prefix lengths.
  All 1,258 pre-existing results and error strings match after removing the new
  diagnostics. This is additional local characterization, not a new source backend.
- Canonical contract is in docs/cljdoc-api-contract.md; usage/extensions link
  there. Updated relevant public docstrings and Unreleased changelog. Added a
  reducer diagnostic example and protected all 12 P03 documentation IDs in the
  verifier's required set. All 13 executable examples pass. Local Markdown links,
  13 Python verifier parser tests and Markdown lint (27 documents) pass.
- Initial checks found a parenthesis error, expected additive test data, nested
  array/sequence comparison mistakes in new tests, redundant lets and a missing
  preloaded EDN alias for compiled documentation expressions. Fixed these and
  reran checks; no gate/threshold was weakened. Final lint after type hints has
  zero kondo warnings/errors; Eastwood has the pre-existing 60 warnings and zero
  exceptions; clean-ns/format report no changes. Local lint tools are newer than
  CI's unchanged pinned versions, as documented for P03.
- The complete check before the allocation cleanup passed JUnit 8 tests and
  Clojure 309 tests / 1,619 assertions, plus offline native smoke. Final checks
  validate the allocation cleanup as well. No Java/native boundary, dependency,
  workflow, release version, tag or publication changed.
- Follow-up allocation characterization in one JVM (50 warm-ups / five runs)
  found equal parser and facade allocation in P03/P04 for successful UDP input.
  Separate-JVM microbench allocation differences therefore include JIT/context
  effects; they do not demonstrate allocation of diagnostic data on success.
  Simplified the facade into explicit success/failure branches to avoid testing
  each failure condition on normal success. Focused P03/P04 regressions after
  this adjustment passed 45 tests / 461 assertions, and kondo remains clean.
  Final performance and complete-check results below refer to this adjustment.

P04 final performance (offline only):

- Final `bash dev/script/codex.sh perf` passed: 50,000 / 74-byte frames,
  479.4 ms against unchanged 1,000 ms warning / 1,200 ms failure budgets.
  Earlier passing runs were 518.0 and 508.9 ms.
- Same macOS 15.4.1 x86_64 host, Temurin 21.0.12.1, Clojure 1.12.1,
  libpcap 1.10.1. Baseline is P03 merge `e778895`, loaded from a temporary
  source archive (not a worktree); revised is this uncommitted P04 source.
  JVM metadata reports HEAD e778895 for both because measurements precede commit.
- Existing perf-worker scenarios: identical 50,000-packet mixed UDP-64/TCP-512
  PCAP, two warm-ups and five measured runs per separate JVM, serial execution
  without concurrent tests/lint. Commands use `clojure -Sdeps <source-paths>
  -M:perf-worker --mode offline --scenario <scenario> --path /private/tmp/p04-mixed.pcap
  --count 50000 --warmups 2 --runs 5`. Every run processed all packets with zero
  decode errors. Lazy full decode uses the default blocking queue; offline workers
  do not expose queue-drop counters. Reducers have no producer queue.

| Scenario | Before pps | After pps | Change | Before alloc B/packet | After alloc B/packet | Change |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| raw-reduce | 954576.6 | 995596.6 | +4.3% | 1019.6 | 1018.1 | -0.2% |
| full-decode | 125163.9 | 165450.4 | +32.2% | 5899.3 | 6115.1 | +3.7% |
| full-reduce | 173512.2 | 186717.4 | +7.6% | 5919.7 | 5918.1 | -0.0% |
| flow-project | 610429.1 | 523583.1 | -14.2% | 1499.6 | 1498.1 | -0.1% |

- Separate pure transformation/extension comparison: 10,000 ordinary UDP-64
  packet maps, 20 warm-ups / 10 measured reductions per mode. Median pps:
  raw 13,058,231 -> 27,600,369; full 356,528 -> 358,965;
  flow 3,159,960 -> 3,459,143; one identity extension in ignore mode
  346,796 -> 360,269. Normal full/extension allocation was 3,519.7 -> 3,687.7
  B/packet in these separate JVMs; raw/flow allocation was unchanged at
  23.7 / 367.7 B/packet. Report success was 3,727.7 B/packet (40 B over ignore)
  due to indexed traversal; it allocates no diagnostic vector on success.
  P03 ignores the previously unknown report option, so only P04's reporting
  behavior is meaningful for that extra mode. No packet bytes are copied.
- Earlier short pure runs produced differing allocation/throughput values;
  one same-JVM comparison with 50 warm-ups showed identical old/new allocation
  for both parse and facade. Existing-worker repeats also varied: flow was
  initially -0.2% and then -14.2%; full decode varied +8.0% to +32.2%.
  These observations do not establish a stable speedup/regression; the flow
  difference warrants longer isolated profiling if it persists in future runs.
  The existing gate passes and all thresholds are unchanged. These are local
  offline observations, not live capture or real-NIC performance validation.
- Reports/scripts remain under `/private/tmp/p04-performance*`, with supporting
  characterization in `/private/tmp/p04-alloc.edn` and `/private/tmp/p04-compat.clj`.
  The default vector-reduction adjustment removed avoidable sequence iteration;
  the final full-decode branch change reduced repeated success-path conditions.

Final delivery checks after the success-path adjustment:

- `bash dev/script/codex.sh check`: passed JUnit 8 tests, Clojure 309 tests /
  1,619 assertions, zero failures/errors, and offline native smoke.
- `bash dev/script/codex.sh lint`: passed kondo zero warnings/errors, Eastwood
  60 existing warnings / zero exceptions, clean-ns/format no changes and Markdown
  lint. `python3 dev/script/verify_doc_links.py`, all 13 executable documentation
  examples, 13 Python verifier parser tests and `git diff --check` passed.
- Commit reuses these completed checks through the hook's documented SKIP_TESTS,
  SKIP_FMT and SKIP_KONDO flags; Markdown lint remains enabled. CI/PR evidence
  is recorded after creation. Review, live capture, real-NIC throughput and other
  unlisted platforms remain unverified. No merge or release action is authorized.

PR delivery:

- Implementation commit `df782ac4337e895fba2b75da97bad52285f0a877`, branch
  `codex/p04-data-diagnostics`, based on latest fetched main / P03 merge e778895.
  Created [PR #31](https://github.com/nantes-rfli/paclo/pull/31) against main and
  attached it to this chat. No merge or release action was performed.
- Re-executed `python3 dev/script/verify_doc_examples.py` at the implementation
  commit: all 13 examples passed, including all 12 P03 examples. Working tree
  was clean immediately after the implementation commit/PR creation.

- [Implementation CI run 38210310136](https://github.com/nantes-rfli/paclo/actions/runs/38210310136)
  at df782ac: all 12 jobs passed, including Linux x64/JDK21, macOS ARM64/JDK17,
  Linux ARM64/JDK21 monitor, build-checks, documentation-checks, three performance
  shards/results, build aggregate, Eastwood and coverage. Existing Java quality,
  pinned lint, namespace-load and performance gates were not changed.
- P04 remains in-progress pending independent review and merge; P05 remains
  blocked and is the next feature after acceptance. This follow-up commit records
  evidence and the PR link only; its own CI is tracked in PR #31, distinct from
  the tested implementation SHA above. No live capture/real-NIC claim is made.

- Downloaded the three supported-platform job logs: each actually ran 309 tests /
  1,619 assertions with zero failures/errors. Build-checks also ran SpotBugs,
  CheckStyle and JaCoCo; the unchanged Java line coverage gate passed at 41.1%
  against the existing 25% threshold. Initial evidence commit Markdown lint
  found one overlong plan line; wrapped it and reran the hook before delivery.

Final contract-test audit:

- Added one explicit successful TCP-port assertion group for full decode and flow
  (`12000 -> 443`), complementing UDP, fragment, truncated transport and real TLS
  path comparisons. `bash dev/script/codex.sh test -n paclo.diagnostics-test`
  passes 12 tests / 270 assertions, including all 300 property cases. Focused
  kondo and format checks pass. This final test-only addition changes no runtime
  or performance code; the complete final CI is tracked in PR #31.

## P05 — design and baseline (2026-10-12)

- Clean supplied checkout; preserved `codex/p04-data-diagnostics`. PR #31 merged
  at `17d8bf1` on 2026-10-12; P05 branch starts at that latest main.
- Public `:linktype` is the nonnegative integer DLT returned by
  `pcap_datalink`, not a copied savefile LINKTYPE. No per-packet native lookup,
  name conversion, byte mutation, extra byte copy or mandatory dependency.
- Acquire once per capture execution after live activation/open and before
  `on-ready`; pass the value explicitly to the shared native packet constructor
  and polling loop. Low-level standalone loops acquire once per invocation.
  No global handle cache or cross-source state. Raw packets, stop predicates,
  user transforms and managed/fan-out consumers receive the same metadata.
- Full decode rejects explicit values other than integer DLT_EN10MB (1) before
  checking frame length. Preserve bytes/metadata and append diagnostic
  `{:stage :decode :reason :unsupported-linktype :linktype value}`; remove
  stale `:decoded`. Flow uses stage `:flow`, retains capture metadata/linktype,
  and excludes bytes and flow fields on failure. Neither executes extensions.
  Missing `:linktype` in standalone packet-xf retains legacy Ethernet behavior;
  explicit nil/invalid/unknown values are rejected. Raw identity is unchanged.
- Statistics remain schema-version 1 with no new fields. Unsupported full/flow
  errors count in existing decode-errors. Diagnostics keep P04 location semantics.
- Negative native results throw ex-info (`:phase :pcap-datalink`, rc/error data);
  native exceptions propagate. Capture owners close on setup failure; synchronous
  and managed setup fail before readiness, legacy async errors use its existing
  background error policy. No guessing Ethernet on native failure.
- Writer remains Ethernet-only. Metadata is not format conversion or full-file
  preservation; broader decoders, PCAPNG and interface metadata remain P08.

P05 implementation and local verification:

- Added `PcapLibrary.pcap_datalink` and internal `pcap/datalink`. Shared packet
  construction retains bytes, timestamps and both lengths and adds the native
  DLT. Each public capture execution acquires once before readiness and passes
  it into polling, including the no-idle path. No global handle cache is used.
- Full and flow share explicit Ethernet eligibility. Missing metadata retains
  standalone compatibility; invalid/unknown presence is rejected before any
  frame parsing. Full rejects stale decoded values and skips global/explicit
  hooks in both failure modes. Flow retains five metadata fields, including
  nil linktype when absent, and never adds bogus IP/port fields on failure.
- Added deterministic SLL/NULL PCAPs plus their Python generator. Each contains
  a proper IPv4/UDP record, a two-byte truncation with original length 1500,
  and an adversarial record that would successfully parse as Ethernet if the
  guard were absent. Existing Ethernet DNS/TLS/IPv4/IPv6/VLAN regressions remain.
- New `paclo.linktype-test` covers all five public processing paths, native DLT,
  ordered bytes/time/length metadata, stop/xform inputs, error counts in stats
  v1, raw/full/flow fan-out with capacity-one blocking branches, diagnostic
  append order, and skipped hooks. Native doubles cover live/offline failures,
  exception identity, deterministic close, readiness/activation ordering and
  once-per-capture acquisition. New JUnit tests exercise real offline DLTs and
  the negative result of a real unactivated handle, closing without activation.
- 150 property cases prove unsupported dispatch, stable stage/reason, EDN
  round trips, metadata preservation and unchanged shared byte-array contents.
  New concurrent tests use futures/promises and bounded waits, without sleeps.
- Public contract, usage, README, extension guidance, changelog and relevant
  docstrings now specify DLT versus LINKTYPE, missing versus explicit values,
  raw access, unsupported dispatch and the unchanged Ethernet-only writer.
  A registered executable SLL example extends the maintained 13 examples to 14.
- Measured allocation adjustment: adding an eleventh flow-map entry crossed
  the 20-argument call boundary of `array-map`. Initial flow-project allocation
  rose from 1498.1 to 2274.1 bytes/packet; a focused map-construction experiment
  measured about 226 versus 994 bytes/construction for ten/eleven entries.
  A small private macro emits a typed Object[] and PersistentArrayMap for
  compile-time-known unique keys. Storage is private during construction and
  never mutated after publishing the immutable map. No public mutable aggregate,
  borrowed buffer, framework or parser redesign is introduced. Final flow
  allocation is 1418.9 bytes/packet; the ordinary byte-only flow path is unchanged.

Local environment: macOS 15.4.1, reported x86_64, Temurin 21.0.12.1,
Clojure library 1.12.1, CLI 1.12.5.1654, libpcap 1.10.1.

- `bash dev/script/codex.sh doctor`: passed, real offline read (four packets).
- `bash dev/script/codex.sh prepare`: passed after native binding/test changes.
- Focused `test` invocation selecting `paclo.pcap-unit-test`, `packet-xf-test`,
  `flow-test`, `diagnostics-test`, `linktype-test`, `pcap-loop-test`,
  `managed-capture-test` and `reduce-test`: passed 124 tests / 1128 assertions
  before the final additional setup/order coverage. All requested namespace
  names exist; no namespace substitutions were needed.
- After the allocation adjustment, focused `flow-test`, `linktype-test` and
  `packet-xf-test`: passed 26 tests / 669 assertions.
- Final `bash dev/script/codex.sh check`: passed JUnit 10/10, Clojure 321 tests /
  2256 assertions with no failures/errors, and offline smoke.
- Final `bash dev/script/codex.sh lint`: passed kondo (zero warnings/errors),
  Eastwood (60 existing warning sites, no exceptions), clean-ns and format
  dry runs, and Markdown lint. New test deprecation/boxing warnings were fixed.
- `clojure -T:build spotbugs`, `checkstyle`, `jacoco`, `jacoco-gate`: passed.
  JaCoCo line coverage 43.8%, with unchanged CI threshold `JACOCO_MIN_LINE=0.25`.
- Final `bash dev/script/codex.sh perf`: passed, 50,000 / 74-byte synthetic frames,
  493.3 ms against unchanged 1000 ms warning / 1200 ms failure budgets.
- `dev/script/mdlint.sh`: passed through the final lint command. Initial sandbox
  npm DNS/cache access failed; the authorized ordinary-environment retry worked.
  Two added double blank lines were fixed before the final successful check.
- `python3 dev/script/verify_doc_links.py`: passed.
- `python3 -m unittest discover -s dev/script -p test_verify_doc_examples.py`:
  passed 13 parser tests. `python3 dev/script/verify_doc_examples.py`: passed all
  14 offline examples, preserving the previous 13.
- `git diff --check`: passed. CI workflows, dependency graph, release versions,
  pinned tools, coverage threshold and performance budgets are unchanged.

P05 offline performance characterization:

Baseline is main `17d8bf1`, from `/private/tmp/p05-baseline` source archive and
baseline compiled classes (not a new worktree). Revised is uncommitted P05 source;
worker git metadata is nil for the archive and baseline HEAD for the revised
checkout, so these source labels, rather than embedded git metadata, identify
what was measured. Dataset is the same `/private/tmp/p05-mixed.pcap`: 50,000
alternating UDP-64/TCP-512 Ethernet records, 14,400,000 captured bytes.

Existing perf-worker commands use `clojure -M:perf-worker --mode offline
--scenario <scenario> --path /private/tmp/p05-mixed.pcap --count 50000
--warmups 2 --runs 5`, in each source directory. Separate JVMs run serially,
with scenario order raw-reduce, full-decode, full-reduce, flow-project for baseline
and then for final revised source; no concurrent tests/lint during these runs.
The runner performs its existing GC/25 ms settling step before each measured run.
Every measured run processed all 50,000 records with zero decode errors.
Reduction modes have no producer queue; lazy full decode uses the default
blocking queue. Offline workers do not expose queue-drop counters.

| Scenario | Before pps | After pps | Change | Before alloc B/packet | After alloc B/packet |
| --- | ---: | ---: | ---: | ---: | ---: |
| raw-reduce | 1223967.8 | 1101714.0 | -10.0% | 1018.1 | 1026.9 |
| full-decode | 134086.0 | 149351.4 | +11.4% | 6055.0 | 5930.7 |
| full-reduce | 161789.3 | 188506.9 | +16.5% | 5778.1 | 5702.9 |
| flow-project | 592963.4 | 676697.4 | +14.1% | 1498.1 | 1418.9 |

These short runs characterize allocation and show substantial JVM/timing
variation; they do not prove throughput gains or regressions. Raw allocation
increased by about 8.8 bytes/packet. No packet byte copies were added. Reports
and the constructor experiment remain under `/private/tmp/p05-*`.
Live NIC values, privileges, sustained live capture and real-NIC performance
remain unvalidated. Supported-platform CI must be assessed on the PR; P05
remains in-progress until independent review/merge, P06 is ready, and P08 remains
blocked until P05 acceptance and a concrete decoder/PCAPNG fixture-backed scope.

The first commit attempt stopped because the local pre-commit hook invokes
`clj`, which requires missing `rlwrap` on this host. All equivalent checks above
ran with `clojure`. The commit reuses their successful results through the
repository hook's existing `SKIP_TESTS`, `SKIP_FMT` and `SKIP_KONDO` flags;
Markdown lint remains enabled. No hook or gate is changed.

P05 PR and CI follow-up:

- Created [PR #32](https://github.com/nantes-rfli/paclo/pull/32) from implementation
  `99c60ee`, attached to this chat. No merge/release action was performed.
- [Initial CI run 38220256645](https://github.com/nantes-rfli/paclo/actions/runs/38220256645)
  passed both compatibility jobs (Linux x64/JDK21 and macOS ARM64/JDK17), Linux
  ARM64/JDK21 monitor, documentation, all three performance shards and their
  merger, Eastwood and coverage. Build-checks passed Java compilation, JUnit,
  offline smoke, SpotBugs, CheckStyle, JaCoCo (43.8%, threshold 25%) and the
  performance gate (724.1 ms), then failed clean-ns on the compact single require
  in `paclo.flow`; build aggregate consequently failed. This is not a passing
  overall run. No native/platform test failed.
- Local clojure-lsp was 2026.05.05-12.58.26; CI uses 2025.11.28-12.47.43. Expanded
  the require to the repository's multiline form. This changes whitespace only.
  Retained CI's pinned tool/version and downloaded its official macOS x64 binary
  into `/private/tmp/p05-tools`, verifying the published SHA-256 before execution.
  Final fixed-version checks and final PR CI evidence follow below.
- `/private/tmp/p05-tools/pinned-lsp/clojure-lsp clean-ns --dry` and `format --dry`
  both passed for the whole project, with no proposed changes. The installed
  local version's focused dry runs also passed after the whitespace adjustment.
- Final implementation head `e611d9a`:
  [CI run 38220870309](https://github.com/nantes-rfli/paclo/actions/runs/38220870309)
  **passed all 12 jobs**. Both Linux x64/JDK21 and macOS ARM64/JDK17 compatibility
  jobs, Linux ARM64/JDK21 monitor, build-checks, documentation-checks, all three
  performance shards, performance-results, Eastwood, coverage and build aggregate
  succeeded. This includes the existing Java/native, pinned lint, documentation,
  performance and coverage gates. No failing/skipped job remains on this run.
- This follow-up records evidence only; no behavior, tests, gates, dependency or
  version changes. PR #32 remains open/unmerged. P05 stays in-progress pending
  independent review/merge; P06 remains ready and P08 remains blocked. Live NIC
  and sustained real-NIC validation are still outside this offline evidence.

## P06 — design and baseline (2026-10-12)

- Clean supplied checkout; doctor passed real offline capture. Fetched latest
  main `7711170` (P05 PR #32 merged), created `codex/p06-flow-analysis`.
- `core` previously required the internal `paclo.flow` projection. Move it to
  responsibility-named `paclo.flow.project`; analysis introduces no decode cost
  into raw/full/flow paths. Structural move is commit `cfb6ff2`.
- Canonical identity is a six-field numeric map including IP version/protocol.
  Bidir compares unsigned IP words, then ports (nil before zero). Validation
  skips missing/invalid numeric fields, absent port keys and flow decode errors.
- Full decode's string-address `:flow-key` remains a legacy display descriptor:
  it never normalizes direction. `parse/make-flow-key` only assembles that
  descriptor, so it is not a second canonical identity algorithm. Keeping it
  avoids breaking v1 data contracts or adding conversions/computation to full
  decoding. Applications needing canonical identity select flow projection.
- Three public functions: key, aggregate-rf, top-n. Reducer state is persistent
  data with input summary separate from flow counts and configuration. Require
  explicit positive cardinality bound, throw on new-key overflow, retain
  existing-key updates; use promoting integer arithmetic for exact counters.
  Eligible packets require valid captured/wire lengths; invalid flows skip.
- CLI retains legacy protocol/IP display and bytes=captured-bytes. Analysis
  moves entirely to the library. CLI bound defaults to 100000 flows, configurable
  with --max-flows; this practical application budget is not a library default.
- P07 can reuse canonical identity, immutable reducer data and exact ranking.
  Event time, expiration, windows and DNS correlation remain outside P06.

P06 implementation and measurement:

- Public analysis is pure, with three functions and ordinary persistent maps.
  Internal projection and all core hot paths retain their prior computation.
  Legacy full decode remains a display descriptor; only the public numeric
  analysis API determines canonical identity and direction. No v1 full-decode
  schema is removed, no version is updated, and no artifacts are published.
- CLI removes its canonicalization, Java HashMap/long-array counters and ranking.
  Display rows and packets/bytes metrics remain, with bytes=captured. Added finite
  --max-flows 100000 default and override; ties now follow numeric canonical order.
  Split optional positional arguments before flags, so documented short async
  invocations work. Underscore mode/metric placeholders now follow usage defaults.
- Async uses a fixed buffer plus offer! for dropping, reporting every dropped
  packet. Timeout returns reduced to stop reading; reader errors propagate.
  An aggregate exception initially revealed a blocked producer: core.async close
  does not release every pending buffered put. A separate stop channel now
  participates in alts!!, releasing that producer before joining it. Full/focused
  runs that stalled before this fix were terminated and do not count as passes.
  Regression coverage includes capacity-one limit failures, reader failures,
  deterministic drop counts and zero-timeout cancellation.
- Public API tests cover IPv4/IPv6 signed words, unknown protocols, absent/nil
  ports, fragments, reversal, invalid data, lengths, integer promotion, bounds,
  deterministic Top-N, EDN and preserved snapshots. 650 property cases cover
  reversal/idempotence, key collision identity, input-order independence and
  exact totals. Real DNS/SLL PCAPs, a real truncated wire-length record, managed
  capture, and capacity-one fan-out reuse the same reducer. Existing projection
  tests moved to paclo.flow-project-test; packet-xf tests target the moved decoder.
- API contract, README, usage, changelog and docstrings explain identity versus
  display, lengths, skipped inputs, bounds, ordering and migration. Two new
  executable examples retain all previous 14, giving 16 examples.

Reproducible aggregation comparison:

`clojure -M:dev -m paclo.dev.flow-perf 7711170` loads the actual historical
CLI add-packet! from git only inside the opt-in development benchmark; the
application/library contain no duplicate analysis implementation. Baseline is
latest main 7711170; revised is the P06 source after direct persistent-map
updates, before the implementation commit. macOS 15.4.1, reported x86_64,
Temurin 21.0.12.1, Clojure 1.12.1. Synthetic numeric IPv4/UDP projected input:
100000 packets, caplen 64/wire 84, 10 or 10000 unique flows. Three warmups and
five timed runs per scenario; median throughput and ThreadMXBean current-thread
allocated bytes. All runs are serial, with no concurrent tests/lint/benchmarks.
No queue/native capture is involved; drops are zero. Measures aggregation only,
excluding decode, formatting and sorting; native/CLI end-to-end rates are not
established by this experiment.

| Flows | Direction | Old pps | New pps | Old alloc B/packet | New alloc B/packet | Old retained B/flow | New retained B/flow |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 10 | unidir | 2012191 | 531108 | 457.7 | 2054.1 | 144.4 | 192.7 |
| 10 | bidir | 1949116 | 588583 | 697.7 | 2054.1 | 165.5 | 192.6 |
| 10000 | unidir | 2140945 | 467839 | 437.7 | 2330.6 | 158.0 | 191.4 |
| 10000 | bidir | 1835399 | 461215 | 677.7 | 2331.6 | 158.5 | 190.3 |

Persistent aggregation is materially slower and allocates more than the old
mutable unchecked two-counter CLI. It adds validation, wire-byte totals, summary,
exact promoting counters, immutable snapshots and cardinality checks. No analysis
throughput target was defined; retain the simple persistent reference rather than
introducing hidden mutable ownership. Future optimization must retain this
contract. Replacing three nested update-in/assoc-in operations with direct map
updates cut allocation from 2614.1 to 2054.1 B/packet at 10 flows, and from
2855.0 to 2330.6 at 10000 flows (initial sample: 439109/389380 unidir pps).

Retained heap is a GC-based estimate, not an object-size profiler or memory cap:
retain 100000 total flow entries across independent results, with one packet/key,
and keep input data reachable across both GC snapshots. The first experiment
retained only 100 low-cardinality entries and produced negative/noisy deltas;
those low-cardinality values were rejected and amplification added. Final
estimates are positive but vary with GC/JIT and sharing. They exclude input
storage and temporary per-update allocations; full peak CLI memory is unmeasured.
Raw reports remain in /private/tmp/p06-flow-perf*.edn; the maintained runner and
this table preserve the method and results. Live capture/real NIC and other
platforms remain separate from these local measurements.

P06 final local verification (after the persistent-map update):

- `bash dev/script/codex.sh test -n paclo.flow-test -n paclo.flow-project-test
  -n examples.flow-topn-test -n examples.cli-contract-test
  -n examples.smoke-test`: passed 56 tests / 212 assertions; all 650 generated
  property cases passed. CLI snapshots and sync/async EDN/JSONL remain covered.
- `bash dev/script/codex.sh check`: passed JUnit 10/10, Clojure 334 tests /
  2354 assertions and real offline smoke (four packets). Waited for process exit.
- `PATH=/private/tmp/p05-tools/pinned-lsp:$PATH bash dev/script/codex.sh lint`:
  passed kondo (zero errors/warnings), Eastwood (82 warning sites, zero exceptions),
  clean-ns/format dry runs and Markdown lint. Explicitly verified lsp version
  2025.11.28-12.47.43, matching CI. Boxed arithmetic warnings are expected for
  validated arbitrary integer counters. New resource-close reflection warnings
  and the CLI primitive recur warning were fixed. Initial sandbox npm/cache
  access failed, then the ordinary-environment lint succeeded; two Markdown
  consecutive-blank-line violations were corrected before success.
- `bash dev/script/codex.sh perf`: passed unchanged 50000/74-byte gate in
  633.6 ms against 1000 ms warning / 1200 ms failure budgets. Run after tests,
  lint and doc execution completed. No analysis computations enter core paths.
- `dev/script/mdlint.sh`: passed after the blank-line fixes; final documentation
  append also checked by the pre-commit hook.
- `python3 dev/script/verify_doc_links.py`: passed.
- `python3 -m unittest discover -s dev/script -p test_verify_doc_examples.py`:
  passed 13 parser tests. `python3 dev/script/verify_doc_examples.py`: passed
  all 16 offline examples after the final reducer changes.
- `bash dev/script/codex.sh package`: passed, serially after other checks.
  JAR contains paclo/flow.clj and paclo/flow/project.clj. A clean consumer in
  /private/tmp/p06-consumer with only the local/root JAR dependency required
  paclo.core and paclo.flow, performed native DNS PCAP aggregation, asserted
  canonical identity and Top-N, and printed :jar-consumer-ok with
  {:seen 4 :aggregated 4 :skipped 0}. It has no checkout source/test paths.
- `git diff --check`: passed. No dependencies, CI/performance budgets, versions,
  default packet transformations or native binding behavior changed.
- Commits keep structural projection movement separate from API/CLI behavior.
  Local hook needs unavailable rlwrap via clj; as in P05, use its existing
  SKIP_TESTS/SKIP_FMT/SKIP_KONDO flags after equivalent checks pass with clojure.
  Markdown lint remains enabled. No gate/hook is modified.
- GitHub Actions/platform checks are assessed on the PR. These offline/local
  results do not validate live capture, sustained real-NIC throughput or other
  platforms. P06 stays in-progress until independent review/merge; next feature
  after acceptance is P07.

P06 PR and first CI follow-up:

- Created [PR #33](https://github.com/nantes-rfli/paclo/pull/33) from `e735609`,
  with structural move `cfb6ff2` as its separate first commit. Attached the PR
  to the task; no merge, version update or publication.
- Initial commit+push was rejected by automatic approval review, which believed
  external publication was unauthorized/unverified. Read the attachment's
  section 15 explicit implementation/test/fix/PR-creation instruction and
  verified GitHub reports the requested nantes-rfli/paclo origin as public.
  Local commit and the direct scoped push were then approved; no workaround
  or alternate destination was used.
- [CI run 38234118064](https://github.com/nantes-rfli/paclo/actions/runs/38234118064)
  passed 11/12 jobs: both Linux x64/JDK21 and macOS ARM64/JDK17 compatibility,
  build-checks/aggregate, documentation, three performance shards and merger,
  Eastwood and coverage. ARM64 monitor failed one new zero-timeout assertion.
  The run is not an all-passing validation. Logs show the four-record PCAP
  finished before core.async's asynchronously scheduled timeout(0) notification.
  Other new API/property tests passed there; no native decoder failure occurred.
- Zero timeout now selects an already-closed cancellation channel, so immediate
  cancellation does not depend on timer-thread scheduling. Positive timeout
  behavior remains timer-based. A regression substitutes a throwing timeout
  scheduler, proving the zero branch avoids it and emits no rows with cancellation.
  Follow-up focused/local and platform verification follows; no CI gate is weakened.

- Zero-timeout follow-up: `bash dev/script/codex.sh test
  -n examples.flow-topn-test -n examples.smoke-test` passed 35 tests /
  98 assertions. Focused clj-kondo passed with zero errors/warnings; pinned
  clean-ns/format found no changes; Markdown lint and diff checks passed.
  The analysis/decoder source and JAR consumer are unchanged by this CLI fix.

P06 verified implementation and CI:

- Final implementation head `64b0df6`: local `bash dev/script/codex.sh check`
  passed JUnit 10/10, Clojure 334 tests / 2355 assertions and offline smoke.
  Final Markdown line wrapping was fixed before the successful commit hook.
- [CI run 38234734283](https://github.com/nantes-rfli/paclo/actions/runs/38234734283)
  **passed all 12 jobs** on `64b0df6`: build-checks and aggregate, documentation,
  Linux x64/JDK21 and macOS ARM64/JDK17 compatibility, Linux ARM64/JDK21 monitor,
  three performance shards and merger, Eastwood and coverage. Zero-timeout
  regression passed on every supported/monitored platform. No failing/skipped
  job remains in this run. This verifies offline native/platform behavior and
  the existing gates, not live/real-NIC throughput.
- The final evidence update changes only this log and plan. The PR description
  records implementation CI and the final evidence head's checks after they
  complete; no behavior, dependency, version or gate changes. PR #33 remains
  open for independent review. P06 remains in-progress pending acceptance/merge,
  with P07 the next feature after acceptance.

Final evidence-head documentation runner follow-up:

- On evidence-only head `f72aeab`, documentation CI failed before executing the
  SLL example: one of the first concurrent CLI JVMs could not load clojure.main,
  while all other examples ran successfully. This is an observed setup failure,
  not a passed run or a failing flow/SLL assertion. Other implementation jobs
  remained successful. The local CLI launcher shows shared .cpcache classpath
  files are generated on cold startup and then read; independent first JVMs
  can observe an incomplete file. The two new examples change startup ordering.
- Prepare exactly the documentation alias serially with
  clojure -P -M:dev:dns-ext before launching the unchanged three-worker pool.
  Preparation failure aborts before workers start. No retry swallows an example
  error, and no example/gate is removed. Two runner regressions verify startup
  ordering and preparation-failure propagation; parser/runner tests now total 15.
  Final verification is recorded in the PR description after CI completion.

- After serial preparation, Python parser/runner unit tests passed 15/15 and
  python3 dev/script/verify_doc_examples.py passed all 16 real offline examples.
  Link and diff checks passed; Markdown lint remains enabled in the commit hook.
  This correction changes only documentation test startup, not packet analysis.
  On run 38235117755, the other ten jobs passed; documentation failure also
  caused the dependent build aggregate to fail. Its failure is not hidden by
  the earlier all-passing implementation run.

## P07-A start — 2026-10-12

- Clean supplied checkout at `523cf47`, no unrelated changes. Doctor passed:
  Mac OS X x86_64, Temurin JDK21, Clojure 1.12.1, native offline PCAP 4 packets.
  All optional lint tools available. Read contribution/API/plan/log, core, flow,
  parse, decode-ext, DNS annotation and existing DNS QPS/RTT examples/tests.
- GitHub confirms PR #33 merged at `0665c09` on 2026-10-12. Fetched latest main
  and created `codex/p07-a-analysis` from it. Ordinary GitHub access and git
  metadata writes need sandbox escalation on this host; authorized scoped
  operations succeeded. No extra worktree. P06 marked done; P07 split A/B.
- API decisions recorded before implementation in [design](p07-a-design.md).
  No DNS header reparser, implicit watermark, orphan buffer or CLI migration.
  Bounded retired-key quarantine makes immediate identical-ID reuse explicit;
  missing questions are classified instead of matching by ID alone.

P07-A implementation and local verification:

- Public APIs: window init/step/advance/finish; DNS packet-time-us/packet->event
  plus init/step/advance/finish. Required count bounds and exact promoting integer
  arithmetic; immutable EDN state and per-call events. Explicit watermark,
  floor-aligned half-open boundaries, late classification and terminal finish.
- DNS uses existing parsed headers and explicitly selected question annotation.
  Exact endpoint/version/ID/question keys; earliest-query retries, immediate
  unmatched responses, signed negative RTT classification, timeout equality and
  bounded retired-key quarantine. Missing questions and quarantined reuse never
  produce guessed matches. No new dependency, global registration, I/O, clock,
  default capture path, CLI migration, version, release or performance-gate change.
- Final source review added EDN-restored window ordering (reading EDN need not
  recreate a sorted map), numeric-address trailing-separator validation, and
  recursive group metadata removal so packet/array/Throwable metadata cannot be
  retained. DNS projection discards arbitrary unknown fields/objects. All three
  have regressions; output EDN can be restored and continued deterministically.
- `bash dev/script/codex.sh test -n paclo.window-test`: final 9 tests / 74
  assertions, including 400 generated property cases. DNS focused command
  `bash dev/script/codex.sh test -n paclo.dns-test`: 15 tests / 196 assertions,
  including 600 property cases. All pass. Five properties total 1000 cases.
- Focused combined new APIs plus dns-ext, flow, decode-ext, explicit extensions,
  diagnostics, examples.smoke-test and examples.cli-contract-test: 101 tests /
  869 assertions passed before the final EDN/metadata boundary regressions.
- Final `bash dev/script/codex.sh check`: passed JUnit 10/10, Clojure 358 tests /
  2625 assertions, offline smoke 4 packets / 438 captured bytes. Real DNS PCAP
  yields two matches; vector/reduce/transduce, offline reduction, managed capture
  and independent fan-out agree with the same ordered events/explicit watermark.
  Actual IPv6 decoder plus native write/read round trip and short DNS header
  rejection are tested. No live capture inference from these offline fixtures.
- `bash dev/script/codex.sh lint`: passed clj-kondo with zero errors/warnings,
  Eastwood with zero exceptions, clean-ns/format dry checks and Markdown lint.
  Eastwood's existing all-linters mode emits warnings (138 on final source),
  including intentionally boxed promoting arithmetic in the new core. No lint
  suppression, gate or coverage threshold was changed. Initial sandbox npm
  access failed at registry.npmjs.org; approved ordinary-environment execution
  passed. Later artifact-sharing validations run serially.
- `bash dev/script/codex.sh perf`: final unchanged 50000/74-byte full-decode gate
  passed at 634.5 ms (1000 ms warning / 1200 ms failure); earlier run 557.9 ms.
  No new analysis is invoked by default decoding/capture. Issue #34 is unchanged.
- Reproducible new measurement: `clojure -M:dev -m paclo.dev.window-dns-perf`.
  macOS x86_64, JDK 21.0.12.1, Clojure 1.12.1; 3 warmups of 10000 work units,
  5 measured runs of 50000; no drops. Window workload: width 1000, 8 groups,
  step+advance per event, at most one retained window; median 84.5 ms and
  99,301,728 thread-allocated bytes (1986 bytes/event), 50 windows emitted and
  zero retained. DNS workload: one reused question/ID with query+response+advance
  per cycle, pending/retired limits 1, timeout 100 us/reuse 50 us, times 200 us
  apart; median 771.5 ms and 936,397,128 bytes (18728 bytes/cycle), 50000 matches,
  zero pending/retired. These include normalization and input construction,
  not parsing/capture; measured runs still show JIT warm-up variation. They do
  not validate high-cardinality expiry, long-run live capture, real NICs or other
  platforms, and are not a comparison against the old unbounded CLI.
- Public contract, README, usage, changelog and plan updated in English. Retain
  all 16 prior executable examples and add three. The doc runner's first new
  example attempt failed because aliases were not loaded before compiling its
  enclosing expression; adding both new namespaces to the existing require
  prelude fixed it. Parser/runner unit tests pass 15/15; all 19 examples passed
  after correction. Required-ID protection now includes the two P06 examples.
- Package and independent consumer validation passed on both initial and final
  packaged source. JAR contains paclo/dns.clj and paclo/window.clj. Consumer in
  /private/tmp/p07-consumer uses only local/root JAR, no checkout source/test
  paths, with -Srepro; asserts jar: resources and native DNS PCAP results,
  EDN round trip, window totals and release after watermark. Prints
  :jar-consumer-ok :matches 2 :packets 4. Final package/consumer passed after
  metadata hardening and final docs execution. Markdown/link/diff checks passed.
- P07-A remains in-progress for CI and independent acceptance; P07-B waits for
  acceptance. CLI migration, sync/async deduplication, snapshots, CSV/JSONL,
  percentiles, group Top-N and cancellation/drops are explicitly deferred.
  Exact all-history statistics require a finite-retention/approximation decision.

P07-A PR and platform verification:

- Committed implementation as `902eef8` and created independent
  [PR #35](https://github.com/nantes-rfli/paclo/pull/35), attached to this task.
  Pre-commit Markdown lint passed. Used existing SKIP_TESTS/SKIP_FMT/SKIP_KONDO
  switches after equivalent explicit tests/lint/dry-format passed; no hook/gate
  was modified. The final supplied checkout is clean after committing evidence.
- [CI run 38258574756](https://github.com/nantes-rfli/paclo/actions/runs/38258574756)
  passed **all 12 jobs** on `902eef8`: build-checks and required aggregate build,
  documentation, Linux x64/JDK21, macOS ARM64/JDK17, Linux ARM64/JDK21 monitor,
  three performance shards and their merger, Eastwood and coverage. No skipped
  or failing job in this implementation run. Existing coverage/performance gates
  and supported-platform requirements were not relaxed.
- This verifies offline native/platform behavior and pure analysis, not live
  capture, high-cardinality performance or sustained real-NIC throughput. The
  PR description includes API decisions/alternatives, memory bounds, validation,
  performance limitations and P07-B handoff. No merge, tag, version change or
  Clojars publication. P07-A remains in-progress only for independent review/
  acceptance; next plan action is review/merge, then P07-B CLI migration.
- This evidence-only follow-up updates plan/log; final evidence-head CI is
  checked separately in the PR description after it completes.

## P07-B start — 2026-10-12

- Clean supplied checkout; doctor passed on macOS x86_64/JDK21/Clojure 1.12.1,
  native offline read 4 packets/438 bytes; lint tools available. Read required
  contribution/API/plan/design/log, analysis core, examples and CLI tests/fixtures.
- Fetched main, verified GitHub PR #35 MERGED at `2e15af7`, created
  `codex/p07-b-dns-cli` on latest main. No extra worktree or unrelated changes.
  P07-A done; P07-B in-progress. P06 issue #34 untouched.
- Pre-implementation contract tables and finite retention/failure/execution
  decisions are in [P07-B design](p07-b-design.md). Old CLI sources saved outside
  the checkout for same-input before/after measurements.

P07-B implementation and verification — 2026-10-13:

- RTT now projects full decode with explicit DNS extension into paclo.dns, using
  strict endpoint/ID/question correlation, advance-before-admission watermarks,
  retry/quarantine/timeout/finish diagnostics and integer microsecond samples.
  Removed header byte readers, ad hoc keys/pending maps and duplicated async
  matcher. Display conversion fixes native RTT and fractional mean; sample
  fixture RTTs are independently fixed at 10.241/15.817 ms, average 13.029 ms.
- QPS uses full DNS app groups directly in paclo.window, never dns/step. Preserves
  packet/captured-byte counts and formats. QR orients client/server IP groups
  consistently across query and response (see final review follow-up below). Removes
  private time/window aggregation, floating fallbacks and silent truncation.
  Empty fill keeps simultaneous groups and preflights full row count, including
  huge timestamps/gaps; Punycode handles non-leading labels. Existing QPS
  snapshot unchanged; added an RTT stats snapshot with exact native time values.
- Finite pending/retired, sample/qname, active window/group and finalized/filled
  row budgets; pairs stores only topN, qstats samples only in groups. Exact
  nearest-rank percentiles fail on overflow, not approximate or truncate. No
  report stdout before successful analysis/finish/fill; error exit 5. Entry
  bounds and additional sorting/serialization space are documented.
- Shared example-only dns-cli adapter owns sync reduction and one async producer
  using reduction, fixed channel, stop-aware puts and observable offer! drops.
  Both use identical pure packet steps. Reader errors propagate; consumer errors
  and cancellation close stop/channel and join producer. Timeout 0 does not open
  input. Partial cancellation/drop output is marked complete? false on stderr;
  metadata is never a DNS pair. No global DNS registration or library API change.
- Found inherited source limits: old QPS read at most 100 packets; both examples
  inherited a 10-second capture duration. New offline adapters read to EOF with
  explicit packet/duration settings; half Long/MAX avoids duration-deadline
  overflow. A real generated 120-packet PCAP passes in sync and capacity-one async.
- Final focused `bash dev/script/codex.sh test -n examples.dns-cli-test`: 19 tests,
  132 assertions, 400 test.check cases passed (Top-N/reference/determinism,
  exact quantiles/mean, packet window boundaries/totals, sample capacity failure).
  Covers retry/reuse/missing questions/negative/late/unmatched/expiry, each
  retention limit, fill, filters/alert/RCODE, EDN/JSONL/CSV/Punycode, native input,
  independent analyses, deterministic drops, timeout/cancel, source/reducer errors,
  native close and producer join. Existing compatibility/smoke focused run passed
  31 tests/84 assertions before the added RTT snapshot.
- Final `bash dev/script/codex.sh check`: JUnit 10/10, Clojure 375 tests/2753
  assertions, offline smoke 4 packets/438 bytes passed. Final `lint` passed:
  clj-kondo 0 errors/warnings, Eastwood 0 exceptions (209 existing/all-linters
  warnings including boxed math), clean-ns/format dry-runs and Markdown lint.
  No lint suppression, performance/coverage threshold or CI job changed.
- `bash dev/script/codex.sh perf`: unchanged mid-50k/74-byte decode gate passed
  at 918.2 ms, below existing 1000 ms warning/1200 ms failure thresholds. This
  gate does not measure DNS CLI throughput. CLI measurements are recorded below.
- Final doc runner: all 20 real offline examples passed, retaining the previous
  19 and adding one RTT/QPS CLI example. Parser unit tests passed 15/15; Markdown
  lint, local links and git diff --check passed. Existing P07-A examples now also
  have required-ID protection. README/usage/changelog and design describe all
  intended changes. Public API contract unchanged, so no contract edits needed.
- Initial focused failures corrected test timestamps to respect watermark order,
  primitive timeout stub signature, and alert helper's double formatting. An
  intermediate run overlapped a formatter rewrite and returned a reader error;
  the serialized final focused/full checks passed without a source syntax repair.
  Kondo initially required declaring the new defspec var; final lint passed.
  Initial sandbox Markdown lint failed DNS lookup at registry.npmjs.org; approved
  ordinary environment run succeeded. Failed attempts are not counted as passes.
- A measured follow-up replaces DNS advance's whole retired-map reconstruction
  with reduce-kv/dissoc of expired keys only. No public contract or CLI-specific
  core option changes; a mixed-quarantine expiry regression protects boundaries.
  Final checks, package and isolated before/after measurements are rerun below.
  GitHub platform, Java quality/coverage and performance-shard results will be
  recorded on the independent PR's checks/description. No live capture, other
  platforms or real-NIC performance is inferred from these local offline checks.
  P07-B awaits independent review/merge; P08 still needs fixture-backed scope.

P07-B measured follow-up and final verification:

- [Performance comparison](p07-b-performance.md) records the same-input baseline,
  final sync/async CLI rates and whole-process thread allocation estimates,
  high-cardinality retained entries/serialized sizes, coarse heap peaks and
  output-only cost. Baseline QPS source limits are normalized to the full 1000
  packets; old nil RTT statistics are not analytically equivalent. Final CLI
  comparison runs are serial with no concurrent test/doc workload.
- Initial bounded RTT pair sync allocation was 68.26 MB/1000 packets. The measured
  retired-map reconstruction was replaced by persistent removal only at expiry,
  preserving mixed-quarantine boundary behavior and immutable snapshots.
  Final allocation/timing and limitations are in the comparison; the remaining
  bounded quarantine scan is not claimed to meet high-cardinality targets.
- After that core-only implementation change, combined DNS/CLI focused tests
  passed 35 tests/335 assertions with 1000 property cases. Final `check` passed
  JUnit 10/10, 376 Clojure tests/2760 assertions and offline smoke. Final unchanged
  `perf` passed at 634.2 ms. Neither public API nor P06 issue #34 changed.
- `bash dev/script/codex.sh package` passed serially; independent JAR-only consumer
  in /private/tmp/p07-consumer passed with -Srepro, jar: namespace resources,
  real PCAP two DNS matches/four packets, EDN and watermark release. An initial
  package invocation used the consumer directory with a relative wrapper path
  and failed before building; rerunning with the absolute wrapper succeeded.
  Package was followed by `check` to restore compiled Java tests.
- Final core-inclusive lint again passed (kondo zero errors/warnings, Eastwood
  209 all-linters warnings/zero exceptions, clean-ns/format dry checks, 30-file
  Markdown lint). Parser tests 15/15 and local links passed again. Explicit
  client 10.0.0.1/server 1.1.1.1 CLI filter returned one exact 15.817 ms pair.
  Full final documentation execution and independent PR/CI links are recorded
  in the PR description. No outstanding local gate failure remains.

P07-B independent PR handoff:

- Implementation committed as `e9cf87b`; created and attached independent
  [PR #36](https://github.com/nantes-rfli/paclo/pull/36) with structure, removal,
  analysis paths, watermark/retention/failure contracts, compatibility changes,
  local checks, measured costs and unverified environments. No merge/tag/version
  or publication. Supplied checkout stays on `codex/p07-b-dns-cli`.
- Final core-inclusive documentation execution passed all 20 examples; parser
  unit tests 15/15 and links passed. Commit-hook Markdown lint passed 30 files.
  Existing optional SKIP_TESTS/SKIP_FMT/SKIP_KONDO switches avoided repeating
  equivalent explicit checks; no hook/gate changed and Markdown hook remained on.
- This evidence-only plan/log follow-up links the PR. CI's final head/run outcomes
  are maintained in the PR description and checks after completion; local offline
  evidence cannot substitute for the supported platform matrix. P07-B remains
  in-progress solely for independent review/merge; next is P08 scope selection.
- The first evidence-only commit attempt was rejected by Markdown MD013 on the
  newly linked plan line; wrapped that line and reran the unchanged hook.

P07-B final client/server group review:

- Correct QPS client/server groups using existing decoded QR information, so
  query source and response destination count under the same client IP, and
  query destination/response source under the same server IP. The initial
  contract preserved raw source/destination grouping; final correctness review
  replaces that misleading role labeling and documents the intentional change.
  No transaction correlation, question requirement or header reparser is added.
  Real default RCODE snapshot, formats and qname performance workload are unchanged.
  Added exact query/response group regression and reran final checks below.
- Final role-aware focused CLI run passed 20 tests/134 assertions and 400 property
  cases; final full check passed JUnit 10/10, Clojure 377 tests/2762 assertions
  and offline smoke. Final performance gate passed at 879.7 ms. Qname benchmark
  branch and packaged library sources are unchanged by this example-only fix.
- CI run 38270838903 on `d6ee497` failed build-checks only at clean-ns import
  layout, causing the dependent build aggregate to fail. Other ten jobs passed,
  including Linux/JDK21, macOS ARM64/JDK17, ARM64 monitor, documentation, all
  performance shards/merger, Eastwood and coverage. This was not a passing CI run.
- Local global clojure-lsp was 2026.05.05 versus CI's pinned 2025.11.28-12.47.43.
  Downloaded official macOS x64 clojure-lsp and kondo v2025.10.23 into ignored
  .dev-tools/bin, verified official GitHub SHA256 asset digests, and fixed only
  QPS's import layout. Global installation/dependencies/CI were not changed.
  Pinned clean-ns/format dry runs and full lint passed (kondo zero errors/warnings,
  Eastwood zero exceptions/209 warnings, Markdown 30 files). Links and parser
  tests 15/15 passed again. Final PR-head CI will verify the correction.

P07-B final implementation CI acceptance evidence:

- [Run 38272297272](https://github.com/nantes-rfli/paclo/actions/runs/38272297272)
  passed all 12 jobs on `30cd06a`: build-checks/required aggregate, documentation,
  Linux x64/JDK21, macOS ARM64/JDK17, Linux ARM64/JDK21 monitor, three performance
  shards/merger, Eastwood and coverage. No failing/skipped job remains in this run.
  The previous import-layout failure is resolved with pinned tooling, not a gate
  relaxation. This establishes offline platform/native behavior, not live/NIC
  performance or a high-cardinality throughput target.
- PR #36 remains open and attached for independent review; no merge or publication.
  This final evidence-only commit changes plan/log only. Its head checks are
  tracked in the PR description after they finish, separately from the passing
  implementation run. Supplied checkout is clean after committing/pushing evidence.
  Next action is independent P07-B review/acceptance, then P08 fixture-backed scope.

## 2026-10-14: P08-A capture format investigation

- Started with clean `git status --short --untracked-files=all` in the supplied
  checkout. Read AGENTS, CONTRIBUTING, accepted plan, work log, public contract,
  pcap/linktype/parse/flow-project/core, Java PcapLibrary and P05 tests/generator.
  Also inspected the managed owner `paclo.capture` and unchanged CI jobs.
- `bash dev/script/codex.sh doctor` passed: macOS x86_64, JDK 21.0.12.1,
  Clojure 1.12.1, CLI 1.12.5.1654, real four-packet offline read. Native libpcap
  is 1.10.1. This local machine is not macOS ARM64.
- Initial sandbox `git fetch origin` could not write .git/FETCH_HEAD; ordinary
  approved Git fetch succeeded. Created `codex/p08-a-capture-inventory` from
  latest origin/main `8312d10` in the supplied checkout, without a new worktree.
  `gh pr view 36 --json state,mergeCommit,url` confirmed MERGED at `8312d10`.
  Updated P07-B to done and recorded P08-A in-progress before fixture work.
- Added [the capability/design inventory](p08-a-capture-formats.md), 28 deterministic
  synthetic Classic PCAP/PCAPNG fixtures and manifest, standard-library generation
  with `--check`, native ctypes precision probes and JNR/public characterization
  tests. Existing Ethernet/SLL/NULL fixtures and their generator remain unchanged.
  No production API, decoder, Java binding, dependency or CI gate is changed;
  performance issues #34/#37 are untouched.
- Measured same-link/snaplen multi-interface and same-endian multi-section reads;
  mixed link/snaplen and changed-endian sections fail after a valid prefix.
  Nano APIs preserve 123456789 ns; current JNR default returns 123456 us.
  Decimal/binary resolution and +7 second offset normalize correctly, while
  interface/section identity and comments/options are absent. Unknown valid
  blocks are skipped. SPB emits epoch zero despite having no timestamp.
- Invalid blocks/caplen/interface produce native -1 and nonempty errors before
  copying invalid packets; invalid IDB option length throws on open. Native
  accepts original length 1 with caplen 64, but writer validation rejects it.
  Public synchronous/lazy/managed reads currently hide negative native read
  errors as clean EOF. This defect is explicitly characterized, not fixed or
  described as safe diagnostic reporting in P08-A.
- Public writer emits Classic Ethernet PCAP even for a .pcapng suffix and
  non-Ethernet input. Internal explicit-DLT writer round trips the packet subset.
  Recommended P08-B B1/B2: observable read errors and explicit single-DLT PCAP
  output/mismatch rejection, before SLL/SLL2 decoder expansion. Future PCAPNG
  fidelity needs a separate metadata source/contract and writer, not a format
  flag that implies reconstruction of discarded information.
- Initial focused test had a parenthesis error, corrected before execution.
  First native test exposed an incorrect DLT_RAW assumption (14 on Darwin);
  measured native DLT is 12. It also exposed changed-endian errors expressed as
  block-size errors on 1.10.1; error-family match widened to cover that legitimate
  version-specific diagnostic. Those attempts were failing checks, not passes.
  Subsequent focused run passed 7 tests/312 assertions before the final extra
  invalid-original-length and writer cases; final full checks are recorded below.
- Initial sandbox GitHub and npm calls lacked network access; approved normal
  network commands succeeded. Markdown lint found a line beginning #37 mistaken
  for an ATX heading in the plan; wrapped that sentence and reran unchanged lint.
  No toolchain, hook, threshold or required gate was relaxed.

Final local verification and independent PR/CI evidence follow after completion.

P08-A local verification before PR:

- `bash dev/script/codex.sh check` passed JUnit 10/10, Clojure 385 tests/3093
  assertions and offline smoke. Final test-only native type hints remove three
  reflection warnings found by Eastwood; focused tests are rerun afterward.
- Generator `--check` verified all 28 fixtures/manifest; Python compilation and
  ctypes precision probe passed. Markdown lint passed 31 files after wrapping
  the plan line; local Markdown links passed. Doc-example parser tests passed
  15/15; maintained example execution is finishing separately.
- An initial full lint reached zero kondo errors/warnings, clean-ns/format checks
  and Eastwood zero exceptions, then hit sandbox npm network access. Final full
  lint runs with ordinary approved network access; no gate is skipped.
- First local performance gate failed at 1555.8 ms versus unchanged 1200 ms
  budget while documentation JVM examples were still running. This is a failing
  measurement, not a pass or a change to #34/#37. Rerun serially after all other
  JVM verification finishes; report both results and the unchanged CI gate.

P08-A final local checks and PR dispatch:

- Final native type-hinted focused run passed 8 tests/331 assertions. Full
  `check` previously passed 385 tests/3093 assertions, JUnit 10/10 and smoke;
  the subsequent test-only type hint changes native method dispatch and was
  verified by the focused run. No production source changed.
- Final `bash dev/script/codex.sh lint` passed: kondo zero errors/warnings,
  Eastwood 209 baseline warnings/zero exceptions (no new reflection warnings),
  pinned clean-ns/format dry checks, Markdown lint 31 files. Maintained example
  execution passed all 20 examples. `git diff --check` and local links passed.
- Serial `bash dev/script/codex.sh perf` passed at 448.0 ms with the unchanged
  1200 ms failure budget after verification JVMs exited. Earlier concurrent
  1555.8 ms failure remains recorded; neither result is a performance improvement
  claim or new target validation.
- Committed `43138ba` and pushed the dedicated branch. Created and attached
  independent [PR #38](https://github.com/nantes-rfli/paclo/pull/38). Commit-hook
  Markdown lint passed; existing optional switches avoided repeating already
  executed tests/format/kondo. Hooks/gates were not edited.
- [Implementation CI run 38426344920](https://github.com/nantes-rfli/paclo/actions/runs/38426344920)
  is running on `43138ba`. Platform version/diagnostic differences and final
  outcomes will be recorded after the jobs finish. No merge, version/tag change,
  publication, live capture or work on performance issues #34/#37.

P08-A implementation CI attempt 1 and infrastructure retry:

- Run `38426344920` on `43138ba` passed ten jobs, including Linux x64/JDK21,
  Linux ARM64/JDK21 monitor, build-checks (Java quality/coverage and existing
  performance gate), documentation, Eastwood, coverage, all three performance
  shards and merger. Each Linux native platform suite passed 385 tests/3093
  assertions. Ubuntu 24.04/kernel 6.17.0-1022-azure, JDK 21.0.12.1, libpcap
  1.10.4 (TPACKET_V3), x64 and aarch64; precision probes also passed on both.
- macOS ARM64 job `115396626458` remained queued for 15m03s, never acquired
  a runner (empty runner name, no steps/logs), then was cancelled. Check
  annotations explicitly report hosted runner acquisition failure and macOS
  arm64 capacity constraints. The dependent required build aggregate failed;
  this attempt is not passing CI and macOS ARM64 remains unverified.
- Queried job/check annotations rather than treating the infrastructure failure
  as a fixture failure. `gh run rerun 38426344920 --failed` retries only the
  unsuccessful jobs on the same implementation commit; successful platform and
  quality checks are retained. No runner/platform/gate change or bypass.
- Diagnostic difference already measured: local macOS/libpcap 1.10.1 leaves a
  stale error string after SPB, Linux/libpcap 1.10.4 leaves it empty. Both return
  EOF -2 and equal packet data; changed-endian errors are block-size errors on
  both measured versions. Native return code must determine terminal status.

P08-A completed investigation and implementation CI:

- [Run 38426344920, attempt 2](https://github.com/nantes-rfli/paclo/actions/runs/38426344920/attempts/2)
  passed all 12 jobs on implementation `43138ba`. Retried macOS job
  `115405230588` actually acquired a runner, passed compilation, 385 tests/3093
  assertions and DNS smoke; dependent required build aggregate passed. Earlier
  cancelled/no-runner attempt remains recorded, not counted as a passing run.
- macOS 26.6.2 ARM64/aarch64, JDK 17.0.20.1, libpcap 1.10.1; its generator and
  six precision probes passed. Linux x64/ARM64 are Ubuntu 24.04, JDK 21.0.12.1,
  libpcap 1.10.4 (TPACKET_V3). All 28 fixture return-code/packet expectations,
  DLT values (including Raw 12), bytes/lengths and timestamp conversions agree.
  SPB leaves a stale native error string on both macOS hosts but not Linux;
  EOF rc -2 determines success. No live or other-platform result is inferred.
- Completed API/metadata/output comparison and ranked P08-B B1/B2 acceptance,
  candidate files and unresolved risks. Additional code-only risk: existing
  `pcap_dump_flush` JNR return type is void whereas the native API returns status;
  write-failure reporting is not validated by successful format round trips.
  This investigation does not change that binding or expand B1/B2 silently.
- P08-A retains the plan's established in-progress status solely for independent
  PR review/merge, as earlier feature slices did. Investigation, tests and design
  are complete. P08-B remains blocked on that acceptance, with B1 read-error
  distinction selected first and B2 explicit Classic output next. No merge is
  authorized by this task; performance issues #34/#37 are untouched.
- The final evidence-only commit updates matrix/plan/log. Its PR-head checks are
  tracked in PR #38 separately from the passing implementation run. No production
  file, new writer API, decoder, dependency, workflow/gate, release version or tag.

## 2026-10-14 — P08-B1 implementation started

Baseline: latest main `8663e69` (merged P08-A PR #38); clean supplied checkout.
Branch: `codex/p08-b1-native-errors`. Reviewed issues #39/#40, P08-A inventory,
28-fixture manifest, native Java binding, capture loops and v1 error contract.
`bash dev/script/codex.sh doctor` passed on macOS x86_64/JDK 21.0.12.1,
Clojure 1.12.1/system libpcap 1.10.1. GitHub CLI required sandbox network
escalation; no credentials or gates changed. P08-A is done; B1 is in progress.

Contract: `:reason :pcap-read-failed`, `:phase :pcap-next-ex`, native `:rc` and
`:native-error` on original ex-info and background wrapper ex-data; reports keep
schema v1/class/message and add these fields. Pass retains valid prefix with
failed/error stats; non-report callers use on-error. No synthetic decode data.
EOF classification never consults native text. Native loops share validation.
Newly acquired handles close once on setup failure through one ownership helper;
cleanup errors are suppressed on the original error. Successful setup transfers
ownership. Lazy terminal state is outside the queue, with a final queue recheck;
packet-delivery abandonment while blocked remains issue #40, not solved here.
The duplicate lazy stop-predicate invocation was removed: loop owns the predicate.
Managed drain also rechecks queued data after terminal observation.

Focused checks so far: capture-format-test 8 tests/1242 assertions; pcap-loop-test
28 tests/142 assertions; managed-capture-test 12 tests/76 assertions, all passing.
Tests cover all 28 real fixtures, throw/pass/public paths, valid prefixes,
capacity-one terminal signaling, unexpected return codes, failing notification,
BPF compile/set and netmask failure instrumentation, configured failure, exact
close and suppressed cleanup errors. Full quality/CI evidence follows below.

Local verification update:

- Focused ownership/loop tests: `bash dev/script/codex.sh test -n
  paclo.pcap-unit-test -n paclo.pcap-loop-test -n paclo.managed-capture-test`:
  92 tests, 355 assertions, zero failures/errors.
- `bash dev/script/codex.sh check`: 10 JUnit tests, 397 Clojure tests /
  4148 assertions, offline smoke all passed. The first full run found six
  historical tests expecting swallowed native errors; those now assert native
  exceptions (the packet/timeout-only test now ends with normal EOF).
- `bash dev/script/codex.sh lint`: passed, including clj-kondo (zero errors /
  warnings), Eastwood, namespace/format dry runs and Markdown. Eastwood reports
  existing warnings; no analyzer exception or gate relaxation. Initial namespace
  ordering/test-local-shadow findings were corrected before the passing run.
- `python3 test/resources/make_capture_format_fixtures.py --check`: all 28
  fixtures/manifest reproduced.
- `dev/script/mdlint.sh`: passed after removing one added blank line. Initial
  sandbox DNS failure for registry.npmjs.org was resolved by rerunning the same
  mandatory command with network escalation.
- `python3 dev/script/verify_doc_links.py`: passed.
- `python3 -m unittest discover -s dev/script -p 'test_verify_doc_examples.py'`:
  15 parser tests passed. Task-generated Python bytecode files were removed.
- `git diff --check`: passed.

Performance, Java quality, executable examples and supported-platform CI are
pending at this checkpoint. Live/NIC capture and hardware throughput have not
been validated; configured/live ownership is covered with deterministic doubles.
The managed startup owner now spans DLT, allocation, ready callback and producer
submission; every injected failure retains the cause and closes once.

`bash dev/script/codex.sh perf` passed: 50,000 synthetic 74-byte Ethernet
packets, full decode 623.4 ms (warning 1000 ms, failure 1200 ms), macOS x86_64 /
JDK21/system libpcap 1.10.1. This is the existing offline gate, not a real-NIC
measurement or a claim about issues #34/#37. CI scenario measurements pending.

Java quality checks passed, run serially: `clojure -M:spotbugs`,
`clojure -M:checkstyle`, `clojure -M:jacoco`, and
`JACOCO_MIN_LINE=0.25 clojure -M:jacoco-gate`. Line coverage was 43.8%,
above the unchanged 25% CI threshold.

Initial commit was stopped before creation by the existing pre-commit hook:
its `clj -M:test` interactive wrapper requires missing `rlwrap`. The noninteractive
Clojure runner is installed and passed all tests. A task-local `/tmp` `clj`
launcher forwards unchanged arguments to `/usr/local/bin/clojure` for this
commit's full hook run; no hook or test/format/Markdown/kondo gate is skipped.

`python3 dev/script/verify_doc_examples.py`: all 20 maintained executable
examples passed. All requested local checks are now successful. The full
pre-commit hook and implementation-commit supported-platform CI remain to run.

P08-B1 implementation verification complete; independent review/merge pending:

- [PR #41](https://github.com/nantes-rfli/paclo/pull/41), implementation commit
  `edc1c4ebac6120fda15970e42cb7a51e24f37407`, includes `Fixes #39`.
- Full existing pre-commit hook passed: unchanged test arguments through the
  noninteractive launcher, 397 tests / 4148 assertions, namespace cleaning,
  formatting, Markdown and clj-kondo. The supplied checkout was clean afterward.
- [Implementation CI run 38498710156](https://github.com/nantes-rfli/paclo/actions/runs/38498710156)
  succeeded in all 12 jobs: build-checks, documentation-checks, eastwood-lint,
  coverage, Linux x64/JDK21 and macOS ARM64/JDK17 compatibility, Linux ARM64
  monitor, three performance shards, 27-scenario merger and required build
  aggregate. No failed/skipped job is counted as validation and no gate changed.
- Linux x64 and ARM64: JDK 21.0.12.1/libpcap 1.10.4; macOS ARM64:
  JDK 17.0.20.1/libpcap 1.10.1. Each platform passed 397 tests / 4148 assertions,
  including all 28 format fixtures and native error/ownership regression tests.
- CI offline full-decode gate: 50,000 packets, 374.3 ms (warning 1000 ms,
  failure 1200 ms). CI JaCoCo: 43.8% line coverage (threshold 25%). All 27
  quick-profile performance scenarios produced and merged successfully.
- The current evidence update changes plan/log only; its final head checks are
  monitored on PR #41. PR review/merge remains explicitly pending and no merge,
  release or version update was performed.

Next: independent review/acceptance of B1, then P08-B2 explicit single-DLT
Classic PCAP writer options/framing validation. Issue #40 packet-delivery
abandonment, SLL/SLL2 decoding, PCAPNG metadata/writing, exact timestamps and
performance issues #34/#37 remain outside this change. Offline/double tests and
CI do not establish live capture behavior, NIC throughput or performance targets.

## 2026-10-14 — P08-B2 explicit single-DLT writer

Baseline: latest main `c729e19` (P08-B1 PR #41 merged), clean supplied checkout;
branch `codex/p08-b2-single-dlt-writer`. Reviewed AGENTS, contribution/API contract,
plan/work log, P08-A inventory, core/pcap/native binding and all requested tests.
`bash dev/script/codex.sh doctor` passed on macOS 15.4.1 x86_64/JDK 21.0.12.1,
Clojure 1.12.1/system libpcap 1.10.1. `prepare` passed after Java binding change.
B1 is done; B2 implementation/verification is in progress.

Three-argument public write-pcap! delegates to the existing internal writer.
Only native DLT/snaplen options are accepted; validate signed native int range
without coercion/overflow. Defaults 1/65536; explicit packet DLT must match;
missing metadata trusts caller framing. Reject excess caplen instead of truncating;
retain timestamps/length validation and order. Incremental output can leave an
empty file or valid prefix. No byte conversion, sniffing, suffix selection,
PCAPNG writer/metadata or exact-nanosecond behavior. The pipeline benchmark had
stripped source framing/timestamp/length fields; it now retains writer metadata
so it cannot bypass known-DLT rejection. Other two-argument call sites retain
source metadata or generate Ethernet; non-Ethernet maps intentionally fail.

Native binding now captures int pcap_dump_flush status. Shared ownership cleanup
attempts every cleanup even if flush/close throws; original error remains primary
and later exceptions are suppressed. Dead-handle null and dump-open failures are
reported (native message for dump-open). The other internal dumper owner was
updated because throwing flush would otherwise leak its resources. Native
pcap_dump and pcap_dump_close return void: no per-record status or observable OS
close-only status, no fsync/durability guarantee. Specification references:
[flush manual](https://raw.githubusercontent.com/the-tcpdump-group/libpcap/libpcap-1.10.5/pcap_dump_flush.3pcap)
and [close manual](https://raw.githubusercontent.com/the-tcpdump-group/libpcap/libpcap-1.10.5/pcap_dump_close.3pcap).
This small binding fix stays in B2; no separate large native task is required.

Focused tests: `bash dev/script/codex.sh test -n paclo.pcap-unit-test -n
paclo.core-unit-test -n paclo.pcap-roundtrip-test -n paclo.capture-format-test`:
75 tests / 1644 assertions, zero failures/errors. All 28 fixtures exercise
conversion or failure/prefix behavior; native DLT readback (including RAW 12
versus savefile LINKTYPE_RAW 101), bytes/order/time/caplen/len retained. SLL/NULL
three-record fixtures include truncated packets. Tests cover byte-array/map/lazy/
empty inputs, options/mismatch/snaplen failure, source/dump exceptions, failed
acquisition and flush/close failures with exact cleanup and suppressed errors.
Real /dev/full flush failure is exercised on Linux CI; unavailable on macOS.
All 20 previous executable examples remain; two explicit SLL writer/readback
examples are registered for CI (22 total). Full local gates and CI follow below.

Native source inspection found an additional small fix necessary: libpcap 1.10.5
pcap_dump_flush checks only fflush, not earlier fwrite failures retained by
ferror. Linux/macOS now inspect borrowed pcap_dump_file through system libc,
without taking FILE ownership or reading stale pcap_geterr. A zero flush rc plus
nonzero :stdio-error is still :pcap-write-failed. The system-libc binding is lazy;
Windows C runtime FILE interoperability is not claimed. Linux /dev/full tests
cover 64/8192/65536-byte writes; deterministic doubles cover sticky-error detection
and cleanup. Native close-only failures remain unobservable through void close.
[Native implementation](https://raw.githubusercontent.com/the-tcpdump-group/libpcap/libpcap-1.10.5/sf-pcap.c).
Additional focused native/roundtrip tests passed: 60 tests / 230 assertions.

Initial broader checks: check passed 10 JUnit tests, 403 Clojure tests / 4348
assertions and offline smoke before the final stream-error enhancement. Lint's
Clojure checks passed but Markdown's npm fetch failed sandbox DNS for
registry.npmjs.org; rerun with network escalation. The first concurrent doc-example
run encountered source/class changes during final enhancement (transient parse/
missing compiled class failures in two examples); all examples will rerun after
compilation, with no active edits. Neither attempt is counted as final validation.

Final local source checks passed: `bash dev/script/codex.sh check` (10 JUnit;
405 Clojure tests / 4358 assertions; offline smoke), `bash dev/script/codex.sh
lint` (kondo zero errors/warnings, Eastwood 211 all-linter warnings / zero
exceptions, clean-ns/format dry checks, Markdown), and
`python3 dev/script/verify_doc_examples.py` (all 22 examples). Markdown lint,
local link verification and the 15 example-parser unit tests passed with network
escalation for npm. Java quality passed SpotBugs/CheckStyle/JaCoCo; line coverage
43.8%, unchanged threshold 25%. `git diff --check` passed. Documentation clarifies
that actual I/O failures can leave incomplete records/headers; only successful
validation/source-error cleanup on healthy output yields a readable prefix.
Final performance/package/clean-consumer and GitHub CI evidence follows.

`bash dev/script/codex.sh perf` passed at 597.0 ms for the existing 50,000-packet
74-byte synthetic full-decode gate (warning 1000 ms / failure 1200 ms), with other
local verification processes finished. This is offline evidence on macOS x86_64,
not real-NIC throughput or resolution of issues #34/#37. `package` passed serially;
JAR contains core/pcap and both native interfaces, including PcapStdioLibrary.
A clean -Srepro consumer in /private/tmp/paclo-b2-consumer uses only the packaged
JAR, asserts the core resource is loaded from jar:, and verifies all six DLT
round trips plus default non-Ethernet rejection. Java test classes are restored
with prepare after package. No dependency/version/release change.

The commit hook's interactive clj launcher requires unavailable rlwrap; as in B1,
a task-local /private/tmp/paclo-b2-tools/clj forwards unchanged arguments to the
installed noninteractive Clojure CLI. The full hook will run all existing tests,
namespace/format, Markdown and kondo gates; none is skipped or weakened.

PR handoff and CI correction:

- Implementation `c08fe6d8903303dc525c5418f203cddab7a69d91`; full existing
  pre-commit hook passed 405 tests / 4358 assertions and all formatting/Markdown/
  kondo gates without skips. Created/attached independent
  [PR #42](https://github.com/nantes-rfli/paclo/pull/42). No merge/release/tag.
- [Initial CI run 38506051039](https://github.com/nantes-rfli/paclo/actions/runs/38506051039)
  passed 10 jobs including all three native platforms, documentation, coverage,
  three performance shards/27-scenario merger and Eastwood. build-checks failed
  kondo on resource-macro binding symbols; required aggregate failed correctly.
  This is not an all-pass run. Native Linux /dev/full tests passed in both Linux
  architectures; all six DLT round trips pass across the supported matrix.
- Root cause was an existing local `.clj-kondo/config.edn` excluded by gitignore,
  not runtime behavior. It already maps the four resource macros to normal let
  binding analysis; local lint therefore passed while clean CI lacked it. Track
  that exact narrow macro-analysis config and retain ignored caches. No linter
  suppression, workflow edit, threshold change or ignored body validation.
- Final head CI outcomes are maintained in PR #42's checks/description, including
  all 12 jobs, native versions and coverage/performance results. The plan records
  implementation/local verification complete and independent review/merge pending;
  subsequent SLL/SLL2 decoding is a separate slice. No live/NIC or unmeasured
  platform validation is claimed.

The same cold lint also passed using the exact CI clj-kondo version 2025.10.23,
downloaded from its official release to /private/tmp/paclo-b2-kondo and verified
against the release SHA256: `clj-kondo --lint src test dev --cache false`, zero
errors/warnings. The initial matrix logs confirm Linux x64/ARM64 JDK21 /
libpcap 1.10.4: 405 tests / 4364 assertions (including real /dev/full); macOS
ARM64 JDK17 / libpcap 1.10.1: 405 tests / 4358 assertions. That run's Java line
coverage was 43.8% (threshold 25%); offline decode gate 608.3 ms; all 27 performance
scenarios merged. These passing jobs do not change the initial run's failed
aggregate; final head must pass all 12 jobs and is tracked in PR #42.

P08-B2 implementation verification complete; independent review/merge pending:

- Corrected implementation head `75c5906420f05e8e7ba41e7929cd407c41abffdb`:
  [CI run 38506619477](https://github.com/nantes-rfli/paclo/actions/runs/38506619477)
  passed all 12 jobs. `gh run view 38506619477 --json status,conclusion,headSha,jobs`
  confirmed success and no failed step, including continue-on-error coverage.
  build-checks, documentation-checks, Eastwood, coverage, both compatibility
  jobs, ARM64 monitor, three performance shards, 27-scenario merger and required
  aggregate all succeeded. No workflow, runner, gate or threshold was changed.
- Linux x64/ARM64 JDK21/libpcap 1.10.4 each passed 405 tests / 4364 assertions;
  macOS ARM64 JDK17/libpcap 1.10.1 passed 405 / 4358. Real /dev/full small/large
  writes fail observably on Linux; all 28 fixtures and six native-DLT round trips
  pass across the matrix. All 22 executable examples passed in CI.
- CI Java line coverage: 43.8%, above unchanged 25%. CI offline decode gate:
  499.7 ms for 50,000 packets (warning 1000 / failure 1200 ms). All 27 quick-profile
  performance scenarios produced/merged. No live/NIC throughput inference.
- This final evidence update changes plan/log only. Its head checks are maintained
  on [PR #42](https://github.com/nantes-rfli/paclo/pull/42), alongside the complete
  implementation run. The queue remains in-progress solely for independent
  review/merge; next is that acceptance, then a separate SLL/SLL2 decode slice.
  Issue #40, PCAPNG metadata/writing, exact nanoseconds and performance #34/#37
  remain outside this completed implementation. No merge/version/tag/release.

## 2026-10-14: P08-C shared framing and cooked decoding

Started with a clean supplied checkout, `git status --short --untracked-files=all`
and successful `bash dev/script/codex.sh doctor`. Read AGENTS, CONTRIBUTING,
API contract, accepted plan, P08-A inventory, full/flow/core sources, P05/P06
regressions and deterministic generator. Fetched origin/main and verified PR #42
was merged at `4998ddcf191a523febd7da9efef6bb956cb7ca53` (GitHub mergedAt
2026-10-14T04:09:40Z). Created `codex/p08-c-shared-framing` from that main in the
supplied checkout; no extra worktree. B2 is done; C is the reviewable next slice.

Implementation:

- `paclo.linktype` owns DLT validation, minimum sizes, Ethernet/VLAN and SLL/SLL2
  bounds/length validation and packed L3 offset/protocol. Successful framing
  constructs no map or packet-byte copy. Full-only link construction reads
  details from validated offsets; Ethernet MAC/VLAN shapes and partial VLAN
  diagnostics are retained. Removed duplicate full/flow VLAN framing and the
  Ethernet-only facade length constant. No generic internal directory/registry.
- SLL/SLL2 full maps honestly name their link wrapper, preserve numeric wire
  fields and represent exactly 0..8 address bytes as lowercase colon-separated
  hex (empty string at zero). SLL2 uint32 interface index and reserved are retained;
  the index is not PCAPNG interface identity. Only cooked IPv4/IPv6 protocols
  are decoded; cooked ARP/VLAN/other values are unsupported protocols.
- Existing full IP/L4 parsers and numeric flow walkers are reused. No fabricated
  Ethernet header, default dependency, public backend, input clone, borrowed
  buffer or resource/lifecycle change. Existing L4 payload copies remain.
  Full keeps the source array; flow excludes bytes and nested decode/link maps.
- Additive `:unsupported-protocol` includes numeric protocol; bad cooked address
  length uses `:malformed-packet`, `:field :address-length`, `:value` and the
  absolute length-field location. Short link headers require 16/20 bytes at
  offset zero. Ethernet error strings and best-effort VLAN shapes stay compatible.
  Shared minimum-header validation also retains the facade's skip-parser/skip-hook
  behavior on short input. Full/flow IP/L4 depth differences remain explicit.
- P07 DNS projection used an Ethernet-only metadata guard; changed it to shared
  supported-DLT validation. Explicit DNS/TLS functions work unchanged. Noninitial
  IPv6 numeric projection now stops at the fragment header, matching full decode
  when its following extension header is absent. No reassembly or analysis redesign.

Fixtures and tests:

- P08-A's 28 files/manifest and P05 captures remain byte-identical. The original
  generator now also checks four new cooked captures (Classic and single-DLT
  PCAPNG for each DLT) plus a separate manifest. Each has 26 deterministic records:
  IPv4/IPv6 DNS request/response, TCP/TLS, ICMP, first/later fragments and extension
  chains, address lengths 0/8, unknown protocol, short link/IP/L4/extension headers,
  invalid IHL/version/address length and Ethernet-looking adversarial bytes.
- All core transformation/lazy/reduction/report/managed paths agree, including
  PCAPNG equivalence, Classic write/read bytes/time/length/DLT round trips and
  independent full/flow bounded fan-out. Tests verify raw/full array identity,
  no mutation, numeric keys/aggregates/Top-N, window counts, IPv4/IPv6 DNS RTT and
  TLS SNI. Explicit depth tests demonstrate four-port-byte flow success while
  full decode diagnoses a short TCP/UDP header. Six oversized address-length
  cases and 300 cooked property cases check link-independent IP data and safe
  truncated prefixes/absolute locations/EDN/ownership.
- Existing P05/P06/P07 expectations are updated for now-supported cooked traffic;
  parser stubs accept the new internal DLT argument. Initial focused/full runs
  exposed the old DNS guard, outdated rejection expectations/stub arities and
  parser-skip assumptions; those were corrected before successful verification.

Verification so far (local macOS 15.4.1 x86_64, libpcap 1.10.1, JDK 21.0.12.1,
Clojure 1.12.1; offline only):

- Focused wrapper tests: 72 tests / 1579 assertions, then the expanded cooked
  namespace: 7 tests / 878 assertions, all passed. `bash dev/script/codex.sh check`
  passed 412 tests / 5164 assertions, 10 JUnit tests and real offline smoke.
- `bash dev/script/codex.sh lint`: kondo zero errors/warnings, Eastwood zero
  exceptions with the existing boxed-math warnings, clean-ns/format dry checks,
  Markdown lint all passed. First sandbox-only npm calls could not resolve
  registry.npmjs.org; the authorized network-enabled rerun succeeded. A single
  extra Markdown blank line was fixed; no lint suppression/gate change.
- `clojure -M:spotbugs`, `-M:checkstyle`, `-M:jacoco`, and
  `JACOCO_MIN_LINE=0.25 clojure -M:jacoco-gate` passed; line coverage 43.8%.
- `python3 test/resources/make_capture_format_fixtures.py --check`, Markdown lint,
  `python3 dev/script/verify_doc_links.py`, the documentation-parser unittest
  (15 tests), and `git diff --check` passed. All 24 executable examples passed,
  preserving the original 22 IDs and adding cooked full/flow samples. The new
  README example's trailing comment initially swallowed the verifier's closing
  form; removed that trailing comment and reran the full example gate successfully.

Performance, packaging, commit/PR and CI evidence follow below. Live capture,
other unmeasured platforms and real-NIC throughput are not established by these
checks. NULL/LOOP/Raw decoding, PCAPNG metadata/writer, exact timestamps, issue #40,
performance issues #34/#37, version updates, publication and merge remain outside C.

Final performance/packaging evidence:

- `paclo.dev.framing-perf` compares baseline/current in one warmed JVM, alternates
  sample order and records current-thread allocation, checksums, array identity
  and unchanged input bytes. Two final independent runs, their method and every
  row are retained in [P08-C performance](p08-c-performance.md). Ethernet full
  allocation falls 416 bytes/packet; flow is 280 bytes for all three DLTs.
  Full throughput is measurably lower (UDP 4.9–7.7%, TCP 8.4–9.8%); this is
  disclosed as the CPU cost of shared framing/link construction, not a speedup.
  Ethernet flow ranges from -4.3% to +0.6% for TCP; UDP outcomes are in the report.
  Investigated early regressions, removed boxed DLT comparison and extra hot-path
  packing calls, and reused the local full-parser ByteBuffer for address reads.
  No whole-frame copy, second full ByteBuffer or intermediate full link map.
- Final `bash dev/script/codex.sh perf` passed at 514.7 ms with the unchanged
  1000/1200 ms warning/failure budgets. Measurements ran after other local checks;
  they do not resolve aggregation issues #34/#37 or establish live throughput.
- `bash dev/script/codex.sh package` builds the unchanged snapshot-version JAR;
  JAR inspection includes linktype/full/numeric-flow/DNS and native bindings.
  Restore Java test classes with `prepare` after packaging. The independent
  `/private/tmp/paclo-c-consumer` uses `clojure -Srepro` and only the packaged JAR,
  checks jar: resource origins, cooked IPv4/IPv6 flow aggregates, DNS/window
  composition, array identity and matching-DLT Classic PCAP round trips.
- The installed local hook refers to removed `script/fmt.sh` and interactive clj
  without rlwrap. A command-local hook shim invokes the same full tests through
  noninteractive `clojure` and the maintained `dev/script/fmt.sh`; no test or
  formatter is skipped, and the repository/global hook configuration is unchanged.

Implementation handoff and supported-platform CI:

- Committed `5d5e848ff23960a4ac0f7354187dce4c5afdc0fb` after the full local hook
  passed 412 tests / 5184 assertions and all maintained formatter checks. Final
  full lint, fixture/link/parser checks and diff checks also pass. Packaged JAR's
  independent consumer printed `:clean-jar-consumer-ok`; `prepare` restored tests.
- Created and attached [PR #43](https://github.com/nantes-rfli/paclo/pull/43).
  Automatic approval initially rejected PR publication because it did not
  recognize authorization. A read-only check of the user's delegated attachment
  confirmed its explicit section 16 instruction to create an independent PR and
  its matching repository destination; retry of the same action was approved.
  No approval bypass, merge, version, tag, release or publication of a library.
- [Implementation CI run 38525529813](https://github.com/nantes-rfli/paclo/actions/runs/38525529813)
  passed **all 12 jobs** on `5d5e848`, with no failed steps (including coverage's
  continue-on-error job). Build/Java/static checks, documentation, both
  compatibility jobs, Linux ARM64 monitor, Eastwood, coverage, three performance
  shards, the 27-scenario merger and required aggregate all succeeded.
- Linux x64 and Linux ARM64: kernel 6.17.0-1022-azure, JDK 21.0.12.1, libpcap
  1.10.4 (TPACKET_V3), each 412 tests / 5190 assertions. macOS 26.6.2 ARM64:
  JDK 17.0.20.1, libpcap 1.10.1, 412 / 5184. Every P08-A/cooked fixture, precise
  record preservation and decoding/analysis path agrees across this native matrix;
  the six additional Linux assertions cover existing /dev/full writer checks.
- CI: 10 JUnit tests, 43.8% Java lines against unchanged 25% gate; all 24 docs
  examples pass; existing 50k gate passes at 989.3 ms against 1000/1200 ms budgets.
  All 27 existing quick performance scenarios merge successfully. Local and CI
  times are separate observations, not directly interchangeable speed comparisons.
- This final evidence update records completion, identifies PR #43 as the next
  independent review/merge item and states the UDP flow range explicitly rather
  than characterizing all variation as small. It changes only plan/log/performance
  prose. Its checks are maintained on PR #43, alongside the complete implementation
  run. P08-C stays in-progress solely for independent review/merge; no merge here.

## 2026-10-14 — P08-D1 Raw IP implementation

Started with a clean supplied checkout, fetched latest main and confirmed P08-C
PR #43 merged at `9d83bb2`. Created `codex/p08-d1-raw-ip` from that commit;
no extra worktree, version/tag/release or merge. Read the contributing/API/plan,
P08-A capability inventory, P08-C performance report, framing/full/project/core
sources, fixture generators and related tests. Doctor passed on local macOS
15.4.1 x86_64, Temurin 21.0.12.1, Clojure 1.12.1, libpcap 1.10.1.

Implementation decisions:

- `paclo.linktype` owns the OS-scoped native DLT_RAW guard (12 on Linux/macOS),
  the single-byte version bound and zero-offset dispatch. Savefile 101 and
  guessed unverified-OS mappings are rejected. Raw IP full wrapper is exactly
  `{:type :raw-ip :l3 ...}`; no synthetic MAC/Ethertype/cooked fields.
- Reuse the existing full IPv4/IPv6/L4 parsers and numeric flow walkers. Full
  retains array identity; flow creates no link-detail/full maps. Existing L4
  payload copies remain. No raw-specific IP parser, native I/O change, frame
  clone, extension policy change, analysis API change or quality-gate change.
- Flow's IP bounds classification now uses `:truncated-header` even at offset
  zero; link framing separately owns `:short-frame`. Invalid Raw version uses
  `:malformed-packet`, `:field :ip-version`, numeric `:value` and offset 0.
  Existing partial parsing depth/unknown-L4 behavior is retained and documented.
- Reuse cooked fixture IP/L4 builders and packets, generating Classic PCAP in
  both byte orders and PCAPNG with LINKTYPE_RAW 101. Add bare malformed/options/
  extension/unknown-protocol/adversarial cases. The original generator's --check
  now covers all 28 original, four cooked and three Raw captures.
- Update the README/usage/API/changelog and register two runnable Raw examples,
  retaining all previous 24 examples. Mark C done; register D1 and D2, with
  D2's source-backed AF/endian/native-conversion probe requirements in
  [the handoff](p08-d2-null-loop.md). NULL/LOOP decoding is unchanged.
- Existing [issue #44](https://github.com/nantes-rfli/paclo/issues/44) already
  tracks C's Ethernet full throughput slowdown (4.9–9.8%); no duplicate Issue
  or unrelated performance optimization is added.

Verification progress:

- Initial focused cooked/linktype/Raw tests passed 23 tests / 2016 assertions,
  including 200 Raw property cases. Added randomized adversarial arrays and
  exact empty/IP/L4/extension absolute-location assertions afterward.
- First full check found four obsolete P08-A assertions that Raw decoding was
  unsupported; updated that capability expectation. A rerun passed 417 tests /
  5737 assertions, 10 JUnit tests and offline smoke. The subsequently expanded
  Raw/capture-format focused run passed 14 tests / 1950 assertions.
- All 26 executable doc examples passed. Fixture --check and 15 doc-parser
  unittests passed. Link verifier and diff whitespace check passed.
- First lint completed kondo (zero errors/warnings), Eastwood (zero exceptions,
  existing boxed-math warnings), namespace/format checks, but npm needed network
  access. The network-enabled Markdown rerun found one long plan line; wrapped
  it and reran full lint. No warning suppression or threshold change.
- A separate JVM with `-J-Dos.name=OpenBSD` loading only `paclo.linktype` rejected
  DLTs 12, 14 and 101 (`:unverified-os-dlts-rejected`). This tests the guard, not
  actual OpenBSD/libpcap behavior.

Final performance, packaging, PR and native CI evidence follows below. Live/NIC
throughput and unmeasured platforms remain unvalidated; D2 cross-endian NULL/AF
runtime probes are pending separately.

Final measurement and local delivery verification:

- Kept Ethernet/cooked literal-set checks before the OS-scoped Raw guard.
  Renamed internal header-size/require-link-header to minimum-size/require-framing
  because Raw has no link header but requires one version byte. Kept Raw version
  validation in a small framing helper, separate from the shared dispatch body.
  Focused final Raw regression: 6 tests / 578 assertions, 200 property cases pass.
- Two final mixed-DLT JVM runs and eight controlled single-DLT JVMs are retained
  in [the D1 performance report](p08-d1-performance.md). Every final sample is
  included. Mixed baseline/current have different framing profiles (three versus
  four DLTs); observed negative medians prompted same-DLT controls. Do not infer
  a particular JIT cause from these timings. Earlier source-version experiments
  are distinguished in the report; no outcome was discarded from a final run.
- Controlled Ethernet full medians versus C: UDP -0.5% to +2.3%, TCP -2.1% to
  +0.7%. All matching existing-link allocations agree within each run. All Flow
  variants allocate 280 bytes/packet. Raw full UDP 573.6–594.8 kpps / 2960–3000
  bytes, TCP 390.0–405.4 kpps / 4896–4976 bytes; Raw flow 4.046–4.118 Mpps UDP,
  4.074–4.321 Mpps TCP. Full input identity and byte snapshots pass; drops zero.
  Negative/mixed variation is disclosed, not called universal equivalence.
- Final `bash dev/script/codex.sh perf` passed at 574.0 ms, against unchanged
  1000/1200 ms budgets. This does not resolve C's measured slowdown or issue #44.
- SpotBugs, CheckStyle, JaCoCo and `JACOCO_MIN_LINE=0.25 clojure -M:jacoco-gate`
  passed, with 43.8% Java line coverage; no Java source change. Full check runs
  with the expanded tests passed 418 tests / 5759–5760 assertions plus 10 JUnit
  tests and offline smoke; final-source check/lint/docs reruns follow below.
- Package built the unchanged snapshot-version JAR; inspected full/flow/linktype,
  DNS/TLS and native resources. The isolated `/private/tmp/paclo-d1-consumer`,
  using only this JAR with `clojure -Srepro`, checked jar: resource origins,
  IPv4/IPv6 Raw decode, DNS/TLS, flow keys/aggregates/Top-N, DNS correlation,
  bounded windows, byte identity, code-101 rejection and Classic writer round
  trip, printing `:clean-raw-ip-jar-consumer-ok`. Repackage the final helper
  source and repeat this consumer before committing; prepare restores test classes.
- D2 investigation found the pinned 1.10.5 post-processing switch has no NULL or
  LOOP case. Record metadata byte swapping therefore does not prove packet AF
  normalization. The handoff distinguishes this source inference from pending
  installed-library/cross-platform byte probes. No NULL/LOOP implementation.

Independent PR creation and CI confirmation remain next. The installed local
hook still invokes removed `script/fmt.sh` and interactive clj; reuse the previous
command-local shim, which runs the full noninteractive tests and maintained
formatter without skipping checks or changing repository/global hook settings.

- Final-source `bash dev/script/codex.sh check` passed **418 tests / 5760
  assertions**, 10 JUnit tests and real offline smoke. Final full lint passed
  kondo with zero errors/warnings, Eastwood with zero exceptions and the existing
  warnings, clean-ns/format checks and Markdown lint. All **26 executable docs**
  passed again. Fixture --check verified 35 captures; the 15 documentation-parser
  unittests, link verifier, separate Markdown lint and diff whitespace check pass.

- Final snapshot JAR rebuild and independent consumer passed again. Java test
  classes are restored with `bash dev/script/codex.sh prepare` after packaging.
  JAR resource inspection and final local links/diff/Markdown checks are clean.

Implementation publication:

- Committed `bc2e9a0a84517bd2b8dd35716c63de0c9747fe84` after the compatibility
  hook passed 418 tests / 5760 assertions and all formatter checks; checkout clean.
- Pushed `codex/p08-d1-raw-ip` and created/attached
  [PR #45](https://github.com/nantes-rfli/paclo/pull/45). No merge, release or tag.
- [Implementation CI run 38543025204](https://github.com/nantes-rfli/paclo/actions/runs/38543025204)
  started on the implementation head. Native matrix and complete quality/perf
  results are recorded below after actual completion; a pending job is not a pass.

Supported-platform CI confirmation:

- Implementation CI run **38543025204** passed **all 12 jobs** on `bc2e9a0`.
  Inspected every job/step: no failed step, including coverage's existing
  continue-on-error path. Build/Java/static gates, docs/cljdoc load, both
  compatibility jobs, ARM64 monitor, Eastwood, coverage, three performance shards,
  27-scenario results merge and required aggregate all succeeded.
- Linux x64 and Linux ARM64: kernel 6.17.0-1022-azure, Temurin 21.0.12.1,
  libpcap 1.10.4 (TPACKET_V3), **418 tests / 5766 assertions** each. macOS 26.6.2
  ARM64: Temurin 17.0.20.1, libpcap 1.10.1, **418 / 5760**. Each verified the
  original 28, four cooked and three Raw captures, including empty records,
  both Classic byte orders, PCAPNG, writer preservation and Raw decoding/analysis.
  The six extra Linux assertions cover existing /dev/full writer checks.
- All **26 executable examples** pass in CI; 10 JUnit tests and Java quality
  gates pass, JaCoCo 43.8% against unchanged 25% threshold. Existing mid-50k
  performance gate passes at **722.9 ms** (1000/1200 ms budgets); all 27 existing
  quick scenarios merge. CI/local times are distinct observations, not speedups.
- This evidence update changes only plan/log/performance prose. Its final-head
  checks are maintained on PR #45. D1 stays in-progress solely for independent
  review/merge; D2 is the next feature after acceptance, with AF/endian/native
  probes still required. No release, merge, live/NIC validation or speculative
  unmeasured-platform mapping.

## P08-D2 native probe prerequisite (2026-10-14)

- Started clean on D1 branch; fetched main and verified PR #45 merged at
  `0d06dd1`. Created `codex/p08-d2-null-loop` from that main; doctor passed
  (macOS x86_64, Temurin 21.0.12.1, Clojure 1.12.1).
- Added 12 deterministic NULL/LOOP Classic/PCAPNG captures: container endian
  varies independently from NULL pseudoheader endian, AF 2/24/28/30, unknown
  999/10, mismatches, short framing and complete Raw IP adversarial corpus.
- `bash dev/script/codex.sh test -n paclo.null-loop-native-test`: 2 tests,
  49 assertions, no failures/errors. Direct physical record extraction,
  `pcap_next_ex` pointer bytes and public raw bytes match for every record.
  Local libpcap 1.10.1 leaves both pseudoheaders unchanged; DLTs 0/108.
- This commit adds probes only. Linux x64/macOS ARM64/Linux ARM64 evidence is
  required before decoder implementation; source inference alone is insufficient.

## P08-D2 implementation and local verification (2026-10-14)

- Probe-only commit `9e36c04` / [PR #46](https://github.com/nantes-rfli/paclo/pull/46)
  completed [CI run 38577395767](https://github.com/nantes-rfli/paclo/actions/runs/38577395767)
  with all 12 jobs successful before decoder edits. Inspected Linux x64/macOS
  ARM64/Linux ARM64 logs: all 736 records in 12 captures have identical stored,
  direct native-pointer and public raw bytes; DLTs 0/108, no header conversion.
  Exact environment and per-file observations are in `p08-d2-native-evidence.edn`.
  Linux kernels 6.17.0-1022-azure/libpcap 1.10.4 (TPACKET_V3); macOS 26.6.2/
  libpcap 1.10.1; all host orders little. This is cross-endian input evidence,
  not validation on big-endian execution hosts or live interfaces.
- All AF/endian/version framing is in `paclo.linktype`, packed L3 offset 4.
  NULL recognizes a unique known uint32 AF under either order; reversing the
  exact known set 2/24/28/30 cannot produce another member. LOOP is strictly
  big endian. AF selects expected IP version before nibble validation. Unknown
  AF (including Linux 10) and AF/version mismatch are distinct failures.
  Full wrappers have `:null`/`:loop`, numeric `:address-family`, existing `:l3`;
  flow reuses numeric walkers without full/link maps. No published byte mutation,
  frame clone, synthesized Ethernet, OS inference or container-order guarantee.
  Unmeasured OSes, including OpenBSD, remain unsupported.
- Focused native/framing/raw/capture tests: 33 tests / 12,259 assertions passed.
  Final NULL/LOOP namespace: 8 tests / 10,003 assertions, including 300 prefix/
  arbitrary-byte cases and 200 unknown-AF cases, passed. Corpus covers all IPv6
  AFs/orders, malformed/truncated IP/L4, fragment/extension chains, DNS/TLS,
  numeric/full equality, array identity/snapshots, all capture paths, physical
  Classic writer bytes/metadata, independent blocking fan-out and P06/P07.
- First full check found one obsolete DNS test assuming DLT 0 was unsupported;
  changed that unsupported-input example to 9999, without changing DNS runtime.
  Final `bash dev/script/codex.sh check`: **428 tests / 15,738 assertions**,
  **10 JUnit tests** and real offline smoke passed. Existing Ethernet/cooked/Raw
  fixtures and behavior remain covered.
- First kondo pass found missing property declaration; added it. First lint
  found new measurement EDN formatting; formatted the artifact. Markdown check
  found line-length/blank-line violations, now corrected. Final full
  `bash dev/script/codex.sh lint` passed: kondo zero errors/warnings, Eastwood
  zero exceptions (existing warning classes), clean-ns/format and Markdown.
  npm access for markdownlint required running with network-capable permissions;
  no tooling version, threshold or gate was changed.
- `python3 test/resources/make_capture_format_fixtures.py --check`: **47 captures**
  (original 28 + cooked 4 + Raw 3 + NULL/LOOP 12) and manifests match bytes.
  `python3 -m unittest discover -s dev/script -p 'test_verify_doc_examples.py'`:
  15 tests passed; `python3 dev/script/verify_doc_examples.py`: **28 examples**
  passed, retaining all previous 26 and adding NULL/LOOP full and flow examples.
  Separate Markdown, local-link and `git diff --check` gates passed.
- `clojure -M:spotbugs`, `clojure -M:checkstyle`, `clojure -M:jacoco` and
  `JACOCO_MIN_LINE=0.25 clojure -M:jacoco-gate` passed: **43.8%** Java line
  coverage, unchanged 25% gate; no Java/dependency source change.
- Existing performance gate passed at **732.1 ms**, unchanged 1000 ms warning /
  1200 ms failure. Controlled same-DLT performance comparisons, package/consumer
  and implementation-head supported-platform CI follow below after completion.
- The initial probe commit attempt failed because `clj` needs missing rlwrap.
  A command-local `/private/tmp/paclo-d2-tools/clj` forwards unchanged arguments
  to `clojure`. The complete existing hook then passed 420 tests / 5809
  assertions, formatter, Markdown and kondo. No global hook/tool config changed.

Initial same-DLT measurements showed unchanged allocations but substantial Flow
variation: worst matching medians -37.2% (Raw UDP) and -28.1% (SLL2 TCP), with
other JVMs much closer. Both initial rounds are retained as
`p08-d2-initial-framing-performance-{1,2}.edn`; the exact runtime source delta
against D1 is `p08-d2-initial-decoder.patch`. No result was discarded. To limit
new overhead on existing dispatch, restored DLT_RAW's direct equality test,
put new-only minimum-size handling in a helper, and moved short-header prose
selection to the failure path helper. This keeps existing successful bounds
branches compact. JIT/inlining influence is a hypothesis, not established by
these timing results. This is confined to D2's added framing; it does not repair
P08-C Ethernet full behavior or issue #44. Measure the final sources separately.

- Final controlled comparisons: two rounds / 12 independent JVMs cover all six
  DLTs; [performance report](p08-d2-performance.md) includes every paired result.
  All existing matching allocations agree, all Flow variants allocate 280
  bytes/packet, all samples parse 50k packets with zero errors/drops, byte snapshots
  and full array identity pass. Ethernet UDP flow remains 3.6–8.6% lower, one
  Ethernet TCP flow median 16.6% lower; cooked UDP flow also has negative medians.
  These concerns remain disclosed, not called regression-free. New NULL/LOOP
  validation adds AF reading/membership/version consistency; no extra flow map
  or frame copy. No compiler cause is asserted. Final perf gate **573.5 ms**.
- `bash dev/script/codex.sh package` built the unchanged snapshot JAR. An isolated
  `/private/tmp/paclo-d2-consumer`, with only the JAR and declared dependencies
  under `clojure -Srepro`, verified jar: namespace resource origins, NULL both
  orders and LOOP, IPv4/IPv6, byte identity, DNS/TLS, numeric aggregates/Top-N,
  DNS normalization/window init, and native Classic writer/read bytes. It printed
  `:clean-null-loop-jar-consumer-ok`. `prepare` restored Java test classes after
  packaging. Source-level tests provide complete P06/P07 correlation/window and
  fan-out evidence; consumer checks packaging isolation.
- After the compact helper change, focused checks passed **25 tests / 11,072
  assertions**. Final full checks and documented examples are rerun on delivery
  sources. The new performance report needed one blank-line correction in
  Markdown; the gate remains unchanged.

Delivery-source reruns: `check` passed again with 428 tests / 15,738 assertions,
10 JUnit and offline smoke; all 28 executable examples passed again. Fixture,
documentation-parser, local-link and diff checks pass. Final full lint rerun
includes the corrected performance report. The implementation commit will run
the unchanged complete pre-commit hook using the local noninteractive clj shim.

Implementation publication and supported-platform CI:

- Committed `93e5cde64b3ce88de5d57b24230d3aabb818cebd` after the complete unchanged
  hook passed 428 tests / 15,738 assertions, formatter, Markdown and kondo.
  Pushed to PR #46 and rewrote its description around the final behavior,
  verified native contract, diagnostics, performance concerns and local checks.
- [Implementation CI run 38582258137](https://github.com/nantes-rfli/paclo/actions/runs/38582258137)
  passed **all 12 jobs**. Inspected every job and failed-step list: none failed,
  including the coverage job's existing continue-on-error path. Java/static,
  docs/cljdoc, compatibility matrix, ARM64 monitor, Eastwood/coverage, three
  performance shards, 27-scenario merge and required aggregate succeeded.
- Linux x64/ARM64 (kernel 6.17.0-1022-azure, Temurin 21.0.12.1, libpcap 1.10.4)
  each passed **428 tests / 15,744 assertions**. macOS 26.6.2 ARM64 / JDK
  17.0.20.1 / libpcap 1.10.1 passed **428 / 15,738**. The Linux +6 assertions
  are existing `/dev/full` writer checks. All three repeat physical/native/raw
  byte equality on all 12 fixtures, with native DLT 0/108 and little host order.
- CI verified all 47 fixtures, 500 new property cases, unchanged raw arrays,
  writer round trips, capture paths, full/flow agreement, DNS/TLS, fan-out and
  P06/P07. All **28 executable docs** passed. Java coverage is **43.8%** against
  unchanged 25%; CI performance gate is **501.8 ms** against 1000/1200 budgets.
  Existing 27 quick scenarios merged. CI/local observations are not speedups.
- A complete branch whitespace check (`git diff origin/main --check`) found
  single-space blank context lines inside the initial-source patch artifact.
  Removed those outer-file trailing spaces; applied both original and cleaned
  patches independently to D1 source copies under /private/tmp and confirmed
  byte-identical reconstructed runtime files. The initial measurement source
  remains exact; no runtime or measurement data changed. Branch diff check passes.
- This final evidence update changes documentation and patch-artifact whitespace
  only. P08-D2 remains in-progress solely for independent review/merge; final
  evidence-head checks are maintained on PR #46. No merge, release, tag, version
  change, live/NIC claim or unsupported-platform mapping was performed.

## P08-E1 design and local verification (2026-10-15)

- Started with a clean supplied checkout. `bash dev/script/codex.sh doctor`
  passed: macOS 15.4.1 x86_64, Temurin 21.0.12.1, Clojure 1.12.1, real offline
  native read. All optional lint tools are available. Fetched main and created
  `codex/p08-e1-pcapng-contracts` at `ccebcad`. Verified PR #46 merged
  2026-10-14 15:06:49 UTC (2026-10-15 JST), merge SHA
  `ccebcad829fe9dc8ef786a24489be4a2ae8bfff8`. No extra worktree.
- Read contributing/v1/accepted plan, P08-A/D2 evidence, native capture/core/
  framing implementation and existing fixture generators/tests. Added
  `p08-e1-pcapng-contracts.md` as the authoritative proposed metadata/time/
  reader/writer contract. P08-A stays historical evidence; v1 stays implemented
  behavior. Corrected D2 merged status and added E1/E2/E3 dependencies/handoffs.
- Decision: separate closeable single-consumer ordered event reduction, qualified
  Section/Interface references, owned bytes/options, no global descriptor cache.
  Exact ticks use arbitrary integer arithmetic with decimal/binary resolution
  and signed offset; compatibility microseconds floor exact time. Absence is
  explicit and different from epoch zero. Separate writer modes preserve known
  semantics, require explicit losses/authoring, reject unrepresentable time,
  missing metadata, no-copy/context conflicts and publish paths atomically.
  Unknown semantics and byte-identical file reproduction are not guaranteed.
- Added ten small deterministic captures and SHA-256 manifest, six Python
  physical-wire/arithmetic tests (500 seeded random cases plus boundaries), and
  three Clojure characterization tests automatically discovered by current CI.
  Existing 47 fixtures and quality gates are unchanged. Large metadata is built
  only in test memory: 4096/4097 IDBs and >8 MiB opaque data. These tests verify
  corpus/math, not a future parser memory ceiling or writer preservation.
- Initial focused run disproved an assumed SPB [0 0] with nonzero offset:
  installed libpcap 1.10.1 returns **[-7 0]** for SPB under interface-0 offset
  -7. Corrected the native characterization/manifest and recorded this observation
  separately from the proposed absent-time contract. Fixed a test looking for
  nested error data: current report flattens :reason. Final focused
  `bash dev/script/codex.sh test -n paclo.pcapng-contract-design-test`:
  **3 tests / 9 assertions, zero failures/errors**, plus six Python tests.
- `python3 test/resources/make_pcapng_contract_fixtures.py --check` and
  `python3 test/resources/test_pcapng_contract_fixtures.py`: passed. Rich native
  output is [1699999993 123456], [1700000000 125976], [-7 0], only existing six
  raw keys, lengths 64/1500, 64/64, 64/64. Mixed endian/DLT/snaplen capture
  yields one valid packet then :pcap-read-failed, not successful EOF.
- `bash dev/script/codex.sh check`: **431 Clojure tests / 15,747 assertions**,
  **10 JUnit tests**, real offline smoke all passed. Includes original native
  inventory/precision probes and unchanged decode/writer/lifecycle regressions.
- `python3 dev/script/verify_doc_links.py`: passed. Full
  `dev/script/mdlint.sh`: 36 files, zero errors (registry access used the approved
  network invocation). First full lint reached kondo zero errors/warnings,
  Eastwood zero exceptions with existing warning classes, clean namespaces,
  then found one new-test indentation difference; corrected and reran.
- E2 implements the reviewed bounded source/exact contracts and proves actual
  lifecycle/state ceilings. E3 adds writer/atomic failure tests and semantic
  round trips. Detailed steps/acceptance are in the E1 document. No production
  reader/writer, public API, version, dependency or CI configuration changes.
  No performance issue, issue #40, P09/P10, release, live capture or NIC work.
  E1 remains in-progress solely for independent review/merge; next implementation
  item is E2 after that prerequisite. Other platforms remain unmeasured in E1
  until its CI actually runs; prior D2 matrix evidence is not E1 validation.
- Final `bash dev/script/codex.sh lint` passed with approved network access:
  kondo zero errors/warnings, Eastwood 254 existing warnings/zero exceptions,
  clean-ns and format no differences, full Markdown zero errors. Restricted
  attempts failed only at npm registry DNS (ENOTFOUND registry.npmjs.org);
  this was resolved by the network-enabled run, not counted as a passing check.
- `python3 dev/script/verify_doc_examples.py`: all **28 maintained examples**
  passed. Proposed E1 snippets are explicitly nonimplemented design examples
  in dev docs, not advertised runnable public API.
- Wire corpus sizes measured with the in-memory generator: 4096 IDBs produce
  345156 bytes; 4097 produce 345240; >8 MiB opaque case produces 8388764.
  These are encoded sizes, not JVM heap/allocation/throughput measurements.
  `git diff --check` passed. Generated Python bytecode was removed; no unrelated
  work or production files were changed.
- Initial commit stopped before creation because the existing pre-commit hook
  invokes `clj`, whose interactive launcher requires unavailable rlwrap here.
  After the full equivalent tests and lint/format passed via `clojure`, used
  the hook's existing SKIP_TESTS/SKIP_FMT/SKIP_KONDO switches to avoid duplicate
  checks; hook Markdown lint remains enabled. No hook or gate configuration
  changes, missing-tool success claims or interactive package installation.

## P08-E1 PR and implementation CI evidence (2026-10-15)

- Implementation commit `baaade4` is published on
  [PR #47](https://github.com/nantes-rfli/paclo/pull/47). The requested title and
  description include design rationale, alternatives, measured native loss and
  E2/E3 acceptance. No merge performed; E1 waits only for independent review/merge.
- [CI run 38591738169](https://github.com/nantes-rfli/paclo/actions/runs/38591738169)
  reports all 12 jobs successful. Read its actual logs with `gh run view --log`:
  Linux x64/JDK21 and ARM64/JDK21/libpcap 1.10.4 pass 431 tests / 15753
  assertions; macOS ARM64/JDK17/libpcap 1.10.1 passes 431 / 15747. The six
  additional Linux assertions exercise existing /dev/full writer checks.
  All three run six Python tests and emit exactly the local rich timestamps,
  including absent-on-disk SPB normalized to [-7 0]. Full documentation executes
  28 examples; build/Java quality/coverage/packaging/performance jobs succeed.
- Log inspection uncovered an existing dedicated Eastwood job limitation despite
  its green status: ClassNotFoundException paclo.jnr.PcapConfigLibrary, one
  exception, 92 namespaces unanalyzed. Confirmed unchanged main `ccebcad` has
  the same exception and 91 unanalyzed namespaces on
  [baseline CI run 38586471628](https://github.com/nantes-rfli/paclo/actions/runs/38586471628).
  This job lacks Java compilation and does not fail on the analysis exception.
  It is **not counted as completed lint**. Full local lint compiled the classes
  and finished with zero exceptions; CI configuration remains unchanged per E1
  scope. A separate CI maintenance task should compile bindings and enforce
  complete analysis. PR/design disclose the exact limitation.
- This evidence follow-up edits documentation only; final PR-head check status
  is maintained on the PR. E2 actual ownership/state bounds and E3 preservation/
  publication remain unimplemented, not validated by E1 tests. No live/NIC,
  other platform, release, performance target or issue #40 claim is added.

## Issue #48: Eastwood incomplete-analysis CI gate (2026-10-15)

- Scope: independent CI maintenance from latest main `2e7e357`, after PR #47
  merged. Supplied checkout was clean; branch
  `codex/fix-eastwood-incomplete-analysis`; no extra worktree. Read AGENTS,
  CONTRIBUTING, v1 contract, accepted plan, existing build/runner/workflow and
  [issue #48](https://github.com/nantes-rfli/paclo/issues/48). No P08-E2/E3,
  production API, dependency, version, release, performance threshold or merge.
- Dedicated Eastwood runner now checks the Eastwood 1.4.3 `:some-errors` result
  and throws unless it is explicitly false. The pinned implementation counts
  analyzer exceptions, linter errors and runtime exceptions; aborted namespace
  traversal retains the triggering exception in that count. `shutdown-agents`
  remains in `finally`. All roots, `[:all]` linters and the two intentional
  excludes are unchanged; existing warnings remain informational.
- CI installs the same libpcap prerequisite used by native/test jobs (namespace
  loading initializes JNR libraries), compiles bindings via the established
  `clojure -T:build javac`, runs the regression probes, then full Eastwood.
  `build` now needs `eastwood-lint` and requires its result to be `success`,
  while retaining every existing required job, `if: always()` and threshold.
- `python3 dev/script/test_eastwood_runner.py`: four real isolated JVM tests
  pass (52.237 s on this local run with other checks active). Broken class
  analysis reports one exception and one dependent namespace unanalyzed, and
  the actual CI entrypoint exits 1. A top-level evaluation exception also
  exits nonzero. Complete analysis and warning-only analysis exit 0. The
  fixture roots alone are overridden; production linters/excludes are used.
  Before adding result enforcement, the negative probe reproduced exit 0
  despite one exception/one unanalyzed namespace. An initial warning assertion
  expected a colon before the printed linter name; corrected to its real format.
- `bash dev/script/codex.sh doctor`: passed on macOS x86_64, Temurin 21.0.12.1,
  Clojure CLI 1.12.5.1654/library 1.12.1; real offline native read and lint tools.
  `bash dev/script/codex.sh check`: passed 10 JUnit tests, 431 Clojure tests /
  15,747 assertions, and real offline smoke; no failures/errors.
- `clojure -M:eastwood`: exit 0, 254 existing warnings, zero exceptions.
  Independent comparison of namespace declarations in all four roots against
  the actual `== Linting ... ==` log entries finds **96 intended / 96 analyzed**,
  no missing/extra namespaces and no `left unanalyzed` report.
- CI YAML parsed successfully with Ruby YAML. Executed the actual aggregate
  shell with Eastwood result success/failure/cancelled/skipped: exits 0/1/1/1.
  Asserted compile and regression steps precede lint. Wrapper shell syntax and
  help passed; unknown command exits 2 as required. Local Markdown links pass.
- Timing baseline is main
  [CI run 38594408077](https://github.com/nantes-rfli/paclo/actions/runs/38594408077):
  Eastwood job **19 s**, lint step **13 s**, but only four namespaces attempted,
  one ClassNotFoundException and 92 namespaces unanalyzed. Required build
  completes **197 s** after workflow creation; workflow **198 s**. This green
  baseline is not successful lint coverage. Updated Linux times and final CI
  outcomes will be recorded after the PR run; local timings are not Linux CI
  performance evidence. Next: PR CI, independent review; no feature work here.
- Final `bash dev/script/codex.sh lint`: passed, kondo zero errors/warnings,
  Eastwood 254 warnings/zero exceptions, clean-ns/format no changes, Markdown
  36 files/zero errors. The restricted attempt failed at npm registry DNS
  (`ENOTFOUND registry.npmjs.org`); the network-enabled rerun passed. Missing
  network was not counted as success. `git diff --check` passes. Removed only
  Python bytecode generated by this task's tests.
- The installed pre-commit test launcher uses `clj`, which needs unavailable
  `rlwrap`. After complete equivalent checks via `clojure` and full lint, use
  the hook's existing SKIP_TESTS/SKIP_FMT/SKIP_KONDO switches to avoid repeating
  those verified checks; leave its Markdown check enabled. No hook/gate edits.

## Issue #48 PR and Linux CI evidence (2026-10-15)

- Implementation `1646588` is published on independent
  [PR #49](https://github.com/nantes-rfli/paclo/pull/49), titled
  `fix: make Eastwood CI fail on incomplete analysis`, with `Fixes #48`.
  [CI run 38596934662](https://github.com/nantes-rfli/paclo/actions/runs/38596934662)
  passes all **12 jobs**, including required `build`, build/Java/package gates,
  documentation, Linux x64/JDK21, macOS ARM64/JDK17, Linux ARM64 monitor,
  all performance shards/merger, coverage and Eastwood. No merge performed.
- Read the actual Linux Eastwood job log, not only its green conclusion:
  Java compilation succeeds on the clean checkout; four negative/positive
  JVM probes pass in **18.555 s**, including the intentional analysis error
  with **exit 1** and one namespace unanalyzed. The following full lint runs
  through **96/96 intended namespaces**, with no missing/extra names,
  **254 existing warnings / zero exceptions**, no ClassNotFoundException and
  no unanalyzed namespace. Compared all source/test declarations to log names.
- Linux compatibility log confirms **431 tests / 15,753 assertions**, zero
  failures/errors, plus the existing six Python fixture tests. Native platform,
  docs/package/coverage/performance job results remain enforced by existing CI;
  none of their dependencies or thresholds was changed. No live capture/NIC
  throughput or new platform/performance claim is made by this maintenance fix.
- Same-workflow cached-run timing comparison (single samples; runner/queue
  variation applies): Eastwood job **19 -> 68 s (+49 s)**; lint step
  **13 -> 27 s (+14 s)**. New libpcap setup **10 s**, Java compilation **4 s**,
  regression step **19 s**. Eastwood's own complete lint reports **24,112 ms**,
  versus the aborted baseline's **7,358 ms**. This replaces incomplete coverage
  with complete analysis and actual failure enforcement.
- Required `build` completed **197 -> 219 s (+22 s)** after workflow creation;
  total workflow **198 -> 220 s (+22 s)**. Eastwood finishes at 72 s after
  creation and does not determine the critical path in this run; macOS
  compatibility started 35 s after creation and ran 179 s. These two samples
  do not isolate a causal overall runtime delta. Baseline and updated run URLs
  above retain step/job timestamps for review.
- This documentation-only evidence update records the completed maintenance
  item and next action (independent PR #49 review). The feature queue remains
  outside this task; no P08-E2/E3 or other implementation. Final evidence-head
  CI status will be maintained in the PR description without another log-only
  commit cycle. Review before merging; no publication/release authorized here.

## P08-E2: bounded metadata-aware PCAPNG reader (2026-10-15)

Started from clean supplied checkout, fetched latest main `008c93b`, and created
`codex/p08-e2-pcapng-reader`. PR #47 merged as `2e7e357`, PR #49 as `008c93b`;
verified merge records through GitHub. Read CONTRIBUTING, v1 API, accepted plan
and authoritative E1 contracts before implementation. No worktree, dependency,
native binding, existing capture/Classic writer API, CI gate or version change.

Implementation: internal FileChannel block cursor plus `paclo.pcapng/open-source`
and `source-info`. One synchronous consumer, no Seqable/Iterable/producer thread,
only the first bounded SHB read at open. Checked framing, byte-order switching,
finite section lengths, current-section interface registry, raw ordered options,
EPB/SPB, permitted opaque blocks, qualified references and explicit unsupported
policies. Closed Linux/macOS LINKTYPE table; unknown mapping stays explicit nil.
Integer uint64 ticks/resolution/int64 offset and derived microseconds preserve
submicrosecond metadata and SPB absence. Every published array is owned.

Cancellation atomically competes with delivery claims; it closes the channel
without waiting on a claimed consumer call and releases retained parser state.
Full/reduced/error reduction owns finally cleanup, exception identity/suppression,
and leaves transducer completion to transduce. Status retains only bounded data,
never raw blocks/arrays, arbitrary consumer messages or exception objects.

Compared downloaded IETF draft 05/06 texts. EPB process/thread option 8 remains
8 bytes and becomes repeatable in 06; added a minimal E1 clarification and test.
Absent option terminators are legal at a block boundary; padding octets are
unspecified, so extents are checked without requiring zero values. NRB/ISB opaque
fixed minima are checked; invalid UTF-8 stays raw without lossy conversion. These
clarifications are recorded in E1, not an expansion into writer/live behavior.

Reader acceptance uses the existing 47 fixture corpus (full native regressions)
and ten E1 fixtures; production reader tests reuse every existing PCAPNG fixture.
Tests include all 256 resolution bytes, uint64/int64 extremes, mixed sections,
all truncation prefixes, declared section bounds, singleton/fixed/minimum options,
unknown/raw octets, caplen/wire/snaplen consistency, all seven exact resource
boundaries, default 4096/4097 option/interface counts and pre-body limit rejection.
Seed 80802 runs 500 exact rational floor checks; seed 80803 runs 50 ordered
qualified-reference cases. Lifecycle tests cover descriptor/packet/opaque reduced,
completion, primary/suppressed/sole close errors, parse/read/consumer errors,
repeat/concurrent consume, unused close, blocked consumer/read cancellation and
instrumented zero post-reduced reads.

Heap evidence: a separate `java -Xmx48m` process streams 246336000 wire bytes,
6000 sections, 12000 IDBs and 6000 opaque blocks with a three-number accumulator.
No event collection. Max active interfaces 2 and metadata policy accounting
33584 bytes, zero after close; no cumulative section/opaque retention. This
workload verifies bounded streaming, not a worst-case exact JVM footprint or
throughput/live/NIC target. The probe runs in the unchanged platform suites.

Local macOS x86_64, Temurin 21.0.12.1, Clojure 1.12.1, libpcap 1.10.1:

| Command / evidence | Result |
| --- | --- |
| `git status --short --untracked-files=all` | Clean before implementation |
| `bash dev/script/codex.sh doctor` / `prepare` | Pass; offline read and prerequisites |
| `bash dev/script/codex.sh test -n paclo.pcapng-test` | 15 tests, 903 assertions, zero failures/errors, including heap subprocess |
| `bash dev/script/codex.sh check` | 10 JUnit tests; 446 Clojure tests, 16650 assertions; smoke passes |
| Full Eastwood analysis | 100 namespaces analyzed; zero exceptions; informational warnings retained |
| `python3 dev/script/test_eastwood_runner.py` | Four JVM probes pass; negative analysis exits 1 and reports unanalyzed dependent namespace |
| `clojure -T:build spotbugs` / `checkstyle` | Pass |
| `JACOCO_MIN_LINE=0.25 clojure -T:build jacoco` / `jacoco-gate` | Pass, line coverage 43.8%, same CI 25% gate |
| Both fixture generators `--check` | 47 existing and ten E1 captures/manifest verified |
| `python3 test/resources/test_pcapng_contract_fixtures.py` | Six independent Python wire/Fraction tests pass |
| Doc example checker parser tests | 15 Python tests pass |
| `dev/script/mdlint.sh` | Initial sandbox npm DNS failure; authorized retry passes, 37 files / zero errors |
| `python3 dev/script/verify_doc_links.py` / `git diff --check` | Pass |

Final full lint, corrected executable examples, quiet performance measurement
and PR/platform CI are still pending at this checkpoint. First performance run
while multiple documentation/Eastwood JVMs competed: 1850.0 ms > unchanged
1200 ms fail budget. Record both attempts; no threshold relaxation. Initial doc
checks exposed missing preloaded pcapng alias and trailing Clojure comments
swallowing the checker's wrapper; corrected harness alias and example formatting.
No final passing claim for those commands until successful process exits.

Commit hook note: `.githooks/pre-commit` invokes `clj`, which failed before
running tests because this local installation lacks rlwrap. The full wrapper
`check` and `lint` already ran the equivalent tests/format/Markdown/kondo checks;
use the hook's documented SKIP_TESTS/SKIP_FMT/SKIP_MD_LINT/SKIP_KONDO flags for
commit only to avoid duplicate runs and automatic whole-repository edits. No
tracked hook/CI configuration or required gate is changed.
