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

### Final local and PR verification

Implementation commit `1bd6994` created independent
[PR #50](https://github.com/nantes-rfli/paclo/pull/50), initially draft during
verification. All Reader implementation steps are complete; independent review
and merge remain. No merge was performed. The follow-up commit records evidence
and clarifies opaque-vs-parsed-option accounting only; production/tests remain
identical to the verified implementation.

- Final `bash dev/script/codex.sh lint` exits 0: kondo zero errors/warnings,
  all 100 Eastwood namespaces analyzed, 366 informational warnings, zero
  exceptions; clean-ns/format dry runs clean; Markdown 37 files / zero errors.
- Final `python3 dev/script/verify_doc_examples.py` exits 0: all 31 maintained
  examples, including three new PCAPNG examples, pass. Fifteen parser tests pass.
- After confirming all competing validation JVMs exited, unchanged
  `bash dev/script/codex.sh perf` exits 0 at **554.5 ms**, below warn 1000/fail
  1200 ms. The earlier concurrent 1850.0 ms failure is retained above. This
  existing offline gate is not a new Reader throughput or live-capture claim.
- Final Markdown/link/diff checks pass. No tracked hooks, CI config, source
  version or default dependency graph were changed.

[CI run 38663798446](https://github.com/nantes-rfli/paclo/actions/runs/38663798446)
for `1bd6994` completed successfully: **all 12 jobs**, including required build
aggregate, full Eastwood, Java quality/JaCoCo/package checks, documentation,
coverage and all three existing performance measurement jobs plus results.

| Platform | Actual runtime/native environment | Suite |
| --- | --- | --- |
| Linux x64 | JDK 21.0.12.1, libpcap 1.10.4 | 446 tests / 16656 assertions, zero failures/errors |
| macOS ARM64 | JDK 17.0.20.1, macOS 26.6.2, libpcap 1.10.1 | 446 / 16650, zero failures/errors |
| Linux ARM64 | JDK 21.0.12.1, libpcap 1.10.4 | 446 / 16656, zero failures/errors |

All platform suites include the separate 48 MiB heap probe and production Reader
regressions. The six extra Linux assertions are unchanged /dev/full tests.
CI Eastwood completed all 100 namespaces with zero exceptions; its four negative
runner probes preserve Issue #48's exit/error/unanalyzed-namespace gate. CI docs
execute all 31 examples. No live/NIC, big-endian host or other-OS validation.

Next: independent review of PR #50, followed by user-authorized merge. P08-E3
remains blocked pending that review/merge; no writer/P09/P10 implementation.

## P08-E2 independent review follow-up (#51/#52, 2026-10-15)

PR #50 review of `c42b82a` requested two corrections before merge. Started with
clean status on the supplied PR branch and reran `bash dev/script/codex.sh doctor`
successfully (macOS x86_64, Temurin 21.0.12.1, Clojure 1.12.1, offline native read).
Read contributor/API/plan/E1 contracts and both complete review comments/issues.
No new worktree, existing API/native binding, dependency, version or CI gate change.

Issue #51: verified draft 06 section 4.2 permits repeated eight-byte IPv4 and
seventeen-byte IPv6 address options. The actual reviewed head already excludes
codes 4/5 from both the production singleton set and negative duplicate test;
GitHub and local cursor blob both equal `07e7357fd1f5623e5fc58cba9f618d8114ff3e67`.
Positive regression tests pass before the behavior correction, so the reported
rejection could not be reproduced at this head. Added mixed IPv4/IPv6 sequences
(including identical repeats) under both byte orders, preserving exact option
order/octets, distinct owned copies, fixed lengths, count/byte/section accounting
at limit and one below. Existing resolution/offset singleton rejection remains.
Added an explicit source comment and public contract explaining that distinction.

Issue #52: reproduced late packet-ceiling enforcement with actual temporary
files whose EPB/SPB payloads are missing or partial. An allocation seam around
ByteBuffer allocation preserves baseline behavior while tests record allocation
sizes and FileChannel read offsets/requests. Before the fix, the two selected
review tests execute 274 assertions with 160 failures, all in the packet-prefix
test; the address option test passes. Failures show a whole-body allocation/read
and `:truncated-block` instead of the required packet `:limit-exceeded`.

Fix: after common block/section/opaque checks, read only EPB's 20-byte fixed body
prefix or SPB's four-byte original length. Resolve the interface, compute caplen,
check the packet ceiling, wire length/snaplen and padded declared body extent,
then allocate/read the remaining block. Validated layout is reused for packet
construction; timestamp/payload/options/trailer validation and ownership remain.
The common max-block ceiling still precedes packet prefix/body allocation.

Added both-endian EPB/SPB tests at declared caplen 64 and 65536 against a ceiling
of 8, snaplen zero/nonzero, absent/three-byte payloads, every partial fixed-prefix
length, invalid wire/snaplen/declared extents, too-short declared fixed headers,
and valid zero-snaplen SPB. Allocation/read traces are reset after IDB delivery,
so packet failures must show only [8 20] or [8 4] buffer allocations and fixed
prefix reads, with no payload/trailer request. A test allocation guard catches
regressions before large allocations. Source failure/close status is checked.

Verification and same-PR re-review handoff are pending at this checkpoint.
Original 12-job green runs above are historical evidence, not acceptance of
these corrections. PR remains unmerged and both review threads remain for the
independent reviewer to assess.

### Local correction verification

- `bash dev/script/codex.sh test -n paclo.pcapng-test`: 18 tests / 1323 assertions,
  zero failures/errors, including the 48 MiB streaming probe.
- `bash dev/script/codex.sh check`: 10 JUnit tests; 449 Clojure tests / 17070
  assertions; offline smoke succeeds; exit 0.
- `bash dev/script/codex.sh lint`: exit 0; kondo clean, all 100 Eastwood namespaces
  analyzed with 383 informational warnings and zero exceptions; clean-ns/format
  dry runs clean, Markdown 37 files / zero errors.
- Both fixture generators `--check` preserve all 47 existing and ten E1 captures;
  six Python physical-wire/Fraction oracle tests pass.
- `python3 dev/script/verify_doc_examples.py`: all 31 executable examples pass.
- With other validation JVMs finished, `bash dev/script/codex.sh perf`: exit 0,
  **523.6 ms**, below unchanged 1000 ms warn / 1200 ms failure thresholds.
- Local link and diff checks pass. Java/native sources and all CI gates remain
  unchanged; the same PR/platform CI will verify the published correction head.

The commit hook's documented skip flags are used only for duplicate checks and
whole-repository auto-formatting after these equivalent checks have passed;
the local `clj`/rlwrap limitation recorded above remains unchanged. No hook edits.

### Correction CI and re-review handoff

Published correction `c0353c5` on the existing PR #50.
[CI run 38684190442](https://github.com/nantes-rfli/paclo/actions/runs/38684190442)
completed with **all 12 jobs successful**, including required build aggregate,
unchanged Eastwood/Java quality/package/coverage/documentation gates and every
existing performance measurement/results job. Actual platform logs confirm:

| Platform | Clojure suite | Result |
| --- | --- | --- |
| Linux x64 / JDK 21 | 449 tests / 17076 assertions | Zero failures/errors |
| macOS ARM64 / JDK 17 | 449 / 17070 | Zero failures/errors |
| Linux ARM64 / JDK 21 | 449 / 17076 | Zero failures/errors |

Each suite includes all new prefix/address regressions and the existing 48 MiB
heap, ownership and timestamp/property tests. The six Linux-only assertions are
unchanged /dev/full checks. CI Eastwood analyzes all 100 namespaces with zero
exceptions (383 informational warnings); Java line coverage remains 43.8% against
the unchanged 25% threshold; the existing performance gate passes at 810.0 ms
against warn 1000 / fail 1200; all 31 executable documentation examples pass.

PR description records the #51 baseline finding and positive coverage separately
from the #52 production correction, plus current verification. Both inline
threads and tracking issues are left for independent reviewer confirmation.
PR stays open for independent re-review; no merge was performed.
The subsequent commit updates only this evidence/plan; production and tests
remain exactly `c0353c5`. Next: independent re-review of PR #50.

## P08-E3 metadata-aware PCAPNG writer (2026-10-15)

User-authorized scope: implementation, tests, English documentation and an
independent PR; no merge/release, Classic writer changes, P09/P10 or performance
issue work. Started with a clean supplied checkout and doctor passing on macOS
x86_64/JDK 21.0.12.1/Clojure 1.12.1/libpcap 1.10.1. Fetched latest main
`8de22e0` (merged PR #50) and created `codex/p08-e3-pcapng-writer` in that checkout.
Read CONTRIBUTING, public API contract, accepted plan and authoritative E1.
No dependency, version or CI-gate changes.

### Implementation and policy decisions

- Added public `(pcapng/write-pcapng! events path [opts])`, consuming one ordered
  event reduction without collecting input. SHB/IDB/EPB/SPB, sections/orders,
  interface ordinals/LINKTYPEs/snaplen, uint64 ticks, signed offsets/resolutions,
  absence, ordered raw options and permitted opaque bodies are encoded.
- Preserve is default; lossy requires explicit drop categories and bounded counts;
  author requires descriptors and permits only exact integral conversion from a
  complete integer microsecond pair when the exact timestamp key is absent.
  Explicit nil is not a fallback. Conflicting or malformed metadata is rejected
  before drops. Declared changed context refuses opaque dependencies unless
  explicitly dropped. Noncopyable codes derive from wire codes, not caller labels.
- Shared internal cursor validation checks constructed block bodies before writes;
  no Reader/native behavior or Classic writer changes. Input section lengths are
  normalized to -1; padding is zero and terminators omitted. Semantic preservation
  is conditional on honest caller declarations; undisclosed edits/subsets are not
  detectable and no hashes/provenance/index are retained.
- Java ATOMIC_MOVE may replace a racing destination. Used the existing JNR
  dependency for exclusive atomic rename: Linux renameat2 flag 1 (NOREPLACE),
  macOS renamex_np flag 4 (EXCL). Default filesystem only, same-directory temp,
  no copy/link/move fallback and no replacement API. Unsupported operations fail.
  Reviewed Linux rename(2) and Apple's xnu bsd/sys/stdio.h flag declarations.
- Writer owns temp/output and flush/close/publication/cleanup. Original input/I/O
  exception identity is preserved; suppressed context includes output coordinates
  and temp path, with secondary close/cleanup failures. Source reduction owns
  close. An internal dynamically bound terminal observer rejects incomplete Paclo
  source reduction even through synchronous eduction; declared lossy/author
  subsets can deliberately stop with reduced. Custom reducibles own undisclosed
  upstream completion and Closeables; no hidden resource lookup is attempted.
- Writer retains only bounded current block/event and active-section descriptors;
  section changes release the registry. Counts have no unbounded detail list.

### Verification checkpoint

- Initial focused Writer suite: 16 tests / 350 assertions, zero failures/errors.
  Includes all valid E1/P08-A/container/framing PCAPNGs through E2->E3->E2,
  independent Python struct-based wire comparisons, seed 80803 / 120 exact-time
  cases, loss policies, timestamp/descriptor/reference errors, I/O failures,
  primary/suppressed cleanup, ownership, eduction and limits.
- Separate 48 MiB process streams 6000 sections / 12000 interfaces / 6000 opaque
  blocks, 246264000 bytes through Reader->Writer. Maximum active registry is two
  interfaces / 33572 accounting bytes, with no event collection. This is bounded
  workload evidence, not live capture, other-OS or throughput validation.
- Corpus generators --check verify 28 capture, four cooked, three Raw IP,
  twelve NULL/LOOP and ten E1 captures/manifests. Six Python E1 oracle tests pass.
- Documentation parser: 15 tests pass. Local Markdown links/anchors pass.
- SpotBugs, CheckStyle, JaCoCo and unchanged 25% gate pass (43.8% Java line coverage).
- Final focused Writer suite: 19 tests / 558 assertions, zero failures/errors.
  Actual ZIP-provider refusal, dangling-symlink and two-writer races pass, as do
  the default 4096/4097 interface boundary tests. Every invalid-metadata/loss test
  also asserts no destination and no sibling temp remains. Reuses the already
  validated encoded block when no drops occur, avoiding duplicate block buffers.
- Initial full check passes: 10 JUnit tests, 465 Clojure tests / 17421 assertions,
  offline smoke. Final check reruns with the additional cases/current encoder.
- All 33 executable documentation examples pass, including preservation and
  authoring. Markdown lint (37 files) passes after correcting three extra blank
  lines. Eastwood initially analyzes all 103 namespaces with 441 informational
  warnings and zero exceptions; final lint runs on the final tests/encoder.

### Initial local validation and implementation CI

Implementation `c44bf5b` created independent [PR #53](https://github.com/nantes-rfli/paclo/pull/53),
initially draft during final gates. These initial gates pass; final review below
subsequently identifies a padding-ambiguous SPB case. PR remains unmerged. This evidence follow-up updates only
plan/log and the writer docstring's complete drop-category list; behavior/tests
remain identical to `c44bf5b`.

| Command | Final result |
| --- | --- |
| `bash dev/script/codex.sh check` | Exit 0; ten JUnit tests; 468 Clojure tests / 17628 assertions, zero failures/errors; offline smoke passes |
| `bash dev/script/codex.sh test -n paclo.pcapng-writer-test` | Exit 0; 19 tests / 558 assertions, including 48 MiB Reader-to-Writer probe |
| `bash dev/script/codex.sh lint` | Exit 0; kondo clean, all 103 Eastwood namespaces, 441 informational warnings / zero exceptions, clean namespace/format dry runs, Markdown 37 files / zero errors |
| `python3 -B dev/script/test_eastwood_runner.py` | Four probes pass; deliberate failed analysis exits 1 and reports one unanalyzed namespace |
| `python3 dev/script/verify_doc_examples.py` | All 33 runnable examples pass |
| Documentation parser tests | 15 tests pass |
| `TMPDIR=/private/tmp python3 -B -m unittest discover -s dev/script -p 'test_verify_doc_links.py'` | Nine tests pass; canonical temp directory avoids macOS /var symlink alias in the unchanged test fixture |
| `python3 -B dev/script/verify_doc_links.py` / `git diff --check` | Pass |
| `clojure -M:spotbugs`, `clojure -M:checkstyle`, `clojure -M:jacoco`, `JACOCO_MIN_LINE=0.25 clojure -M:jacoco-gate` | Pass; Java line coverage 43.8% against unchanged 25% gate |
| `bash dev/script/codex.sh perf` | Exit 0; 460.3 ms, below unchanged 1000 warn / 1200 fail; competing validation JVMs finished first |
| `bash dev/script/codex.sh package` | Exit 0; JAR contains public PCAPNG/core namespaces, writer/cursor and compiled native bindings |
| Independent JAR consumer `clojure -Srepro -M consumer.clj` | Exit 0; only local/root packaged JAR in /private/tmp/paclo-e3-consumer-c44bf5b; resource URLs use jar protocol; three rich PCAPNG packets retain exact time/absence, four Classic packets round-trip |
| cljdoc dry-run command from CI | Exit 0; :cljdoc-loaded |

Initial optional link-checker unit test used macOS's aliased /var temp path and
failed its existing fragment-only path fixture; the canonical TMPDIR command
above passes, with no checker changes. The actual repository link check passes
with both environments. Initial independent-consumer harness incorrectly assumed
Classic write-pcap! returns a count; corrected the harness to verify actual
read-back count, with no production change. Markdown's three extra-blank-line
findings were corrected before commit. No outstanding local failure.
The commit hook's documented SKIP_TESTS/SKIP_FMT avoid duplicate checks and
whole-tree formatting after equivalent wrapper checks passed; hook Markdown and
kondo still ran successfully. No hook or gate was changed.

[CI run 38688045251](https://github.com/nantes-rfli/paclo/actions/runs/38688045251)
on `c44bf5b` completes with **all 12 jobs successful**: build-checks,
documentation-checks, three performance-measurement shards, performance-results,
two compatibility jobs, arm64-monitor, eastwood-lint, coverage and required build.
Actual platform logs show:

| Platform | Suite | Result |
| --- | --- | --- |
| Linux x64 / JDK21 | 468 tests / 17634 assertions | Zero failures/errors |
| macOS ARM64 / JDK17 | 468 / 17628 | Zero failures/errors |
| Linux ARM64 / JDK21 | 468 / 17634 | Zero failures/errors |

Each includes Writer ownership/loss/atomic/no-clobber/48 MiB heap tests and all
existing Reader/Classic regressions. The six extra Linux assertions remain the
existing /dev/full checks. CI Eastwood analyzes all 103 namespaces with 441
informational warnings and zero exceptions. CI Java coverage is 43.8% / 25%;
existing decode performance gate passes at 562.6 ms / 1200 ms. All documentation
steps, including runnable examples and cljdoc, succeed. All 27 performance smoke
scenarios are retained across the three shards and results aggregate. No CI
configuration or quality/performance thresholds changed.

Next: independent review of PR #53. No merge, publication, live/NIC validation,
other-OS claims, byte-for-byte reproduction, issue repairs, P09/P10 or release.

### Final-review SPB correction

Review of the encoding path found that SPB has no explicit wire caplen, so the
shared wire validator alone cannot distinguish payload lengths in the same
four-byte padding cell. An authored one-byte packet with wire length two could
be accepted and reread as two bytes (the second byte synthesized from padding).
A separate consumer against the packaged `c44bf5b` JAR reproduces this exact
input-caplen 1 / output-caplen 2 case; this is implementation evidence, not a
hypothetical concern. Existing valid-fixture and CI successes above did not
exercise that invalid authored input.

Added an explicit equality check between array/caplen and SPB's inferred
min(wire length, nonzero snaplen), or wire length with snaplen zero, before any
block write/publication. No fallback, truncation, repair or timestamp conversion.
The regression covers seven invalid payload/snaplen cases in all three modes,
including adjacent lengths sharing padding, and six valid short/truncated/zero
snaplen SPBs. Invalid cases assert no destination/temp. Focused Writer suite
passes **20 tests / 627 assertions**. Full check and lint are rerunning; the
corrected implementation/platform CI is pending. Classic/decode, dependencies,
versions and CI gates remain unchanged.

### SPB correction final verification and review handoff

Correction `249acdc` completes every required gate. The final source/test change
is the explicit SPB payload check and its padding-cell regressions. No further
production changes follow this commit.

- `bash dev/script/codex.sh test -n paclo.pcapng-writer-test`: exit 0, **20 tests /
  627 assertions**, including all original round-trip/loss/failure/heap cases.
- `bash dev/script/codex.sh check`: exit 0, ten JUnit tests, **469 Clojure tests /
  17697 assertions**, no failures/errors, offline smoke passes.
- `bash dev/script/codex.sh lint`: exit 0; kondo clean, clean-ns/format dry runs
  clean; all **103 Eastwood namespaces**, 443 informational warnings, **zero
  exceptions**; Markdown 37 files / zero errors. The two additional warnings
  are boxed arithmetic in the explicit SPB length check; no linter is disabled.
- After validation JVMs exit, `bash dev/script/codex.sh perf`: exit 0,
  **760.9 ms**, below unchanged warn 1000 / fail 1200. The earlier 460.3 ms
  reading and CI measurements remain separate observations, not a comparison
  or new Writer throughput claim.
- `bash dev/script/codex.sh package`: exit 0. JAR contents include updated
  writer source with the SPB check, core/public cursor namespaces and native
  bindings. A fresh JAR-only `-Srepro` consumer in
  `/private/tmp/paclo-e3-consumer-249acdc` passes rich exact/absence round-trip,
  existing Classic four-packet round-trip and rejection/no-publication of the
  padding-ambiguous invalid SPB. Only the packaged local/root dependency is used;
  namespace resources use jar protocol and no checkout source/test path.
- Repository link/diff checks pass. Fixture generators/oracles and the 48 MiB
  probes run again in the full suite. Corrected CI runs all 33 runnable examples,
  cljdoc and unchanged Java/coverage/performance gates.

[Corrected CI run 38688916752](https://github.com/nantes-rfli/paclo/actions/runs/38688916752)
for `249acdc` completes with **all 12 jobs successful**. Actual logs confirm:

| Platform | Suite | Result |
| --- | --- | --- |
| Linux x64 / JDK21 | 469 tests / 17703 assertions | Zero failures/errors |
| macOS ARM64 / JDK17 | 469 / 17697 | Zero failures/errors |
| Linux ARM64 / JDK21 | 469 / 17703 | Zero failures/errors |

Eastwood analyzes all 103 namespaces, with 443 informational warnings and zero
exceptions; the dedicated runner negative probes also pass. Java coverage stays
43.8% against 25%; existing CI decode gate is 617.4 ms against fail 1200. All 33
executable examples and cljdoc pass. Three performance shards, all 27 scenarios,
results aggregate, required build and coverage remain successful. No gate or
threshold changes. Initial green CI is superseded by this corrected evidence.

PR #53 is ready for independent review and remains **unmerged**. This final
follow-up records evidence/plan only; production/tests remain `249acdc`.
No outstanding implementation checks. Next is independent review, with no
release, live/NIC/other-OS claim, P09/P10 or unrelated issue work.

## Issue #40 lazy capture lifecycle investigation

2026-10-15. Independent stabilization work starts from latest main `b83bd31`
(P08-E3 merged through PR #53); supplied checkout was clean. Branch:
`codex/issue-40-lazy-capture`. P08-E3 status now reflects the completed review
and merge. No P09/P10, unrelated performance work, versions or gate changes.
Read AGENTS.md, CONTRIBUTING.md, the v1 API contract, accepted plan, Issue #40
and lazy/managed/read-loop implementations before editing behavior.

### Reproduction and observed ownership

The new `paclo.capture-lifecycle-test` creates a real Classic PCAP containing
128 ordered 64-byte Ethernet/IPv4/UDP packets, timestamp seconds 1 and usec
0..127. It uses public `core/packets`, capacity one, blocking delivery, max
1000, and a 1000 ms time limit. Instrumentation delegates to the actual native
read loop and `pcap_close`, records completed/attempted handler calls, observes
the producer Future/Thread stack, and always interrupts/awaits any stranded
test producer before removing probes. No production cancellation API is inferred
from that test-only Future interception.

After `(take 1 packets)` returns timestamp 0, exactly two enqueues have returned
and the third is parked in `LinkedBlockingQueue.put`: one packet delivered,
one queued, one awaiting space. The producer is not done, native close count
is zero, and the final queue callback has not run. After changing the stop
predicate and waiting 1100 ms, the same conditions hold. The read loop checks
count/time/idle/predicate limits only outside the handler; it cannot run them
while blocked in put. Resuming the same sequence drains timestamps 1 and 2,
lets the predicate run, finishes the producer, and calls real native close
exactly once. Final counters are capacity/max-depth 1, enqueued 3, dropped 0.
Queue occupancy here is proven by completed enqueues minus consumed packets
plus the parked put stack, rather than exposing an internal queue as API.

The no-consumer dropping case terminates and closes once: 1 enqueued, 127
dropped, max-depth 1. Blocking full consumption preserves all 128 timestamps
in order and closes once with zero drops. If the source finishes before a
blocked packet enqueue (for example its output fits available slots), even a
full queue does not prevent termination. Existing terminal signaling uses a
separate atom; Issue #40's original blocking-sentinel description is historical
and was already addressed by P08-B1. Existing full-queue read-error tests cover
both throw/pass and callback failure without requiring any terminal queue slot.

### Decision and managed cleanup correction

A plain lazy sequence has no supported close/cancel operation and cannot report
whether the caller abandoned it or paused it. Preserve the existing lossless
blocking behavior. Do not add timeout-based dropping, GC cleanup, an unbounded
queue, a drain task or an implicit API change. Lazy `take`, reducing xforms and
consumer exceptions do not cancel capture. Dropping remains lossy delivery,
not cancellation. Document these limits for files and devices, and materialize
prefixes inside managed `with-open` or use synchronous `reduced`. README and
usage offline prefix examples now demonstrate actual explicit ownership.
Leave Issue #40 open for independent review of accepting this limitation;
the PR intentionally does not contain a closing keyword.

Testing the supported managed alternative exposed a separate concrete race
within the same lifecycle boundary: one thread could enter native breakloop,
then the producer could call native close before breakloop returned. A gated
fake-native regression on the initial implementation failed both assertions:
close completed while breakloop was held, and close observed breakloop active
(`focused-before-fix.log`: 4 tests / 70 assertions, 2 failures, zero errors).
The fixture-based abandonment assertions already passed in that run.

Serialize managed break/close with the existing handle-closed atom as the
monitor, including the closed check. Invoke error callbacks outside that lock.
No read-loop or packet hot-path lock is added. Clear queued values again after
producer completion because a timed offer already in flight can refill the slot
freed by close's initial clear. Preserve first stop reason/error, error messages,
background wrapper/cause, single-consumer ownership and close timeout. Stop
alone preserves queued values; close abandons them and waits. Timeout does not
confirm native release; blocking user callbacks/native calls must return.

### Verification

- `bash dev/script/codex.sh doctor`: exit 0; macOS x86_64, Temurin JDK
  21.0.12.1, CLI 1.12.5.1654, Clojure library 1.12.1, native libpcap 1.10.1;
  real four-packet/438-byte offline read passes; all optional lint tools present.
- First corrected focused run (before additional regression cases/docstrings):
  `bash dev/script/codex.sh test -n paclo.capture-lifecycle-test -n
  paclo.managed-capture-test -n paclo.pcap-loop-test -n
  paclo.capture-format-test`: exit 0, 57 tests / 1709 assertions. Full native
  fixture corpus and queue-saturated error tests pass.
- Final focused/full check, lint, perf, documentation and GitHub Actions results
  are pending below. Local logs are ignored under `target/issue40/`.

Live capture/NIC behavior is not validated by these offline tests. Platform
claims will be recorded only from actual CI; no performance gain is claimed.
Next unfinished item: finish required checks and independent PR review; do not
merge before review or start P09/P10.

### Final local validation

- Final `bash dev/script/codex.sh test -n paclo.capture-lifecycle-test -n
  paclo.managed-capture-test -n paclo.pcap-loop-test -n
  paclo.capture-format-test`: exit 0, **59 tests / 1735 assertions**.
- Final `bash dev/script/codex.sh check`: exit 0, **10 JUnit tests**, **477
  Clojure tests / 17817 assertions**, zero failures/errors, offline smoke
  passes. This supersedes the earlier 475-test run: the final run includes
  source-output-fits-queue and stop-retains-queued-prefix tests, and the native
  race test observes the producer blocked on the lifecycle monitor rather than
  guessing a scheduling delay.
- `bash dev/script/codex.sh lint`: final exit 0; kondo zero warnings/errors,
  all **104 Eastwood namespaces**, 446 informational warnings, **zero
  exceptions**, clean-ns/format dry runs clean, Markdown 37 files / zero errors.
  Three added informational warnings are test `with-open` reflection; no
  production warning or suppressed linter. The first sandbox run reached
  Markdown then failed npm DNS (`ENOTFOUND registry.npmjs.org`); rerunning the
  identical wrapper with authorized external access succeeded. This was an
  environment limitation, not a passing initial lint run or changed gate.
- `clojure -M:spotbugs`, `clojure -M:checkstyle`, `clojure -M:jacoco`,
  `JACOCO_MIN_LINE=0.25 clojure -M:jacoco-gate`: all exit 0; Java coverage
  **43.8% / 25%**. No Java source or native library dependency changed.
- `python3 -m unittest discover -s dev/script -p
  'test_verify_doc_examples.py'`: 15 tests pass.
  `python3 dev/script/verify_doc_examples.py`: exit 0, **34 executable
  documentation examples** pass, including both explicitly closed prefix
  examples. `python3 dev/script/verify_doc_links.py` and `git diff --check`
  pass. The unchanged link-parser unit suite initially failed one case with
  macOS's symlinked default temp path (`outside repository` for local anchors);
  `TMPDIR=/private/tmp python3 -m unittest discover -s dev/script -p
  'test_verify_doc_links.py'` uses the canonical writable path and passes all
  nine cases. No checker behavior or CI configuration was changed.

Performance and independent PR/CI evidence follow. Only offline native
ownership has been validated locally; live/NIC capture is still unvalidated.

After the other validation JVMs exited, `bash dev/script/codex.sh perf` passes
at **613.6 ms**, below unchanged warn 1000 / fail 1200. Input is the existing
50,000-packet / 74-byte synthesized decode gate, local macOS x86_64 / JDK21 /
Clojure 1.12.1 as above. This is a gate observation, not a throughput improvement
or a comparison with another platform. The shutdown monitor is outside the
packet hot path. CI performance measurements remain independent.

### PR and supported-platform CI handoff

Implementation/test/documentation commit **`f256b72`** is on
[PR #54](https://github.com/nantes-rfli/paclo/pull/54), based on main `b83bd31`.
The pre-commit hook's documented SKIP_TESTS/SKIP_FMT flags avoid repeating the
successful full checks and whole-tree formatting; the hook's Markdown and kondo
checks still run and pass. Post-commit working tree is clean. PR targets main,
has no auto-merge request and no closing Issue references. Issue #40 remains
open for independent review of accepting the documented lazy lifetime limit.

[CI run 38704727593](https://github.com/nantes-rfli/paclo/actions/runs/38704727593)
on `f256b72` completes with **all 12 jobs successful**, including required
`build`, build-checks, documentation-checks, Eastwood, both compatibility
jobs, ARM64 monitor, coverage, three performance shards and results aggregate.
Actual job logs confirm:

| Platform | Suite | Result |
| --- | --- | --- |
| Linux x64 / JDK21 | 477 tests / 17823 assertions | Zero failures/errors |
| macOS ARM64 / JDK17 | 477 / 17817 | Zero failures/errors |
| Linux ARM64 / JDK21 | 477 / 17823 | Zero failures/errors |

The six Linux-only assertions are existing /dev/full coverage. The new native
lifecycle cases run in all three jobs. Dedicated Eastwood analyzes all 104
namespaces with 446 informational warnings and zero exceptions; its deliberate
failure probes pass. Java coverage remains **43.8% / 25%**. CI's existing decode
performance gate passes at **780.7 ms / 1200 ms**. All **34 runnable examples**,
cljdoc, links, Markdown, formatting and existing JAR/Java checks pass. All three
performance shards and their required 27-scenario validation/aggregate pass.
No public API signature, dependency, release version or CI quality/performance
threshold change.

This follow-up updates the plan/log with completed evidence only; production
and tests remain `f256b72`. The PR carries the final-head CI link as well.
Investigation and supported cleanup correction are complete. Next is independent
review of PR #54, including whether Issue #40 can close as a documented
compatibility limitation. No merge, release, P09/P10, unrelated performance
implementation, live capture or NIC validation is performed.

## Issue #34 — exact flow aggregation performance (2026-10-15)

Start: supplied checkout clean; doctor succeeds (JDK 21/Clojure 1.12.1, real
4-packet libpcap read). Read AGENTS, CONTRIBUTING, API contract, accepted plan,
Issue #34, PR #33, P06 evidence and flow/project/perf/test sources. PR #54 is
merged as `e069657824ff2cdaf61af1210073b194bebff805`; fetched main and created
`codex/issue-34-flow-performance` in the supplied checkout, without a worktree.
No unrelated work, dependency/version/gate changes or issue #37/#44/P09/P10 work.

Original `clojure -M:dev -m paclo.dev.flow-perf 7711170` succeeds. Current main
IPv4 aggregation: 1052500 / 947289 pps at 10 flows, 640530 / 663379 at 10000,
unidir/bidir; allocation 1662.1 / 1662.1 / 1938.6 / 1939.6 B/packet. Old unchecked
CLI values remain background, not equivalent API evidence. Baseline source has
not changed since P06; JIT/call shape/host variation precludes historical timing
as the optimization baseline. Added paired runner with serial alternating
same-JVM baseline/current measurements and separate retained-memory experiments.
The unchanged-source control agrees on allocation; timing differs by a few %.

Initial JFR allocation samples and portable Java stack sampler identify map
hashing/equality, persistent updates, variadic assoc argument sequences and IPv6
sequence traversal. The initial empty-configuration JFR recording had no ExecutionSample events;
setting an explicit 10 ms period in the final runner yields 827 baseline / 615
current samples. Attribution uses JFR hot methods plus perturbed stack sampling,
while throughput experiments separately use ThreadMXBean CPU time. No CPU percentages are inferred
from allocation weights. See [the analysis](issue-34-flow-performance.md).

Candidate comparisons:

- Binary bounds: microprobe improvement disappears in warmed aggregate allocation;
  mixed throughput, rejected. Reusing six lookups by merging validation/key creation:
  +3.8% unidir / -5.4% bidir initially, unchanged allocation, rejected.
- Single-key persistent assoc: +8.6–14.5% initially, -304 B/packet; adopted.
- Indexed IPv6 validation/comparison vs assoc-only: +4.2–14.8%, -352 B/packet
  unidir / -432 bidir; adopted. Keep full validation, unsigned ordering, exact
  arithmetic, limit/error behavior and all intermediate immutable state.
- No mutable accumulator backend or fresh special-case state-map constructor:
  snapshot/fork/metadata contracts make that a substantially different tradeoff.

The first development control/candidate-A commands completed measurement rows
but exited 1 because the new runner attempted to close a nil optional Recording.
Fixed ownership by always owning a Recording; those exits are not passing checks.
A temporary source-formatting parenthesis error was caught by kondo and fixed
before performance/regression validation. No production behavior was accepted
based on those failed invocations.

Focused `bash dev/script/codex.sh test -n paclo.flow-test`: exit 0, 14 tests,
115 assertions and the existing 650 property cases. New regressions cover
immutable forks, EDN resume, completion identity, state/summary metadata and
unknown entries, summary overflow including skips, exact counts after 2^100,
BigInt bounds and reused reducer initialization. Existing IPv4/IPv6, lengths,
cardinality, ranking, native fixture/fan-out/shared-byte tests remain intact.
`git diff --check` and documentation links pass at this stage. Full paired
repetitions and all required delivery gates follow below.

Controlled final comparison: two independent serial JVMs complete successfully,
100000 packets, ten warmups/nine alternating samples per implementation; all
36 baseline/current scenario rows per repetition match exactly. Committed
[raw data](issue-34-flow-measurements.edn) includes samples, input/flow/summary
checks, GC, allocation, CPU, retained results, original/control/candidate data and
final JFR/portable stack summaries. Measured production blob is
`faec3910fe0efc81a088ed8a27aca2931b38f014` (before implementation commit).

- Synthetic aggregate throughput improves **4.7–35.3% in every pair**, with lower
  thread CPU; IPv4 allocation falls 304 B/packet, IPv6 624–848 B/packet. Independent
  JVM absolute allocation differs even for baseline; compare within-JVM deltas.
- Projected DNS/SLL2 replay improves in both repetitions. Raw/decode replay gains
  are smaller. Native DNS unidir is +0.5%/+7.6%, bidir **-12.4%/+6.7%**: no repeatable
  native end-to-end throughput gain is claimed. Native allocation falls 304
  B/packet in both. Preserve negative CPU/wall samples, not just favorable ones.
- Retained high-cardinality state remains ~190 B/flow; low cardinality ~198–206,
  including ~5 B/flow first-scenario heap noise. No retained-memory reduction or
  memory cap is established. GC generally falls with allocation, but there are
  counterexamples in both count and milliseconds; no latency guarantee.
- Final JFR records 53917/26275 allocation samples and 827/615 execution samples
  (baseline/current). ArraySeq/vector-seq/RestFn allocations leave the dominant
  list after the change; lookup, hashing, equality, persistent maps/HAMT copies
  and exact boxed counters remain. JFR includes input setup/warmup; portable
  sampling perturbs timing; neither is used for the unprofiled speed comparison.
- Tiny fixture replay/native repeated DNS bytes are not a production trace or
  live/NIC evidence. Linux/macOS ARM64 performance is unmeasured by these runs.

Full `bash dev/script/codex.sh check`: exit 0; **JUnit 10/10, Clojure 480 tests /
17858 assertions, smoke 4 real packets**. Includes 650 P06 property cases, new
snapshot/exactness/IPv6 regressions, CLI, invalid/length/limit/overflow, capacity-one
fan-out, cooked/Raw/NULL/LOOP and P06/P07/P08 composition. No test/gate excluded.
`python3 dev/script/verify_doc_examples.py`: exit 0, **all 34 examples**.
`python3 dev/script/verify_doc_links.py` and `git diff --check`: exit 0.
Machine-readable evidence parses as EDN and an independent integrity probe checks
two complete sets of 36 rows, nine samples/row, all equality/reachability flags,
and 100000 seen packets/sample. Original fixture SHA-256 values are in the report.

First full lint: kondo clean, all Eastwood analysis completes with zero exceptions;
exit 1 at lsp format because the new measurement EDN required standard formatting.
Applied the existing formatter to that file only and rerun the unchanged full
lint command. No rule, root, exclusion, warning policy or threshold changed.
Test-created Python bytecode caches were removed from the worktree.

Second lint attempt passes Clojure analysis/format, then exits 1 because sandbox
DNS cannot resolve `registry.npmjs.org` for the existing pinned markdownlint-cli2
0.18.1 invocation (`ENOTFOUND`); npm cannot write its default log directory there.
Rerun the identical `bash dev/script/codex.sh lint` with network-capable execution;
this is an environment remediation, not a passing blocked check or gate change.
A final `git fetch origin main` still reports baseline `e069657`.

Final native/offline gate `bash dev/script/codex.sh perf`: exit 0, **896.7 ms**,
unchanged warning/failure budgets **1000/1200 ms**. Ran separately from tests,
lint and all paired benchmarks. `bash dev/script/codex.sh package`: exit 0,
unchanged `paclo-1.3.0-SNAPSHOT.jar` version. JAR contains core/flow/project,
window, PCAPNG source/writer; packaged flow bytes exactly match measured blob.

Independent `/private/tmp/paclo-34-consumer-788lyb5g` has only a local/root JAR
dependency and runs `clojure -Srepro -M consumer.clj`: exit 0,
`:jar-consumer-ok :flow :exact :snapshots :pcapng :window`. All public resource URLs
use the jar protocol. It checks real DNS aggregation, EDN and independent
snapshots/completion, IPv6 unsigned keys, 2^100 exact counters and max-flows,
and mixed-section PCAPNG → flow projection/aggregate → pure time windows.
No repository source path leaks into its dependency classpath.

Network-capable lint completed all Clojure checks and exposed MD012 (a doubled
blank in the new report). Fixed it; standalone full Markdown lint passes all
38 files. Rerun the full wrapper again after that correction to obtain a clean
end-to-end exit. No suppression, tool downgrade or gate edit.

Final `bash dev/script/codex.sh lint` with network-capable execution: **exit 0**.
Kondo has zero warnings/errors, Eastwood analyzes **106 namespaces**, zero
exceptions (467 informational warning sites); lsp clean-ns/format have no changes;
Markdown lint has zero errors across 38 files. All requested local commands now
have successful completed exits; final links and diff whitespace checks pass.
Implementation and evidence are ready for the independent PR and unchanged
12-job GitHub Actions verification. Independent review/merge remain outstanding.

First commit attempt stops in the unchanged pre-commit hook because Homebrew
`clj` requires missing `rlwrap`. For this noninteractive hook invocation only,
a temporary PATH-local `clj` wrapper execs the installed `clojure` CLI with all
arguments unchanged. No hook check is skipped, no repository hook/config is
edited and no system package is installed. The hook reruns tests/format/Markdown/
kondo. Its network-enabled execution uses the already required npm registry.

Implementation commit **`c4f2a27`** creates independent
[PR #55](https://github.com/nantes-rfli/paclo/pull/55), titled
`perf: optimize exact flow aggregation (Issue #34)`, against unchanged main
`e069657`. Commit hook completes without skipping checks: 480 tests / 17858
assertions, clean formatting, Markdown and kondo; source blob stays exactly
`faec3910fe0efc81a088ed8a27aca2931b38f014`. Generated Python caches are removed.

[CI run 38738630317](https://github.com/nantes-rfli/paclo/actions/runs/38738630317)
for `c4f2a27` completes with **all 12 jobs successful**: build-checks,
documentation-checks, Linux x64/JDK21 and macOS ARM64/JDK17 compatibility,
Linux ARM64 monitor, Eastwood, coverage, three performance shards, merged
performance results and required build aggregate. Inspected decoded job logs:

- Linux x64 and ARM64: actual runner arch/OS verified; **480 tests / 17864
  assertions**, zero failures/errors. macOS: Darwin ARM64/JDK17, **480 / 17858**,
  zero failures/errors. Different platform assertion counts retain existing
  native/platform-specific tests; no exclusion or gate changed.
- Build-checks: JUnit 10/10, Java quality, **43.8% JaCoCo** versus unchanged
  **25%** gate, existing perf gate **588.9 ms** versus unchanged 1000/1200 budgets,
  clean lsp/kondo and zero Markdown errors. Performance merger validates all
  **27 scenarios**. Documentation completes all **34 examples** and cljdoc load.
- CI uses pinned clj-kondo **2025.10.23** and clojure-lsp
  **2025.11.28-12.47.43**. Local available tools were kondo **2026.05.25** and
  lsp **2026.05.05-12.58.26**; the unchanged CI pins also pass. Eastwood completes
  with 467 informational warnings and zero exceptions, matching local analysis.

Implementation meets Issue #34's measured-optimization/correctness acceptance;
add `Fixes #34` to the PR body. The plan records implementation/validation done
and **independent review of PR #55** as next unfinished work. PR remains open
and unmerged; no release, artifact publication, issue #37/#44 or P09/P10 work.
The final evidence-only commit records these outcomes; its CI checks are followed
on the PR. Other-platform performance and live/NIC performance remain unvalidated.

## Existing flow key reuse follow-up (2026-10-16)

Supplied checkout starts clean at `a79f1be`; its tree exactly matches fetched
latest main `6095c7fa8b1c2ec982064860d0b08c7e5bd931f4` (PR #55 squash merge).
GitHub reports no open PRs and Issue #34 closed. Created
`codex/flow-key-reuse` from origin/main in the supplied checkout. Read AGENTS,
CONTRIBUTING, v1 contract, accepted plan, current source/tests, CI and prior
Issue #34 evidence. Doctor passes JDK 21.0.12.1, Clojure 1.12.1, macOS x86_64
and actual four-packet native read. No dependencies or Java sources changed.
The prior research was found at `/private/tmp/paclo-flow-study-20261015`;
report/prototype were inspected, and its measurements remain historical context.

Candidate changes only the eligible-packet lookup/update: PersistentHashMap
uses find/val and stored key; other maps retain get and the fresh canonical key.
All arithmetic, length validation, nil-value/cardinality convention, error data,
summary/state updates and completion remain unchanged. No constructor cache,
mutable state, new API or implementation selector. Hash-map node traversal still
occurs for lookup and update; key identity avoids the second deep comparison.

Initial focused test exits 0: 18 tests / 814 assertions and 750 property cases.
Coverage adds 7/8/9 transitions, explicitly supplied hash and sorted maps, equal
but distinct keys, metadata/caller entries, forks/EDN/completion, exact Long and
2^100 counters on hash maps, precise errors and reduced termination. Existing
PCAP, fan-out and P06/P07/P08 composition tests remain. A subsequent test-only
clarification explicitly seeds PersistentHashMap.EMPTY (rather than hash-map).

Extended the existing paired runner, without a new framework: boundary sizes,
25/50/75% revisit fractions, all-new IPv4/IPv6, a deterministic hot set and native
SLL2 replay. Each timed sample compares its complete result after all counters
stop. Separate retained experiments hold at least two results (about 100k entries
normally, 200k for all-new) to fit the same 512 MiB heap. Timing comparisons run
serially without concurrent tests/lint/builds. Measured production blob:
`13fa5acd21ad03dda2bcf50f3d9ca0466d04f35c`; runner blob at measurement start:
`0e977854c914c81cb78baceda1860a6209f6871c`. Final evidence follows.

### Paired performance acceptance

Both independent serial JVMs exit 0, each with 50 paired conditions / 900 timed
samples; repetition 2 swaps namespace roles and initial implementation order.
Separate main/main control exits 0 for 12 pairs / 216 samples. The summarizer
validates all 2016 complete results, 100000 seen packets per sample, nine samples
per row, retained-result equality and reachable inputs. No sample was removed.
Commands (all with -J-Xms512m -J-Xmx512m -M:dev): runner main
`6095c7fa8b1c2ec982064860d0b08c7e5bd931f4 key-reuse`, swapped script and control
script in `/private/tmp/paclo-flow-key-reuse-20261016`. The report contains exact
reproduction forms; the CSV records normalized roles, all sample counters,
summary/flow counts, retention and timing dispersion.

Adopt the candidate, contingent on delivery gates. Repeated 9/10/10000-flow
aggregates improve 7.1–21.1% in both IP versions/directions/JVMs; reproducible
allocation savings are 352 / 316.8 B/packet. JVM 2 has an additional IPv6
24 B/packet offset even on fallback/all-new; do not attribute it to key reuse.
Main/main allocation agrees in all twelve control conditions. Small 7/8-flow
throughput ranges -4.7 to +3.6%, all-new -2.6 to +4.9%, versus main/main -3.4 to
+5.4%. Small-map negative extrema do not recur in JVM 2. 25/50/75% revisit cases
range -0.6 to +11.3%; hot-set input +12.2 to +16.1%. DNS native -1.8 to +3.1%
with no allocation improvement; SLL2 native +0.7 to +3.1%, -203 B/packet.
These are this implementation's observations, separate from prior research.

No retained-memory reduction is claimed: estimates differ by about -5.3 to
+5.3 B/flow. GC count/time increase in 28/40 of the 100 paired comparisons,
respectively. Outliers remain, including two baseline rows with about 54%
elapsed CV. Two JVMs/nine samples do not establish formal significance or
universal bounds. No production trace, live/NIC, other-platform performance,
RSS/peak-memory or long-run GC-pause validation. Full tables and limitations:
[performance report](flow-key-reuse-performance.md) and
[measurement CSV](flow-key-reuse-measurements.csv).

### Local delivery validation

After benchmarks completed, added explicit hash-seeded SLL2 native reduction,
report, early reduced termination and capacity-one fan-out using the same reducer
in both futures, one resumed from EDN. Seed remains immutable. Final focused
`bash dev/script/codex.sh test -n paclo.flow-test`: exit 0, 19 tests / 821
assertions, including 750 property cases. Full `bash dev/script/codex.sh check`:
exit 0, 484 tests / 18553 assertions, JUnit 10/10 and real four-packet smoke.
All P06/P07/P08, native formats/PCAPNG, CLI, lifecycle and fan-out suites remain.

`clojure -M:spotbugs` and `clojure -M:checkstyle`: exit 0.
`clojure -M:jacoco`, followed by `clojure -M:jacoco-gate`: complete reports,
43.8% line coverage against unchanged 25% threshold, PASS/exit 0.
`python3 dev/script/verify_doc_links.py` and `git diff --check`: exit 0.
Remaining full lint, executable examples, existing performance gate,
package/independent JAR consumer and CI evidence follows.

All 34 maintained executable examples complete with exit 0. First full lint
passes kondo, all 106 Eastwood namespaces (481 informational warnings, zero
exceptions), lsp clean-ns/format, then fails MD012 at three added blank lines.
The second full invocation again passes Clojure checks but catches the remaining
extra blank at report EOF. Trimmed that trailing blank as well; standalone
Markdown lint passes all 39 files. No rule/exclusion/threshold changed.
Final full lint is rerun after these corrections and local-evidence updates.

`bash dev/script/codex.sh perf`: exit 0, 630.2 ms against unchanged 1000/1200 ms
warning/failure budgets; no concurrent tests/lint/benchmarks. `package`: exit 0,
unchanged `paclo-1.3.0-SNAPSHOT.jar`. JAR resource inspection includes core,
flow/project, window, PCAPNG source/writer and native binding. Packaged flow
source exactly equals the measured production source.

Independent `/private/tmp/paclo-flow-key-reuse-20261016/consumer` has only a
local/root JAR dependency and executes `clojure -Srepro -M consumer.clj`: exit 0,
`:jar-consumer-ok :flow-key-reuse :exact :snapshots :pcapng :window`.
Resource URLs use jar protocol; checks include real DNS aggregation, exact
2^100 counters/limits, IPv6 unsigned ordering, hash-map snapshots/forks/EDN and
mixed PCAPNG-to-flow/window composition. `prepare` exits 0 afterward, restoring
Java test classes deleted by packaging. Local kondo/lsp versions are
2026.05.25 / 2026.05.05-12.58.26; unchanged CI pins will also be validated.
GitHub main remains `6095c7f` at the pre-PR check.

Final complete `bash dev/script/codex.sh lint`: exit 0. Kondo has zero
warnings/errors; Eastwood analyzes all 106 namespaces with 481 informational
warnings and zero exceptions; lsp has nothing to clean/format; Markdown checks
all 39 files with zero errors. All requested local gates now have successful
completed exits. Production and runner blobs remain the measured versions.
For the noninteractive commit hook, a temporary PATH-local `clj` wrapper execs
the installed `clojure` CLI with unchanged arguments, as in the preceding task;
this avoids Homebrew clj's missing rlwrap requirement. No hook or check is skipped
and no repository/system tool configuration is changed. CI/PR evidence follows.

### PR and supported-platform CI

Implementation commit `3d37a8890a55cb97296bbb6d974ec24c203cee54` completes the
unchanged pre-commit hook (484 tests / 18553 assertions, clean formatting,
Markdown and kondo) and creates [PR #56](https://github.com/nantes-rfli/paclo/pull/56)
on `codex/flow-key-reuse`, against main `6095c7f`. PR is attached to this chat,
open and unmerged. Committed production/runner blobs exactly match measurement.
Generated Python bytecode caches are removed; no unrelated work is present.

[CI run 38908188042](https://github.com/nantes-rfli/paclo/actions/runs/38908188042)
on exact head `3d37a88` completes successfully. JSON integrity check confirms
all 12 jobs succeed: build-checks, documentation-checks, Linux x64/JDK21 and
macOS ARM64/JDK17 compatibility, Linux ARM64 monitor, Eastwood, coverage,
three performance shards, performance-results and required build aggregate.
Downloaded job logs confirm actual OS/architecture checks, 484 tests / 18559
assertions on both Linux environments and 484 / 18553 on macOS. All have zero
failures/errors. CI has JUnit/Java quality, 43.8% / unchanged 25% coverage gate,
unchanged performance gate 769.9 ms / 1200 ms, all 34 examples and cljdoc load,
all 27 merged performance scenarios, pinned kondo/lsp and full Eastwood with
481 informational warnings and zero exceptions. No gate/configuration changed.

This evidence-only follow-up records the accepted implementation and independent
review handoff; no production/test/measurement source changes. The PR carries
final-head CI results after this commit as well. Independent review of PR #56
is the next unfinished item. Leave it open and do not merge/release; Issue #34
stays closed and #37/#44/P09/P10 remain outside this task. Offline CI does not
establish live/NIC or other-platform paired-performance validation.

## Issue #37 DNS performance investigation (2026-10-17)

Started with a clean supplied checkout on `codex/flow-key-reuse`. Read AGENTS,
CONTRIBUTING, v1 API contract, accepted plan, Issue #37/PR #36, P07-B design/
measurements and current DNS/window/CLI/tests/fixtures. Fetch latest main and
create `codex/issue-37-dns-performance` from
`452de98cf6d1a604e5823e80dc1cf5edadfe4b67`, after merged PRs #55/#56.
The first sandbox fetch could not write `.git/FETCH_HEAD`; approved Git execution
succeeded. GitHub CLI network reads similarly succeeded in network-capable
execution. No worktree, dependency, version, flow/P06 or CI gate changes.
Issue #34 stays closed; Issue #44/P09/P10/release/merge work is excluded.

`bash dev/script/codex.sh doctor`: exit 0, JDK 21.0.12.1 / Clojure 1.12.1 /
macOS x86_64, four-packet actual libpcap read. Required source checks confirm
retired-map scans and sorting of all pending keys at each advance. Reproduced
unchanged original runner on fixed main; extracted only old RTT/QPS sources
from `2e15af7` and reproduced its normalized full-input CLI measurement.
Raw EDN is retained under `dev/measurements/issue-37/`. Old nil-RTT output is
context, never an equivalent correctness/performance target.

Exploratory candidate 1 filters pending before sorting, preserving deadline/key
order. Candidate 2 adds a conservative optional integer lower bound for the next
expiry. It avoids all scans before the hint, accepts old EDN without it, and
keeps immutable state/forks. Removing a key may leave an early hint; a scan
recomputes it. Earlier retries lower it. Finish clears it. No per-key index or
new public option. An initial per-key `[aggregate minimum]` scan allocation was
rejected after retired sparse/sequential measurements; final scan confines one
volatile scalar to the call and publishes only its integer plus persistent data.
Exploratory raw data is kept with its limitations in the report (including the
first header's mistyped abbreviated ref and CPU-counter boundary correction).

Added a full-scan expiry oracle, legacy/EDN/fork comparisons, earlier retry,
stale hint, simultaneous expiry, BigInt times and atomic bound-error coverage.
Both focused DNS invocations complete with exit 0: 19 tests / 298 assertions,
including existing 600 and new 300 property cases. Kondo initially flags one
unused benchmark import; removed it, then all changed Clojure files lint clean.
LSP clean-ns/format completes for production/test/measurement sources before
final measurements. Production measured blob is
`802b23940d749d2dfb85717e90f15b4b18ea57d0`.

Two independent serial 512 MiB JVM repetitions are running for expiry, pipeline,
anomalies, windows, 100000-key states and a public real trace. Timed suites use
five warmups/seven alternating samples, reversed initial order in repetition 2;
complete results must agree after excluding only the internal hint. Native,
projection, delivery and output same-source pairs quantify control variation.
Benchmark setup errors (raw capture retaining decode-only options; in-memory
raw packets missing explicit caplen for QPS) were corrected before final runs.
They were harness failures, not production changes; incomplete files were
replaced by complete reruns. Full final results and delivery validation follow.

Fetched Wireshark SampleCaptures `dns.cap` outside the repo: 4338 bytes,
SHA-256 `041eeb6f98bb398f1ee8b09651b5b5a84f6a62639f95bf226f9e7b77355d9f28`.
Record exact public source/reproduction in the report; do not redistribute the
capture or claim it represents a long production/resolver workload. Long/high
cardinality coverage uses generated offline PCAP and reports that limitation.

### Expiry candidate refinement

Complete initial-scalar paired measurements are retained under
`dev/measurements/issue-37/initial/`; no negative samples were removed.
At 10000 retired keys / 1000 actual successive expiries, the initial scalar
hint takes 231.5/325.2 ms versus main 119.5/179.1 ms. At 100000, 8726.9/8508.9
versus 5281.3/5762.7 ms. This exposes extra minimum-recalculation work, while
mixed pending/retired expiry and no-expiry paths improve strongly.

Two independent isolated scan comparisons motivate skipping keys at least the
known live minimum: that minimum is already above the watermark, so such keys
need neither another comparison nor a volatile write. A separate scalar-return
reduction with a volatile retained-map holder shows noisier full-deletion costs;
reject it in favor of the smaller branch change. These isolated method timings
compare scan methods, not main or full CLI. Both method raw series are retained.
Final production blob is `85d9fea2b46d9666165fe2cfdb414a3fc64b4ce6`.
Focused DNS suite again exits 0 (19 / 298, including 900 property cases), LSP
format/clean-ns and changed-source kondo pass. Only dev consumer formatting
changed in this pass; no production formatting drift. Final runner records
production and runner blobs automatically. Re-running complete paired suites
on this accepted source, plus 100000-entry EDN/retention and unchanged original
CLI. Full final evidence and delivery checks follow below.

### Final paired evidence and local delivery checks

Final source remains `85d9fea2b46d9666165fe2cfdb414a3fc64b4ce6`.
The summarizer validates 354 paired conditions / 4940 timed samples, all
complete results equal after excluding only the optional internal scalar.
Final and initial raw files, rejected-candidate patches and both summaries are
retained; no negative timing samples are removed. Same-main dispatch controls
show -1.7% to +0.9% throughput with effectively identical allocation.

The 4000-packet/2000-qname native RTT stats pipeline, excluding output,
improves about 2.0x sync and 2.5x async in both independent JVMs. A separate
40000-packet/default-timeout steady workload crosses actual quarantine expiry
and improves 1.9-2.2x, with all 20000 matches and bounded 10000 retired entries.
Long low-density results are small/noisy. Standalone original complete-CLI
timings are slower than the earlier main measurement, including unchanged QPS;
no universal CLI speedup is claimed. The tiny real Wireshark trace agrees
exactly but establishes no attributable throughput benefit. No suitable long
production trace or sustained wall-clock/live-NIC performance was validated.

Repeated actual retired expiry remains slower: 16.9-38.4% lower throughput
at 10000 keys, 12.6-15.4% at 100000. The report explicitly records this
tradeoff. One integer avoids the strong no-expiry/mixed-workload cost without
per-key index retention. A future index requires separate update/retention
evidence. Do not use a closing keyword for Issue #37; leave closure to review.
Forced-GC roots/EDN round-trips cover 1000/10000/100000 pending and retired;
100000-root heap estimates remain about 83 MB / 49 MB. These inputs add
35 EDN characters per root, not per key. Arbitrary integer width follows the
existing time contract; no strict byte-memory or per-key reduction is claimed.

Local results (exit 0 unless a failed attempt is described):

- `check`: 487 Clojure tests / 18648 assertions, 10 JUnit tests, native
  four-packet smoke. Existing regression, properties, CLI, window, PCAPNG and
  independent-consumer tests remain in the unchanged suite.
- `perf`: 50k full-decode 501.8 ms, unchanged 1000/1200 ms warn/fail limits.
- `verify_doc_examples.py`: all 34 examples; `verify_doc_links.py`: maintained
  local links and anchors. Parser tests: 15; link tests: nine. Link tests first
  fail on the macOS `/var` temporary-root alias; rerunning with canonical
  `TMPDIR=/private/tmp` passes without changing checker or assertions.
- `test_eastwood_runner.py`: four real JVM exit-status probes pass, including
  deliberate unanalyzed-namespace failure. Full analysis covers 108 namespaces,
  551 informational warnings, zero exceptions. Initial lint stops at manifest
  indentation; fix it. A later sandboxed Markdown invocation cannot access npm;
  the network-capable invocation identifies 15 long report prose lines, now
  wrapped. No gate, threshold, warning policy or analysis scope changes.
- `package`: JAR built. JAR-only `-Srepro` consumer outside the checkout passes
  exact DNS, old/EDN state, concurrent capacity-one fan-out, BigInt retries and
  quarantine, authored PCAPNG native-byte replay/decode and window composition.
  All production/native-binding/extension resources are asserted to load from
  `jar:` URLs. `prepare` restores development Java test classes afterward.
- SpotBugs, CheckStyle, JaCoCo and gate pass; line coverage 43.8% versus the
  unchanged 25.0% threshold.
- The opt-in benchmark rejects an unknown suite with a nonzero exit and the
  expected error; real successful suites and summary commands are exercised.
- `git diff --check` passes; raw measurement SHA-256 values remain unchanged
  across final formatting. Generated untracked Python bytecode is removed.

Full lint completion and independent PR/CI evidence follow below.

Final full `bash dev/script/codex.sh lint` completes with exit 0 after the
document wrapping fix: zero kondo warnings/errors, 108 Eastwood namespaces /
zero exceptions, no namespace/format differences, 40 Markdown files /
zero errors. Production and measurement files remain at their measured
hashes. All requested local gates are now complete; PR CI is the next check.

### Independent PR and CI handoff

Created [PR #57](https://github.com/nantes-rfli/paclo/pull/57),
`perf: optimize bounded DNS analysis (Issue #37)`, from independent branch
`codex/issue-37-dns-performance`. Latest remote main is still `452de98`.
Commit `f507d425dd292f4ceb0f8b6f479bea5648bb7ed0` contains the implementation,
tests, investigation and raw data. All existing pre-commit checks pass without
skip flags: 487 tests / 18648 assertions, format/ns checks, all Markdown and
kondo. `clj` uses a temporary wrapper forwarding to the installed Clojure CLI,
so the hook retains its checks without requiring interactive rlwrap.
Measured production hash and all raw EDN/JSONL files remain unchanged.
Reproduction patches pass `git apply --check` against their documented source;
trailing blank context at patch EOF is trimmed with hunk counts adjusted, so
the staged full `git diff --check` also passes.

[CI run 38944789749](https://github.com/nantes-rfli/paclo/actions/runs/38944789749)
on `f507d42` completes successfully: all 12 jobs, no failed/skipped jobs.
`gh run view --json jobs` confirms the actual cloverage step succeeds as well.
Downloaded logs confirm 108 Eastwood namespaces, 551 warnings, zero exceptions,
all four failure-exit probes, 34 doc examples and the unchanged 749.3 ms
50k decode gate (warn/fail 1000/1200). JaCoCo remains 43.8% / 25%.
Linux JDK21, Linux ARM64 JDK21 and macOS ARM64 JDK17 each pass 487 tests
(18654 assertions on Linux; 18648 on macOS). All three performance shapes,
their aggregate, build-checks and build aggregate succeed.
The namespace count matches actual `== Linting <namespace> ==` records in both
local and CI logs; an earlier count of 109 included the completion summary
line and is corrected here. This does not change the analysis roots or scope.

Only this delivery record, report and plan change after the implementation
head. Check all twelve jobs again on that final documentation head; preserve
the exact final-head run link/result in PR #57 to avoid another evidence-only
commit cycle. GitHub workflows, gates, dependencies and Issue #34/P06 code are
unchanged. Leave Issue #37 open for review of the remaining retired-expiry
tradeoff and real-production evidence gap. Do not merge, release, or start
Issue #44/P09/P10 work.

Final plan consistency review also updates the dedicated Issue #37 section from
in-progress to implemented/verified on PR #57, and removes stale PR #56 review
and old current-task labels now that it is merged as `452de98`. This changes
only the plan and delivery log; implementation, raw measurements, dependencies
and gates remain unchanged. Final-head CI is still recorded on PR #57.

## Issue #44: Ethernet decode performance investigation

Started 2026-10-17 from latest main
`e444b10ba84513b460916482e1236c202fa27b84`, after PR #57 merged, on independent
branch `codex/issue-44-ethernet-performance`. Initial
`git status --short --untracked-files=all` is empty; no unrelated changes.
Read AGENTS, CONTRIBUTING, the v1 API contract, accepted plan, Issue #44 and
its D2 follow-up comment, PR #43, historical P08-C report/raw data/runner,
full/flow/linktype/core implementation and relevant fixtures/tests/CI gates.
No Issue #37 remaining work, P09/P10, version, release or merge work is included.

`bash dev/script/codex.sh doctor` passes: macOS 15.4.1 x86_64, Temurin
21.0.12.1, CLI 1.12.5.1654 / library Clojure 1.12.1, libpcap 1.10.1;
real native four-packet offline read and all optional lint tools available.
A first Git fetch is denied by the filesystem sandbox; the authorized elevated
`git fetch origin main` succeeds, then a new branch is created from origin/main.
No additional worktree. GitHub CLI network access is sandboxed, so connected
GitHub reads provide the Issue/PR context.

Runner validation and initial evidence:

- Original `clojure -M:dev -m paclo.dev.framing-perf 4998ddc 1` succeeds unchanged.
  The old internal `unsupported?`/packet-xf contracts still match this loader;
  each old core calls its own old parse API. Preserve the original output.
- The opt-in `paclo.dev.ethernet-perf` loads unmodified B2 `4998ddc`, C `9d83bb2`,
  D2 `ccebcad` and current-main source under separate names, recording original
  hashes. Only comparison code changes; no baseline implementation is patched.
  All non-renamed dependencies/native capture lifecycle are deliberately shared.
- Initial independent JVMs use fixed 512 MiB heap, five warmups and nine
  alternating 50k samples; run 2 reverses initial order and additionally includes
  D2. Complete decoded values agree, full input identity/bytes are preserved,
  Flow excludes full/byte maps, sample checksums agree and drops are zero.
  B2-to-C allocation savings of 416 B/packet reproduce; timing and absolute
  allocation vary with JIT/escape analysis and call-site context. Same-main
  aliases reveal timing noise. Raw measurements are in `dev/issue-44/`.
- Separate 2 ms perturbed stack sampling and raw JFR allocation/execution/GC
  profiles isolate Full and Flow. Reflective Array.setChar is the Full leaf in
  1596/4627 samples. Generic component probes are explanatory, not additive
  exclusive CPU costs or production allocation measurements.

Candidate decisions:

- Retain only local primitive-char-array `aset` stores in full address formatting.
  MAC-only pilot JVMs reproduce Full improvements with unchanged paired
  allocation. No packet-byte mutation, shared cache, map/field/DLT/parser change.
- Revert direct VLAN case expansion: paired Flow allocation grows 280 → 304
  B/packet and throughput declines about 34–39%. Both negative JVMs and the
  candidate reproduction patch are preserved.
- Revert DLT presence-lookup simplification: MAC-only comparison changes UDP
  Flow +0.9/+6.4%, TCP -3.9/+3.9%, with similar control movement in Full.
  Benefit is insufficiently repeatable. Preserve both outputs and patch.
- Do not adopt unmeasured full-map, ByteBuffer, lookup-table, success/error-map
  or Ethernet-specific parser rewrites. The accepted change is small and local.

Focused `bash dev/script/codex.sh test -n paclo.ethernet-perf-test` passes:
three tests / 388 assertions, including 250 random address/VLAN cases, exact
MAC text/VLAN fields, both IP versions/protocols, identity/no mutation and
all 128 generated framing cases. Existing cooked tests cover random addresses
of every declared length 0–8; existing truncation/diagnostics, extensions,
fragments, capture/fan-out, P06/P07 and PCAPNG gates remain required below.

The first broad matrix exposes startup/JIT outliers in short Flow rows. Keep it
as pilot evidence. Subsequent runs globally prewarm all 32 protocol/framing
shapes, both implementations/modes, before five local warmups and nine alternating
10k samples per case. Independent JVM 2 reverses initial order. Separate
Flow-only and same-source controls distinguish alias/JIT effects from delivered
address code. All final comparisons and remaining verification are recorded
below and in `dev/issue-44-ethernet-performance.md`.

### Final measurements and local gates

The complete report is `dev/issue-44-ethernet-performance.md`; raw EDN, four raw
JFR recordings and summaries, compiler bytecode, checked candidate patches and
SHA-256 manifest are under `dev/issue-44/`. The CSV contains all 944 comparison
pairs, including the underwarmed pilot and both rejected candidates. No negative
result is discarded. Final enhanced driver hashes are for reproduction; the
report identifies earlier driver warmup/countdown differences rather than
asserting every pilot used the final driver.

Two globally warmed JVMs complete all 128 packet-xf cases and all 96 native
Classic/PCAPNG cases. Full throughput improves 9.1–76.1% Ethernet, 3.7–61.2% SLL,
3.8–44.6% SLL2; native Full improves 9.6–32.3%, 5.1–29.2%, 2.8–18.2% respectively.
Every final packet-xf allocation pair is equal; native differences are at most
one 24-byte invocation object per 10k packets. Real seven-fixture replay and a
small external actual Wireshark DNS trace confirm Ethernet Full benefits;
external native replay improves 23.7–26.9%. No DNS/TLS extension, downstream
analysis, live/NIC, long production or other-platform performance claim.

Flow implementation is unchanged. Mixed Ethernet rows range -22.8 to +31.9%.
Independent Flow-only 50k samples and identical-source controls retain large
single-case outliers even with identical source hashes. No isolated Flow case
loses more than 10% in both JVMs. The report gives ranges, per-case medians,
CPU, 280/480 B IPv4/IPv6 allocation parity, GC counts/times and source/JIT limits;
it does not claim Flow speedup or throughput equivalence. Raw/NULL/LOOP also
retain negative/noisy results; no repeated large native regression is observed.

AOT/javap confirms all three writes compile to `RT.aset:([CIC)C` rather than the
old aset-char Var invocation. Stack profiles remove reflective setChar from the
top 30 leaves, leaving persistent maps/IP strings as substantial costs. JFR
summaries filter allocation/execution to main while reporting excluded sampler
threads. Initial allocation weights of 1.9 GB Full / 14.6–14.8 GB Flow warn of
pre-recording carry-in; preserve them and use ThreadMXBean for exact allocation.
No weighted per-packet/percentage claim. Full GC attribution moves in opposite
directions between matrix/native; no GC benefit is established. Forced-GC 20k
output roots estimate Full 1091→1117 B and Flow 237→237 B; this noisy one-pair
probe establishes no strict byte bound or native/RSS retention result.

Commands and results (exit 0 unless an intentional failure is noted):

- `bash dev/script/codex.sh check`: 490 Clojure tests / 19036 assertions,
  ten JUnit tests, native offline smoke. Existing API, malformed/boundary,
  fragments/extensions, multi-DLT, fan-out, P06/P07/P08 and PCAPNG suites pass.
- `bash dev/script/codex.sh lint`: all 112 actual namespace records, 593
  informational Eastwood warnings, zero exceptions; zero kondo warnings/errors,
  namespace/format checks and 41 Markdown files pass. No analysis roots or
  warning/exit policy changes. `python3 dev/script/test_eastwood_runner.py`
  passes all four actual-JVM probes, including intentional exit 1 with one
  unanalyzed namespace.
- `python3 dev/script/verify_doc_examples.py`: all 34 examples. Local link
  checker passes. All five related generator `--check` commands pass:
  capture-format (including cooked/Raw/NULL/LOOP), cooked, Raw, NULL/LOOP and
  PCAPNG contracts. Existing fixtures and generator sources are unchanged.
- `clojure -T:build spotbugs`, `checkstyle`, `jacoco`, and
  `JACOCO_MIN_LINE=0.25 clojure -T:build jacoco-gate`: pass, 43.8% line coverage
  versus unchanged 25.0% gate.
- `bash dev/script/codex.sh perf`: 457.4 ms for 50k Full packets, unchanged
  warning/failure 1000/1200 ms. Run after other JVM work finishes.
- `bash dev/script/codex.sh package`: snapshot JAR builds, expected library,
  decoder/project, extension and native-binding resources present.
  Outside-checkout JAR-only `-Srepro` consumers pass full/flow/extensions/identity
  for all six DLTs and existing exact DNS/snapshots/bounded fan-out/PCAPNG/window
  composition. Resources are asserted to load from `jar:` URLs. CLI emits its
  informational implicit-main deprecation warning; no classpath fallback.
  `prepare` restores Java test classes after package deletes target.
- Opt-in CLI invalid suite: intentional exit 1 and expected error, checked in a
  fresh JVM. All real successful suites and the 944-pair summary command run.
  Four zero-context patches apply to unchanged main with `--unidiff-zero`.
- `git diff --check`: passes. Production linktype SHA-256 remains
  `5a63c9a7169f234e02d7044cbe8e132db5f50d001a906270777adfd7b3bbdc41`
  across final formatting, profiling and all gates.

Independent PR and final-head CI handoff follow. Issue #44 stays open for
review of the evidence and remaining limits; no closing keyword, merge,
release/version or unrelated Issue #37/P09/P10 work.

### Independent PR handoff

Created [PR #58](https://github.com/nantes-rfli/paclo/pull/58),
`perf: investigate and optimize Ethernet decoding (Issue #44)`, from the scoped
branch. Implementation commit is `68ed59adcc3dc738155a7d2fb15d50a87daa5714`.
All existing pre-commit checks run without skip flags: 490 tests / 19036
assertions, namespace/format, Markdown and kondo. A temporary `clj` wrapper
forwards to the installed Clojure CLI so no interactive rlwrap is required.
Source/driver/artifact manifest hashes remain unchanged after the hook.

Before push, `git fetch origin main` confirms main is still `e444b10`.
The PR is attached to this chat. Its initial CI run is
[38954618210](https://github.com/nantes-rfli/paclo/actions/runs/38954618210).
The only subsequent changes are this record, plan and performance-report
handoff links/wording.
Check all twelve jobs on the resulting final head and record exact run/status
in the PR description, rather than making another evidence-only commit.
Do not treat an interrupted earlier-head run as final verification. No workflow,
threshold, dependency, version, production code or measurement data changes
follow the implementation commit. Issue #44 remains open for independent
acceptance; no review approval, merge or release is implied.

## 2026-10-17: Release readiness audit after P06–P08

Requested scope: current implementation/API/doc/CI/package/Issue audit from latest
main, document corrections and an independent PR; no tag, publication, Issue
closure or merge. Initial `git status --short --untracked-files=all` was clean.
Fetched main and created `codex/release-readiness-p06-p08` from
`752c3646eab58070f05b6fa11aa8ff4142173022` in the supplied checkout.
Read CONTRIBUTING, API contract and accepted plan before editing.

The [readiness report](release-readiness-p06-p08.md) records complete inventory,
format/lifetime/OS boundaries, SemVer alternatives, required fixes, Issue decisions
and the recommended release sequence. P01–P08 and follow-up implementations are
merged; P09/P10 remain blocked. Prefer 1.4.0 only after explicit compatibility
acceptance and the Java17 artifact correction; publication is not ready.

Confirmed blocker: `javap -verbose target/classes/paclo/jnr/PcapLibrary.class`
reports major 65; `build.clj` has no release target, while Publish builds with
JDK21 and docs advertise JDK17. The cached Clojars v1.3.0 JAR also has major 65.
Source-build CI on JDK17 does not test that distributed JAR. No local JDK17 is
installed (only 21/13); require a separate build correction and identical JAR
consumers on 17/21. No runtime/build/workflow fix is made in this docs-only scope.

Live GitHub checks via the connected GitHub API confirm main run 38988905927 and
PR #58 final-head run 38955008505 all twelve jobs successful. PR #58 is reviewed
and merged as 752c364 on 2026-10-17. Issue #44 remains open; recommend evidence-
bounded closure after accepting its remaining measurement limits. PR #57 review
explicitly keeps Issue #37 open for actual retired expiry and production-trace
work. #40 and #34 are closed, without claiming lazy abandonment repaired.
Dependency Audit run 38428605480 succeeded 2026-10-13 at 8312d10; a fresh release
scan remains a release acceptance check. `git diff v1.3.0..HEAD -- deps.edn` is empty.

Direct Clojars API GET reports latest/version 1.3.0; GitHub latest release and
versioned cljdoc agree. Web search's project-page cache showed 1.2.0 and was not
treated as current state. Local network sandbox initially prevented GitHub/Clojars
reads; approved read-only network commands succeeded. Fetch/switch required normal
Git metadata write escalation. No approval rejection occurred.

Document corrections preserve the authority structure: README/ROADMAP now state
P01–P08 complete but Unreleased; README includes PCAPNG writer and P07-B migration;
API/usage remove stale future-P07 language; PCAPNG availability is explicit;
performance distinguishes quick measurements from the existing timed gate;
CHANGELOG retains phase scope/history and its Unreleased boundary. CONTRIBUTING
links current release conditions and explains Publish's partial gate coverage.
Plan review/merge/next-item states are updated, without rewriting old work-log
handoffs or released changelog sections.

Verification commands and results:

- `bash dev/script/codex.sh doctor`: exit 0, macOS x86_64, Temurin 21.0.12.1,
  Clojure 1.12.1, real offline read four packets / 438 bytes.
- `bash dev/script/codex.sh check`: exit 0; 490 Clojure tests / 19036 assertions,
  zero failures/errors; ten JUnit tests and offline native smoke pass. Real
  captures, PCAPNG wire/heap and property regressions remain unchanged.
- API source comparison against v1.3.0 plus runtime public Var/arity inspection
  via `/tmp/paclo-release-api-audit.clj`: exit 0, baseline names/arities retained.
  Behavioral exceptions are separately recorded; constructors are unsupported.
- Five existing fixture generator `--check` commands (with `python3 -B`): pass
  28 format, 4 cooked, 3 Raw, 12 NULL/LOOP and 10 PCAPNG-contract captures.
- `python3 -m unittest discover -s dev/script -p test_verify_doc_examples.py`:
  15 tests pass. `python3 dev/script/verify_doc_examples.py`: exit 0, all 34
  maintained examples pass. Two existing Flow examples were subsequently corrected and re-executed below.
- `python3 dev/script/test_eastwood_runner.py`: exit 0; four real subprocess
  probes, including expected negative analysis exit 1/unanalyzed namespace.
- `clojure -M:spotbugs`, `clojure -M:checkstyle`, `clojure -M:jacoco`,
  `JACOCO_MIN_LINE=0.25 clojure -M:jacoco-gate`: exit 0; line coverage 43.8%,
  unchanged 25% gate.
- Link-checker unit tests initially failed on macOS's symlinked default temp
  directory (`/var` versus resolved `/private/var`), not a bad repository link.
  `TMPDIR=/private/tmp python3 -m unittest discover -s dev/script -p
  test_verify_doc_links.py` passes all nine tests unchanged. The expected
  invalid-fixture error printed by one passing test is intentional. An interim
  real-link check caught the not-yet-written work-log heading; final check follows.

Additional validation results, package details and PR handoff follow below.

- Initial `bash dev/script/codex.sh lint` analyzed all 112 Eastwood namespaces
  (593 informational warnings, zero exceptions), kondo zero warnings/errors and
  clean-ns/format dry runs, then failed solely at npm network access. The same
  full wrapper is rerun with approved network access; no linter/rule changed.
  Markdown lint independently passes all 42 files after correcting two audit
  formatting errors (line length and an Issue number at start of line).
- `clojure -Sdeps '{:deps {cljdoc/cljdoc {:mvn/version
  "0.0.1315-c9e9a7e"}}}' -M -e "(require 'cljdoc.doc-tree) (println
  :cljdoc-loaded)"`: exit 0. This is the existing CI namespace-load check, not
  an actual remote documentation publication.
- `bash dev/script/codex.sh perf`: exit 0, 452.1 ms, unchanged 1000/1200 ms
  warning/failure budgets. Local checks do not establish a new live/NIC target.
- `bash dev/script/codex.sh package`: exit 0; inspected 41 JAR entries, all
  expected public/annotation/internal resources and ten binding classes, with
  no test/dev roots or fixtures. All ten class versions are 65. Embedded POM
  coordinates/version/SCM are org.clojars.nanto/paclo / 1.3.0-SNAPSHOT /
  v1.3.0-SNAPSHOT; five dependencies match default deps. MIT is in the POM,
  standalone LICENSE text is absent. No release version override was used.
- Isolated `/private/tmp/paclo-release-candidate-consumer/deps.edn` contains
  `:paths []` and only the local/root JAR dependency. Existing Ethernet and DNS
  consumer scripts loaded with `-i` run under `clojure -Srepro -M` outside the
  checkout: both exit 0, asserting jar-protocol resources and checking all six
  DLTs/full/flow/extensions/byte identity, exact DNS/EDN snapshots, independent
  fan-out, PCAPNG author/read and Window composition. A separate Flow probe
  checks bidirectional keys, exact totals and immutable/EDN-resumed snapshots.
  Its first temporary script had an unmatched parenthesis and failed to compile;
  the script was corrected without repository changes and rerun.
- Published v1.3.0 JAR-only API baseline check: exit 0. A shared eight-case
  writer probe against published/candidate JARs confirms legacy time retention,
  changed dual-pair precedence, partial/nil/fractional validation, truncated wire
  length preservation and explicit DLT mismatch rejection. Concrete results are
  tabulated in the readiness report.
- `prepare` restores Java test classes after package; no packaging runs concurrently
  with compilation/tests/performance. Generated Python `__pycache__` files are
  removed before submission; they were absent in the initial clean checkout.

Final local results: all three JAR consumers pass on JDK21 (Flow included),
`prepare` exits 0, all 34 executable docs and cljdoc loading pass. Real repository
links and `git diff --check` pass. The network-enabled full lint retry repeated
all Clojure analyses successfully but caught Markdown interpretation of a newly
appended unquoted `__pycache__` name in this log; it is now quoted and the full
wrapper is rerun unchanged. No functional source, dependency, workflow, threshold,
release version or historical release section is changed. Audit authoring and
local verification complete; PR review and the separate Java17 correction are
the next unfinished work.

Final API call-site inspection found two maintained usage snippets calling
`flow/top-n` with a number instead of its documented options map. They happened
to pass because the implementation used default n=10 and the tiny fixtures had
at most eight flows. Corrected them to `{:n 10}` / `{:n 8}` without changing
runtime validation. Re-execute those two examples with the unchanged registered
checks; also exercise `{:n 1}` to demonstrate actual requested limiting.

Final full `bash dev/script/codex.sh lint` exits 0: kondo zero errors/warnings,
112 Eastwood namespaces / 593 informational warnings / zero exceptions,
namespace and formatting dry runs clean, all 42 Markdown files pass. Both
changed documentation examples and their n=1 variants exit 0. The successful
result supersedes the intermediate environmental/Markdown failures above.

For committing, the existing hook uses `clj`, but this host lacks `rlwrap`.
A temporary PATH shim invokes the installed Clojure CLI noninteractively; the
hook still runs its original full tests, formatter, Markdown and kondo checks.
No SKIP flag or repository hook change is used. PR/final CI evidence is tracked
on the submitted PR to avoid repeated evidence-only commits.

Audit implementation commit: `303198180aa7f8d5e4617c00e1cfa38641e5e520`.
[PR #59](https://github.com/nantes-rfli/paclo/pull/59) is open for independent
review against main `752c364`, with only twelve Markdown files changed. The
existing commit hook passed its complete 490-test suite, format/namespace,
Markdown and kondo checks without a skip. This handoff records the PR link;
final-head CI/platform results are maintained in that PR's description/checks.
No review, merge, issue closure or publication is claimed. Next unfinished work:
review this audit and then make the separate Java17 distribution/consumer fix
before versioned release preparation.

## 2026-10-17 Java 17 distribution compatibility correction

Task starts from clean supplied checkout; fetched latest main `3f63c1e6be59816e1f26df437e32a8da39998171`
(PR #59 merged), branch `codex/java17-distribution`. No new worktree.
Read CONTRIBUTING, API contract, accepted plan and authoritative readiness audit.
`doctor` passes on macOS x86_64/Temurin 21.0.12.1/Clojure 1.12.1/libpcap,
including the real four-packet offline read. Local JDKs are 21 and 13; no JDK 17.

Reproduced the pre-fix Publish/package route by temporarily restoring exactly
`origin/main:build.clj`, running `bash dev/script/codex.sh package`, saving
`/private/tmp/paclo-java17-before.jar`, then restoring the correction. All ten
class headers are major 65. Corrected package is ten major 61 with the same POM
coordinates/dependencies and production source inventory. No public/runtime
behavior changes. `jar`, `javac`, `javac-test` share release17/strict options;
three CI direct-javac fallbacks removed. An isolated `List.getFirst()` canary
fails on JDK21 with `--release 17` and succeeds with default JDK21 javac, proving
the API restriction as well as the class target. Existing bindings compile.

Added exact JAR inspection and external isolated consumer bundle. Seven Python
regressions pass: valid17, one nested65, preview, missing namespace, leaked
test/fixture/dev-root, coordinate/dependency/scope changes, modified same-name JAR.
Consumer uses only local/root paclo.jar plus original POM dependencies with
`-Srepro`, checks JAR resource/code origins and classpath directories, and runs
real offline/native/all-DLT/writer/analysis/annotations/ownership probes.
Initial harness corrections: use a Class local for binding CodeSource reflection;
fan-out needs two branches, both consumed concurrently. These were harness errors,
not product regressions. Final local JDK21 consumer prints
`:distribution-consumer-ok ... :annotations :closed`, exit 0.
Preliminary JAR SHA-256 `6bbfe480fd39671c86bc738e9e259fe7b553f42ea3810e45b3b806ed2139727f`,
base commit `3f63c1e`, dirty true; clean CI identity/results recorded separately.

CI uploads the one JDK21 build-checks JAR, with provenance and external inputs;
checkout-free JDK17/21 jobs each verify hashes before execution and JAR identity
after execution, then upload runtime reports. Required build includes both.
Publish inspects/saves provenance without changing version/publication controls.
No Publish run, tag, deployment, merge, dependency update, performance optimization
or P09/P10 work. Full local checks, CI timing/results and PR evidence follow.

Local gate progress before opening the independent PR:

- `bash dev/script/codex.sh prepare`: exit 0.
- `bash dev/script/codex.sh check`: exit 0; ten JUnit, 490 Clojure tests /
  19036 assertions, zero failures/errors, real offline smoke.
- `clojure -T:build spotbugs`, `checkstyle`, `jacoco` and
  `JACOCO_MIN_LINE=0.25 clojure -T:build jacoco-gate`: all exit 0; 43.8% line
  coverage, unchanged 25% gate. Production and test output majors all 61.
- `bash dev/script/codex.sh perf`: exit 0, 718.7 ms; unchanged 1000/1200 ms
  warning/failure budgets. This is the offline gate, not a throughput claim.
- `bash dev/script/codex.sh package`: exit 0; embedded POM and every Clojure
  source entry are byte-identical before/after. JDK21 independent consumer
  repeated after harness finalization: exit 0 with the same preliminary JAR.
- `python3 -B -m unittest discover -s dev/script -p 'test_verify_distribution.py'`:
  seven tests pass. Both workflow YAML files parse, shell syntax and
  `git diff --check` pass.
- Initial full `lint` reached zero Kondo errors/warnings, all Eastwood namespaces
  without exceptions and clean namespace/format dry runs, then failed at npx:
  sandbox DNS `ENOTFOUND registry.npmjs.org` and unwritable npm logs. Offline npx
  also reports `ENOTCACHED`; these are not counted as passing lint. The exact
  wrapper is rerunning with normal network/cache permissions. No rule changed.
- Executable docs/link and five fixture generators/Python contract checks are
  running; complete results and GitHub CI are still pending at this commit.

Independent [PR #60](https://github.com/nantes-rfli/paclo/pull/60) opened with
implementation `e008dd0be3ce41ae9a41c92ce34088546f83da99`; base main `3f63c1e`.
Local `gh` authentication is invalid, so PR/Actions inspection uses the connected
GitHub tools; git fetch/push uses the existing SSH remote. No login/token changes.
The configured `.githooks/pre-commit` initially fails because `clj` requires absent
rlwrap. Used its documented SKIP_TESTS/SKIP_FMT flags after successful equivalent
`check` and lsp dry runs; its Markdown and Kondo checks ran successfully. No hook,
rule, test or gate was removed or edited. The working tree remained scoped.

Completed local verification:

- Full `bash dev/script/codex.sh lint` rerun with normal network/cache permissions:
  exit 0. Kondo zero errors/warnings; all 113 Eastwood namespaces (including the
  standalone consumer), 599 informational warnings, zero exceptions; clean-ns
  and format dry runs clean; 42 Markdown files, zero errors. Initial 600-warning
  run preceded making the explicit decode-ext registry probe use its require.
- `python3 dev/script/verify_doc_examples.py`: exit 0, all 34 maintained examples.
- `python3 dev/script/verify_doc_links.py`: exit 0.
- All five `make_capture_format_fixtures.py`, `make_cooked_fixtures.py`,
  `make_raw_ip_fixtures.py`, `make_null_loop_fixtures.py`,
  `make_pcapng_contract_fixtures.py --check` commands: exit 0 (28 + 4 + 3 + 12 + 10).
  `python3 test/resources/test_pcapng_contract_fixtures.py`: six tests pass.
- Local independent consumer's final harness runs against the same preliminary
  JAR digest already recorded, with only current consumer directory/JARs on its
  classpath. No local JDK17 runtime pass is claimed.

Actual clean CI candidate identities, both runtime results, all jobs and measured
CI duration follow. No release/tag/deploy/merge is authorized or performed.

### PR #60 implementation CI and identical distribution JAR

[Run 38993389235](https://github.com/nantes-rfli/paclo/actions/runs/38993389235)
for head `e008dd0be3ce41ae9a41c92ce34088546f83da99`: **all 14/14 jobs pass**.
Original 12 jobs all succeed (including informational coverage and Linux ARM64),
as do both mandatory artifact consumers. Required aggregate prints
`distribution-consumer=success`; no gate/threshold was weakened or bypassed.
Linux x64 and ARM64 source tests: 490 / 19042 assertions; macOS ARM64 JDK17:
490 / 19036. Zero failures/errors. Existing CI perf gate 336.7 ms, Java line
coverage 43.8% / unchanged 25%. Full Eastwood, docs and all 27 measurement
scenarios/results pass.

Single JDK21 candidate:

- Actions checkout/source commit `66f81b8549750a708c6a2ef903d75b370f135600` is the
  synthetic PR merge of implementation `e008dd0` and base main `3f63c1e`.
  Provenance says tracked-file dirty false; build JVM Temurin 21.0.12.1.
- Artifact `distribution-jdk21-38993389235`, ID `12085732197`, ZIP SHA-256
  `1085f515df0b9532d83e258879d350cd3cb42ec0f210aa57e22f3de3f59ba7f5`.
  Downloaded it through the connected GitHub artifact tool, extracted outside
  the checkout and ran the local `verify_distribution.py verify` on the actual
  files. ZIP digest matches Actions, and JAR/provenance/POM/inventory all pass.
- JAR SHA-256:
  `358b8d526d744939a47559f6b4189c37d325c31288e3e3e290bc5c2f5ed78d89`.
  Every class is major61. External and embedded POM match; five dependencies and
  coordinates remain original. All 18 source entries remain original bytes.
- `distribution-consumer (17)`, job `117280805042`: Temurin 17.0.20.1,
  success with exactly that SHA-256 before/after and source commit; prints
  `:distribution-consumer-ok` for every probe. Runtime report artifact
  `distribution-consumer-jdk17-38993389235`, ID `12086341073`.
- `distribution-consumer (21)`, job `117280804991`: Temurin 21.0.12.1,
  same success, full SHA-256 and source commit. Runtime report artifact
  `distribution-consumer-jdk21-38993389235`, ID `12086261257`.
- Both jobs have no checkout or Java compilation/build step. They download the
  same immutable Actions artifact, verify all manifest hashes, then execute a
  fresh `-Srepro` consumer outside the checkout with only local/root JAR plus
  unchanged dependencies. Neither runtime consumes recompiled source bindings.
  This resolves the JDK17 failure's identified class-major cause, rather than
  treating a source rebuild or workaround as success.

CI time measured from log timestamps: verifier/regressions/bundle 0.15 s;
artifact upload 1.1 s; JDK17 consumer setup-through-upload 27.4 s; JDK21 39.5 s
in parallel after build-checks. The new consumers add about 46 s after the
build-checks finish (99.3 s in this run; prior main run 38988905927 took 147.7 s).
The build-checks-start through required aggregate finish interval is 193.4 s,
versus 190.8 s before (+2.6 s); source compatibility, not artifact consumers,
finishes last here. These are single runs with runner/cache/network variation,
not a speedup claim or fixed added budget. There are two new jobs (12 to 14),
with all existing work/quality/performance thresholds retained.

Remaining limits: no local JDK17 installation, Windows, other JDKs/platforms,
live/NIC capture, arbitrary filesystem or performance-target validation. Linux
same-artifact 17/21 and existing Linux x64/ARM64/macOS ARM64 source checks are
actual passes. No release version assignment, tag, Publish dispatch, deployment,
merge, issue closure, feature/dependency work or optimization was performed.
Next: independent PR #60 review. Evidence-only commit final checks remain on PR.

## 2026-10-17: Next-release compatibility and version proposal

Requested scope: independent documentation/assessment PR from latest main after
PR #59/#60, no version assignment/publication or production/API correction.
Initial `git status --short --untracked-files=all` clean. Read AGENTS,
CONTRIBUTING, API contract, accepted plan, readiness report, changelog and prior
work-log evidence. Fetched origin and created `codex/release-compatibility-version`
from `2f97ab25cc9e46550aa24be80d11ccc667dab2d3` in supplied checkout. Git metadata
and GitHub/network reads used normal approved sandbox escalation. No rejection.

Read live PR #59/#60 merge/body/check data, PR #58 independent review and Issue
Issues #37/#44 original requirements/current open states. PR #60 is merged as 2f97ab2.
Main CI 38996721327 reports all 14 jobs successful, with no skipped/failed jobs.
Downloaded main distribution/provenance and both consumer report artifacts to
`/tmp/paclo-main-distribution`. Clean source commit 2f97ab2; build Temurin21.0.12.1;
all ten classes major61. Both Temurin17.0.20.1 and21.0.12.1 reports identify the
same SHA-256 `8f153f45daa9a4e00176923bb3c75169ecac64157f0272f03436a5bd9a1812e8`;
local JAR hash agrees. PR #60 final CI38993735942 also reports 14/14 success.
These are separate run identities, not mixed artifacts or rebuilt consumers.

Fresh Clojars download `/tmp/paclo-published-1.3.0.jar` matches cached JAR SHA-256
`65a98348320ad905939e72fbf825b57111d704057698718863487edd22797a1b`.
Nine released binding classes are major65. Inspected tag-v1.3.0 API/README/usage,
migration/deprecation policy, actual Writer and CLI sources rather than using
current docs to redefine old guarantees. Read SemVer2.0.0 rules6–8 from upstream.

The [assessment](release-compatibility-version.md) separates guaranteed,
incidental and erroneous behavior for every requested compatibility category.
Preferred 1.4.0 remains conditional on unresolved D1 Writer-extra-metadata and
D2 official-CLI policy interpretations. Human acceptance cannot waive a genuine
SemVer break: require a separate restoration PR or 2.0.0 if a formal guarantee
is broken. No public API is changed. The user migration draft is linked from the
docs index and adds two registered executable examples; exact API rules stay in
the existing canonical contract. P01–P08/stabilization/performance/build fixes
are proposed in scope, P09/P10 excluded, #37 open/non-blocking, #44 closure only
after separate issue-level acceptance with no Flow/historical/NIC speedup claim.

Added an opt-in external comparison driver and standalone dev probe; they never
compile library code or modify JARs. Each variant uses a fresh temporary consumer
with `-Srepro`, local/root JAR and verified Java/Clojure JAR resource origins.
CLI sources are extracted unchanged from each revision as external inputs because
the dev examples are not packaged in the library. Raw output/status is retained.
Direct record-header inspection distinguishes old invalid writes from reader
rejection. Initial comparison passes all probes; then probe forms were wrapped
in a side-effect-free namespace/-main so ordinary lint loading is safe, formatted,
and rerun with extra RTT stats/server group cases. No library change resulted.

Observed: old dual-pair time uses legacy versus capture on main; partial new,
nil/fractional/range/length/framing/snaplen cases change as documented. All old
supported names/arities retained. Old native truncated header appears as EOF;
main throws with structured native rc/reason. Same four real packets give equal
Flow rows/totals with changed ties; RTT gains 10.241/15.817ms; QPS client groups
combine both directions. Four buckets with max-buckets1 go from truncated row/
exit0 to no stdout/exit5. New Flow bound uses JVM exit1, not DNS exit5.
This is explicit valid-input behavioral migration, not an arity-only conclusion.

Local verification so far:

- `bash dev/script/codex.sh doctor`: exit0, macOS x86_64, JDK21.0.12.1,
  Clojure1.12.1, libpcap offline four packets/438 bytes.
- `bash dev/script/codex.sh check`: exit0; ten JUnit tests, 490 Clojure tests /
  19036 assertions, no failure/error, native offline smoke. Existing fixtures,
  properties and heap/wire tests run unchanged.
- `python3 dev/script/verify_doc_links.py` and `git diff --check`: pass during
  authoring. Final lint/docs/package/performance/consumer results follow below.

Additional final local evidence:

- Final `compare.py OLD.jar MAIN-CI.jar OUTPUT.json`: exit 0; 16 subprocess cases
  (eight per version), expected nonzero bound/unknown-flag cases preserved in
  `dev/release-compatibility/comparison.json`. RTT stats change from with-rtt 0 /
  nil average to with-rtt 2 / 13.029 ms; server groups confirm QR role orientation.
  No source recompilation, altered historical sources or normalized old limits.
- `python3 -m unittest discover -s dev/script -p test_verify_doc_examples.py`:
  15 tests pass. Full executable-document gate passes all 36 examples. The
  invalid-time migration example was then strengthened from preparation-only
  validation to real Writer rejection plus successful corrected-file readback;
  that exact changed example is independently rerun and passes.
- `TMPDIR=/private/tmp python3 -B -m unittest discover -s dev/script -p
  test_verify_doc_links.py`: all nine pass, including the intentional printed
  invalid-link fixture. Actual local Markdown links/heading anchors pass.
- `python3 -B -m unittest discover -s dev/script -p
  test_verify_distribution.py`: seven artifact-gate regressions pass.
- Initial full `lint` has zero kondo warnings/errors, all 113 Eastwood namespaces
  complete (600 informational warnings, zero exceptions), then fails only on the
  new probe's require layout in clean-ns. Corrected that layout; independent
  clean-ns/format/kondo checks pass. Initial Markdown run catches an issue number
  at the beginning of a work-log line (MD018); corrected prose. Complete wrapper
  is rerun unchanged below; no rule, gate or threshold is relaxed.
- `bash dev/script/codex.sh perf`: exit 0, 594.4 ms; unchanged 1000/1200 ms
  warning/failure limits. No performance improvement claim from this run.
- `bash dev/script/codex.sh package`: exit 0. `verify_distribution.py prepare`
  and `consume --report` both pass for `/tmp/paclo-version-local-distribution`.
  Local JAR SHA-256 `e41328d23b1ac09b64749671810f78a31aa3e3e2006c966a096543792f4d5132`;
  source base 2f97ab2 with tracked docs dirty (not clean-release provenance), ten
  major-61 classes. Inventory and all production source/class/POM bytes match
  the downloaded main CI JAR; only pom.properties build timestamp differs.
  Isolated JDK 21 consumer covers all existing offline public/format/lifetime
  probes and reports passed. JDK 17 execution is from actual main CI, not local.
- `prepare` restores Java tests after package; packaging did not overlap tests,
  compilation or performance. cljdoc namespace-load command with existing pinned
  `0.0.1315-c9e9a7e` succeeds (`:cljdoc-loaded`); historical harmless cuerdas name
  shadowing warnings remain. No remote cljdoc publication is attempted.

Final wrapper/PR handoff and final-head CI are recorded after these checks.
The release version, D1/D2 and issue closure remain human decisions. No Publish
workflow (including dry run), tag, release, deploy, issue mutation or merge occurs.

Final full `bash dev/script/codex.sh lint`: exit 0; zero kondo warnings/errors,
113 Eastwood namespaces / 600 informational warnings / zero exceptions, clean-ns
and format dry runs unchanged, all 44 Markdown files pass. Local links and
`git diff --check` pass after the final status update. All new examples remain
registered in the existing CI gate. No source/dependency/build/workflow/changelog
implementation diff. Assessment and local verification are done; human D1/D2,
version/scope and issue acceptance plus independent PR review remain unfinished.
Final-head GitHub CI results will be recorded on the PR rather than generating
an additional evidence-only commit after that CI run.

Commit hook's first attempt stops before tests because installed `clj` requires
missing rlwrap. A temporary `/tmp/paclo-version-hook-bin/clj` delegates the same
arguments to `/usr/local/bin/clojure` for noninteractive use. No hook/config/rule
is edited or skipped. Retry runs the ordinary tests/format/Markdown/kondo hooks.

Implementation commit: `docs: assess next release compatibility and version scope`
on `codex/release-compatibility-version`. The independent PR uses the requested
`docs: decide next release compatibility and version scope` title. Final-head
14-job CI and identical JAR runtime identities are maintained in its description;
independent review and human D1/D2/version/scope approval are the next work item.

## 2026-10-17 — v1.4.0 release preparation

User-authorized scope: v1.4.0, keep D1 Writer capture metadata/strict validation
and D2 exact bounded DNS/failures, publish migration guidance, include P01–P08
and merged fixes, exclude P09/P10. Publication, tag, GitHub Release, Clojars,
non-dry-run Publish and merging are prohibited. Even Publish dry-run is deferred
until a separate request after review/merge. No issue mutation is requested.

Started with clean `git status --short --untracked-files=all`. Read AGENTS,
CONTRIBUTING, readiness/compatibility reports, migration/API/PCAPNG docs,
CHANGELOG/ROADMAP/plan, CI/Publish/build/distribution scripts and PR #59/#60/#61.
All three PRs are merged. `git fetch --no-tags origin main` and
`git switch -c codex/prepare-v1.4.0-release origin/main` use latest main
`82705b9c601b2361be8f9446f519f54673aa0d64` in the supplied checkout. Git metadata
writes needed sandbox escalation and were approved. No extra worktree.
`gh auth status` reports its existing token invalid; connected GitHub tools work,
and the existing SSH Git remote fetch works. No interactive auth or token changes.
Read-only public API curl requests needed approved network escalation.

Prepared a clearly unreleased v1.4.0 CHANGELOG section without a release date,
retained v1.3.0 installation coordinates, completed migration guidance and aligned
API/PCAPNG/roadmap/plan availability. Added draft release notes and a final
acceptance checklist with blockers and post-merge dry-run steps. Corrected stale
README text claiming the PR #60 Java17 artifact repair was still outstanding,
while recording that the already published v1.3.0 JAR itself has major65.
The earlier compatibility report is retained as dated evidence with the user's
subsequent D1/D2/version/scope decision at its top, without pretending observable
migration impacts disappeared.

Development default and distribution verifier default advance to 1.4.0-SNAPSHOT.
CI build-checks explicitly packages PACLO_VERSION=1.4.0 once and sends that
candidate to the existing checkout-free 17/21 consumers. All 14 jobs, compiler
options/dependencies/thresholds remain. Source compatibility jobs still build the
snapshot. Publish metadata validation now permits an explicitly unreleased
heading only in manual dry-run, so future dry-run does not need a fictitious
publication date. Actual publishing requires a valid calendar date. Added four
regression tests covering candidate-vs-publication, dated headings, invalid dates,
wrong/missing headings and invalid version syntax; CI and Publish run them.
Only the metadata checker is run locally; no Publish workflow is dispatched.

Verification so far:

- `bash dev/script/codex.sh doctor`: exit0, macOS x86_64, Temurin21.0.12.1,
  Clojure1.12.1, four real libpcap fixture packets / 438 bytes.
- `bash dev/script/codex.sh check`: exit0, ten JUnit and 490 Clojure tests /
  19036 assertions, zero failures/errors, native smoke. Includes existing
  PCAP/PCAPNG real round-trip, independent wire, property/lifecycle/heap checks.
- `python3 -B -m unittest discover -s dev/script -p test_verify_release_metadata.py`:
  four tests pass. `python3 dev/script/verify_release_metadata.py 1.4.0 --dry-run`
  accepts the explicit candidate heading (metadata check only).
- Documentation parser/link/distribution regression suites: 15/9/7 pass. The
  link suite's deliberately printed absent.md error is an expected negative
  fixture; suite exit0. Actual `verify_doc_links.py` and `git diff --check` pass.
- Live Clojars API recheck: latest_version and latest_release are 1.3.0.
  Latest main CI [38999502746](https://github.com/nantes-rfli/paclo/actions/runs/38999502746)
  succeeds at baseline 82705b9. Final PR acceptance is separate.
- Latest existing Dependency Audit [38428605480](https://github.com/nantes-rfli/paclo/actions/runs/38428605480)
  succeeds, 2026-10-13, source 8312d10. This is not a fresh release-SHA scan;
  refresh/triage before publication. No dependency update/audit dispatch here.
- Live issues #37/#44 are still open. Keep #37 non-blocking; record PR #58
  gains with JIT/thermal/retained-heap/negative-result limits for #44. Neither
  issue is closed, and no Flow/historical-speed/live-NIC claim is made.

Full lint, executable docs, Java quality, unchanged performance gate, candidate
package/POM and independent consumer results follow below. Local JDK17 is not
installed (java_home lists 21/13); final candidate CI must supply same-JAR JDK17
execution, not infer it from a source build or old CI artifact.

Completed local acceptance:

- Full lint stages: clj-kondo zero warnings/errors; all 113 Eastwood namespaces
  analyzed, 600 informational warnings, zero exceptions. clean-ns/format dry runs
  report nothing to clear/format. Initial Markdown invocation failed because the
  sandbox could not resolve registry.npmjs.org or write npm logs. Approved
  network/cache retry `bash dev/script/mdlint.sh` uses unchanged pinned
  markdownlint-cli2 0.18.1 and passes all 46 files. No rules are relaxed.
- `python3 -B dev/script/test_eastwood_runner.py`: four tests pass, including
  deliberate failures/unanalysed namespaces producing nonzero exit status.
- `clojure -M:spotbugs`, `clojure -M:checkstyle`, `clojure -M:jacoco`,
  `JACOCO_MIN_LINE=0.25 clojure -M:jacoco-gate`: exit0; line coverage43.8%,
  unchanged25% threshold. XML reports copied to /tmp/paclo-v140-quality before
  packaging deletes target. No Java implementation changes.
- `python3 -B dev/script/verify_doc_examples.py`: all36 examples pass, including
  both real-I/O Writer migration examples. `verify_doc_links.py` passes local
  paths/anchors; it deliberately does not validate every external URL.
- `python3 -B -m unittest discover -s test/resources -p test_*.py`: six pass.
  All five existing fixture-generator `--check` commands pass: 28 capture,
  four cooked, three RawIP, twelve NULL/LOOP, ten PCAPNG contract captures.
  Writer independent wire checks also run in the full Clojure suite.
- Existing pinned cljdoc namespace-load command succeeds (`:cljdoc-loaded`);
  historical cuerdas name-shadowing warnings remain. No cljdoc publication.
- `bash dev/script/codex.sh perf`: exit0, 446.5ms; existing1000/1200ms warning/
  failure budgets. This is gate acceptance, not a performance improvement claim.
  The existing three-shard/27-scenario measurement remains required in final CI.
- `PACLO_VERSION=1.4.0 bash dev/script/codex.sh package`: exit0. Followed only
  after tests/compilation/perf completed by distribution prepare/consume in
  /tmp/paclo-v140-distribution using explicit `--version 1.4.0`; both pass.
  JAR SHA256 `1378838db828b784556698c4aa2d8ad2d3a67e02af591582ebe81f1a49af95ad`;
  embedded/external POM SHA256 `91a5f668b7e9daf06735f09a10efe9dba9daec8946704cc7ce696456d2338d56`.
  All ten classes exactlymajor61; production inventory/bytes, five unchanged
  dependencies, coordinates, pom.properties, MIT and SCM URL/connections/tag
  v1.4.0 verified. SCM tag text does not create a Git tag.
  Local provenance is baseline82705b9 with tracked preparation changes dirty,
  Temurin21.0.12.1; it is not clean release provenance. Independent consumer
  verifies hash before/after and passes all offline API/format/lifetime probes.
- CI/Publish YAML parsed with platform Ruby YAML, all50/eight run-step scripts
  pass bash syntax checks without executing Publish. Four new metadata guard
  tests run in ordinary CI and remain part of the future Publish metadata step.
- GitHub latest release API confirms v1.3.0, published2026-08-01; Clojars latest
  release/version both1.3.0. No install coordinate is changed to an unavailable
  published version. Current dependency graph is unchanged.

Implementation/local verification are done. Create the independent preparation
PR titled `chore: prepare Paclo v1.4.0 release candidate`; final-head CI URL,
all14 results and its single candidate JAR/17/21 runtime identities are maintained
in that PR description so recording evidence does not create a new untested head.
Independent review/merge and separately requested post-merge Publish dry-run are
the next unfinished work. The checklist records security refresh, dry-run and
publication/date authorization as remaining publication gates. No new runtime
blocker was found locally; CI/platform/consumer evidence must actually pass.
No tag, Publish dispatch (even dry-run), GitHub Release, Clojars deploy, issue
closure, quality relaxation, new public API or merge is performed.

Before commit, `prepare` restores Java test classes after package. The ordinary
pre-commit hook is retained: a temporary /tmp/paclo-v140-hook-bin/clj delegates to
/usr/local/bin/clojure because this machine lacks rlwrap. No hook or check is
skipped or edited. Final links, metadata regressions and diff whitespace checks
pass before staging; the commit hook runs its normal tests/format/Markdown/kondo.

## v1.4.0 Publish dry-run verification (2026-10-17)

Completed the explicitly requested dry-run and Dependency Audit from latest main
`dfc5c5b4dbe39859b06431fa9c4b12714b89498d`, after PR #62 merged. Initial
`git status --short --untracked-files=all` was clean; the supplied checkout was
retained, with local branch `codex/verify-v1.4.0-dry-run` selected from origin/main.
No new worktree, remote source changes, commit or PR was needed for validation.
Read CONTRIBUTING, the v1 API contract, accepted plan and release checklist.
`bash dev/script/codex.sh doctor` passed (macOS x86_64/Temurin21.0.12.1,
Clojure1.12.1, four offline packets/438 bytes).

Preconditions and authorization:

- GitHub PR #62 is merged, merge SHA equals main. There were no GitHub review
  submissions or comments, so Publish was held until the maintainer explicitly
  confirmed completed independent review outside GitHub and instructed proceeding.
- `gh api .../actions/runs/39012456023/jobs` confirms all 14 latest-main CI jobs
  successful, including arm64-monitor and distribution-consumer17/21.
- Clojars official API latest_version/latest_release both1.3.0 before/after;
  no v1.4.0 tag or GitHub Release. Main CHANGELOG has the exact unreleased heading.
- `git fetch --no-tags origin main` and a diff confirmed candidate checkout
  contents match current main. Local CLI initially could not reach GitHub from
  the sandbox; approved network access succeeded with existing authentication.
  No login/token changes or credential export was performed.

Commands and results:

- `gh workflow run publish.yml --repo nantes-rfli/paclo --ref main -f version=1.4.0 -f dry_run=true`:
  [run39013121398](https://github.com/nantes-rfli/paclo/actions/runs/39013121398)
  success. Source guard fetched origin/main and required SHA equality. Logs show
  PACLO_DRY_RUN=true; version1.4.0. Main remained dfc5c5b before/after execution.
- All validation/build/upload steps passed. Release gates ran 490 tests /
  19042 assertions, zero failures/errors; unchanged performance gate335.2ms.
  Publish to Clojars and Publish summary skipped; Dry-run summary succeeded.
- `gh run download 39013121398 --name paclo-1.4.0` fetched the actual Publish
  JAR/POM/provenance. Independent artifact ZIP download/hash matched GitHub's
  digest225bc2fb47e337d41c645fa9c79a47dc85542b94a2459926d012ac772ef35e0e.
  JAR SHA256d226794493dcd4a5840d2f04ead8068c02e47a8c6b9ac275ca9f5adaacbddd10;
  POM SHA25691a5f668b7e9daf06735f09a10efe9dba9daec8946704cc7ce696456d2338d56.
- `python3 dev/script/verify_distribution.py prepare <downloaded-jar> <fresh-bundle> --version 1.4.0`
  inspected/copied without rebuilding. Exact source/inventory, ten major61
  classes, coordinates/properties and five unchanged direct dependencies pass.
  Separate XML/byte inspection confirms external/embedded POM equality, SCM
  URL/connections/intended tag v1.4.0 and MIT license. No tag was created.
  Every bundle-file digest matches original Publish provenance; restore that
  unchanged original provenance after local support-file assembly, preserving
  the actual GitHub build JVM and clean source identity.
- `python3 <bundle>/verify_distribution.py consume <bundle> --report <jdk-report>`
  with only JAVA_HOME/PATH switched to Temurin17.0.20.1+1 and21.0.12.1+1:
  both exit0 on macOS x86_64, same actual Publish JAR before/after. Separate
  temporary projects use -Srepro and assert all library/binding origins are the
  JAR; public/native/six-DLT/Classic/PCAPNG/Flow/DNS/window/annotation/lifecycle
  probes pass. No package/javac task was run per consumer. Official JDK17 archive
  was checksum-verified and extracted under /tmp only, without system installation.
- `gh workflow run dependency-audit.yml --repo nantes-rfli/paclo --ref main`:
  [run39013091814](https://github.com/nantes-rfli/paclo/actions/runs/39013091814)
  success on dfc5c5b. Downloaded reports show 23 production-classpath dependencies,
  zero detected/suppressed vulnerabilities, severity NONE; NVD last checked
  07:18:17Z and last modified07:16:50Z on2026-10-17. Report ZIP digest verified.
  OSS Index disabled without credentials; NVD CVE analysis completed. Default
  production classpath audit does not clear all development/build dependencies.
  Node20/setup-java-v4 deprecations and ubuntu-latest migration are non-blocking
  workflow maintenance notices. No dependency/workflow update was performed.

Full downloads/logs, consumer bundle and JDK were kept in temporary local storage;
durable original provenance, both runtime
reports, inspection, step results and audit summary are retained in
`dev/release-1.4.0-evidence/`. The detailed
[verification report](release-1.4.0-dry-run.md) links the GitHub artifacts.
Updated plan/checklist record completed gates and the next unfinished item:
separate publication authorization, actual-date/availability metadata and full
validation of any resulting release SHA. No new technical blocker was detected
within this verification scope. Issue37/44 follow-ups and existing live/platform/
format/lazy-lifetime limits remain unchanged; offline results do not clear them.
No Clojars deploy, tag, GitHub Release, dry_run=false, merge or publication occurred.

Documentation checks: `python3 dev/script/verify_doc_links.py` and
`git diff --check` pass. Initial sandbox Markdown lint waited on restricted npm
access and was interrupted (exit130); the approved network/cache retry
`bash dev/script/mdlint.sh` passed all 47 files with zero errors using unchanged
markdownlint-cli2 0.18.1. Retained JSON identities and Publish skip/success states
were checked together after copying evidence. No behavior change was made.

## v1.4.0 final metadata/evidence PR (2026-10-17)

The requested finalization carries forward the previous task's uncommitted
Publish dry-run report, plan/checklist/log updates and six JSON evidence files.
Initial status contained exactly those changes; no unrelated work was discarded.
The supplied checkout is based on main dfc5c5b4dbe39859b06431fa9c4b12714b89498d;
renamed its local working branch to codex/finalize-v1.4.0-release. GitHub main
still points to dfc5c5b and Issue #37 remains open. No new worktree was created.
Read CONTRIBUTING, API contract, accepted plan, dry-run report and release notes/
migration/checklist. `bash dev/script/codex.sh doctor` passes on macOS x86_64,
Temurin 21.0.12.1, Clojure 1.12.1, real libpcap fixture: four packets / 438 bytes.

Finalization decisions:

- The actual publication day has not been confirmed and this request prohibits
  publication. Keep the exact unreleased CHANGELOG heading; explicitly record
  the dated-heading publication blocker and future dated-commit revalidation.
  No provisional date is presented as an actual release date. README and all
  published install coordinates remain v1.3.0.
- Retain original Publish provenance and actual-JAR JDK 17/21 reports as baseline
  evidence, not as final-PR build identities. Remove newly added local temporary
  paths from durable records; no machine-specific paths or credentials are added.
- Replace stale checklist preparation/dirty-local evidence with measured main CI,
  Publish and audit results, then define exact final-PR acceptance and later
  publication steps. The checklist states that a tag push deploys to Clojars and
  must wait for separate formal authorization. No workflow/dependency changes.
- Final-check release notes and migration against the implemented v1 contract:
  D1/D2 migration, published v1.3.0 coordinates, bytecode compatibility, exact
  bounded DNS failure/completeness behavior, format/lifecycle/performance limits
  remain intact. Only evidence/availability handoff prose changes; examples and
  API behavior remain unchanged. Issue #37 stays non-blocking and open.

Local Markdown/link, metadata guard and retained-evidence checks are performed
before commit; the ordinary pre-commit hook remains enabled. After final push,
record the exact final PR head, synthetic merge build source (and tree equality),
all 14 CI conclusions, new single-JAR/POM SHA-256, both matching runtime reports,
branch-head Dependency Audit and review in the PR description. This avoids an
extra source commit after verification. Do not attribute old main dry-run hashes
to the new CI artifact or call a synthetic merge SHA the PR head.

Next unfinished item is maintainer acceptance, then separately authorized
publication with a confirmed day and complete validation of any resulting main
commit. This task creates the PR and performs review; it does not merge, create
or push tags, deploy, dispatch dry_run=false, or create a GitHub Release.

Pre-commit local verification passed: Markdown lint 47 files / zero errors,
local links/anchors, four release-metadata regression tests, dry-run metadata
acceptance and explicit undated-publication rejection, original artifact and
retained JSON identity/class/POM checks, and diff whitespace. A removed checklist
heading initially broke one README link; preserving the Distribution verification
anchor corrected it. No checker, threshold or behavior was changed. `prepare`
restores compiled Java test classes before the retained hook runs. The system's
missing rlwrap is handled by a temporary clj launcher delegating unchanged
arguments to the installed Clojure CLI, without changing or skipping the hook.

## v1.4.0 formal release — dated metadata (2026-10-17)

The maintainer explicitly authorized formal Clojars publication, GitHub Release,
actual-day metadata, required PR review/merge, final verification, single tag
creation/push and post-publication documentation. Retain D1/D2, P01–P08 scope,
all dependencies/APIs/quality budgets; P09/P10 remain out of scope.
Initial working tree was clean. Fetched latest main c8982fd after PRs #59–#63
merged; GitHub APIs confirmed all five merges, stable v1.3.0, no v1.4.0 tag or
Release, and Clojars API latest_version/latest_release1.3.0 with no1.4.0 version.
Main's checklist/Publish workflow match PR #63. UTC08:19 corresponds to Japan
17:19 on2026-10-17, so the approved actual-day CHANGELOG date is appropriate.
`bash dev/script/codex.sh doctor` passes on macOS x86_64/Temurin21.0.12.1,
Clojure1.12.1, four real offline libpcap packets/438 bytes. Use the supplied
checkout on codex/release-v1.4.0; no extra worktree.

Metadata changes date CHANGELOG to2026-10-17, remove obsolete date-unconfirmed
prose, correct its two incoming heading links, and retain explicit unpublished
availability in release notes/migration. README installation is unchanged.
The compatibility report's historical assessment is preserved; only its local
changelog link follows the new heading. The new publication record separates
source-bound gates and deployment stages from prior historical dry-run evidence.
Plan/checklist reflect actual authorization and tag-only deployment, including
stop-on-failure/no-redeployment rules. No production/script/workflow change.

Local dated-metadata validation succeeds in publishing and dry-run modes. Run
existing metadata regressions, Markdown/link and whitespace checks; retain the
ordinary commit hook. Record exact final PR head, review and CI in its description
before merge. After merge pin the resulting main SHA and verify complete CI,
same-JAR consumers, examples/quality/performance, fresh audit and actual Publish
dry-run bytes before the single authorized tag push. Published-byte checks,
GitHub Release and a separately reviewed/green post-publication docs PR follow.
Do not mark deployment complete from dispatch or workflow success alone.

## v1.4.0 publication and post-publication documentation (2026-10-17)

Reviewed/green dated metadata PR #64 merged as release main
74a17b00c0f20f3ab51ef4aa10578088ccafe923. This SHA remained fixed through
publication. Main CI39017426361 passed all14 jobs, including ARM64, source
compatibility and same-JAR17/21 consumers; logs confirm 490 Clojure tests/zero
failures, ten JUnit tests, Java quality/lint/Eastwood/format, all36 examples,
unchanged317.1ms performance gate and all27 measurement scenarios.
Audit39017436182 succeeded at this SHA:23 production dependencies, zero detected/
suppressed CVEs; NVD checked08:28:04Z, modified08:16:28Z, engine12.1.6. OSS Index
was disabled without credentials; development/build-only coverage is not implied.

Final Publish dry-run39017696585 used main/1.4.0/dry_run=true at that SHA. Dated
metadata/gates/build/inspection/upload pass; both publishing steps skipped,
Dry-run summary success. Downloaded actual JAR/POM/provenance passed exact
inventory/source/class/coordinates/dependency/SCM/license checks. Hash-matched
support files retain original build provenance. Both independent JDK17/21
consumers passed without rebuilding, checking JAR identity before/after.
Rechecked unchanged main, Japan date17:34 on2026-10-17 and absent version/tag/
Release immediately before tag creation.

Created annotated v1.4.0 objectfb98630904ec1f9cef9604d387c1289c07480514 at the
fixed release SHA and pushed once. Tag eventpush run39017886556 started and
succeeded, including Clojars publish/Publish summary; Dry-run summary skipped.
No manual dry_run=false, fallback, tag movement/recreation or duplicate deploy.
Actual Clojars JAR/POM both download and match the tag-run artifacts. Both
published-byte17/21 consumers pass using fresh temporary -Srepro projects with
no Paclo rebuild, covering public/native/six-DLT/Classic/PCAPNG/analysis/
annotation/lifecycle probes. Previous1.3.0 remains downloadable with its original
JAR hash. GitHub Release v1.4.0 was created only after these checks, on the
existing tag, stable/non-draft, at08:38:16Z (17:38 JST). Release notes preserve
D1/D2 migration and data-loss/partial-report/platform/lifecycle/performance limits.

Independently verified JAR SHA256 values: mainCI
379b8ab805dcfbb9eec517949ae5c013059e058956465fd83b9b5d231dfb6928;
finaldry-run ed8e4f4a2686d1b09574c3d99f8a35d573a0afc4414bbfe1adca71018450bf57;
tagrun/deployed fe70ac9005edfea4d48fee30c69383ce3dd814e0e56c8b432d573193fc26eb2e.
External/embedded/deployed POM SHA256
91a5f668b7e9daf06735f09a10efe9dba9daec8946704cc7ce696456d2338d56.
The publication record links actual runs/downloads; durable provenance, consumer,
audit and publication JSON is retained in dev/release-1.4.0-evidence, without
machine-specific absolute paths or credentials. Historical dry-run facts remain
unchanged; only a subsequent-publication note is appended.

cljdoc initially offered a build form for1.4.0. Submitted build117558; it succeeded
and imported18 namespaces. All nine supported API/annotation pages return200
and show expected vars. Initial articles use the release tag and retain its
pre-publication README. After this docs PR passes normal CI/review and merges,
use the documented cljdoc-1.4.0 article-only tag/rebuild; it does not match the
Publish v* trigger and cannot change the release tag/JAR. Later docs-tag SHA,
article refresh and exact docs PR CI/review/merge are retained in its PR description.

This separate PR updates only published installation/availability and measured
release records. D1/D2, code/scripts/workflows/dependencies/APIs/quality budgets
and development fallback version remain unchanged. Issue #37 stays open and
non-blocking. Issue #44 acceptance supports closing the measured Ethernet
investigation/optimization scope with JIT/thermal/retention/live-NIC limits;
issue-level acceptance remains separate and no issue is closed. P09/P10 stay blocked.

The updated README Maven installation coordinate was exercised in a separate
-Srepro JDK17 project: Clojars downloaded1.4.0, core/flow/pcapng loaded and the
native fixture yielded four packets. Its resolved Maven JAR hash matches the
actual deployed/tag artifact. No local/root dependency substitutes for this
coordinate-resolution check. Initial consumer command launch preceded creation
of its temporary working directory and did not start; creating that directory
first corrected the setup, after which the actual validation passed.

## Issue #37 remaining retired-key expiry evaluation (2026-10-17)

Explicit post-v1.4.0 follow-up; P09/P10, release/version/dependency changes,
merge and issue closure remain outside implementation scope. Initial working
tree was clean on codex/publish-v1.4.0-docs at
14a92d513de1c26dd7cdc059434acd409343278d. Use the supplied checkout, no worktree.
Read CONTRIBUTING, the published API contract, plan, DNS source/tests, PR #57's
report/measurements and connected GitHub Issue #37 / PR #57. GitHub confirms
issue #37 open and #57 merged as e444b10. The initial gh issue/pr reads could not
connect to api.github.com under the shell network restriction; connected GitHub
reads succeeded. No remote write was attempted.

`bash dev/script/codex.sh doctor` passes: macOS x86_64, Temurin 21.0.12.1,
Clojure 1.12.1 (CLI 1.12.5.1654), four native offline packets/438 bytes, lint tools
available. sw_vers reports 15.4.1. Current DNS blob 85d9fea2b46d9666165fe2cfdb414a3fc64b4ce6
matches v1.4.0 exactly. The old legacy and pre-#57 baselines are not rerun.

The opt-in dns-expiry-perf runner reuses dns-perf generators, alternating paired
counter/equality machinery and native PCAP controls, but loads the fixed current
DNS/window/CLI baseline into separate namespaces. Only temporary candidate source
is loaded in the experiment JVM. Production/test/API/CI source remains unchanged.
Patches retain both the initial deadline-vector index and the compact singleton /
bulk-release refinement. Independent process logs in dev/measurements/issue-37-final
record source identities, fixed 512MiB heap, warmups, samples, CPU/allocation/GC,
public result equality and retention/EDN checks. No timing runs overlap builds,
tests, lint or other timing runs. A harness startup failed before sampling during
initial runner editing; the completed runs retain every timed sample.

The compact candidate's isolated DNS namespace run passes 19 tests/298 assertions,
including900 generated property cases. Its existing test-only normalization helper
also removes the optional prototype index, so full-scan oracle and legacy snapshot
checks remain meaningful. No regression test or production source is edited.
Detailed results, final decision and verification follow below after the two
independent compact repetitions complete.

Final evaluation chooses A: adopt the hybrid metadata index. Complete final
matrix:55 distinct timed conditions in two independent JVMs, 110 pairs / 1524
samples. Additional 20-warmup sensitivity runs and identical-source controls
retain all short/native samples. The existing summarizer validates 340 paired
conditions / 4720 timed samples across all candidates/controls. All public results
agree; run-ID completeness, retention root counts and EDN round trips are checked.
The manifest records SHA256s and all five exact measurement-time runner blobs.
Reapplying the final patch reproduces source SHA256
76cbd1aba39f565aaadf3c929789a9a69301d746696729749fba2c89c96622be.
Final production code tokens match that measured source, ignoring only formatting
and comments. The detailed report includes every negative row and scope limit.

At 100000 keys / 1000 actual expiries, baseline 4075/4861 ms becomes 1.915/1.998 ms.
EDN-restored replay including rebuild becomes 113/114 ms instead of 5173/4389 ms.
Steady native 40000-packet stats improves 2.9–3.4x. Longer-warmed ordinary native
medians change −3.6%..+4.6%, within same-source control variation −5.4%..+5.5%.
Low-density native replay costs about 1–3% elapsed, with slightly less allocation.
Direct short 1000-key spaced builds show large alias/loading sensitivity even
for identical source (+29/+41% with 20 warmups); no regression/speedup attribution
is made from those percentages and no unrelated-run subtraction is used.
Large spaced-state construction costs 7–11% more elapsed. The index adds roughly
7–8% retained DNS heap (~3.8 MB / 100000 keys), keeping standard EDN character count
and initial restored heap unchanged. First large spaced EDN index rebuild costs
roughly 100 ms/~77 MB transient allocation; frequent restore/single-step/checkpoint
workflows can be slower. No suitable representative long production PCAP, live
NIC/soak/RSS or other-platform performance validation is claimed.

Small initial states retain the old scan path through 1024 keys. Larger states
build a persistent deadline index in retired-map metadata, keep it until empty,
and release due buckets without scanning every key. Equal-deadline singletons /
vectors and full-release clearing limit overhead. Exactly one membership per
retired key, no stale queue entries or mutable published data. Standard EDN omits
the cache; explicit metadata EDN and old snapshots remain readable. No public
option/state-data key, new dependency, version, workflow, threshold or P09/P10
change. Published v1.4.0 bytes/contracts remain unchanged; this is unreleased.

Fetched main 17e2088 (reviewed docs PR #65). Its tree 7805ed71099001a28c4a85318d6bc8ca5b91aa08
matches the initial 14a92d5 tree exactly. Switched to a new branch from fetched
main, codex/issue-37-retired-expiry, preserving all task files and avoiding the
squashed docs commit in the PR diff. No additional worktree.

Actual local verification after implementation:

- `bash dev/script/codex.sh test -n paclo.dns-test`: 22 tests/387 assertions,
  including 1000 generated DNS property cases, exit 0. The three added tests cover
  indexed/EDN/legacy forks, cache membership/limits, exact errors/atomic failures,
  explicit printed metadata and promoting Long.MIN/MAX/BigInt retry/expiry time.
- `bash dev/script/codex.sh check`: 493 tests/19125 assertions, ten JUnit tests,
  native four-packet/438-byte smoke, exit 0.
- `bash dev/script/codex.sh lint`:kondo 0 errors/warnings, Eastwood 115 namespaces /
  632 informational warnings/zero exceptions, ns/format dry-runs unchanged.
  The final Markdown stage failed on sandbox ENOTFOUND registry.npmjs.org and
  an unwritable npm log directory. Reran only that stage with network access;
  fixed two new-document formatting errors and reran unchanged rules: 49 files,
  zero errors. This is not recorded as an exit 0 for the failed wrapper command.
- `python3 dev/script/verify_doc_examples.py`:all 36 examples pass, exit 0.
  `python3 dev/script/verify_doc_links.py`:all local links/anchors pass.
- `clojure -M:spotbugs`, `clojure -M:checkstyle`, `clojure -M:jacoco`,
  `JACOCO_MIN_LINE=0.25 clojure -M:jacoco-gate`:exit 0,43.8% line coverage with
  the unchanged 25% threshold.
- `bash dev/script/codex.sh perf`: 446.4 ms, unchanged 1000/1200 ms warning/failure
  thresholds, exit 0. No overlapping lint/tests/benchmarks during this gate.
- `bash dev/script/codex.sh package`, distribution prepare and JAR-only JDK 21
  consume all pass. Local dirty-tree snapshot JAR SHA256
  6bd94bbbee0a839ab83d692d76ac6d63588df5025bd6cc894ff475766438c609.
  This is not the published 1.4.0 artifact. `prepare` passes afterward to restore
  compiled test classes. Local JDK 17 is unavailable; the unchanged same-JAR CI
  consumers must validate 17/21 from the committed source.
- `git diff --check` passes. CI workflow/deps/build files have no diff; all 14
  existing jobs and quality/performance budgets are preserved.

Implementation and local acceptance are complete. Independent PR creation and
final-head CI results are recorded in the PR description attached to this chat;
Issue #37 remains open for review/closure judgment. Do not merge before review.
Next item is independent review of this scoped optimization and its documented
tradeoffs; Issue #44 acceptance, P09/P10 and publication stay separate.

All four reproducible patches use zero-context unified diff format to avoid
whitespace-only diff-context lines in newly tracked artifacts. After that format
correction, each reapplies to its exact recorded source SHA256; no measured
source or sample is changed. The future runner selects canonical main17e2088,
whose four loaded sources and complete tree match measured14a92d5 byte-for-byte.

The first commit attempt stopped before hook tests: the installed interactive
`clj` launcher requires unavailable `rlwrap`. The repository hook is unchanged.
A task-local `/tmp` launcher forwards `clj` arguments to the same `clojure` CLI
for noninteractive `-M:test`; no hook or test stage is skipped. This avoids adding
an interactive editor dependency solely for the commit environment.

Implementation commit: `660b287444cf444505c18d042753ec3cc1174c90`.
Its normal pre-commit hook completes all 493 tests / 19125 assertions, namespace
cleanup/format, Markdown lint and kondo without skipping a stage. The task-local
noninteractive launcher changes no repository hook. The following evidence
commit adds this immutable implementation reference only; final-head remote CI
and the independent review URL are retained in the PR description.

## Next-development planning after v1.4.0 (2026-10-18)

Scope: Markdown planning documents only: `docs/ROADMAP.md`, `dev/codex-plan.md`
and this appended record. Initial checkout was clean on
`codex/issue-37-retired-expiry` at `3161432`. Fetched latest GitHub main
`443bc66377ba1f5b0c6c5333bf286cccaac0cfb9` and created
`codex/next-development-plan` from it in the supplied checkout; no worktree.
Read AGENTS, CONTRIBUTING, the public API contract, roadmap, accepted plan,
relevant work-log/release/performance records, and current GitHub issues/PRs.

Current-state evidence checked on GitHub:

- [v1.4.0](https://github.com/nantes-rfli/paclo/releases/tag/v1.4.0) was published
  at 2026-10-17 08:38:16 UTC (17:38:16 Asia/Tokyo). Its tag resolves to `74a17b0`.
  P01–P08 remain complete and published; release evidence and measurements are unchanged.
- [PR #57](https://github.com/nantes-rfli/paclo/pull/57) merged as `e444b10` before
  the release and is an ancestor of its tag. [PR #66](https://github.com/nantes-rfli/paclo/pull/66)
  merged as `443bc66` at 2026-10-17 13:10:29 UTC, after publication. It is unreleased.
  The PR records all 14 final-head CI jobs passing; this is prior implementation
  evidence, not a CI result for this planning PR.
- [Issue #37](https://github.com/nantes-rfli/paclo/issues/37#issuecomment-6234378455)
  closed as completed on 2026-10-17 after both PRs. Acceptance explicitly retains
  additional heap/rebuild/update costs and missing representative long production
  PCAP/live-NIC evidence; concrete future problems require a separate issue.
- [Issue #44](https://github.com/nantes-rfli/paclo/issues/44#issuecomment-6232073683)
  closed as completed on 2026-10-17 after merged
  [PR #58](https://github.com/nantes-rfli/paclo/pull/58). Acceptance does not
  establish historical-speed recovery, Flow-wide or live-NIC improvements.
- [PR #65](https://github.com/nantes-rfli/paclo/pull/65) merged as `17e2088`;
  its completed article-only `cljdoc-1.4.0` refresh/build 117560 is recorded in
  its description. The local docs tag resolves to that same merge commit.

Updated current-state wording in the roadmap/plan, including the obsolete
release-candidate, publication-docs-pending and issue-review-pending statements.
Earlier work-log entries and historical reports remain verbatim. Added P11–P17
scope, dependencies and acceptance only in the plan; the roadmap summarizes the
direction. P11 is the only ready item. P12 follows P11; P13 follows P12;
P14–P16 follow P11 and can be selected separately; P17 follows P12 plus an
explicit need/maturity decision. P09/P10 retain their original blocked conditions.
Clojure 1.12.6 is a candidate to recheck in P11, not an audit result from this
task. JDK 25 support and Clojure 1.13 adoption remain evidence-based decisions.
`v1.5.0` is a possible release without committed scope, date or version change.

Read the actual CI/build files: `build-checks` overrides `PACLO_VERSION=1.4.0`
and verifies the corresponding 1.4.0 artifact, while the fallback is
`1.4.0-SNAPSHOT`. Record the development-artifact identity mismatch for P11
and a separate small SNAPSHOT maintenance PR. No source, tests, dependencies,
CI/build settings, API, version, tag, release or performance budget is changed.

Verification and delivery:

- `git status --short --untracked-files=all`: clean before work.
- `bash dev/script/codex.sh doctor`: exit 0; macOS x86_64, Temurin 21.0.12.1,
  Clojure library 1.12.1 / CLI 1.12.5.1654, four offline native packets / 438 bytes;
  optional lint tools available. This is a local environment check, not P11's
  upstream-version inventory or new platform validation.
- `python3 dev/script/verify_doc_links.py`: exit 0, local paths/heading anchors pass.
  New external evidence links were checked through GitHub issue/comment/PR and
  Release reads; the local-link checker deliberately does not check external URLs.
- `dev/script/mdlint.sh`: initial sandbox run failed with npm DNS `ENOTFOUND`
  for `registry.npmjs.org` and an unwritable npm log directory. The same pinned
  command rerun with network access passed all 49 Markdown files, zero errors,
  exit 0. The failed attempt is not counted as a pass.
- One-off read-only consistency assertions pass: exactly the three intended
  Markdown files changed; all previous work-log bytes are preserved; P01–P10
  table rows and P08–P10 expansion conditions are unchanged; P11 alone is ready;
  P12–P17 table/section dependencies, blocked status and acceptance agree.
- `git diff --check` passes; author's full diff review confirms status/release
  boundaries and unchanged historical measurements. GitHub main was rechecked
  at `443bc66`; the branch has no protected required-check configuration, but
  the normal CI workflow and its `build` aggregate remain the delivery gates.
- No runnable examples changed. Runtime/Java/performance/package tests are not
  required locally for this Markdown-only change; normal PR CI remains enabled.
  The documentation commit uses the repository hook's `SKIP_TESTS=1`,
  `SKIP_FMT=1`, `SKIP_KONDO=1` flags to avoid unrelated runtime stages and code
  auto-formatting; its Markdown stage remains enabled. No hook file is edited.
  Exact final-head PR CI results are recorded in the PR description.

Next execution target: P11 inventory, after independent review of this planning
PR. Do not start P12–P17, P09/P10 or maintenance implementation in this task.
Leave the independent PR open for review without merging. Its URL, exact head
and final CI results belong in the PR description/chat to avoid a self-referential
evidence-only commit. No independent approval is claimed by the author's diff review.

## P11 environment inventory (2026-10-18)

Investigation only, using the supplied checkout. Initial status was clean on
`codex/next-development-plan` at `90e82a4`. Fetched origin main/tags, verified
[PR #67](https://github.com/nantes-rfli/paclo/pull/67) merged at
2026-10-18 00:41:22 UTC as `97873f79eb5360d47b59692127e760e4ea1ec188`, and created
`codex/p11-environment-inventory` from that latest main. No extra worktree.
Read AGENTS, CONTRIBUTING, the accepted plan/public API contract, roadmap,
deps/build, all four workflows, native/distribution/stream code and release evidence.

Created [dev/p11-environment-inventory.md](p11-environment-inventory.md), with
2026-10-18 check date, source URLs, current/candidate comparisons for every
deps.edn dependency, local/floating/pinned tool distinctions, CI coverage and
an independent-PR/acceptance matrix. Official release notes, source histories,
GitHub release/tag APIs, Maven Central POMs and Clojars artifact APIs were read;
no candidate was installed, resolved into Paclo or executed.

Key decisions and findings:

- Clojure1.12.6 and CLI1.12.5.1664 are separately confirmed stable candidates.
  Recommend P12 early for correctness and the upstream Java-deserialization
  security advisory; found no ObjectInputStream/readObject usage in Paclo source,
  Java, examples or tests, without claiming downstream applications are safe.
- Record Clojure1.13-alpha9/Java17/map/tooling risks for conditional P17.
  JDK25 remains unverified. `environment-check` explicitly rejects JDK25 and
  Clojure1.13; propose direct experimental commands instead of broadening support.
- Native Paclo `.pcap_lib_version` reports1.10.1, while local tcpdump4.99.7 links
  libpcap1.11.0. Loaded library provenance matters; neither updates the other.
  JNR2.3.2's published POM still selects jffi1.4.0 despite separate1.4.1 availability.
- Recommend independent development-SNAPSHOT identity maintenance before upgrade
  comparisons. `1.5.0-SNAPSHOT` is a proposed identifier only. Inventory covers
  CI override/JAR path/verifier defaults/tests/docs/POM SCM identity and release
  guards; no version or configuration is changed. Public1.4.0 remains `74a17b0`;
  DNS PR #66 is unreleased. No release scope/date/tag/publication is assigned.
- P11 investigation is complete, pending independent review. P12 is the next
  unfinished main item after review; P14–P16 become selectable but are not started.
  P13/P17 dependencies and P09/P10 blocked conditions remain unchanged.
  New findings are proposals, with no implementation added to later items.

Actual verification:

- `git status --short --untracked-files=all`: initially clean.
- `bash dev/script/codex.sh doctor`: exit0 before/after selecting main baseline;
  macOS15.4.1 x86_64, Temurin21.0.12.1+1, Clojure1.12.1/CLI1.12.5.1654,
  four native offline packets/438 bytes. Existing Java compilation only.
- `clojure -Stree`, native version call, JDK/CLI/kondo/LSP/Node/npm/tcpdump
  version reads: exit0; observations and transitive graph recorded in inventory.
  Local kondo2026.05.25/LSP2026.05.05 differ from pinned CI. No local JDK17/25.
  `uname -sm` reports Darwin x86_64; sandbox blocks the optional sysctl CPU-model
  query, so no physical CPU-model claim is made.
- `dev/script/mdlint.sh`: network-enabled run passes all50 Markdown files,
  zero errors, exit0. Initial sandbox npx attempt failed with npm ENOTFOUND for
  registry.npmjs.org and an unwritable npm log directory; it is not counted as
  a passing run. Same pinned tool/rules.
- `python3 dev/script/verify_doc_links.py`: exit0, local paths and heading anchors.
  External sources were read separately; this checker does not validate URLs.
- Read-only consistency assertions: P01–P10 rows/expansion conditions unchanged;
  P11–P17 task scopes/dependencies preserved, readiness agrees between table and
  sections; only the intended Markdown files differ. Previous log bytes preserved.
- `git diff --check` and author's complete diff review pass. No runnable examples
  change; no local check/static-analysis/coverage/performance/package suite is
  claimed. Such runtime checks are unnecessary locally for this documentation-only
  task; unchanged normal PR CI is still required and checked before delivery.
- GitHub baseline [CI39083684502](https://github.com/nantes-rfli/paclo/actions/runs/39083684502)
  at main97873f7: all14 jobs success, including actual Run cloverage step and
  Linux ARM64. Inspected job conclusions and failure steps. Main branch API
  reports no branch protection/required contexts; retain workflow build aggregate
  and independent review. Latest successful audit39017436182 covers release74a17b0,
  not a new main audit. Its saved NVD/OSS Index scope limits remain explicit.

Delivery uses the hook's supported `SKIP_TESTS=1`, `SKIP_FMT=1`, `SKIP_KONDO=1`
flags for Markdown-only work; Markdown lint remains enabled. No hook is edited.
Final commit/PR URL and final-head normal CI results belong in the PR description
and chat rather than a self-referential log commit. Leave P11's independent PR
open and unmerged, awaiting review. No independent approval is claimed here.

## P11 review: published JNR candidate correction (2026-10-18)

Address [PR #68 review comment](https://github.com/nantes-rfli/paclo/pull/68#issuecomment-6244034488).
Initial checkout was clean on `codex/p11-environment-inventory` at `3e62b0d`;
fetched main/PR branch without changing the baseline. The initial inventory
mistakenly treated latest GitHub Release 2.3.2 as the latest published JNR candidate.
Its 2.3.2/jffi1.4.0 POM observation was correct but incomplete.

Rechecked official sources at 2026-10-18 10:07 Asia/Tokyo using GitHub tag/release/
compare APIs, tagged source POM and Maven Central metadata/POMs. The 2.3.3
annotated tag is dated 2026-09-15 17:54:57 UTC and points to `d6883b44`;
Central metadata lists 2.3.3 (lastUpdated 20260915181839). Both 2.3.3 POMs select
jffi 1.4.3 for compile and runtime/native dependencies and retain ASM 9.10.1.
The 2.3.2-to-2.3.3 official diff changes only project version and those jffi pins.
GitHub latest Release still reports 2.3.2. Downloaded/read POMs only; no candidate
JAR/native binary was installed, resolved into Paclo or executed.

Corrected the dependency table, transitive comparison, P14 PR slice and P11 plan
completion note. Keep 2.3.2 as explicitly labeled GitHub Release/historical POM
evidence, with 2.3.3/jffi 1.4.3 as the published evaluation candidate. Update PR
body to match and keep previous-head CI evidence distinct from corrected-head CI.
The previous work-log entry is preserved as historical evidence; this correction
supersedes its incomplete candidate selection. No implementation/dependency/CI/
build/version changes and no new task/adoption/support decision.

Verification: `bash dev/script/codex.sh doctor` passes with existing macOS x86_64,
JDK21.0.12.1/Clojure1.12.1/CLI1.12.5.1654 and four offline packets/438 bytes.
`dev/script/mdlint.sh` passes all 50 files/zero errors after fixing one new-log
blank-line warning; `python3 dev/script/verify_doc_links.py`, `git diff --check`
and read-only POM/candidate/scope/plan/log-preservation assertions pass.
Final-head normal CI results are retained in the PR body.
No runnable example changes; local runtime/performance/package suites and
candidate compatibility tests are not run for this documentation correction.
Use the existing Markdown-only hook flags, retaining Markdown lint. Leave the
PR open and unmerged for independent review; no merge authority is inferred
from the reviewer's recommendation.

## Development artifact identity before P12 (2026-10-18)

Independent maintenance selected by the user from the P11 finding. Initial
`git status --short --untracked-files=all` was clean on P11 branch `3f71e5b`.
Confirmed [PR #68](https://github.com/nantes-rfli/paclo/pull/68) was reviewed/merged
on 2026-10-18 as `58aeb544d1b5f7a5c2884931eb1dcbb843dfebd5`; fetched main and
created `codex/development-snapshot-identity` from that merge in the supplied
checkout. Read CONTRIBUTING, the v1 API contract, accepted plan and P11 inventory.
No unrelated work was present. Historical work-log entries and published release
evidence remain unchanged.

The user selected `1.5.0-SNAPSHOT` only as a development identifier. The default
build and verifier, ordinary main/PR CI JAR path and upload/download bundle name,
current README/CONTRIBUTING examples now agree. Removed CI's published-version
override rather than building unreleased changes as `1.4.0`. Published install
coordinates remain `1.4.0`; no future release scope/date is assigned.

Version precedence remains explicit `PACLO_VERSION`, then matching GitHub tag
context, then the development default. Tag inference now requires
`GITHUB_REF_TYPE=tag`, preventing a similarly named branch from becoming a release.
Non-SNAPSHOT POMs retain `v<version>`. SNAPSHOT POMs require the actual full Git
HEAD commit; missing Git identity fails rather than inventing `v...-SNAPSHOT`.
Distribution preparation/consumption verify SCM syntax and SNAPSHOT/source-commit
agreement, and record SCM/version in provenance and consumer reports. Dirty edits
remain separately visible as `source_dirty`; SCM alone does not identify edits.

Added actual `build/pom` regressions for default/tag/branch/explicit override and
missing-Git behavior. Added execution of the existing Publish workflow shell
version/source/metadata guards with controlled git responses; no tag or publication
is created. Distribution tests cover release and SNAPSHOT identities, wrong
versions/properties/SCM/provenance, a different source commit and external POM
mismatch even with a refreshed file hash. Existing dependency semantics,
source/class inventory, Java17/preview checks and hash failures remain enforced.
The Publish workflow itself, complete CI aggregate, compatibility/coverage/
performance gates and all dependency versions are unchanged.

Local verification on macOS x86_64, Temurin21.0.12.1+1, Clojure1.12.1 and
CLI1.12.5.1654:

- `bash dev/script/codex.sh doctor`: exit0; real native offline four packets/438 bytes.
- `python3 -B -m unittest discover -s dev/script -p 'test_build_identity.py'`:
  all5 tests pass, including six actual POM-resolution contexts and unchanged
  Publish source/version guards (valid and rejected cases).
- `python3 -B -m unittest discover -s dev/script -p 'test_verify_distribution.py'`:
  all13 tests pass; existing rejection cases retained and identity cases added.
- `python3 -B -m unittest discover -s dev/script -p 'test_verify_release_metadata.py'`:
  all4 tests pass; real dated release metadata is accepted, missing/unreleased
  publication metadata is rejected.
- `bash dev/script/codex.sh package`, default `verify_distribution.py prepare`
  and isolated `consume --report` pass. JAR/POM/properties/provenance all name
  `1.5.0-SNAPSHOT`, all10 classes have major61, exact production dependencies
  remain unchanged. Initial dirty-tree JAR SHA-256:
  `0889192f9a277601b4b24bb61c7651310a6709af1528597b1559abf2b32810d3`;
  SCM/source commit is `58aeb54`, `source_dirty=true` is accurately recorded.
  Final CI builds its own clean-head JAR once for both JDK consumers.
- `bash -n dev/script/codex.sh dev/script/setup-lint-tools.sh dev/script/mdlint.sh`
  and verifier help paths pass. `python3 dev/script/verify_doc_links.py` and
  `git diff --check` pass. Markdown lint passes all50 files, zero errors.

`clj-kondo --lint build.clj` passes with zero errors/warnings;
`clojure-lsp format --filenames build.clj --dry` reports nothing to format.
`bash dev/script/codex.sh check` passes: JUnit10/10, Clojure493 tests with
19,125 assertions and zero failures/errors, then native offline smoke. Removed
only the four generated untracked fixture `__pycache__` files after the suite.
Full static/PR/CI delivery details follow.
Local JDK17 is unavailable; same-JAR17/21 and Linux/macOS ARM64
verification require the unchanged normal CI. No live/NIC, JDK25, other-platform
or dependency-audit claim follows from offline tests. Local lint tools differ
from pinned CI as recorded by P11. No Clojure/dependency/API update, P12–P17,
P09/P10 work, release dispatch/tag/publish or merge is performed. P12 is the next
main plan item only after this PR passes full CI and independent review/merge.

Delivery: implementation commit `c74c011` and
[PR #69](https://github.com/nantes-rfli/paclo/pull/69). The following documentation
commit records this URL and completed local checks. `bash dev/script/codex.sh lint`
passes: kondo zero errors/warnings; Eastwood completes with632 informational
warnings and zero exceptions; clean-ns/format dry-runs report no changes;
Markdown lint passes all50 files with zero errors. No lint configuration changes.
The initial new-log Markdown blank-line/line-length failures were corrected and
rechecked; neither is counted as a passing attempt. Commit hooks use supported
`SKIP_TESTS=1`, `SKIP_FMT=1`, `SKIP_KONDO=1` only to avoid repeating already-passed
checks or autoformatting; Markdown lint remains enabled and no hook is changed.

Final-head normal-CI job URLs/results, both consumer artifact hashes/version/SCM
agreement and any remaining limitations are recorded in the PR description and
chat after completion, avoiding a self-referential CI-results commit. Local
performance/Java analyzers/coverage and maintained runnable examples are not
rerun separately; the unchanged full CI retains those gates. A source/diff audit
confirms dependency versions, production/test code, Publish workflow, historical
v1.4.0 release documents/evidence and P11 inventory are untouched. Leave PR #69
open and unmerged for independent review. Plan status denotes implemented/local
verification complete, with review/merge still pending; P12 remains unstarted.

## P12: Clojure 1.12.6 adoption (2026-10-18)

User-selected P12 implementation, based on latest fetched main `e05e0c6`
(merged development-identity PR #69). Initial `git status --short
--untracked-files=all` was clean; use the supplied checkout and branch
`codex/p12-clojure-1.12.6`. Read AGENTS, CONTRIBUTING, the v1 API contract,
the accepted plan and P11 inventory. Rechecked official Clojure downloads,
versioned 1.12.6 changes and GHSA-q527-rxcp-97g8; references and the detailed
compatibility assessment are in [the P12 report](p12-clojure-1.12.6/README.md).

Update only Clojure 1.12.1 to 1.12.6 in root and standalone performance-merger
deps. Preserve all other production/optional/tool versions, CLI, Java17 target,
JDK17/21 support, `1.5.0-SNAPSHOT`, public behavior/errors/ownership/bounds and
all gates. Exact before/after production dependency trees differ only in Clojure;
spec.alpha0.5.238/core.specs.alpha0.4.74 and core.async1.6.681/JNR2.2.14 remain.
Align the distribution allowlist and mutation tests: reject old Clojure,
unintended async/JNR upgrades and changed semantics, checking that each mutation
actually changes the fixture. Update current README/CONTRIBUTING baseline,
Unreleased changelog and clarify EDN versus Java object serialization in the
API contract. Retain historical versioned evidence unchanged.

Compatibility uses the existing real-fixture, lifecycle, transducer, protocol,
lazy-stream, EDN-restoration and bounded-state regressions, rather than introducing
a production workaround without a failure. Java serialization of LazySeq/Iterate/
FnLoaderThunk is outside Paclo's EDN restoration contract. Production-source
search finds no ObjectInputStream/readObject path; that is not a downstream
security audit. No new Java deserialization path or compatibility shim is added.

Local environment: macOS15.4.1/x86_64, Temurin21.0.12.1+1,
CLI1.12.5.1654, system libpcap1.10.1. Local kondo2026.05.25 and
LSP2026.05.05-12.58.26 differ from pinned CI. JDK17 is not installed locally.
Initial doctor passes on baseline1.12.1 with four native packets/438 bytes.
The first sandboxed prepare failed to write the uncached1.12.6 Maven directory;
authorized normal-cache retry succeeds, downloads1.12.6 and compiles bindings/tests.
`clojure -Stree` before/after is retained in the report directory. A standalone
merger invocation prints1.12.6/JDK21 and passes an exact-version assertion;
its existing external-path deprecation warning is retained, without CLI changes.

Completed local checks so far:

- `python3 -B -m unittest discover -s dev/script -p 'test_verify_distribution.py'`:
  all13 pass, including actual mutations for Clojure/core.async/JNR.
- `python3 dev/script/test_eastwood_runner.py`: all4 pass; deliberate failed
  traversal returns exit1 with an unanalyzed namespace, not success.
- `clojure -T:build spotbugs`, `checkstyle`, `jacoco` and
  `JACOCO_MIN_LINE=0.25 clojure -T:build jacoco-gate`: all exit0;
  Java line coverage43.8% exceeds unchanged25% threshold.
- Documentation parser unit tests: all15 pass. Local-link checker and
  `git diff --check` pass. Markdown lint passes51 files with zero errors using
  normal network access after the sandboxed npm lookup stalled.

Full check/lint, executable examples, cloverage, same-condition ABBA performance
comparison, package/consumer results and final delivery follow below. Incomplete
commands and unavailable environments are not counted as passes. No live/NIC,
JDK25/1.13, P14–P17, release/tag/publication or merge work is authorized here.

P12 verification finding: initial `clojure -M:coverage` completes all493 tests/
19,125 assertions but exits1 for one DNS assertion requiring an empty metadata
map after finish. Coverage is91.38% forms/95.43% lines. The fresh empty map has
only cloverage source positions at `dns.clj:270`, not a retained expiry cache.
The exact failure also occurs on1.12.1 with cloverage1.2.4 (DNS-only instrumentation,
22 tests/387 assertions/one failure), isolating it from the runtime update.
The first baseline probe unintentionally retained the alias's broad test regex;
it was stopped and replaced with a main-opts override that runs only DNS tests.
Neither interrupted nor failing probes count as passes.

Correct `retired-expiry-cache-edn-boundaries-and-independent-snapshots` to finish
an annotated indexed state and explicitly require empty pending/retired data,
no expiry-cache metadata and no caller metadata. This removes an incidental
source-location assumption while strengthening the actual cleanup assertions;
no test is excluded and no budget or production behavior changes. Recheck normal
DNS tests, baseline instrumented DNS tests, full candidate cloverage and static
analysis. The initial full `check` already passes JUnit10/10, Clojure493 tests/
19,125 assertions and native offline smoke on1.12.6. All36 documentation examples
pass. Build-identity5 tests and release-metadata4 tests pass.

The first full lint run completes kondo (zero warnings/errors), Eastwood632
warnings/zero exceptions, clean-ns/format (no changes), then fails on sandboxed
npm registry/cache access. The separate normal-network Markdown run succeeds;
offline npm retry reports ENOTCACHED. Rerun the complete lint wrapper with normal
network access after the DNS-test correction; do not label failed wrappers passes.

After the test correction, normal DNS22 tests/390 assertions and baseline
instrumented DNS22 tests/390 assertions both exit0. Full candidate cloverage
now exits0:493 tests/19,128 assertions, zero failures/errors,17 instrumented
namespaces,91.32% form/95.40% line coverage. Unlike the original failure,
these are actual passing tests, not merely a generated coverage report.
The candidate's report percentages differ slightly between randomized property
runs; the code/instrumented namespace set and CI budgets are unchanged.

Repeated lint completes all analysis: kondo0 warnings/errors, Eastwood632
informational warnings/zero exceptions/full traversal, LSP clean-ns/format no
changes. Its Markdown stage catches one double blank line in this new log;
fix it and rerun Markdown successfully,51 files/zero errors. No broad formatting
or lint configuration change. Remove only four fixture-generated untracked
Python cache files after the tests. Performance follows serially after all
CPU-heavy analysis/tests; production and benchmark worker source remain identical
to main for both runtimes.

P12 performance/package completion: `bash dev/script/codex.sh perf` exits0 at
635.9ms (unchanged1000ms warning/1200ms fail). Run the retained comparison driver
serially after other heavy checks, using identical classpaths except Clojure,
unchanged worker/source/bindings, JDK21,512MiB heap and one deterministic50k
mixed TCP/UDP PCAP. ABBA runtime batches, reverse scenario order, five warm-ups
and seven measured samples per worker produce20 workers/140 samples. All samples
report50,000 packets/14,400,000 bytes. Retain driver, source/input hashes, raw EDN
and median/range/batch JSON in the P12 directory. Pooled throughput changes:
raw-reduce -4.9%, full-decode +1.7%, full-reduce +0.5%, flow-reduce +3.0%,
write-pipeline +3.3%. Allocation changes range -0.9% to +1.4%. Raw's two candidate
batch medians are both lower; overlapping ranges do not prove equivalence.
Record that slowdown explicitly, without inventing/weakening any gate or claiming
live/NIC/general speedup. Existing CI retains all27 offline measurement scenarios.

`bash dev/script/codex.sh package`, `python3 dev/script/verify_distribution.py
prepare target/paclo-1.5.0-SNAPSHOT.jar /tmp/paclo-p12-distribution` and `consume
/tmp/paclo-p12-distribution --report /tmp/paclo-p12-consumer-jdk21.json` all exit0.
Exact source inventory, POM/dependency/properties/SCM identity, ten major61 classes,
no previews and isolated -Srepro public-API/fixture execution pass. JAR SHA-256:
`e37dae1b723242d8c0052cbfba8bbe1c9297816648bca4587cf8b24cf60efa11`.
Retain local provenance/consumer JSON: source HEAD e05e0c6 with source_dirty=true,
accurately distinguishing the edited candidate from main. Final CI builds its
own clean-head artifact once for both17/21 consumers. No local JDK17 claim.

Next main item is P13 after P12 review/merge, not an automatic support extension.
All other production/tool/CLI versions, workflows, gates and release identity
remain unchanged. Full required/ARM64/actual coverage-step results and same-JAR
identities are verified against the final PR head and recorded in its description.

P12 delivery: implementation commit `c5f8b86` and
[PR #70](https://github.com/nantes-rfli/paclo/pull/70), based on main `e05e0c6`.
This documentation follow-up records the PR link before checking its final-head
normal CI. The PR description owns exact final revision/job URLs, actual coverage
step success and both consumers' source/version/JAR-hash agreement, avoiding a
self-referential CI-results commit. Keep the PR open and unmerged for independent
review. P12 implementation/local verification is complete; P13 remains blocked
on that review/merge and is not started.

Final local Markdown lint passes all51 files/zero errors, local links/diff checks
pass, and a scope audit confirms production source/Java, benchmark workers,
workflows/build settings and all non-Clojure dependencies are unchanged. The initial
existing test edit removes the reproduced instrumentation-metadata assumption
and adds explicit cleanup assertions. Commit hooks use supported SKIP_TESTS=1,
SKIP_FMT=1 and SKIP_KONDO=1 to avoid repeating completed checks/autoformatting;
Markdown lint stays enabled. No hook/configuration is changed. The CLI GitHub
auth check was invalid; use connected GitHub tools for PR/CI and existing SSH
Git for push, without an interactive login or credential changes.

P12 first CI finding: final head df90816, run39089499187, macOS ARM64/JDK17
job117563237437 fails only `capture->seq-respects-queue-cap` (three assertions:
expected3 packets/[42 42 42]/one break, observed1 packet/[42]/zero breaks).
The synthetic capture's50ms wall-clock deadline expires before EOF; production
`loop-n-or-ms!` correctly checks it between reads and does not fabricate EOF.
All other initial jobs, including Linux/ARM64, docs/analysis/performance and both
same-JAR17/21 consumers, are kept distinct from the next final-head run.
Initial actual cloverage tests493/19,134 pass with95.48% lines; the initial
required aggregate fails because of macOS, so this run is not a full CI pass.

Reproduce the same three failures on both1.12.1 and1.12.6 by delaying each fake
packet read60ms while retaining the original50ms capture deadline. Correct this
queue/EOF test's input to a finite10000ms capture budget and retain the slow read
as a deterministic regression. Keep the original packet/order/EOF checks and add
capacity2/enqueued3/dropped0/max-depth<=2 statistics checks. Both runtime probes
then pass1 test/five assertions. No production time limit, public default,
deadline-specific test, CI timeout/quality gate or performance threshold changes.
The optional latency is confined to the existing test fake and this test alone.
Repeat full check, cloverage and lint, then push this correction to PR #70 and
require every job on the new final commit; do not accept or rerun away the old
failure. Production/benchmark source and dependency graphs remain unchanged, so
the retained performance and local package evidence still applies to those bytes.

P12 queue-correction verification completes: full `bash dev/script/codex.sh check`
exits0 with JUnit10/10,493 Clojure tests/19,130 assertions/zero failures/errors,
and native1.12.6 offline smoke4 packets/438 bytes. Repeated `clojure -M:coverage`
exits0 with the same493/19,130 and zero failures/errors,17 namespaces,
91.39% forms/95.46% lines. Repeated full `bash dev/script/codex.sh lint` now exits0:
kondo0 errors/warnings, Eastwood632 warnings/zero exceptions, LSP no clean-ns or
format changes, Markdown51 files/zero errors. Both corrected single-var queue
probes pass five assertions on1.12.1/1.12.6. Keep the prior failing probes and first
macOS CI failure explicit, rather than counting them as successful verification.
Remove only the four regenerated fixture Python cache files. This correction
and its report/plan/log updates are committed on the same PR; no second PR,
production/benchmark source change, dependency/tool update or weakened gate.
The new final-head normal CI and same-JAR identities supersede earlier-head CI
results in the PR description after all required jobs actually complete.

## P15: Offline REPL workflows (2026-10-18)

Started from fetched latest main `0ce949048baa0aeecff942b30fea89055dd58ba4`
on the supplied clean checkout; branch `codex/p15-repl-workflows`.
Read AGENTS, contributing/API contracts, accepted plan, usage guide, executable
example checker, and existing PCAP/filter/Flow/DNS examples before editing.
`bash dev/script/codex.sh doctor` passed on macOS x86_64, Temurin21.0.12.1,
Clojure1.12.6/CLI1.12.5.1654, with native offline PCAP4 packets/438 bytes.

P12 merge confirmation: GitHub PR #70 is MERGED as `0ce9490`, at
2026-10-18T06:02:57Z (15:02:57 Asia/Tokyo). Its independent review reports no
blocking findings and final head `a5e5afe` passing all14 CI jobs on
[run39090074823](https://github.com/nantes-rfli/paclo/actions/runs/39090074823),
including identical-JAR JDK17/21 consumers. Update the plan's P12 completion and
P13 dependency readiness only; no P13 implementation is included.

Implementation and usability decisions:

- Add [the REPL walkthrough](../docs/repl.md), linked from README, docs index
  and usage guide, with four self-contained copyable blocks. Start with the
  existing `bash dev/script/codex.sh repl`; no new alias, dependency, public API,
  framework or runtime behavior is necessary.
- Use `with-open` and materialized data for prefix inspection; synchronous
  reducers for complete analysis; explicit empty/DNS extension vectors; numeric
  Flow addresses/protocols and bounded bidirectional aggregation. Explain the
  existing lazy-sequence lifetime, read-ahead, default capture limits and
  `reduced` behavior through existing contracts rather than suggesting automatic
  cleanup. Synchronous examples use an explicit60-second wall-clock budget.
- Real `dns-sample.pcap` expectations: the two selected `1.1.1.1` packets total
  260 captured/wire bytes; canonical bidirectional Flow has2 packets; two DNS
  matches have RTT15817us/10241us and rcode0. The full source has4 packets.
- The DNS example intentionally collects this small fixture's projected events
  and calls `finish`. It explains unadvanced watermarks/unfinished diagnostics,
  retained-key bounds and the need for incremental consumption/`advance` for
  longer inputs, linking the existing bounded reporting/contract guidance.
- Write raw selected maps to a temporary Classic Ethernet PCAP and read back;
  compare byte contents, timestamps, caplen, wire length and DLT, then delete in
  `finally`. The BPF selection matches the Flow predicate's selected traffic.
  No PCAPNG/production interoperability validation (P16) is claimed.
- Register all four exact expectations and required IDs in the existing docs
  execution gate. First focused execution exposed a checker problem: a trailing
  REPL `;; =>` comment swallowed appended runner forms and produced EOF while
  reading. Add a newline at the wrapper boundary and a focused Python regression;
  the documented forms themselves needed no API change. Initial failure is not
  counted as a pass.
- No concrete need for a new public API was found. Existing resource ownership,
  Flow representation and DNS policy requirements are covered by the guide.
  P13/P14/P16/P17, dependency updates, release/tag/publication and merge are out
  of scope. Independent P15 review remains required before any merge.

Verification in progress; final commands/results and PR/CI evidence follow below.

Verification checkpoint:

- Focused execution of all4 new registered snippets passed exact expectations.
- A fresh `bash dev/script/codex.sh repl` process received all four guide blocks
  as stdin, followed by assertions against each REPL `*1`; exit0, no stderr,
  and all4 success markers. This checks the actual REPL entrypoint and imports
  without the documentation checker's namespace prelude.
- `python3 -B -m unittest discover -s dev/script -p 'test_verify_doc_examples.py'`:
  16 tests pass, including the trailing-comment runner regression.
- `python3 dev/script/verify_doc_links.py`: all local paths/anchors pass.
- Additional unchanged link-parser tests initially failed1/9 on this macOS host:
  the default `/var/folders/...` temporary root resolves to `/private/var/...`,
  causing same-page fragment checks to report outside-repository paths. Running
  `TMPDIR=/private/tmp python3 -m unittest discover -s dev/script -p
  'test_verify_doc_links.py'` passes9/9 with a canonical root. No link-checker
  production/parsing change is included. This environment-specific first failure
  is retained explicitly; ordinary repository link validation already passes.
- `bash dev/script/mdlint.sh` with npm network/cache access: all52 Markdown
  files pass, zero errors. The first sandboxed npm attempt could not complete;
  the same fixed markdownlint-cli2@0.18.1 command succeeds with normal access.
- `bash dev/script/codex.sh check`: exit0; Java compilation/JUnit10 successful,
  493 Clojure tests/19,130 assertions with zero failures/errors, then native
  offline smoke4 packets/438 bytes. Waited for the process to exit successfully.
- `python3 dev/script/verify_doc_examples.py`: exit0; all40 registered examples
  pass, including the four new exact fixture expectations and every prior ID.
- Static analysis checkpoint: clj-kondo reports zero errors/warnings; Eastwood
  completes all configured roots with632 informational warnings and zero
  exceptions. LSP namespace cleaning reports no changes; formatting completion
  and the wrapper's final npm step are checked below.
- LSP format dry-run completes with `Nothing to format!`; namespace cleaning
  also needs no changes. Thus every Clojure static stage passes. The sandboxed
  lint wrapper's npm step is subject to the same network/cache restriction as
  the first standalone Markdown command; the separately allowed identical
  Markdown stage passes52 files/zero errors. Do not count a blocked wrapper as
  an exit0 result; all constituent stages have actual successful evidence.
- `git diff --check`: clean. Remove only the four Python fixture caches
  regenerated by the suite and the four parser/checker caches from manual tests.

P15 implementation/local verification is complete. Keep independent review
pending and P13 as the next unfinished item; no other plan implementation was
started. The single P15 PR will carry final-head CI URLs and results before
handoff, including platform/Java-quality/performance/distribution gates that
are outside this documentation change's local checks. No live capture, JDK25,
production interoperability or new performance measurement is claimed here.

Commit environment note: the first commit attempt stopped in the existing
`.githooks/pre-commit` before creating a commit, because its `clj -M:test`
requires unavailable `rlwrap`. The supported `clojure`-based development wrapper
has already passed the entire test suite, and kondo/LSP/Markdown checks have
completed separately. Use the hook's documented per-command
`SKIP_TESTS=1 SKIP_FMT=1 SKIP_MD_LINT=1 SKIP_KONDO=1` flags for the commit to avoid
rerunning those verified stages or introducing tooling changes. Hook files and
repository quality gates are unchanged.

P15 delivery: implementation commit `cc771ea` opens
[PR #71](https://github.com/nantes-rfli/paclo/pull/71) against main `0ce9490`.
This final handoff update adds only the PR reference and execution record.
Final-head normal CI results/URLs are maintained in the PR description after
all jobs complete; an earlier-head run is not evidence for this updated head.
The PR remains open for independent review, with no merge or publication.

The sandboxed `lint` wrapper exits1 at npm network/cache access after all Clojure
static stages pass; the identical Markdown command with normal access exits0.
The PR-reference append initially introduced one extra blank line (MD012);
remove it and rerun Markdown before committing the correction.

## 2026-10-18 — P13 JDK 25 compatibility experiment

User-authorized scope: implement P13, provision/run real JDK25 source and
independent distribution checks, retain17/21 and existing quality/performance
checks, record evidence and create one PR without merging/releasing/tagging.
The checkout was clean. Fetched latest main and confirmed P15 PR #71 merged
at2026-10-18T08:10:36Z as `e2a5eb11617aa5e364da340672424fac284d0251`; created
`codex/p13-jdk25` there in the supplied checkout. Read CONTRIBUTING, API contract,
accepted plan and P11's JDK25 experiment policy before implementation.

Implementation: retain all production sources/dependencies and release17 flags.
Add three real native JUnit ABI/error/close checks; extend the existing consumer
with real BPF and failed-open/interface checks, JSON runtime/loader identity,
and diagnostic-only dladdr of the loaded libpcap symbol. `verify_distribution`
retains hash/source/classpath checks and default launch, supports separately
scoped JVM diagnostic options and preserves runtime evidence. New
`verify_jdk25.py` uses actual-major guard and direct source/JUnit/Clojure/native
commands with unfiltered logs. Two negative controls cover incorrect JDK aliases
and fatal JUnit failure/warning preservation; the distribution regression covers
runtime report preservation and diagnostic-option scoping. Add required Linux
x64 source job and third same-JAR consumer, preserving all previous aggregate,
17/21, quality, performance and platform checks. No support-guard widening.

Local results and environment details are in
[the P13 report](p13-jdk25-verification.md) and `dev/p13-evidence/`:

- `bash dev/script/codex.sh doctor` on Temurin21.0.12.1+1: exit0, actual native
  read4 packets/438 bytes. CLI1.12.5.1654; Clojure1.12.6; macOS15.4.1 x64.
- Provisioned official checksum-verified Temurin17.0.20.1+1 and25.0.4.1+1-LTS
  under `/tmp/paclo-p13/jdks`. Excluded Homebrew `openjdk@25` alias because it
  actually resolves to26.0.2.1. CPU Intel i7-8700B; exact archive URLs/checksums
  and JVM identities retained in JSON. No system JDK/library was replaced.
- JDK21 `bash dev/script/codex.sh package` and `verify_distribution.py prepare`:
  exit0, ten major61 binding classes, fixed POM dependency graph. Single candidate
  JAR SHA256 `1acc1ee887dfcf9f9ac2ad18ceabad0267c14f20fa4826d7e066493e774aa015`.
  Source main SHA retained with dirty harness edits explicitly recorded.
- Bundle verifier `consume` on17/21/25: each exits0, isolated temporary project,
  `-Srepro`, verified unchanged same JAR, real native/BPF, DNS/Flow/TLS/window,
  six DLT Classic round trips, rich PCAPNG round trip, early close and managed
  fan-out shutdown. Final harness reports dladdr `/usr/lib/libpcap.A.dylib`,
  libpcap1.10.1, JNR2.2.14/jffi1.3.11, 8-byte pointers/C-long on all three.
- JDK25 `python3 dev/script/verify_jdk25.py /tmp/paclo-p13/source25-final`:
  exit0; direct javac/javac-test with unchanged release17/Werror flags,
  JUnit13/13 (zero skipped), Clojure493 tests/19,130 assertions, zero failures/
  errors, native smoke/interface enumeration and dependency inventory. No
  doctor/smoke guard bypass or skipped tests. Initial new double-close test
  placement failed `-Xlint:try`/Werror; explicit try/finally fixed the test while
  retaining double-close coverage, flags and production behavior.
- Default JDK25 reports jffi StubLoader/System.load native-access and
  UnsafeMemoryIO64/putLong warnings. Separate native-access-enabled + Unsafe
  debug consumer exits0 and retains full call-site stacks. Unsafe deny (native
  access enabled) intentionally exits1 with UnsupportedOperationException
  putLong in jffi registration. This future restriction belongs to P14; no
  native-access option or warning suppression is added to default execution.
- Distribution Python gate14/14 and actual build identity5/5 pass. New JDK25
  runner negative controls2/2 pass. clj-kondo changed harness: zero warnings/
  errors; applied only its namespace/format corrections using existing LSP.
- Local raw logs are retained at `/tmp/paclo-p13`; CI will upload logs and JSON.
  JDK21 full check, quality/lint/docs and final-head CI results follow below.

Decision: default JDK25 runtime/source compatibility is demonstrated on this
macOS x64 host. Keep17/21 formal support; require separate platform/live/workload/
JDK25-tool evidence before a broader declaration. Current JDK21 quality gates
remain mandatory. P14 is the next unfinished independent queue item; P16 remains
ready. P17/P09/P10 conditions are unchanged. No merge/publication is authorized.

P13 supported-runtime verification and delivery checkpoint:

- `bash dev/script/codex.sh check` on21: exit0, JUnit13/13;493 Clojure tests /
  19,130 assertions with zero failures/errors; native smoke4 packets/438 bytes.
- `clojure -M:spotbugs`, `clojure -M:checkstyle`, `clojure -M:jacoco` and
  `JACOCO_MIN_LINE=0.25 clojure -M:jacoco-gate`: each exits0; coverage80.8%,
  unchanged25% threshold. No JDK25 analyzer/coverage validation is claimed.
- `clj-kondo --lint src test dev extensions/dns/src`: zero warnings/errors.
  `clojure -M:eastwood`: exit0,636 informational warnings, zero exceptions.
  LSP clean-ns/format dry-runs: exit0, no changes. Added development diagnostic
  functions explain the informational-warning count difference from P15.
- `bash dev/script/codex.sh perf`: exit0,628.5ms, unchanged warn1000/fail1200ms.
  This is the existing JDK21 gate, not a JDK25 performance target measurement.
- `python3 dev/script/verify_doc_links.py`: pass. `bash dev/script/mdlint.sh`
  with normal npm access: exit0,53 files/zero errors. Initial sandboxed npm
  access exited1; it is not counted as a passed wrapper run.
- New Python runner help and distribution consume help exit0; missing runner
  argument and unknown consumer option exit2. Actual non25 runner invocation
  exits1 before compilation. Actual JDK25 environment-check doctor exits1 with
  its unchanged "Use a supported JDK (17 or 21)" error; direct equivalent
  source/native/JAR checks above pass. This is not treated as library failure.
- Commit `84b6d0e` created [PR #73](https://github.com/nantes-rfli/paclo/pull/73).
  The hook's documented per-command skip flags avoid rerunning the already
  verified test/lint stages through its unavailable `clj`/rlwrap entrypoint;
  no hook or CI gate is changed. No merge/tag/release/publication performed.
- Implementation [CI run39113249185](https://github.com/nantes-rfli/paclo/actions/runs/39113249185)
  already passes the required Linux x64 JDK25 source experiment: compilation,
  JUnit13/13 with zero skipped;493 Clojure tests/19,136 assertions, zero failures/
  errors; native smoke and dependency inventory. The extra six assertions are
  Linux-specific existing suite coverage. Runtime/steps JSON copied separately
  into `dev/p13-evidence/source-jdk25-linux-*`; raw logs remain Actions artifacts.
  Exact Temurin25.0.4.1+1-LTS, Ubuntu24.04 x64/kernel6.17.0-1022-azure, Clojure
  CLI1.11.1.1435/library1.12.6, libpcap1.10.4 (TPACKET_V3) and loaded
  `/lib/x86_64-linux-gnu/libpcap.so.1.10.4` are recorded. Existing build-checks,
  Eastwood and all three performance shards/merger have also passed. Remaining
  initial-run jobs and final evidence-head CI are checked before final handoff.

The implementation CI's independent consumers17/21/25 now all pass, including
the25 native-access/Unsafe debug run; supported macOS ARM64/JDK17 and Linux
x64/JDK21 source jobs, Linux ARM64 monitor and optional coverage also pass.
CI checks out PR merge ref `67becc16d0fffc776f07cda4792cc3f6babcc9d3` for head
`84b6d0e`; its JDK21-produced JAR hash is
`69d61cd21cb536150e836cadb1e7c320b586cf3c76d97117850474179a7146db`, identical
across17/21/25 and debug. This is explicitly separate from the local main-built
candidate hash. Producer/consumer JSON has been copied into `dev/p13-evidence/`.
P13 implementation/compatibility evidence is complete; independent review is
pending, with P14 next and P16 independently ready. Final evidence-head CI is
recorded in PR #73 before handoff; neither earlier-head success nor optional
coverage success substitutes for the final required build aggregate.

Implementation CI39113249185 completes successfully: all16 jobs, including the
required build aggregate, documentation40 examples, JDK25 source, same-JAR17/21/25,
old supported platforms, Linux ARM64, performance and quality gates. The Linux
source job records native packages `libpcap0.8t64:amd64` and `libpcap-dev:amd64`
build1.10.4-4.1ubuntu3.1. Final evidence commit adds only completion/PR records
and copied machine-readable reports; it does not alter the verified implementation.

## 2026-10-18 — P14-A: JNR-FFI update and native compatibility

Requested implementation, verification and a separate PR, without merge/release/
publication. Initial `git status --short --untracked-files=all` was clean.
`bash dev/script/codex.sh doctor` exits0 on Temurin21.0.12.1+1-LTS/macOS15.4.1
x64: Clojure1.12.6, real libpcap read4 packets/438 bytes. Fetched latest main;
PR73 is merged as `4a86d666be839e89480bd02d5772dbc5cf87cdb8` at09:58:37UTC
(18:58:37 Asia/Tokyo), after independent review of final head `ee74766` and all16
passing jobs in CI39113609011. Review tracks the old Unsafe-denial problem in
Issue74. Created `codex/p14-a-jnr-ffi` from that main in the supplied checkout.

Official Central metadata/tag/POM recheck confirms latest stable JNR2.3.3,
although GitHub Releases still labels2.3.2 latest. `deps.edn` changes only JNR;
Clojure1.12.6, core.async1.6.681, other production/tools, release17 flags and
1.5.0-SNAPSHOT remain. Details/sources: [P14-A report](p14-a-jnr-verification.md).

Completed local checkpoint (unfiltered logs `/tmp/paclo-p14-a`):

- Before update, `bash dev/script/codex.sh perf`: exit0,849.1ms against unchanged
  warn1000/fail1200ms, JDK21/macOS x64,50k synthetic74-byte packets. This cold
  gate has no separate warm-up/allocation/drop instrumentation; it is not a
  statistically controlled benchmark or NIC throughput result.
- `bash dev/script/codex.sh prepare`: exit0 with actual Central downloads and
  bindings/tests compilation. `clojure -Stree`: JNR2.3.3, jffi1.4.3 Java/native,
  all five ASM9.10.1 modules, assembler1.0.0/1.0.2; analyzer's ASM9.2 is excluded.
- `bash dev/script/codex.sh package`; `verify_distribution.py prepare`: exit0.
  JDK21-built JAR918f9da3e2275a367c5bfff69a4cec59369e68eda7a64d37314857b47fda5f79,
  ten major61 classes, exact inventory/POM and dirty-main provenance recorded.
- Bundle `verify_distribution.py consume` under actual Temurin17.0.20.1+1,
  21.0.12.1+1-LTS,25.0.4.1+1-LTS: all exit0, same hashes before/after, external
  temporary projects/-Srepro and exact native dependency graph/JAR hashes.
  Actual loaded `/usr/lib/libpcap.A.dylib`, libpcap1.10.1,8-byte C-long/pointer.
- Separate25 debug and deny consumers both exit0. Default retains StubLoader/
  System.load native-access warning, no Unsafe warning observed. Debug has no
  Unsafe trace; deny now passes the entire consumer. Official jffi1.4.3 sources
  deliberately choose non-Unsafe memory access at JDK>=23. This resolves the
  measured P13 restriction on this host; no future/all-platform guarantee.
- Python distribution gate15/15; real build identity5/5; JDK25 runner2/2 and
  executable-example parser regressions pass. New graph negative controls reject
  stale/missing/duplicate native and mixed ASM; direct-POM guard now rejects
  rollback to2.2.14 while retaining other dependency/version/semantics guards.
- SpotBugs, CheckStyle, JaCoCo and `JACOCO_MIN_LINE=0.25` gate all exit0;
  coverage80.8%. Same existing JDK21 tool versions and rules.
- Extra link-parser regression initially fails on this Mac's symlinked default
  temp path (`/var` versus `/private/var`), unrelated to JNR. Repeating with
  `TMPDIR=/private/tmp` passes9/9 without source edits; real local-link check
  passes. No initial failure is counted as success.

Added separate CI Unsafe-deny diagnostic with full logs/original exit status;
success or specifically attributed old putLong failure is recorded, unexpected
failures fail the step. Default/debug remain required successes. Supported macOS
ARM64/Linux ARM64 source jobs additionally run the existing13 JUnit ABI tests
and native identity/CPU diagnostics. No platform, quality or performance gate
is removed or weakened. Machine-readable local reports are in `p14-a-evidence`.
Full21/source25, lint/docs, after-update perf and CI results follow below.
P14-A is in progress; P14's other candidates remain separately selectable,
P16 independently ready, P09/P10/P17 conditions unchanged. Independent review
must precede merge; no release/tag/publication performed.

P14-A completed local verification and CI checkpoint:

- JDK21 `bash dev/script/codex.sh check`: exit0, JUnit13/13,493 Clojure tests /
  19,130 assertions,0 failures/errors; offline smoke4 packets/438 bytes.
- Actual JDK25 `python3 dev/script/verify_jdk25.py /tmp/paclo-p14-a/source25`:
  exit0; all seven steps, release17 Java compilation/JUnit13/13,493 Clojure
  tests/19,130 assertions, native BPF/interface/error smoke and dependency tree.
  Native library/versions match the independent consumers. Actual25 memory
  class probe returns `com.kenai.jffi.MemoryIO$NativeImpl64`; its unfiltered
  native-access warning is retained in `p14-a-evidence/jffi-memory-jdk25-macos-x64.log`.
- `bash dev/script/codex.sh lint`: exit0, clj-kondo zero errors/warnings;
  Eastwood636 informational warnings/zero exceptions; LSP clean-ns/format dry
  runs unchanged; Markdown54 files/zero errors. `verify_doc_examples.py`:
  exit0, all40 maintained examples. Link validation passes. All51 multiline CI
  shell blocks pass `bash -n`; no workflow gate changed to hide failures.
- After all other local suites ended, `bash dev/script/codex.sh perf`: exit0,
  777.1ms against unchanged1000/1200ms budgets. Before/after849.1/777.1ms is a
  coarse single-run/cold gate comparison, not a speedup claim, allocation/drop
  measurement, JDK25 performance result or real-NIC throughput evidence.
- Implementation commit `c0fd760` creates [PR #75](https://github.com/nantes-rfli/paclo/pull/75),
  attached to this chat. Commit uses the hook's supported `SKIP_TESTS=1` and
  `SKIP_FMT=1` because those suites/dry-runs are executed explicitly above;
  hook Markdown/kondo checks still pass, with no hook or CI rule edit.
- Implementation [CI39124535933](https://github.com/nantes-rfli/paclo/actions/runs/39124535933)
  already passes JDK25 source:13/13 JUnit,493 Clojure tests/19,136 assertions,
  zero failures/errors; exact Linux native/JVM report/steps copied separately.
  Linux has six extra existing platform assertions. Producer21, Eastwood,
  quality gates, all three performance shards/merger and optional coverage pass.
  Full platform, three same-JAR consumers and documentation CI still pending.
- CI builds merge-ref `59020db917798efd04bcfc50d35b684ea20be308`, clean tracked
  source, JAR3097d9c215ae832635d4d80c9d356b55fa64f2e093a31a24266ea0335293ba7d.
  Its copied producer provenance is distinct from the local dirty-main candidate;
  same-JAR consumers must match this CI hash. Generated Python fixture bytecode
  was removed; no tracked fixtures, version, production source or API changed.

P14-A implementation CI completed: **all16 jobs pass** in CI39124535933,
including the required build aggregate, documentation40 examples, source25,
single-JAR17/21/25 consumers and separate25 debug/deny, supported macOS ARM64/
JDK17 and Linux x64/JDK21, Linux ARM64 monitor, quality/performance/lint gates,
and optional coverage. All three platform source jobs also pass13 JUnit tests.
CI's mid-50k gate is827.1ms; JaCoCo80.8% against25%. Same CI JAR hash above is
confirmed in all five consumer reports; native/ASM dependency hashes match.
Default Linux25 reports native-access only, no Unsafe warning; debug/deny pass
with no Unsafe warnings, denial's original exit status0 retained in artifact.

Additional actual CI identities: Linux x64 source25 AMD EPYC9V74 with installed
`libpcap0.8t64:amd64`/`libpcap-dev:amd64`1.10.4-4.1ubuntu3.1; supported x64
source21 AMD EPYC7763; Linux ARM64 Neoverse-N2/Temurin21.0.12.1+1-LTS loads
`/lib/aarch64-linux-gnu/libpcap.so.1.10.4`, version1.10.4 TPACKET_V3; macOS26.6.2
ARM64 Apple M1(Virtual)/Temurin17.0.20.1+1 loads `/usr/lib/libpcap.A.dylib`,
version1.10.1. Linux kernels6.17.0-1022-azure; every measured C-long/pointer8bytes.
Exact platform identity log excerpts and separate Linux producer/consumer JSON
are copied into `p14-a-evidence`; full logs remain Actions artifacts. Source25
and Linux suites have19,136 assertions; macOS has19,130, all493 tests/zero failures.

Decision: accept JNR2.3.3 as the P14-A implementation candidate. No native/API
fix is necessary; existing regression fixtures pass. The former P13 Unsafe
restriction no longer reproduces under measured25 default/debug/deny, explained
by jffi's JDK>=23 JNI selection. Native-access restrictions still need deliberate
permission in future JDKs. Keep formal support17/21, all public/binary contracts
and existing gates. P14-A is implemented/verified; independent review pending.
P14 remains in-progress for separate unselected dependency/tool slices; P16 is
independently ready. No live NIC, operational throughput, JDK25 ARM64/tools/
coverage/performance or future-JDK validation is claimed. Final evidence commit
adds records/reports only; final-head CI is checked in PR75 before handoff.

## 2026-10-18 — P14-B core.async update and async compatibility

Authorized scope: implement the next P14 slice, update stable core.async, verify
async contracts/load/memory/performance and distribution, run JDK17/21/25 CI,
and create a separate PR without merge/publication. Initial status was clean
on `codex/p14-a-jnr-ffi`. `git fetch origin main` and `gh pr view75` confirmed
PR75 merged at12:00:29 UTC (21:00:29 Asia/Tokyo) as `4a113c6`; created
`codex/p14-b-core-async` directly from that latest main in the supplied checkout.

Official upstream README and Maven Central metadata confirmed stable1.9.865;
1.10 versions remain prereleases. Updated only core.async1.6.681→1.9.865 as a
direct dependency. `clojure -Stree` before/after records six selected transitive
updates (analyzer.jvm/analyzer/memoize/cache/priority-map/reader) and unchanged
JNR2.3.3/jffi1.4.3/ASM9.10.1. Full graph files are in `dev/p14-b-evidence/`.
Production stream implementation is unchanged: released source inspection shows
identical fn-handler behavior and unchanged used protocol signatures.

Added immediate-handler compatibility, nil/false dropping/abandon accounting,
concurrent capacity-one runtimes, blocked branch close/sibling independence,
and sampled large-payload retention regressions. Added a reproducible bounded
heap stress probe with ordered dual delivery, dropping and50 saturated-close
cycles, keeping terminal handles alive while payload weak references clear.
Distribution verification now validates/hashes the exact async graph and rejects
old/missing/duplicate JARs. Installed-JAR consumers check public nil/false
capacity-one delivery too. Changelog and API notes record the dependency change.

Initial commands/results:

- `bash dev/script/codex.sh doctor`: pass, macOS x64 Temurin21.0.12.1+1,
  Clojure1.12.6, real offline libpcap read. JDK17/25 are available in the existing
  `/tmp/paclo-p13/jdks/` cache; no tool/runtime versions were changed.
- `bash dev/script/codex.sh prepare`: pass after permitting dependency download
  and Maven-cache writes. The first sandbox attempt failed on cache permissions;
  it is not counted as passing verification.
- Focused `test -n paclo.stream-impl-test -n paclo.stream-test`:23 tests/707
  assertions, no failures/errors. The same regressions also pass with a CLI-only
  core.async1.6.681 override, preserving the previous behavior baseline.
- Python distribution negative controls:16 tests pass, including actual async
  graph hashes, old analyzer/core.async, missing and duplicate entries.
- SpotBugs/CheckStyle/JaCoCo/JaCoCo gate:pass;80.8% against existing25%.
- Two independent baseline JVMs ran the existing real-PCAP combined benchmark:
  200000 packets, three warmups and five measured runs per scenario; raw
  before results are retained. Candidate comparisons and remaining gates follow.

Full results and final PR/CI identity will be recorded after completion in this
log and [the P14-B report](p14-b-core-async-verification.md). P14 remains
in-progress; other tools/dependencies are unselected, and independent review
must precede merge. No release/tag/publication or support expansion.

Local full check completed:498 Clojure tests/19,669 assertions and13 JUnit
checks pass; offline smoke passes. All40 documentation examples pass. Static
analysis completed all namespaces with648 informational Eastwood warnings and
zero exceptions; clj-kondo has zero warnings/errors and namespace cleanup is
clean. The first format check found one indentation difference in a new test;
it was corrected. Markdown lint initially failed due to sandboxed npm network/
cache access, then passed with the same pinned command outside that sandbox.
Local Markdown links/anchors and four Eastwood-runner exit-status probes pass.
Remaining: final format recheck, candidate performance/load evidence, package/
consumers, JDK25 source and PR CI. The implementation PR will be a draft while
these finish; no merge is authorized.

Commit environment: the first attempt stopped before creating a commit because
the installed pre-commit hook calls `clj`, requiring unavailable `rlwrap`.
Use its documented per-command SKIP_TESTS/SKIP_FMT flags after the successful
wrapper test and LSP dry-run evidence; retain hook Markdown/kondo checks.
No hook or tool version is changed. The final full-project LSP format dry-run
exits0 after correcting the one indentation difference.

Performance follow-up: the unchanged mid50k gate passes at514.1ms (1000ms warn,
1200ms fail). Initial two independent before/after combined measurements show a
material dual-stream regression, with higher allocation; investigate rather than
claim improvement or alter gates. A later `recheck-new` overlapped the start of
JDK25 compilation and is retained as contaminated diagnostic data, excluded from
acceptance comparisons. Callback adapter/dispatch controls will run after source
checks finish to avoid concurrent benchmark load. No upstream overrides ship.

P14-B final implementation evidence (PR76, head `da7a8c7`):

- Same-condition combined benchmark: initial old/new dual medians409631→266400
  and386138→273354pps (−35.0%/−29.2%); dropping481943→401492 and469472→400904
  (−16.7%/−14.6%). Allocation rises; managed control remains about645B/packet.
  All counts/order/drops/capacities remain correct. Raw files and full CPU/GC/
  allocation/stats are in `dev/p14-b-evidence/`. Before/after initial reports
  share baseHEAD4a113c6; candidate dependency edits were later committed as
  da7a8c7. Do not identify those edits solely by the base SHA.
- Clean later old dual control473099pps/996B; new default303834pps/1256B.
  Diagnostic-only old-style callback adapter372756pps/1051B; adapter plus fixed
  eight-thread dispatch422678pps/1012B. These support partial attribution to
  upstream callback metadata/dispatch changes, without claiming exact per-class
  causality. No override or workaround ships. Existing perf gate passes514.1ms;
  no thresholds change. Independent review must explicitly assess this cost.
- `clojure -J-Xmx256m -M:dev -m paclo.dev.stream-retention 8000000 65536 ...`:
  JDK21 passes in87.8s,524288000000 generated payload bytes,8050/8050 sampled
  payloads released while handles stay alive,50 saturated-close cycles. Both
  blocking consumers receive8000000 in order; idle branch drops7999996. Every
  terminal accounting/capacity assertion passes. Heap-pool peak sum126923064B,
  GC5848/4026ms; these are not RSS or a retained-heap census.
- Same256MiB probe at2000000 values passes on actual JDK17.0.20.1 (22.3s),
  21.0.12.1 (22.6s) and25.0.4.1 (22.1s),2050/2050 references released each.
- `verify_jdk25.py /tmp/paclo-p14-b/source-jdk25`: all source steps exit0,
  including13 JUnit tests and498 Clojure tests/19,669 assertions. Native/BPF/
  interface smoke and dependencies pass; default native-access warnings remain.
- `package` and `verify_distribution.py prepare`: strict source/classfile17/
  POM/SCM/dependency inventory passes. Local JDK21 JAR hash94f54fc37690fb7640ff84b2795bb0cb87917368a170ed5d6537116a329be792,
  source da7a8c7 with source_dirty:true (evidence/docs edits). Fresh consumers
  on17/21/25 plus25 native-access/Unsafe debug and denial all exit0 on this same
  JAR, with exact native and seven async JAR hashes. No rebuild between consumers.
- [CI39127114926](https://github.com/nantes-rfli/paclo/actions/runs/39127114926)
  passes all16 jobs: required build, supported Linux21/macOS ARM64-17,
  LinuxARM64, JDK25 source, three same-JAR consumers,25 debug/deny, analyzers,
  coverage, docs, all three perf shards/27-scenario merge. CI producer uses clean
  merge ref7b7a91e; its distinct JAR hash9dfdf2294d2fb4310bb76eda901e33738495c12e12e6a6aacc88f539b85fd745
  matches all consumers. Retained CI/local provenance, runtime/graph hashes,
  job conclusions and source steps are linked in the report.

P14-B implementation and requested verification are complete in
[PR #76](https://github.com/nantes-rfli/paclo/pull/76); independent review,
including the performance trade-off, is pending. The final evidence-only head
will be checked separately and recorded in the PR description. P14 as a whole
remains in-progress; the next unfinished P14 candidates are remaining tools/
dependencies, unselected. P16 stays independently ready. P09/P10/P17 stay
blocked. Live NIC/representative long production workloads, all-platform JDK25,
Windows/32-bit remain unverified. No API/contract/gate/version identity change,
release/tag/publication or merge. Remove only regenerated Python fixture caches.
