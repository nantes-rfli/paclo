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
