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
