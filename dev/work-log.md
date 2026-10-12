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
