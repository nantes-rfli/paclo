# Paclo development instructions

Paclo makes packet processing native to Clojure data workflows. Read
`CONTRIBUTING.md`, `docs/cljdoc-api-contract.md`, and `dev/codex-plan.md`
before changing behavior. The accepted development plan is in `dev/codex-plan.md`;
its API sketches are proposals, not implemented features.

## Start each task

- Inspect `git status --short --untracked-files=all` and preserve unrelated work.
- Use the supplied checkout. A managed cloud task is already isolated; do not
  create another worktree unless requested.
- Run `bash dev/script/codex.sh doctor`. The wrapper activates the existing
  `/workspace/.paclo-env/activate.sh` when available, without requiring it on
  other machines. Use `prepare` if dependencies or compiled Java classes changed.
- Pick the requested plan item. When asked to continue the accepted plan without
  a specific item, take the first unfinished item whose dependencies are complete.
- Check the implementation before relying on historical release notes. Record
  progress and verification in the plan as each item is completed.

## Design constraints

- Prefer ordinary maps, vectors, functions, reducers, and transducers. Keep
  transformation independent of capture, scheduling, serialization, and CLI I/O.
- Keep state and resource ownership explicit. Retain `with-open`, `reduced`,
  bounded queues, deterministic close, and single-consumer contracts.
- Preserve the v1 public API. Add explicit extension configuration without
  changing the existing global registration behavior for existing callers.
- Existing packet byte arrays are mutable and shared across fan-out branches.
  Do not mutate a published packet or introduce borrowed buffers by default.
- Preserve existing data keys and error strings when adding structured data.
  Specify timestamp units, missing values, precedence, and lifecycle semantics.
- Prefer measured changes over speculative optimization. Local mutation confined
  to a reduction is acceptable when justified; do not expose mutable aggregates.
- Keep optional integrations outside the default dependency graph. Do not add a
  framework, pipeline DSL, or public backend selector without a concrete need.

## Verification and delivery

- Add regression tests for behavioral fixes. Exercise real offline PCAP fixtures
  for I/O and use property tests for meaningful invariants, not implementation detail.
- Use `bash dev/script/codex.sh test -n paclo.some-test` for focused Clojure tests;
  `check` runs Java compilation, JUnit, the Clojure suite, and an offline smoke check.
- Use the change-specific checks in `CONTRIBUTING.md`. Missing tooling or blocked
  dependencies are not passing checks; report the exact limitation.
- Public behavior changes need API documentation and a changelog entry. Keep
  maintained user-facing documentation in English.
- Keep commits and PRs scoped to reviewable plan items. Do not change release
  versions, publish artifacts, or merge as part of ordinary implementation work
  unless the user's task authorizes it.
- Record commands, results, outstanding concerns, and the next unfinished item.
  Do not mark live capture, other platforms, or performance targets validated
  based solely on offline tests or historical measurements.
