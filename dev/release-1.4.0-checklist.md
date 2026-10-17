<!-- markdownlint-disable MD013 -->
# v1.4.0 release preparation and acceptance

Status: **unpublished candidate; local preparation verified, independent review pending**, 2026-10-17 (Asia/Tokyo).
Source baseline: latest main `82705b9c601b2361be8f9446f519f54673aa0d64`, after
merged [PR #59](https://github.com/nantes-rfli/paclo/pull/59),
[PR #60](https://github.com/nantes-rfli/paclo/pull/60) and
[PR #61](https://github.com/nantes-rfli/paclo/pull/61).
The preparation PR must be independently reviewed and merged; this task does
not merge or dispatch Publish, including dry-run.

## Approved scope and documentation

- [x] v1.4.0; retain D1 Writer metadata correctness/strict validation and D2 exact
  bounded DNS aggregation/explicit failures. Public function/arity compatibility
  alone is not a claim of identical behavior on every old input.
- [x] Include all P01–P08 and merged stabilization/Flow/DNS/Ethernet/build fixes.
  P09/P10 remain outside scope; no new feature/API, dependency or quality-budget change.
- [x] [CHANGELOG](../CHANGELOG.md#140-unreleased) groups the candidate under
  `## [1.4.0] (unreleased)` and leaves `[Unreleased]` for subsequent changes.
  No release date is invented; only actual publication changes it to a dated heading.
- [x] README/install/versioned availability, [migration guide](../docs/migration-from-1.3.md),
  [API contract](../docs/cljdoc-api-contract.md), [PCAPNG guide](../docs/pcapng.md),
  [ROADMAP](../docs/ROADMAP.md) and [plan](codex-plan.md) agree.
- [x] [Release notes draft](../docs/release-notes-1.4.0.md) explains scope, operational
  migration and performance/format/platform/lifecycle limits in English.
- [x] Published stable and install coordinates remain **v1.3.0**. Clojars API
  `latest_version` / `latest_release` both returned `1.3.0` on 2026-10-17.
- [x] Development default is `1.4.0-SNAPSHOT`; explicit candidate is built with
  `PACLO_VERSION=1.4.0`. Neither implies publication or creates a Git tag.

## Quality acceptance

Final preparation-PR evidence will be linked in its description on the exact
final head, without generating another evidence-only source change afterward.
A green base/old PR is supporting history, not the final candidate's acceptance.

| Gate | Current evidence | Acceptance |
| --- | --- | --- |
| All existing 14 CI jobs | Base main run [38999502746](https://github.com/nantes-rfli/paclo/actions/runs/38999502746): 14/14 success; final-head result/run URL recorded on the preparation PR | Require all 14, including Linux ARM64 separately from aggregate build |
| Clojure/JUnit/native smoke | Local `check`: 490 tests / 19036 assertions, ten JUnit tests, zero failures/errors | Passed on local macOS x86_64/JDK21 |
| Full lint/Eastwood/format/Markdown | Local kondo clean; Eastwood 113 namespaces / zero exceptions; clean-ns/format dry runs and all 46 Markdown files pass | No skipped namespaces/exceptions; informational warnings are not failures |
| Java quality and coverage | Local SpotBugs/CheckStyle pass; JaCoCo 43.8% | SpotBugs, CheckStyle, JaCoCo; unchanged CI line minimum 25% |
| Performance | Local gate 446.5 ms; 27-scenario/three-shard result enforced by PR CI | Existing 1000/1200 ms warn/fail gate and 27 quick scenarios, unchanged |
| Docs/examples/links/cljdoc | All 36 executable examples, local links/anchors and pinned cljdoc namespace load pass locally | All maintained examples, local paths/anchors and cljdoc namespace load |
| Real PCAP/PCAPNG fixtures | Existing fixture/round-trip/heap tests in local `check` passed | Generators: 28 capture, 4 cooked, 3 Raw IP, 12 NULL/LOOP and 10 PCAPNG fixtures verified; six Python regressions pass; supported-platform CI required |
| Distribution/consumers | Local v1.4.0 inspection/JDK21 consumer pass; final CI runtime identities recorded on the PR | Exact inventory/POM and same JAR on JDK17/21 |
| Dependency audit | Latest existing run [38428605480](https://github.com/nantes-rfli/paclo/actions/runs/38428605480) succeeded, 2026-10-13, SHA `8312d10`; checked live 2026-10-17 | Historical scan; refresh/triage at final release SHA before publication |

The CI keeps its original 14 jobs: build-checks, documentation-checks, three
performance shards, performance-results, two source compatibility jobs, Linux
ARM64 monitor, Eastwood, informational coverage, two distribution consumers and
aggregate build. No threshold is relaxed. Representative runners cover Linux
x64/JDK21, macOS ARM64/JDK17 and Linux ARM64/JDK21; this is not every OS/JDK pair.

## Distribution verification

CI build-checks explicitly builds `PACLO_VERSION=1.4.0` once on JDK21. It uploads
the inspected candidate bundle to checkout-free JDK17/21 consumers; neither
consumer rebuilds the library. Other source-build jobs keep the development
snapshot. Publication behavior is unchanged by candidate packaging.

Local reproduction (package deletes `target/`; do not overlap it with checks):

```bash
PACLO_VERSION=1.4.0 bash dev/script/codex.sh package
python3 dev/script/verify_distribution.py prepare target/paclo-1.4.0.jar /tmp/paclo-v140-distribution --version 1.4.0
python3 dev/script/verify_distribution.py consume /tmp/paclo-v140-distribution --report /tmp/paclo-v140-consumer-jdk21.json
```

Use a fresh bundle directory. Switch only the runtime to JDK17 and consume that
same bundle with a separate report; do not rebuild. The verifier checks all ten
binding classes at major <=61 (the candidate must contain exactly major61), the
exact production source/class inventory, coordinates, dependency versions,
pom.properties and source-byte identity. Fixtures/dev/test harnesses stay outside
the JAR. Inspect SCM URL/connections/tag `v1.4.0`, MIT license and external POM
identity separately. The SCM tag is intended release metadata; no such tag is
created by packaging. Record JAR/POM SHA-256, source SHA/dirty state and JVM.
Local uncommitted provenance is not clean release evidence. CI's synthetic merge
source SHA must be recorded separately from the PR head SHA.

Local candidate (source baseline `82705b9`, tracked preparation changes dirty,
Temurin21.0.12.1/macOS x86_64):

- JAR SHA-256: `1378838db828b784556698c4aa2d8ad2d3a67e02af591582ebe81f1a49af95ad`.
- Embedded/external POM SHA-256: `91a5f668b7e9daf06735f09a10efe9dba9daec8946704cc7ce696456d2338d56`.
- All ten packaged classes are exactly major61; exact production inventory,
  five unchanged dependencies, `org.clojars.nanto/paclo:1.4.0`, MIT license and
  SCM URL/connections/tag `v1.4.0` verified. The independent JDK21 consumer passed
  all offline API/format/resource probes with that JAR unchanged before/after.
- Local JDK17 is unavailable; use the final PR's required JDK17 consumer of the
  same CI v1.4.0 JAR. Do not transfer the above local hash to a different CI build.
- Quality reports were saved outside `target/` before packaging. Initial local
  Markdown execution hit sandbox npm DNS/cache restrictions; an approved retry
  with the same pinned markdownlint-cli2 0.18.1 passed all 46 files. Other full
  lint stages passed; no lint rule was changed. Eastwood's 600 warnings remain
  informational, with zero exceptions; all four runner failure-control tests pass.
- Workflow YAML parses and all 50 CI / eight Publish shell steps pass `bash -n`.
  This syntax/metadata validation does not dispatch or execute Publish.

## Remaining publication blockers and carry-over

1. Independent review and merge of the preparation PR, with all final-head 14 CI
   jobs successful and same-candidate runtime reports checked.
2. Separately authorized Publish dry-run from then-current main, followed by
   inspection of its newly built JAR/POM/provenance. A prior CI or local JAR is
   not assumed byte-identical to this new build.
3. Refresh/triage dependency-audit evidence at the final release SHA. Latest
   existing successful scan is not a current-SHA security clearance.
4. Separate publication authorization and actual publication date; dated
   CHANGELOG, version availability and announcement updates must reflect that day.
   Release preparation approval is not publication approval.

No newly identified runtime blocker is established by the completed local tests;
remaining gates above must actually pass. Issue #37 remains open/non-blocking.
PR #57 reduces premature DNS scans but repeated actual retired expiry remains
O(retired), with long representative production traces outstanding. Issue #44
remains open for separate issue-level acceptance: PR #58's recorded Ethernet
Full improvements are 9.1–76.1% transformation / 9.6–32.3% native, with allocation
parity and JIT/thermal/retained-heap limits. No Flow, historical-speed recovery or
live/NIC performance claim is made; no issue is closed in this task.
Legacy lazy abandonment, opaque PCAPNG semantics and unmeasured platform/live
limits remain documented, rather than hidden or inferred from offline checks.

## Next Publish dry-run after review and merge

These are **handoff instructions only**. No workflow is dispatched by this task.

1. Obtain a separate request for the dry-run after this PR is reviewed/merged.
   Re-read current main and ensure its full 14-job CI, including ARM64, is green.
   Recheck that v1.4.0 is still unpublished and the intended source is current main.
2. In GitHub Actions → Publish → Run workflow, select **main**, version **1.4.0**,
   and **dry_run=true** explicitly. CLI equivalent for an authorized operator:

   ```bash
   gh workflow run publish.yml --repo nantes-rfli/paclo --ref main -f version=1.4.0 -f dry_run=true
   ```

3. The source guard requires dispatch SHA == fetched origin/main. Metadata
   validation accepts the exact unreleased v1.4.0 heading only for dry-run.
   Actual publishing still requires a real dated heading; no placeholder date
   is needed for this dry-run. Regression tests cover rejection of undated
   metadata for publishing, wrong versions and invalid dates.
4. Require all Publish validation/build steps successful, candidate artifact
   `paclo-1.4.0` uploaded, dry-run summary present and both publishing steps
   **skipped**. Inspect embedded/external POM, dependencies, SCM, every class,
   provenance and hash. Re-run independent consumers on that exact JAR on 17/21
   before a later publication decision; Publish alone does not run all 14 CI jobs.
5. Report the run URL/source SHA, hashes, consumer identities and outstanding
   audit findings. Stop for separate publication authorization. Do not create a
   tag, GitHub Release, Clojars deploy or run `dry_run=false` as part of the dry-run.
