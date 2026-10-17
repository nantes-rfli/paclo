<!-- markdownlint-disable MD013 -->
# v1.4.0 release preparation and acceptance

Status: **unpublished; final metadata/evidence PR awaiting acceptance**,
2026-10-17 (Asia/Tokyo). No publication date is confirmed. Stable installation
coordinates remain v1.3.0; CHANGELOG retains `## [1.4.0] (unreleased)`.
Formal publication requires a separate explicit authorization.

## Scope and completed baseline

- [x] v1.4.0 includes P01–P08 and merged correctness, lifecycle, Flow/DNS,
  Ethernet and Java distribution fixes. P09/P10 remain outside scope.
- [x] Retain D1 capture-preserving Writer precedence/strict validation and D2
  exact bounded DNS aggregation/explicit failures. The [migration guide](../docs/migration-from-1.3.md)
  explains observable input/result changes; stable names/arities do not imply
  identical behavior on all formerly accepted inputs.
- [x] [PR #62](https://github.com/nantes-rfli/paclo/pull/62) merged at main
  `dfc5c5b4dbe39859b06431fa9c4b12714b89498d`. The maintainer confirmed completed
  independent review outside GitHub; there are no GitHub review submissions.
- [x] README, [release notes draft](../docs/release-notes-1.4.0.md), migration,
  [API contract](../docs/cljdoc-api-contract.md), PCAPNG guide and roadmap retain
  accurate unpublished availability. The development default is 1.4.0-SNAPSHOT;
  explicit candidate packaging uses PACLO_VERSION=1.4.0.

Measured acceptance for **dfc5c5b**, not a future commit:

| Gate | Evidence | Result |
| --- | --- | --- |
| Complete CI | [39012456023](https://github.com/nantes-rfli/paclo/actions/runs/39012456023) | All 14 jobs successful, including Linux ARM64, both source compatibility jobs and both same-JAR consumers |
| Publish dry-run | [39013121398](https://github.com/nantes-rfli/paclo/actions/runs/39013121398), main/1.4.0/dry_run=true | Source/metadata guard, release gates, package inspection and upload successful |
| Release gates | Publish log | 490 tests / 19042 assertions, zero failures/errors; performance 335.2 ms, unchanged 1000/1200 ms budgets |
| Actual Publish JAR | [Artifact 12094105818](https://github.com/nantes-rfli/paclo/actions/runs/39013121398/artifacts/12094105818) | Exact inventory/source bytes, all ten classes major 61, coordinates/POM/dependencies/SCM/license verified |
| Same Publish JAR consumers | [JDK 17](release-1.4.0-evidence/consumer-jdk17.json), [JDK 21](release-1.4.0-evidence/consumer-jdk21.json) | Both pass on macOS x86_64; no rebuilding, hash unchanged before/after |
| Dependency Audit | [39013091814](https://github.com/nantes-rfli/paclo/actions/runs/39013091814) | 23 production-classpath dependencies, zero detected/suppressed CVEs; NVD updated and parsed |
| Non-publication | Publish step results and post-run registry/tag/Release checks | Clojars publish/Publish summary skipped; Dry-run summary succeeded; latest published version still 1.3.0 |

The [dry-run report](release-1.4.0-dry-run.md) and retained original provenance
separate this actual Publish JAR from PR #62 CI and earlier local builds:

- JAR SHA-256: `d226794493dcd4a5840d2f04ead8068c02e47a8c6b9ac275ca9f5adaacbddd10`.
- Embedded/external POM SHA-256: `91a5f668b7e9daf06735f09a10efe9dba9daec8946704cc7ce696456d2338d56`.

## Distribution verification

The finalization PR records its exact final head, review outcome, CI run and
all 14 conclusions, artifact identities and fresh Dependency Audit in its
**PR description**. This avoids adding another evidence-only source commit
after final validation. Repository evidence above is immutable baseline history;
it must not be relabeled as a scan/build of this PR.

Before accepting that PR, verify:

1. Only release documentation/evidence changed; no dependency, runtime behavior,
   performance budget, workflow, release version or published install coordinate changed.
2. All 14 CI jobs pass on the final PR revision, including Linux ARM64 separately
   from the aggregate build, and both checkout-free JDK 17/21 distribution consumers.
   Coverage is informational in the existing workflow, but its job must also succeed.
3. Download the newly generated single JDK 21 candidate bundle and both consumer
   identity reports. Record its JAR/POM SHA-256 and original clean provenance;
   require both consumers to identify that same JAR without rebuilding.
   Record PR head SHA separately from the synthetic merge SHA used by PR CI,
   and confirm the merge tree equals the intended candidate tree.
4. Dispatch Dependency Audit on the final PR branch, verify its head SHA equals
   the final PR head and triage the reports. Do not update dependencies silently.
5. Review the complete diff and final evidence. The PR remains open for maintainer
   acceptance; neither review nor CI authorizes merge, tag creation or publication.

No release date is inserted in this PR because the actual publication day is
unconfirmed. A dated CHANGELOG is therefore still a **publication blocker**.
The existing publishing metadata guard must continue rejecting this undated
candidate, while its dry-run check accepts it. A future dated commit must pass
these checks again; passing finalization CI does not bypass that requirement.

## Remaining issues and validation limits

No new technical blocker was found in the completed baseline checks. The final
PR's checks and review must actually complete before claiming its acceptance.

[Issue #37](https://github.com/nantes-rfli/paclo/issues/37) remains open and
non-blocking. PR #57 avoids premature DNS scans, but repeated actual retired-key
expiry remains O(retired), with long production-trace evidence outstanding.
[Issue #44](https://github.com/nantes-rfli/paclo/issues/44) retains merged offline
Ethernet Full gains of 9.1–76.1% transformation / 9.6–32.3% native reads, with
allocation parity and JIT/thermal/retained-heap limits. Neither issue is closed here.

The audit covers the default production dependency graph; development/build-only
dependencies are outside that scan. Sonatype OSS Index is disabled without
credentials; NVD CVE analysis completed. Actions deprecation/image-migration
notices are non-blocking maintenance findings, not detected library CVEs.
Existing legacy lazy-abandonment, shared mutable packet bytes, opaque PCAPNG,
unmeasured-platform and live/NIC limits remain documented. Offline CI does not
establish every OS/JDK pair or live performance target. No gate is relaxed.

## Publication handoff — requires separate explicit authorization

These are instructions for a later authorized release task; they are not executed
by finalization, review, merge acceptance or dry-run approval.

1. Obtain explicit formal publication authorization and confirm the actual
   publication day. Recheck that v1.4.0 is absent from Clojars, tags and Releases.
2. Prepare the real `## [1.4.0] - YYYY-MM-DD` CHANGELOG heading for that day.
   Update availability/announcement wording only when it is true; keep README
   installation at v1.3.0 until Clojars publication is confirmed. Review and merge
   the release metadata through the separately authorized process.
3. Validate the exact resulting main SHA: all 14 CI jobs, same-JAR JDK 17/21
   consumers and refreshed/triaged Dependency Audit. Any later source/date change
   invalidates that SHA's acceptance and requires fresh checks.
4. Run Publish with **main**, **version=1.4.0**, **dry_run=true** explicitly:

   ```bash
   gh workflow run publish.yml --repo nantes-rfli/paclo --ref main -f version=1.4.0 -f dry_run=true
   ```

   Require the source guard, release gates, package/inspection/upload and Dry-run
   summary to succeed; Clojars publish and Publish summary must be skipped.
   Inspect the new actual Publish JAR/POM/provenance and consume that same JAR
   on JDK 17/21 without rebuilding; never reuse an earlier JAR hash by assumption.
5. Before publication, confirm main/date/authorization still match the accepted
   candidate. An authorized operator may then create/push the release tag at
   that exact SHA. **Pushing a v* tag starts Publish and Clojars deployment**;
   tag creation/push must wait for formal publication authorization. Do not also
   dispatch another publishing run. This task creates no tag or GitHub Release
   and never runs dry_run=false.
6. Verify deployed JAR/POM coordinates/hashes and Clojars availability. Only then
   update stable installation/availability documentation and, if separately
   authorized, publish the GitHub Release/announcement. Record actual publication
   evidence and any mismatch rather than assuming the deployed JAR equals a
   previous dry-run build.
