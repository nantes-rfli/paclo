<!-- markdownlint-disable MD013 -->
# Paclo v1.4.0 publication record

Status: **authorized; final gates pending**, 2026-10-17 (Asia/Tokyo).
The maintainer explicitly approved version 1.4.0, the real publication date,
Clojars deployment through a single v1.4.0 tag push, GitHub Release creation,
and reviewed metadata/post-publication documentation PRs. D1/D2 remain unchanged.
This authorization does not waive any failed gate or artifact mismatch.

## Starting state

- PRs #59–#63 are merged; latest main is
  `c8982fdea8860622bbb10c2da7bc4b752184dba1`.
- Clojars latest_version/latest_release and GitHub latest Release are v1.3.0.
  No v1.4.0 tag, Clojars version or GitHub Release exists at task start.
- The checklist and Publish workflow match the prior finalization contents.
- Local doctor passes: macOS x86_64, Temurin 21.0.12.1, Clojure 1.12.1,
  real offline libpcap fixture (four packets / 438 bytes).
- Date confirmed as 2026-10-17 in Japan before metadata preparation. CHANGELOG
  uses the real dated heading. README installation remains v1.3.0 until verified
  deployment; release notes and migration explicitly state deployment pending.

## Required execution and evidence

The metadata PR records its exact head, complete CI and review before merge.
After merge, record the final main SHA and bind all pre-publication checks to it:

1. Full main CI: 14 successful jobs, separately including Linux ARM64 and the
   two checkout-free JDK 17/21 consumers of one JDK 21-built distribution JAR.
   Verify Clojure/JUnit, Java quality, lint, all 36 executable examples and
   unchanged performance gates from actual logs, not an earlier commit.
2. Dependency Audit on that main SHA: inspect NVD freshness, dependency count,
   vulnerabilities/severity, suppression and OSS Index availability. Do not
   silently update dependencies or infer development/build coverage.
3. Publish manual dry-run with main/version=1.4.0/dry_run=true only. Require
   exact source equality, dated metadata, gates, package/inspection/upload,
   Clojars publish and Publish summary skipped, Dry-run summary successful.
   Download its actual JAR/POM/provenance, inspect every class at major 61,
   coordinates/dependencies/SCM/license, and consume the same JAR on 17/21 without
   rebuilding. Record independent hashes for each build.
4. Recheck unchanged main, Japan date, absence of existing version/tag/Release
   and complete successful gates. Create v1.4.0 at that exact SHA and push once.
   Require the tag-triggered Publish run; do not fall back to manual publishing.
5. After Publish success, fetch the actual Clojars 1.4.0 JAR/POM and compare both
   SHA-256 values with the tag-run artifacts. Inspect compatibility/metadata and
   run isolated consumers on published bytes. Verify v1.3.0 remains available.
6. Only after successful deployed-byte verification, create a stable GitHub
   Release named v1.4.0 using the existing tag and calibrated release notes.
7. Prepare a separate documentation PR for published availability, README
   coordinates, API/PCAPNG/roadmap/release-note status, cljdoc checks and this
   record's final URLs/hashes. Review and pass normal CI before merge.

Final run URLs, SHA identities and review outcomes are recorded in the metadata
PR description without creating another pre-release source commit. After actual
publication, append those measured facts here in the post-publication PR.
Historical reports and their source/artifact identities remain unchanged.

## Failure boundary and remaining issues

Before publication, a failed required check, moved main, wrong date or mismatched
artifact blocks tag creation. If a tag push does not trigger Publish, stop.
On deployment failure inspect partial Clojars publication; do not force-move,
delete/recreate tags or duplicate deployment. A deployed artifact mismatch is
not success and requires investigation before GitHub Release creation.

Issue #37 remains open/non-blocking, with repeated actual retired-key expiry
and long production traces outstanding. Issue #44 closure remains a separate
issue-level decision based on recorded evidence; no live/NIC or historical-speed
claim is added. P09/P10, new features, optimizations and dependency changes are
outside this release task. Existing data-loss/partial-report, format, mutable
byte sharing, platform and lazy-lifetime limits remain in the release notes.
