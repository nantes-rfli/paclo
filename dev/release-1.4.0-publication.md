<!-- markdownlint-disable MD013 -->
# Paclo v1.4.0 publication record

Status: **published and deployed bytes verified**, 2026-10-17 (Asia/Tokyo).
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

## Required execution and evidence (completed procedure)

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

## Actual publication and final evidence

The dated metadata [PR #64](https://github.com/nantes-rfli/paclo/pull/64) passed
all 14 PR CI jobs and implementer review, then merged. The release main was
fixed at `74a17b00c0f20f3ab51ef4aa10578088ccafe923`. It stayed unchanged through
final dry-run, single tag push and deployment. The annotated `v1.4.0` tag object
is `fb98630904ec1f9cef9604d387c1289c07480514`, resolving to that release commit.

| Gate | Actual run/result |
| --- | --- |
| Final main CI | [39017426361](https://github.com/nantes-rfli/paclo/actions/runs/39017426361), 14/14 success at the release SHA |
| Platforms/runtimes | Linux ARM64; Linux x64/JDK21 and macOS ARM64/JDK17 source suites; same-JAR JDK17/21 consumers all pass |
| Tests and Java quality | 490 Clojure tests (19042 Linux / 19036 macOS assertions), zero failures/errors; 10 JUnit tests; SpotBugs, CheckStyle, JaCoCo, lint/Eastwood/format successful |
| Executable docs/performance | All 36 examples pass; existing performance gate 317.1 ms with unchanged 1000/1200 ms budgets; all 27 measurement scenarios validated |
| Final-SHA Dependency Audit | [39017436182](https://github.com/nantes-rfli/paclo/actions/runs/39017436182), success; 23 production dependencies, zero detected/suppressed CVEs |
| Final Publish dry-run | [39017696585](https://github.com/nantes-rfli/paclo/actions/runs/39017696585), main/1.4.0/dry_run=true, same SHA; dated metadata/gates/build/inspection/upload pass; publishing steps skipped, Dry-run summary successful |
| Actual dry-run JAR consumers | Independent JDK17/21 consumers pass without rebuilding, before/after hash checked |
| Tag-triggered Publish | [39017886556](https://github.com/nantes-rfli/paclo/actions/runs/39017886556), event push, ref v1.4.0, same SHA; Clojars publication and Publish summary successful, Dry-run summary skipped |
| Published bytes | Both Clojars JAR/POM download and match the tag-run artifacts; independent JDK17/21 consumers pass on those downloaded bytes |
| Previous release | Clojars v1.3.0 remains downloadable; JAR SHA-256 remains 65a98348320ad905939e72fbf825b57111d704057698718863487edd22797a1b |
| GitHub Release | [v1.4.0](https://github.com/nantes-rfli/paclo/releases/tag/v1.4.0), published 2026-10-17T08:38:16Z (17:38 JST), neither draft nor prerelease; existing release tag used |

NVD last checked 2026-10-17T08:28:04Z, last modified 08:16:28Z;
Dependency-Check 12.1.6. OSS Index was disabled without credentials; NVD CVE
analysis completed. This does not clear every development/build-only dependency.
No new major release blocker was detected within these checks.

### Artifact identities

Every build was inspected independently; previous hash equality was never assumed.

| Actual build | JAR SHA-256 |
| --- | --- |
| Final main CI | `379b8ab805dcfbb9eec517949ae5c013059e058956465fd83b9b5d231dfb6928` |
| Final Publish dry-run | `ed8e4f4a2686d1b09574c3d99f8a35d573a0afc4414bbfe1adca71018450bf57` |
| Tag Publish and actual Clojars download | `fe70ac9005edfea4d48fee30c69383ce3dd814e0e56c8b432d573193fc26eb2e` |

Embedded/external/deployed POM SHA-256:
`91a5f668b7e9daf06735f09a10efe9dba9daec8946704cc7ce696456d2338d56`.
All ten packaged classes are exactly major 61. Coordinates/properties are
org.clojars.nanto/paclo:1.4.0; five direct dependencies, MIT license and SCM
URL/connections/tag v1.4.0 match. Provenance records the clean release SHA and
actual JDK21 build JVM. Existing inspectors check exact production inventory
and source bytes. Consumers use independent temporary projects with -Srepro,
verify JAR resource/binding origins and cover real six-DLT Classic/PCAPNG I/O,
Flow/DNS/window/annotations and resource lifecycle probes without rebuilding.

Durable evidence: [publication summary](release-1.4.0-evidence/publication-summary.json),
[final dry-run provenance](release-1.4.0-evidence/final-dry-run-provenance.json),
[tag-build provenance](release-1.4.0-evidence/release-provenance.json),
[dry-run JDK17](release-1.4.0-evidence/final-dry-run-consumer-jdk17.json) /
[JDK21](release-1.4.0-evidence/final-dry-run-consumer-jdk21.json),
[published JDK17](release-1.4.0-evidence/published-consumer-jdk17.json) /
[JDK21](release-1.4.0-evidence/published-consumer-jdk21.json), and
[audit summary](release-1.4.0-evidence/release-audit-summary.json).
The README Maven coordinate also resolved from Clojars in a separate -Srepro
JDK17 consumer, loaded core/flow/pcapng and read four native offline packets;
its resolved JAR hash equals the deployed artifact
([Maven consumer](release-1.4.0-evidence/published-maven-consumer.json)).
Actual distribution:
[Clojars version](https://clojars.org/org.clojars.nanto/paclo/versions/1.4.0),
[JAR](https://repo.clojars.org/org/clojars/nanto/paclo/1.4.0/paclo-1.4.0.jar),
[POM](https://repo.clojars.org/org/clojars/nanto/paclo/1.4.0/paclo-1.4.0.pom).

### cljdoc and post-publication documentation

The [initial cljdoc build 117558](https://cljdoc.org/builds/117558) succeeded and
imported 18 namespaces from the published JAR. The versioned docs/API are
available at [cljdoc 1.4.0](https://cljdoc.org/d/org.clojars.nanto/paclo/1.4.0).
All nine supported API/annotation pages returned HTTP 200 and display expected
public vars; [API verification](release-1.4.0-evidence/cljdoc-api-verification.json)
retains the checked URLs. Initial articles came from the release tag and retain its pre-publication README
wording. The post-publication docs PR updates current installation/availability,
API/PCAPNG/roadmap/release notes and records actual evidence without changing code,
dependencies, APIs or budgets.

After that PR passes normal CI/review and merges, use cljdoc's documented
`cljdoc-1.4.0` article-override tag at that docs commit, then rebuild and verify
articles/API. This docs-only tag is outside Publish's v* trigger; it does not
change the release tag, API JAR or deployed artifacts. See the
[official article override procedure](https://github.com/cljdoc/cljdoc/blob/master/doc/userguide/for-library-authors.adoc#overriding-cljdoc-config--articles).
The docs PR description records its final head/CI/review/merge and later docs-tag
SHA/build verification, avoiding another source commit just to record itself.

Issue #37 stays open/non-blocking. Reviewing Issue #44's actual acceptance and
PR #58's 944-pair evidence supports closure for the measured Ethernet investigation/
optimization scope, with JIT/thermal/retention and live/NIC limitations retained.
Issue-level acceptance remains separate; it is not closed by this release task.
No P09/P10 work, manual dry_run=false, alternate deployment, tag replacement or
repeated deploy was performed. Publication completed on the CHANGELOG's actual
Japan date, 2026-10-17.
