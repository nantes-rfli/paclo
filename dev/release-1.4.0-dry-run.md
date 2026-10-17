<!-- markdownlint-disable MD013 -->
# v1.4.0 Publish dry-run verification

Status: **passed; unpublished**, 2026-10-17 (Asia/Tokyo).
Candidate source: `dfc5c5b4dbe39859b06431fa9c4b12714b89498d`.
Formal publication still requires separate maintainer authorization.

## Preconditions and authorized dispatch

- [PR #62](https://github.com/nantes-rfli/paclo/pull/62) merged into main at the
  candidate SHA on 2026-10-17. GitHub has no submitted reviews/comments; the
  maintainer explicitly confirmed completed independent review outside GitHub
  in this task before Publish was dispatched.
- [Latest main CI](https://github.com/nantes-rfli/paclo/actions/runs/39012456023)
  passed all 14 jobs at this exact SHA, including Linux ARM64 and both
  distribution consumers. These CI artifacts are separate from the Publish JAR.
- Clojars API returned latest_version/latest_release `1.3.0` before and after
  the dry-run; v1.4.0 is absent. No v1.4.0 tag or GitHub Release exists.
- Main retains `## [1.4.0] (unreleased)` in CHANGELOG. The release checklist,
  Publish workflow and distribution verifier match the checked-out candidate.
- Local `bash dev/script/codex.sh doctor` passed on macOS x86_64/JDK 21,
  Clojure 1.12.1, real offline libpcap input (4 packets / 438 bytes).

The only Publish dispatch was:

```bash
gh workflow run publish.yml --repo nantes-rfli/paclo --ref main -f version=1.4.0 -f dry_run=true
```

[Publish run 39013121398](https://github.com/nantes-rfli/paclo/actions/runs/39013121398)
completed successfully at 16:19 JST. Its event is workflow_dispatch, branch main,
and head SHA is the candidate above. Main was checked immediately before
dispatch and after completion; it stayed at that SHA. The workflow's source
guard fetched origin/main and successfully required dispatch SHA equality.
Logs explicitly record `PACLO_DRY_RUN: true` and version 1.4.0.

## Publish and artifact inspection

| Step | Result |
| --- | --- |
| Verify release source and metadata | success; four metadata regression tests |
| Run release gates | success; 490 Clojure tests / 19042 assertions, zero failures/errors; performance 335.2 ms, unchanged 1000/1200 ms budgets |
| Build release artifact | success; explicit PACLO_VERSION=1.4.0, JDK 21 |
| Verify release JAR compatibility, contents and identity | success |
| Upload release candidate | success |
| Publish to Clojars | skipped |
| Publish summary | skipped |
| Dry-run summary | success: Validated v1.4.0 without publishing |

The downloaded [paclo-1.4.0 artifact](https://github.com/nantes-rfli/paclo/actions/runs/39013121398/artifacts/12094105818)
contains the actual JAR, external POM and original provenance. The artifact ZIP
SHA-256 was independently checked against GitHub's recorded digest:
`225bc2fb47e337d41c645fa9c79a47dc85542b94a2459926d012ac772ef35e0e`.

| File | SHA-256 |
| --- | --- |
| paclo-1.4.0.jar | `d226794493dcd4a5840d2f04ead8068c02e47a8c6b9ac275ca9f5adaacbddd10` |
| External and embedded pom.xml | `91a5f668b7e9daf06735f09a10efe9dba9daec8946704cc7ce696456d2338d56` |

The exact production inventory and source bytes match main; all ten classes
are exactly major 61 (no preview classes). Coordinates and pom.properties are
`org.clojars.nanto/paclo:1.4.0`. The five unchanged direct dependencies are
Clojure 1.12.1, core.async 1.6.681, jnr-ffi 2.2.14, data.json 2.5.0 and
spotbugs-annotations 4.8.6, with expected compile dependency semantics.
External and embedded POMs match byte-for-byte. MIT license, SCM URL
`https://github.com/nantes-rfli/paclo`, HTTPS connection, SSH developer connection
and intended SCM tag `v1.4.0` all match; this metadata creates no Git tag.

[Original Publish provenance](release-1.4.0-evidence/publish-provenance.json)
records the clean source SHA, build Temurin 21.0.12.1, class versions,
dependencies, JAR/POM hashes and consumer support-file hashes. See also the
[inspection](release-1.4.0-evidence/artifact-inspection.json) and
[step results](release-1.4.0-evidence/publish-result.json).

## Same-JAR independent consumers

The downloaded JAR was never rebuilt. `verify_distribution.py prepare` only
inspected/copied that JAR and candidate-source harness/fixtures. Every assembled
bundle file matched the original Publish provenance's SHA-256 manifest; the
original provenance was retained, including the actual GitHub build JVM.
Each `consume` created a separate temporary project outside the checkout,
used `clojure -Srepro`, verified library resources/classes came from paclo.jar,
and checked the JAR hash before and after execution.

| Runtime on macOS x86_64 | Result | Identity report |
| --- | --- | --- |
| Temurin 17.0.20.1+1 | passed, exit0 | [JDK 17](release-1.4.0-evidence/consumer-jdk17.json) |
| Temurin 21.0.12.1+1 | passed, exit0 | [JDK 21](release-1.4.0-evidence/consumer-jdk21.json) |

Both reports identify source `dfc5c5b` and the Publish JAR hash above. Each
consumer passed public namespace/native binding checks, six DLT Classic PCAP
round trips, exact semantic PCAPNG round trip, Flow/DNS/window analysis,
DNS/TLS annotations and managed/early-close lifecycle probes. JDK 17 was extracted
in temporary storage from an official Adoptium archive after checking its published
SHA-256 `c01975da12ed4235250ff891fe8bba73a9e73037d444b269c9d0922b5dbc8e0a`.
Neither a PR #62 CI JAR nor any prior local JAR hash was used as identity evidence.

## Dependency Audit

The authorized `gh workflow run dependency-audit.yml --repo nantes-rfli/paclo --ref main`
created [run 39013091814](https://github.com/nantes-rfli/paclo/actions/runs/39013091814)
at the same candidate SHA. It succeeded, uploaded reports, and scanned 23
default production-classpath dependencies with OWASP Dependency-Check 12.1.6:
**0 vulnerabilities, 0 suppressed vulnerabilities, severity NONE**.
NVD last checked: 2026-10-17T07:18:17Z; last modified: 07:16:50Z.
The report JSON hash and artifact identity are retained in the
[audit summary](release-1.4.0-evidence/dependency-audit-summary.json).

No dependency vulnerability was detected to block this release. Sonatype OSS
Index analysis was disabled because credentials are absent; NVD CVE analysis
completed. The audit does not cover every development/build-only dependency.
Actions emitted Node 20/setup-java-v4 deprecation and upcoming ubuntu-latest
image migration notices; these are non-blocking workflow maintenance findings,
not reported library CVEs. No dependency or workflow was changed.

## Publication decision and remaining work

The candidate passes this requested dry-run, same-JAR runtime verification and
current-SHA NVD audit. No new technical release blocker was found within these
checks. Formal publication may proceed only after separate authorization and
the real release-date/availability documentation changes required by the
checklist. Any resulting source commit needs its own complete CI and current-main
release validation; this evidence applies only to `dfc5c5b`.

No Clojars deployment, Git tag, GitHub Release, publishing dispatch, dependency
update or merge was performed. Issue #37/#44 follow-ups and documented live/NIC,
platform, opaque-PCAPNG and legacy lazy-abandonment limits remain as recorded
in the release checklist; offline success does not validate those environments.

## Subsequent publication

This report remains the historical dfc5c5b dry-run record, with its original
hashes and unpublished-at-the-time status. v1.4.0 was subsequently published on
2026-10-17 after fresh checks of a different release SHA; see the
[publication record](release-1.4.0-publication.md). Do not transfer this report's
JAR identity to the later deployed artifact.
