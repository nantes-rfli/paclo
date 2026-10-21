# P14-D: Dependency audit update and reliability

Started 2026-10-19 (Asia/Tokyo) from latest main `0047ac5`, after PR80 and PR78.
Implementation and execution verification are complete, including the PR82
review correction; independent review is required before merge. P14 overall stays in-progress; PR76/Issue77 remain
unchanged. No production dependency/API/release version changes.

## Tool identity and scope

The [official 5.3.0 guidance](https://github.com/rm-hull/nvd-clojure#clojure-cli)
recommends a separate helper project. `dev/audit/deps.edn` contains
nvd-clojure 5.3.0, the review correction's explicit Dependency-Check12.2.2 pin,
and no source roots. The root `:nvd` alias is removed.
Both processes use `-Srepro`, avoiding user deps and classpath interference.
The root default graph supplies only production JARs to the helper. This preserves
the previous intended target; no optional/dev/build/tool audit is added.

Initial local resolution before review: **23 production JARs**, **82 tool JARs**. Shared
libraries legitimately appear in both independent inventories; the entire tool
classpath is never supplied as scan input. The tool resolves Clojure 1.12.5 (the CLI system default wins over its declared
1.12.4) and data.json2.5.2 independently of production1.12.6/2.5.0. Actual loaded versions
from `nvd.task.check/version`: nvd-clojure 5.3.0, Dependency-Check12.2.0.
Tool transitive versions include H2 2.4.240, Jackson 2.20.1, Lucene 9.12.3,
commons-compress 1.27.1 and open-vulnerability-clients 9.0.2; full selected versions
and dependency paths are saved in `tool-tree.log` and `tool-jars.json`.
Production retains core.async 1.6.681, JNR 2.3.3/jffi 1.4.3/ASM 9.10.1,
Clojure 1.12.6 and all other root pins. tools.build 0.10.14, CLI 1.12.5.1664 and
1.5.0-SNAPSHOT are unchanged.

Each execution records production/tool classpaths, trees and JAR SHA256 hashes,
source identity/dirty state, CLI/JVM, commands/exits and actual loaded versions.
The final runner passes only absolute JAR paths (`scanner-input-classpath.log`),
so relative source folders cannot be reinterpreted in the helper working directory.
Reports must cover every production hash, including merged related-dependency
entries. Unexpected physical JARs fail verification. Source/class directories
remain unscanned, as in the old nvd regular-file scan. The pinned tool can scan
non-JAR files, but none are added to this target. OS libpcap, live capture and
native platform advisories are outside this Maven/CPE scan.

## Reliability corrections

Inspection of the published 5.3.0 JAR's `nvd/config.clj` and `nvd/report.clj`
identified two issues with relying on the previous configuration/tool alone:

- EDN is wrapped in `:nvd` by the tool. The repository's previous `{:nvd {...}}`
  adds an extra layer, so threshold/output-format were ignored. Flat options now
  apply 7.0 and `"ALL"` (the API expects a string, not a keyword vector).
- Upstream computes maxima of impact/exploitability components, prefers v2 over
  v3, coerces to longs and compares strictly `>`; it does not implement the
  required CVSS base score >=7.0. The independent JSON verifier checks all available
  v2/v3/v4 base scores without truncation, including exactly 7.0. Unscored/invalid
  findings fail for triage. Any upstream nonzero status also remains fatal.

No suppression rule is introduced. The policy wrapper refuses nested options,
changed threshold/output/update/freshness settings or a suppression file.
The old `NVD_CVE_CHECK_VALID_FOR_HOURS=168` environment variable is not read by
this published config parser. Replace it with explicit `:nvd-api
{:valid-for-hours 24}` and `:auto-update true`. The report must record Last Checked
within 24 hours and Last Modified within 7 days, with 5-minute clock tolerance;
the report timestamp must belong to this execution. Missing metadata fails.

Database storage/cache is explicit, versioned for the selected engine (now12.2.2). Each workflow
run saves a new cache snapshot and restores the latest compatible snapshot.
A cache hit or file mtime cannot pass verification. Evidence is uploaded with
`if: always()` and includes failures, inventory and original reports. Existing
Monday 03:00 UTC/manual triggers and all 16 CI jobs remain.

nvd-clojure rethrows Dependency-Check analysis/update exception collections.
Logged ERROR and known remote/update/analysis failure warnings also fail verification,
even if a scanner returns zero with otherwise valid cached reports.
The runner retains nonzero exits, rejects report exceptions, and refuses an
existing output folder, preventing old/partial report success. No report after
fetch/auth/analysis failure means incomplete, never zero vulnerabilities.
OSS Index credentials/status are recorded separately; unavailable credentials
leave it disabled, without claiming that NVD covers its advisories. No external
service is disabled to hide findings.

## Reproduction and execution evidence

Use CLI 1.12.5.1664 and JDK 21. From the repository root:

```bash
python3 -B -m unittest discover -s dev/script -p 'test_dependency_audit.py'
python3 dev/script/dependency_audit.py /tmp/paclo-audit-production
```

`NVD_API_TOKEN` is required; inject it through the environment. Use a new output
folder on every attempt. NVD data evolves; later runs can legitimately differ.
JAR/report hashes, source identities and data timestamps identify each result.
`--resolve-only` is a separately labelled resolution
check. `--data-directory` chooses a persistent engine-specific cache. See
[developer instructions](../CONTRIBUTING.md#dependency-security-audit).

Local macOS x64/JDK 21.0.12.1/CLI 1.12.5.1664 execution completed both independent
resolutions, inventories, config generation and actual tool-version reporting.
It exited 1 at `No NVD API key supplied as config settings or env var.` because
no local token exists. Summary status is **incomplete**; no NVD data or report
was created, and no clean local audit is claimed. Local evidence is retained
in `/tmp/paclo-p14d-local` (not a portable/committed artifact).

The 18 offline regressions pass: resolution/process nonzero, missing/malformed
report, error collection, timestamps, coverage/contamination, suppressions,
score validity, v2/v3/v4 and 6.9/7.0/7.1, resolve-only and stale-output refusal.
Regression tests run in both ordinary CI and the audit workflow.
Remote cold attempt [39273706099](https://github.com/nantes-rfli/paclo/actions/runs/39273706099)
resolved both graphs and loaded 5.3.0/12.2.0, then retrieved 250,000/410,078 NVD
records (61%) before the initial 45-minute scanner limit. No auth/communication
error was logged. It is **incomplete**, not a clean audit: no vulnerability report
or accepted Last Checked/Last Modified metadata exists. Original logs/inputs are
retained in the uploaded artifact; [audit evidence](p14-d-audit-evidence.json)
commits exact production/tool JAR versions and hashes and the partial-run status.

The initial time budget was too short. Two120-minute attempts also failed:
[39281069841](https://github.com/nantes-rfli/paclo/actions/runs/39281069841) reached
170,000/410,157 records (41%) and
[39352651707](https://github.com/nantes-rfli/paclo/actions/runs/39352651707) reached
240,000/410,449 (58%), both with NVD HTTP503 retries. No completed dependency
analysis, report or accepted NVD database timestamps exist for these attempts.
The final scanner budget is300 minutes, with600s for other commands and the
existing default six-hour Actions ceiling. No failure/quality criterion changes.

An attempted legacy-cache migration was never exercised: restores missed. Both
engines declare directory schema11.0/data.version5.5, but this alone proves no
migration. Removing a redundant Maven-cache path changed GitHub's
[archive-version input](https://github.com/actions/cache#cache-version); restoring
the exact original path list still did not recover the listed old main cache.
Therefore path shape alone is not asserted as the cause of the persistent miss.
Keep the original Maven path list and fallback keys, but remove the unverified
old-database copying. Only a completed import for the selected engine is cached for subsequent
runs. A missing snapshot performs full import; no partial data is certified.

Each command emits its stage and persists incomplete evidence before launch.
`--refresh` uses validity0 and requires Last Checked within this execution;
weekly/manual CI always uses it. Default local cached mode retains24h. No503,
incomplete import or cache hit is treated as clean, and no analyzer, threshold,
suppression or target is changed to obtain a passing result.

Before review, functional implementation `5f5748a` passes all 16 jobs in
[CI 39413198962](https://github.com/nantes-rfli/paclo/actions/runs/39413198962),
with no failed steps. Downloaded artifacts confirm five same-JAR consumers
(JDK 17/21/25 plus both JDK25 diagnostic modes), SHA256
`ef1dac7808e59f9ac28959c05c6bd1da89d944ecdc8381ce2b09c9b5fda0ef96`.
All three P16 platforms pass 5 tests / 377 assertions. Exact source identities,
job IDs, consumer reports and platform evidence are in
[CI evidence](p14-d-ci-evidence.json). Earlier implementation revisions also
passed all 16 jobs. The local updated launcher writes validity 0 and exits 1
for the absent token; 18 regressions and targeted kondo (0 errors/warnings)
pass. All 105 JAR versions/hashes match across local and three Actions attempts.
These checks do not replace actual vulnerability analysis.

The 300-minute-budget attempt
[39413194592](https://github.com/nantes-rfli/paclo/actions/runs/39413194592)
**finished with failure**, running 11:11:44Z–13:46:13Z on 2026-10-20. Scanner exit0
and a fresh report covering23 JARs with zero findings did not clear the audit:
`NvdApiProcessor` logged failed imports for CVE-2026-6785/6786. Their Mozilla
reference URLs (1585/1115 characters) exceeded H2's `VARCHAR(1000)` column.
The wrapper correctly returned exit1/status `incomplete` / `Scanner logged an error`.
The DB cache save was skipped. Original
[artifact12268562962](https://github.com/nantes-rfli/paclo/actions/runs/39413194592/artifacts/12268562962)
and compact evidence retain the invalid report and errors; zero findings is not
security clearance. The review correctly blocks merge.

## PR82 review correction: upstream long-URL import fix

[Upstream issue8466](https://github.com/dependency-check/DependencyCheck/issues/8466)
identifies these exact CVEs and lengths.
[Fix8467](https://github.com/dependency-check/DependencyCheck/pull/8467), shipped in
[12.2.2](https://github.com/dependency-check/DependencyCheck/releases/tag/v12.2.2),
widens reference URLs to8000 characters and bumps the DB schema from5.5 to5.6.
Pin `org.owasp/dependency-check-core`12.2.2 explicitly in the isolated helper,
keeping nvd-clojure5.3.0. Its matching utils12.2.2 and transitive changes resolve
only in the tool graph (now79 JARs); all23 production JAR versions/hashes match
the failed run. H2 remains2.4.240. Actual loaded versions confirm5.3.0/12.2.2.
Use a fresh `12.2.2` data/cache namespace, with no restore from12.2.0 or manual
schema patch. All existing score, freshness, coverage and failure gates remain.

Local offline verification:19 Python regressions pass, including both exact
NVD import error signatures with exit0/zero findings rejected. The resolved
engine's actual H2 initialization SQL preserves1115-,1585- and8000-character
synthetic URLs byte-for-byte (`dev/audit/verify_schema.clj`); the audit workflow
runs this regression before scanning. Local actual `--refresh` still exits1/
incomplete for the absent NVD token; it is not an audit pass. The successful
remote cold import and forced-refresh warm replay below supply the actual audit
evidence.
Review-correction head `4cb62dc` passes all16 jobs in
[CI39444140068](https://github.com/nantes-rfli/paclo/actions/runs/39444140068)
(attempt2). The UDP shard initially failed before measurements because CLI
installation returned HTTP500 on all retries; the unchanged rerun passed.
Downloaded artifacts verify five successful same-JAR consumers, SHA256
`02c40a9f3d96d87c02303e39d0d666db2e65eeb07fd5f631d3db060804d8b583`, and
three P16 platforms with5 tests/377 assertions each. Compact exact evidence is
in `p14-d-ci-evidence.json`. Local full check passes13 JUnit and493 Clojure tests /
19,130 assertions plus smoke. Kondo, full116-namespace Eastwood traversal
(zero exceptions), clean-ns, corrected format and Markdown/link checks pass.
Initial CI found namespace/layout issues in the new probe; `4cb62dc` corrected
it to a namespace-free standalone script, preserving the default graph.

## Completed real NVD verification (2026-10-21 Asia/Tokyo)

Both replacement audits pass with nvd-clojure 5.3.0 / Dependency-Check 12.2.2,
scanner exit 0, all 23 production JAR hashes covered, zero findings and no NVD
import or analysis errors. All 79 tool JAR versions/hashes match local resolution;
production versions/hashes match the failed run. OSS Index remains separately
disabled without credentials; these results cover the production NVD/CPE scan.

| Check | Cold import | Forced-refresh warm replay |
| --- | --- | --- |
| Run | [39442903205](https://github.com/nantes-rfli/paclo/actions/runs/39442903205) | [39457673751](https://github.com/nantes-rfli/paclo/actions/runs/39457673751) |
| Scanner source | `88a4cc0` | `4cb62dc` (same scanner, dependency and policy code) |
| Execution, UTC 2026-10-20 | 14:50:43–16:26:35 | 16:28:17–16:28:40 |
| NVD Last Checked | 16:26:27Z | 16:28:27Z |
| NVD Last Modified | 16:17:19Z | 16:26:06Z |
| Cache before | Empty; downloaded 410,693/410,693 records | Restored the cold run's DB (250,671,104 bytes) |
| Production coverage / findings | 23 / 0 | 23 / 0 |
| Effective update validity | 0 hours (`--refresh`) | 0 hours (`--refresh`) |
| Original reports | [artifact12280863020](https://github.com/nantes-rfli/paclo/actions/runs/39442903205/artifacts/12280863020) | [artifact12280688184](https://github.com/nantes-rfli/paclo/actions/runs/39457673751/artifacts/12280688184) |

The cold run saved `nvd-data-12.2.2-Linux-39442903205-1`, cache ID 9228378913,
121,149,390 compressed bytes. The warm job log explicitly confirms restoration
from that exact key, not a miss; the runner records the existing `odc.mv.db`.
The warm Last Checked belongs to its own execution, and its dataset watermark
advanced. The warm run also saved `nvd-data-12.2.2-Linux-39457673751-1`.
Cache keys, report/log SHA256 hashes and original summary metadata are retained
in `p14-d-audit-evidence.json`. Independent local revalidation of both downloaded
reports and logs passes with the unchanged coverage/freshness/score/error gates.
No CVE, analyzer, threshold or failure check was suppressed to obtain these results.

The review's import fix, clean real audit, compatible-cache save and forced-refresh
replay requirements are verified. P14-D remains in-progress only for independent
review/merge; PR82 remains Draft for that review. No merge or publication is
performed by this correction.

## Remaining boundaries

No audit establishes absence of all vulnerabilities: source coverage and CPE
matching remain limited. Optional CSV, development/test/build tools and the
scanner itself have inventories only where explicitly recorded, not an NVD
clearance. Historical release audit 23/zero findings with engine 12.1.6 does not
clear current main. Preserve original reports and triage any findings by selected
dependency path/severity/scope rather than updating unrelated libraries or
loosening gates. Live capture, other platforms and throughput are unvalidated
by the offline audit.
