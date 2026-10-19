# P14-D: Dependency audit update and reliability

Started 2026-10-19 (Asia/Tokyo) from latest main `0047ac5`, after PR80 and PR78.
Implementation and execution verification are in progress; independent review
is required before merge. P14 overall stays in-progress; PR76/Issue77 remain
unchanged. No production dependency/API/release version changes.

## Tool identity and scope

The [official 5.3.0 guidance](https://github.com/rm-hull/nvd-clojure#clojure-cli)
recommends a separate helper project. `dev/audit/deps.edn` contains only
nvd-clojure 5.3.0 and no source roots. The root `:nvd` alias is removed.
Both processes use `-Srepro`, avoiding user deps and classpath interference.
The root default graph supplies only production JARs to the helper. This preserves
the previous intended target; no optional/dev/build/tool audit is added.

Actual local resolution: **23 production JARs**, **82 tool JARs**. Shared
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

Database storage/cache is explicit, versioned for engine 12.2.0. Each workflow
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

The time limit was too short for the measured cold import. The scanner now gets
120 minutes, other commands 10 minutes and the job 135 minutes. Each command emits
its stage and persists incomplete evidence before launch. Both engines' published
properties use directory schema 11.0 and data.version 5.5. If the new database cache
is absent, the workflow can copy the old 12.1.6 database from the existing Maven
cache (preserving its source), then perform a forced NVD refresh and the same
strict verification. It never treats a copied database as a clean result.
`--refresh` uses validity 0 and additionally requires Last Checked within this
execution; weekly/manual CI always uses it. Default local cached mode retains 24h.

Initial implementation and logged-error follow-up pass all 16 jobs in
[CI39273699992](https://github.com/nantes-rfli/paclo/actions/runs/39273699992) and
[CI39275334254](https://github.com/nantes-rfli/paclo/actions/runs/39275334254),
including all three P16 platforms and same-JAR17/21/25 consumers. See
[CI evidence](p14-d-ci-evidence.json).

The improved implementation is378d289 in [draft PR82](https://github.com/nantes-rfli/paclo/pull/82).
[Forced-refresh recovery39281069841](https://github.com/nantes-rfli/paclo/actions/runs/39281069841)
and [implementation CI39281076913](https://github.com/nantes-rfli/paclo/actions/runs/39281076913)
remained queued at the verification handoff (2026-10-20 JST); no jobs had started.
A documentation follow-up runs normal CI as well; its status is recorded on PR82.
The GitHub API intermittently returned502 during observation; no broader service
outage is inferred. The old run's displayed workflow status lagged its recovered
scanner timeout evidence, so the original summary/logs are the outcome authority.

Final NVD vulnerability results, accepted database check/update timestamps,
legacy-cache migration, warm-cache replay and final-head CI are **unverified**.
No security pass, zero findings, complete cold import or completed cache refresh
is claimed. Draft status and P14-D in-progress are retained for that reason.
The actual local --refresh command compiled/ran the updated launcher, wrote
validity0 and exited1 for the absent token;18 regressions and targeted kondo
(error0/warning0) pass. All105 selected JAR versions/hashes match between local
and Actions inventories. These checks do not replace the queued real audit.

## Remaining boundaries

No audit establishes absence of all vulnerabilities: source coverage and CPE
matching remain limited. Optional CSV, development/test/build tools and the
scanner itself have inventories only where explicitly recorded, not an NVD
clearance. Historical release audit 23/zero findings with engine 12.1.6 does not
clear current main. Preserve original reports and triage any findings by selected
dependency path/severity/scope rather than updating unrelated libraries or
loosening gates. Live capture, other platforms and throughput are unvalidated
by the offline audit.
