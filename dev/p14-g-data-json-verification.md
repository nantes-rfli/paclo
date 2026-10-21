# P14-G: data.json maintenance and adopted P14 scope closure

Selected on 2026-10-21 (Asia/Tokyo) from latest fetched main `ecf3f19`, the merge
of independently reviewed PR84. The checkout was clean. PR76 is still open and
unmerged; Issue77 is still open. This work changes neither item.

## Adoption decision and actual use

Adopt **data.json 2.5.0 -> 2.5.2**. At task start, the
[official README/history](https://github.com/clojure/data.json#change-log) and
[Maven Central metadata](https://repo.maven.apache.org/maven2/org/clojure/data.json/maven-metadata.xml)
both identify 2.5.2 as latest stable (released 2026-01-02). The versioned JAR
source diff contains the numeric-reader EOF fix from 2.5.1 and the 2.5.2
control-character diagnostic fix, plus comments/docstrings. Writer implementation
is unchanged. Parent/Clojure baseline updates do not change Paclo's selected
Clojure1.12.6. This is a small maintenance adoption with demonstrated fixes and
compatible output, not an urgent security update or a performance claim.

Paclo's production source does not call data.json directly. Existing usage is:

- `examples.common/emit`: packet statistics, flow Top-N, DNS RTT, TLS scan and
  packet-filter metadata JSONL. `examples.dns-qps`/`dns-topn` write JSONL directly.
- `paclo.dev.perf-merge/write-results!`: performance runner/standalone merger
  `results.json`; `dns-perf-summary`: comparison JSONL.
- Fixture manifest readers in tests and P16, and JSON runtime reports in the
  independent distribution consumer.

The root dependency, `dev/perf-merge/deps.edn` and exact distribution POM check
now agree on2.5.2. No Paclo public JSON-input API is introduced. Existing
v1 API keys, error strings, JSONL framing and performance report schema remain.
The numeric-EOF fix is defensive dependency maintenance; current Paclo call sites
mostly read whole strings, so it is not described as a previously observed
production Paclo failure.

## Compatibility and regression evidence

Seven regression tests cover273 assertions: Long extrema/BigInt/Double/BigDecimal,
null/boolean/nested values, Unicode including supplementary characters, escaping,
all32 writer control characters, Reader/Writer parity, repeated numeric EOF,
empty/truncated/malformed inputs, control diagnostics, exact JSONL bytes and
EDN/JSON performance values. The old-version negative control deliberately fails:
174 failures and6 errors; new2.5.2 passes. These failures are confined to the
corrected control-character and repeated numeric EOF cases.

The reproducible `paclo.dev.json-compat` probe runs in separate old/new JVMs on
real offline PCAPs and fixed report data. [Comparison evidence](p14-g-evidence/compatibility.json)
records hashes and actual old/new diagnostic values:

| Comparison | Result |
| --- | --- |
|13 representative JSON writes and read values/classes|Identical|
|PCAP stats, flow Top-N, DNS QPS, RTT stats/pairs/qstats, DNS Top-N, TLS scan|Identical JSONL bytes|
|Common emitter with Unicode, newline, quote and backslash|Identical bytes|
|Fixed performance report, including nil/keyword/integer/Double values|Identical bytes|
|10 empty/truncated/malformed input outcomes|Identical classes/messages|
|5 numbers ending at EOF in caller-owned PushbackReader|Old next read throws on U+FFFF; new returns requested EOF sentinel|
|29 non-whitespace controls outside strings|Old EOFException; new Exception identifying actual character|

The controls test also exercises array/object value contexts. Reader buffer size
is64 as required upstream; ownership stays with `with-open`. Numeric comparison
uses exact integer/decimal values, with default decimals remaining Double and
`:bigdec true` remaining BigDecimal. Keyword values become strings as before.
Neither JSON object order nor Clojure-specific types gain a new public guarantee.

Limits retained from upstream: default reading consumes one value, so trailing
JSON is not automatically rejected. Invalid escape `\\q` and incomplete exponent
`1e` retain their existing `IllegalArgumentException` messages. A raw control
inside a quoted string is still accepted by the upstream reader (the comparison
records U+0000); the update does not claim strict validation of arbitrary JSON.
Writers escape controls. Paclo does not expose these as new input contracts or
change upstream parsing in this maintenance PR.

## Production graph, POM, distribution and audit scope

[Before](p14-g-evidence/production-before-tree.txt)/[after](p14-g-evidence/production-after-tree.txt)
production resolution has23 JARs in both cases. Exactly one JAR changes:
data.json2.5.0 ->2.5.2; the other22 hashes are identical. The
[dependency evidence](p14-g-evidence/dependencies.json) records every hash.
No new integration or audit-tool dependency enters production.

The existing isolated audit runner resolves the updated default production
classpath with `-Srepro`, excludes source directories and preserves the separate
nvd-clojure5.3.0/Dependency-Check12.2.2 scanner graph. Local run is explicitly
**resolved-only**, not a new vulnerability-audit pass. P14-D's earlier full
cold/warm scans are historical evidence for their old hashes; they do not cover
the new data.json JAR. Weekly/manual forced-refresh audit remains unchanged and
will select the new root dependency after merge. No CVSS/freshness/error gate or
suppression changes. Optional CSV, tests/build/tools and native OS advisories
remain outside that production-only audit scope.

Distribution validation inspects embedded/external POM agreement, exact source/
class inventory, Java17 bytecode,1.5.0-SNAPSHOT/SCM identity and selected runtime
graph. Independent consumers assert actual data.json2.5.2 from its JAR metadata,
Unicode/numeric/null round trip and numeric EOF, in addition to existing native/
PCAP/PCAPNG/DNS/lifecycle checks. The same JDK21-produced JAR is used by CI's
17/21/25 default and25 debug/Unsafe-denial consumers.

## Verification

Local platform: macOS x86_64, Temurin21.0.12.1+1, OS libpcap1.10.1.
Initial doctor used installed CLI1.12.5.1654 and passed; all subsequent checks
select the existing checksum-verified reference CLI1.12.5.1664 from
`/private/tmp/paclo-cli-1.12.5.1664/bin`. Only JDK21 is installed locally.

- Doctor/prepare pass; full check passes13 JUnit and501 Clojure tests /
  19,410 assertions with zero failures/errors and offline smoke success.
- JSON regressions pass7 tests/273 assertions. First test authoring attempt
  incorrectly expected a generic JSON-error prefix for invalid escapes; corrected
  to the observed unchanged upstream class/message, then reran successfully.
- Distribution negative controls, audit validation controls and doc-parser tests
  pass (15/19/16 tests respectively). Audit resolution passes as resolved-only.
- SpotBugs retains its one intentional native-pointer exposure finding with no
  analysis error; CheckStyle passes; JaCoCo59/73 lines (80.8%) passes25% gate.
- Full static checks,40 executable docs, P16, performance gate and distribution
  execution: final results recorded below after completion.
- Remote full16-job CI, native platforms and same-JAR17/21/25: pending PR execution.

Logs and original local outputs are under `/tmp/paclo-p14g`. Initial kondo rejects
three unused-value patterns in new exception tests; corrected without suppression.
Formatted only the new probe/tests; full lint rerun. Packaging is sequenced after
all tasks using `target/classes`; performance is measured without competing checks.

Reproduction (reference CLI selected, fresh output directories):

```bash
bash dev/script/codex.sh doctor
bash dev/script/codex.sh prepare
bash dev/script/codex.sh test -n paclo.json-test
clojure -Sdeps '{:deps {org.clojure/data.json {:mvn/version "2.5.0"}}}' -M:dev:dns-ext -m paclo.dev.json-compat /tmp/paclo-json-old
clojure -M:dev:dns-ext -m paclo.dev.json-compat /tmp/paclo-json-new
bash dev/script/codex.sh check
bash dev/script/codex.sh lint
python3 dev/script/verify_doc_examples.py
python3 dev/script/verify_interop.py /tmp/paclo-json-interop
clojure -T:build spotbugs
clojure -T:build checkstyle
clojure -T:build jacoco
JACOCO_MIN_LINE=0.25 clojure -T:build jacoco-gate
python3 -B -m unittest discover -s dev/script -p 'test_verify_distribution.py'
python3 -B -m unittest discover -s dev/script -p 'test_dependency_audit.py'
python3 -B -m unittest discover -s dev/script -p 'test_verify_doc_examples.py'
python3 dev/script/dependency_audit.py /tmp/paclo-json-audit --resolve-only
bash dev/script/codex.sh perf
bash dev/script/codex.sh package
python3 dev/script/verify_distribution.py prepare target/paclo-1.5.0-SNAPSHOT.jar /tmp/paclo-json-distribution
python3 dev/script/verify_distribution.py consume /tmp/paclo-json-distribution --report /tmp/paclo-json-consumer21.json
```

## P14 completion and explicit deferrals

P14's **adopted maintenance scope A/C/D/E/F/G is complete**, subject to independent
review of G before merge. A/C/D/E/F are independently reviewed and merged through
PR75/80/82/83/84 respectively; their existing reports retain detailed evidence.
This is one G implementation PR containing adoption, verification and scope closure.
No investigation-only or later completion-only PR is needed.

**Independent unresolved hold:** core.async PR76 remains unmerged, Issue77 remains
open and1.6.681 stays selected. The documented fan-out regression is neither fixed
nor accepted by this closure. Do not infer their completion from P14's scoped status.

- Defer data.csv/test.check until a concrete need is demonstrated.
- Reevaluate deps-deploy only when release procedures require an update.
- CheckStyle/JUnit major migrations are outside this scope.
- Keep Eastwood1.4.3/Cloverage1.2.4.
- P17 stays blocked pending Clojure1.13 maturity and a clear adoption reason.
  P09/P10 remain blocked by their existing prerequisites.

No further implementation PR is selected merely to exhaust update candidates.
Clojure1.12.6, JNR-FFI2.3.3, core.async1.6.681, formal JDK17/21 support,
experimental JDK25, Java17 target,1.5.0-SNAPSHOT and all quality/performance
thresholds remain fixed. No release/tag/publication, PR76/Issue77 mutation,
P17/P09/P10 implementation or merge. Offline evidence does not validate live
capture, real-NIC performance, untested platforms or all-platform JDK25 support.
