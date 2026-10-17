<!-- markdownlint-disable MD013 -->
# Next stable release: compatibility and version proposal

Status: **release policy approved; publication not authorized**, 2026-10-17 (Asia/Tokyo).
The maintainer's subsequent release-preparation request approves v1.4.0, retention
of D1 Writer metadata correctness/strict validation and D2 exact bounded DNS
aggregation/explicit failures, and inclusion of P01–P08 plus merged fixes.
P09/P10 are excluded. This settles the earlier decision queue for preparation;
it does not claim that every formerly accepted input behaves identically.
The completed [migration guide](../docs/migration-from-1.3.md) explains those effects.
[Current checklist](release-1.4.0-checklist.md) owns remaining acceptance and
publication steps. Issue closure is not authorized by that request.

The original proposal below is retained as dated evidence. Its pending-approval
language and old candidate paths describe the assessment before that approval.
Baseline: latest main `2f97ab25cc9e46550aa24be80d11ccc667dab2d3`, after
[PR #59](https://github.com/nantes-rfli/paclo/pull/59) and
[PR #60](https://github.com/nantes-rfli/paclo/pull/60) merged. All implementation
versions remain unchanged. This document proposes a decision; it does not assign a release.

## Recommendation and decision boundary

**Keep 1.4.0 as the first candidate, conditional on resolving the two contract
interpretations below. Do not approve an unconditional compatibility claim for
current main.** P01–P08 add public functionality, so 1.3.x is unsuitable.
The implementation has substantial observable changes, including on valid files.
Most restore intended capture/time/DNS meaning or add bounded analysis. Neither
function-name retention nor green tests establishes compatibility by itself.

[SemVer 2.0.0, rules 6–8](https://semver.org/spec/v2.0.0.html#spec-item-6)
distinguishes compatible fixes/additions from incompatible public changes.
Maintainer acceptance of a breaking change does **not** make it compatible.
If either disputed behavior is confirmed as a formally supported v1 guarantee,
current main needs **2.0.0**, or a separately reviewed compatibility restoration
before 1.4.0. Feature count and P06's old “v1.5” planning label do not decide this.

| Human decision | Evidence and proposed interpretation | Consequence |
| --- | --- | --- |
| D1: Writer maps carrying both old time and extra metadata | v1.3.0 explicitly accepts `{:bytes ... :sec ... :usec ...}`; it neither reserves `:ts-*`/`:caplen`/`:len`/`:linktype` nor documents precedence for extra keys. Main can override a valid old pair or reject a map with that pair. Treating every such map as invalid retroactively is unjustified. Prefer interpreting conflicting metadata as previously unspecified; approval is still pending. | If the legacy pair was guaranteed authoritative regardless of additional keys, propose a separate PR preserving the two-argument legacy path and making capture-preserving interpretation explicit. Do not silently change the current API here. Retaining that guarantee's break requires 2.0.0. |
| D2: Official CLI success/failure and group semantics | The v1.3.0 README labels CLI references stable; its migration guide fixes stdout/stderr and codes 1–4 and promises notice before deprecation/removal. It names `client`/`server`, but does not promise source/destination grouping, arbitrary-size success, or truncation at max-buckets. Prefer QR role correction and explicit bounded failure as fixes, while recognizing a valid large file can now fail. | Require owner review of CLI policy, high-cardinality behavior, max-buckets and new code 5. If old truncation/success or a closed exit-code set is a guarantee, propose a separate opt-in CLI policy/legacy adapter with advance deprecation, or select 2.0.0. A migration note alone cannot cure a guarantee break. |

No unequivocal removal of a documented library function/arity was found. D1/D2
remain **undecided**, rather than claiming that every observed difference is a
SemVer-compatible bug fix. Do not restore silent corruption, guessed DNS pairs,
or unbounded memory simply to keep benchmark/output parity. A compatibility
adapter must explicitly define valid legacy inputs, safety and loss reporting;
reject unsafe restoration and take the major-release path when necessary.

## Baseline and evidence hierarchy

Use the released tag's
[API contract](https://github.com/nantes-rfli/paclo/blob/v1.3.0/docs/cljdoc-api-contract.md),
[README](https://github.com/nantes-rfli/paclo/blob/v1.3.0/README.md),
[usage](https://github.com/nantes-rfli/paclo/blob/v1.3.0/docs/usage.md) and
[migration policy](https://github.com/nantes-rfli/paclo/blob/v1.3.0/docs/migration-0.4-to-1.0.md).
The versioned cljdoc [contract](https://cljdoc.org/d/org.clojars.nanto/paclo/1.3.0/doc/public-api-contract-v1-x-)
and [migration policy](https://cljdoc.org/d/org.clojars.nanto/paclo/1.3.0/doc/migration-guide-0-4-1-0)
were also checked; they retain these released promises.
Current [API contract](../docs/cljdoc-api-contract.md) owns current precise rules;
it cannot retroactively narrow a released guarantee. Historical sketches are
not API promises. The old freeze draft also records uncaught JVM exception
exits; therefore “codes 1–4” is not by itself proof that all other errors were forbidden.

The published Clojars JAR was freshly fetched from
[the versioned artifact](https://repo.clojars.org/org/clojars/nanto/paclo/1.3.0/paclo-1.3.0.jar).
SHA-256: `65a98348320ad905939e72fbf825b57111d704057698718863487edd22797a1b`.
It matches the local Maven cache; its nine binding classes are major 65.
The candidate is the actual JDK 21-built main CI artifact, not recompiled source.
See [comparison harness](release-compatibility/compare.py),
[shared library probe](paclo/dev/release_compatibility_probe.clj) and
[raw comparison](release-compatibility/comparison.json). Both run outside the
checkout under JDK 21 with `-Srepro`, a local JAR dependency and verified JAR
resource origins. CLI example files are extracted unchanged from each revision:
examples live in `dev/`, outside the distributed library JAR. They are explicitly
external consumer inputs, not evidence that example namespaces ship in Clojars.

Reproduce after package, substituting the actual candidate path:

```bash
python3 dev/release-compatibility/compare.py /tmp/paclo-published-1.3.0.jar target/paclo-1.3.0-SNAPSHOT.jar /tmp/compatibility.json
```

This is characterization, not a universal equivalence test. Output/errors and
exit status are retained; timed native/CLI metadata is not a stable snapshot.
The shared probe inspects written record headers directly so old invalid records
are not misreported as writer rejection by a later native read.

## v1.3.0 → current main assessment

Legend: **guaranteed** = released prose; **incidental** = implementation with no
corresponding promise; **bug** = violates intended data/operation meaning.
“Fix/addition” permits a minor only within the D1/D2 decisions above.

| Change | Released contract and observed implementation | Main behavior and evidence | Affected users / response | SemVer assessment |
| --- | --- | --- | --- | --- |
| Valid legacy Writer time | Guaranteed map form; complete integer `:sec/:usec` writes that time | Same for an otherwise plain map; probe `:legacy` | Ordinary generated Ethernet records need no edit | Compatible |
| Capture and dual-pair time | `:ts-*` precedence not specified; implementation ignores it and uses old pair or clock | Complete capture pair wins even over invalid legacy values; `:captured`/`:both` | Capture rewriters gain original time; intentional retiming must remove stale capture keys | Fix/addition; D1 unresolved for conflicting valid legacy maps |
| Partial time | Partial legacy uses clock; partial capture keys were ignored | Partial legacy still clock; partial capture throws even with complete valid legacy pair | Do not silently complete unknown capture time; supply both fields or deliberately select a complete legacy pair | Validation fix; D1 for formerly accepted annotated maps |
| Nil/fractional/out-of-range time | Numeric coercion or clock fallback incidental; no published promise of nil meaning absent or fractional microseconds | Selected complete pair must be integers, seconds uint32, usec 0..999999; zero valid | Validate at boundary; reject/quarantine malformed data, do not blanket catch and substitute now | Correctness fix; pre-epoch/overflow coercion was not a portable valid Classic output guarantee |
| Captured/original lengths | Released Writer has no metadata-preservation promise; implementation writes array length to both fields, ignoring map lengths | Explicit caplen must equal array length, len >= caplen; uint32 integers; preserves truncation | Round-trip users retain wire length; repair producers supplying stale/nil lengths | Fix/addition; D1 if ignored extra keys were promised |
| Snaplen/framing | Two-argument writes Ethernet/snaplen 65536; implementation could label cooked bytes Ethernet or emit caplen > snaplen | Same defaults; mismatch and caplen excess fail; arity 3 selects DLT/snaplen, never truncates/converts | Non-Ethernet and large-frame exporters specify accurate options; split mixed DLTs or use PCAPNG | Invalid-output fix plus minor API addition; D1 applies to metadata recognition |
| DLT detection/decode | Full decode success/error guaranteed, Ethernet assumption incidental on other DLTs | Raw maps add native `:linktype`; six DLTs decode; unsupported explicit/nil DLT yields `"unsupported linktype"`, no Ethernet fallback; absent standalone key keeps Ethernet default | Non-Ethernet users get truthful framing; raw mode retains unsupported packets | Additions and misdecode fix; no guarantee of valid Ethernet decoding of arbitrary framing |
| Native read failure | Errors may propagate; `:throw/:pass` documented; old native -1 could look like EOF | Error distinct from EOF; default throws, lazy wrapper may carry cause; pass retains prefix with callback/failed report | Corrupt/mixed-format pipelines must handle failure and inspect stats; prefix is not complete success | Clear bug fix, operational impact; no valid guarantee of silent corrupt EOF |
| Diagnostic keys | `:decode-error` and data-only schema-versioned stats promised; exact closed map schema not promised | Existing strings/schema 1 retained; `:diagnostics`, reasons/stages/location and native exception data added; extension reporting opt-in | Use key selection/open schemas; unknown diagnostics tolerated; separate source failures from decode issues | Compatible additions; whole-map comparisons must migrate |
| Flow CLI output | EDN/JSONL `:flow/:packets/:bytes` and captured-byte meaning; old ties depended on HashMap iteration | Same rows/meaning; canonical numeric ties/bidir endpoints, exact bounded counts, async source errors propagate; default max-flows 100000 | Ranking snapshots can reorder; set positive `--max-flows`; exhaustion throws/JVM nonzero, **not DNS code 5** | Analysis addition; arbitrary tie order incidental; finite success policy subject to D2 |
| DNS RTT computation | RTT command advertised, but native timestamps wrongly read as absent legacy fields; mean truncated fractional milliseconds | Exact native microseconds, proper mean then ms display; strict endpoint/version/ID/question matching, retries/quarantine/late diagnostics | Rebaseline RTT/alerts; fewer defensible pairs; don't recreate nil/guessed pairs | Clear time/mean bugs fixed; strict matching is correctness policy with visible impact |
| DNS QPS computation/group | Packet counts/captured bytes and group names advertised; source/destination role interpretation incidental | Still packet counts, not transactions or normalized rate; floor-aligned event time; QR-oriented client/server; deterministic ties; label-wise Punycode | Response groups change; divide counts by bucket seconds for rate; use raw/library projection for source/destination grouping | Role/time/fill fixes; D2 if old source/destination meaning was guaranteed |
| DNS report/output/bounds | Formats and positional invocation stable; max-buckets existed but silently truncated after retaining rows; QPS accidentally stopped at 100 packets/10s | Same EDN/JSONL/CSV data shapes; full offline EOF, complete bounded fill or failure; finite pending/retired/sample/qname/window/group/row bounds | Larger output/pair counts and code 5 possible; tune finite bounds/reorder horizon; no stdout on failed report; drop/cancel can exit 0 with incomplete stderr | Correctness/resource policy; valid-file success-to-error risk remains D2 |
| DNS exit/stdout | Shared codes 1 usage, 2 missing file, 3 enum, 4 flags; stdout data/stderr diagnostics | Codes 1–4 meanings retained; source/analysis/capacity exit 5, no result; incomplete delivered reports explicitly marked | Wrappers must handle all nonzero exits and inspect complete? even on zero | New error classification, not reassignment; D2 policy approval required |
| Existing public functions | Released core/stream/decode-ext function names and arities; internal namespaces excluded | All retained including packet-xf and variadic -main; apply! adds 2/3 and Writer adds 3; global registration remains default | Internal flow projection consumers migrate at own risk; generated opaque-handle constructors unsupported | Compatible additions; name/arity probe is only one part of this assessment |
| JDK 17/21 | README explicitly supports both; published JAR major 65 violates JDK 17 support | Shared release 17 compiler target; ten classes major 61; identical artifact consumers succeed on 17/21 | Java17 JAR users gain promised support; keep Clojure1.12.x/system libpcap | Support repair, no JDK baseline removal |

### Concrete consumer observations

The same four-packet real DNS fixture produces two RTT rows in both versions.
v1.3.0 rows omit RTT; main ranks measured **10.241 / 15.817 ms**, with
mean **13.029 ms** and `:with-rtt 2` instead of 0. QPS client
rows change from four source-address rows to two role-oriented rows for
`10.0.0.1`, each count 2 (260 / 178 captured bytes). Flow has the same four
rows/totals with changed tie order. Shifting only fixture record times into four
separate second buckets makes `--max-buckets 1` return one truncated row/exit 0
on v1.3.0, versus empty stdout/exit 5 on main. This last case demonstrates a
**valid-input success-to-failure change**, not just malformed-input rejection.
The new Flow bound is rejected as an unknown flag/exit 4 on v1.3.0; main accepts
the flag and reports actual exhaustion/exit 1. Old native truncated-header input
reports zero packets/EOF; main throws `pcap-read-failed`, rc -1. Full short-frame
error text is retained and gains structured location data.

Source anchors for review: released/current Writer normalization in
[`pcap.clj` at v1.3.0](https://github.com/nantes-rfli/paclo/blob/v1.3.0/src/paclo/pcap.clj)
and [current source](../src/paclo/pcap.clj),
[round-trip/writer regressions](../test/paclo/pcap_roundtrip_test.clj),
[Flow CLI regressions](../test/examples/flow_topn_test.clj),
[DNS CLI regressions](../test/examples/dns_cli_test.clj), and the
[recorded P07-B before/after policy](p07-b-design.md). The design is change
history, not a substitute for released promises.

## CI and distribution identity

Verified live GitHub data and downloaded artifacts for main
[CI 38996721327](https://github.com/nantes-rfli/paclo/actions/runs/38996721327):
**14/14 jobs successful**, commit `2f97ab2`, clean tracked source, build Temurin
21.0.12.1. Candidate SHA-256:

```text
8f153f45daa9a4e00176923bb3c75169ecac64157f0272f03436a5bd9a1812e8
```

Both checkout-free Linux consumers report this exact digest and source commit:
Temurin **17.0.20.1** and **21.0.12.1**, status passed. Local hashing of the
downloaded JAR agrees; provenance lists every class at major 61. PR #60's final
[CI 38993735942](https://github.com/nantes-rfli/paclo/actions/runs/38993735942)
also has 14/14 success. Different runs produce distinct JAR identities; only
within-run equality proves the same artifact was consumed.

The workflow retains build-checks, documentation-checks, Eastwood, coverage,
Linux x64/JDK21 and macOS ARM64/JDK17 source jobs, Linux ARM64 monitor, three
performance shards, merger, both distribution consumers and aggregate build.
Coverage remains informational as before; both consumers are required by build.
This PR changes no workflow, threshold, dependency, production code or version.
Local JDK21 evidence does not imply a local JDK17 pass, live/NIC performance,
Windows support or every OS/JDK combination. Final PR CI must also be green.

## Proposed scope and carry-over

Include all completed P01–P08 (E1 design plus E2/E3 implementation), explicit
extensions, diagnostics/DLTs, Flow/Window/DNS analysis and CLI migration,
Classic/PCAPNG I/O, the managed break/close race stabilization, PR #55/#56 Flow
allocation/key reuse, PR #57 DNS expiry hint, PR #58 typed MAC stores and PR #60
artifact correction. See the [readiness inventory](release-readiness-p06-p08.md#implemented-inventory)
and [v1.4.0 candidate changelog](../CHANGELOG.md#140---2026-10-17). P09/P10 are outside this release.

- **Keep [Issue #37](https://github.com/nantes-rfli/paclo/issues/37) open, non-blocking.** PR #57 reduces premature scans but repeated
  actual retired expiry and long production-trace evaluation remain. No claim
  of complete DNS performance resolution.
- **Recommend [Issue #44](https://github.com/nantes-rfli/paclo/issues/44) closure after separate human issue-level acceptance.** Its
  original acceptance permits evidence-backed optimization or accepting remaining
  cost. [PR #58 review](https://github.com/nantes-rfli/paclo/pull/58)
  found no merge blocker and explicitly deferred issue closure. The
  [944-pair investigation](issue-44-ethernet-performance.md) shows Ethernet Full
  transformation +9.1–76.1%, native reads +9.6–32.3%, with CPU/allocation controls.
  Flow implementation is unchanged; JIT/thermal/retained-heap noise and negative
  comparisons remain. Closure means bounded investigation/optimization accepted,
  **not** Flow speedup, recovery of all historical throughput, real-NIC speedup,
  or other-platform performance validation. This PR leaves the issue open.
- Keep the accepted legacy lazy-abandonment limitation visible (#40 closed after
  investigation). Own prefixes with managed with-open or synchronous reduced.
- Unmeasured live/NIC, other OS mappings, richer PCAPNG blocks/semantics and
  optional integrations remain future work, not inferred from offline CI.

## Required explicit approvals and next action

1. Approve or reject D1/D2 classifications using the released promises. If a
   guarantee break remains, choose the separate correction route or 2.0.0.
1. Approve final version **and** migration/release scope; 1.4.0 remains a proposal.
1. Accept #44 closure wording separately; keep #37 non-blocking and open.
1. Independently review/merge this documentation PR. A later, separately
   authorized release task must recheck final 14-job CI, candidate JAR consumers,
   dependency scan and versioned documentation before changing versions/tagging
   or publishing. CI success is not authorization to release.

The [migration draft](../docs/migration-from-1.3.md) is a concise user checklist
with executable examples, linked to the API contract rather than duplicating it.
Actual local commands/results and any limitations belong in [the work log](work-log.md).
