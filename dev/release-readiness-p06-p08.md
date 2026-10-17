<!-- markdownlint-disable MD013 -->
# Release readiness after P06–P08

Audit date: 2026-10-17 (Asia/Tokyo). Audited latest main:
`752c3646eab58070f05b6fa11aa8ff4142173022`, after PR #58.
Compatibility baseline: tag `v1.3.0` and its published JAR, not historical plan sketches.

**Decision: proceed with release preparation, but do not publish yet.** The
Java 17 distribution mismatch below is a release blocker. Complete that separate
build/consumer correction, accept the migration changes explicitly, and verify
the final release candidate before publication. P09/P10 are not prerequisites.
The preferred version candidate is **1.4.0**, conditional on that compatibility
acceptance; a patch cannot represent the added public APIs. No version, tag,
publication, issue state or merge is changed by this audit.

## Sources and authority

- [Public API contract](../docs/cljdoc-api-contract.md) defines supported behavior;
  [usage](../docs/usage.md) and [PCAPNG](../docs/pcapng.md) explain composition.
- [Accepted plan](codex-plan.md) owns task status/dependencies;
  [work log](work-log.md) owns commands/results and historical handoffs.
- [CHANGELOG](../CHANGELOG.md) owns changes by release; all P01–P08 additions
  remain under Unreleased. [ROADMAP](../docs/ROADMAP.md) summarizes direction.
- [CONTRIBUTING](../CONTRIBUTING.md), [CI](../.github/workflows/ci.yml) and
  [Publish](../.github/workflows/publish.yml) own verification/publication mechanics.
  Archived release checklists retain historical facts; they are not current gates.

GitHub reports [v1.3.0](https://github.com/nantes-rfli/paclo/releases/tag/v1.3.0)
as the latest stable release (2026-08-01). The live
[Clojars API](https://clojars.org/api/artifacts/org.clojars.nanto/paclo) reports
latest release/version 1.3.0; the
[versioned cljdoc page](https://cljdoc.org/d/org.clojars.nanto/paclo/1.3.0/doc/readme)
is available. A cached Clojars project page still showed 1.2.0, so it was not used
as current publication evidence. Repository main and Clojars CURRENT are different
surfaces until a new artifact is published.

## Implemented inventory

| Item | Implemented behavior and evidence | Public surface |
| --- | --- | --- |
| P01 | Current/API/history separation and executable documentation | Documentation; no runtime addition |
| P02 | Preserve captured time and wire length; validate metadata; real truncated PCAP round trips | Existing `core/write-pcap!` two-argument form |
| P03 | Ordered explicit functions, empty selection, dynamic legacy registry when omitted; independent pipelines | `:extensions`; public DNS/TLS annotators; `decode-ext/apply!` arity 2 |
| P04 | Raw/full/flow contracts; additive EDN diagnostics and opt-in extension failures; stats schema 1 retained | `:extension-error-mode`; `decode-ext/apply!` arity 3 |
| P05 | Native DLT on all capture paths; explicit unsupported-type rejection; missing-DLT standalone Ethernet default | Packet `:linktype`; existing core APIs |
| P06 | Canonical IPv4/IPv6 uni/bidirectional keys; exact immutable bounded counters; deterministic ranking | `paclo.flow/key`, `aggregate-rf`, `top-n` |
| P07-A | Pure bounded event-time windows and strict UDP DNS correlation, explicit watermark/finish | `paclo.window` and `paclo.dns` |
| P07-B | DNS RTT/QPS CLIs share analysis and source ownership; finite reports, explicit failure/incomplete diagnostics | Repository example commands; no new library namespace |
| P08-A | Native format acceptance/precision/loss inventory and reproducible fixtures | Characterization, not a new reader |
| P08-B1/B2 | Read failure distinct from EOF, setup cleanup, explicit single-DLT Classic writer, write/flush errors | Writer arity 3 with `:linktype`/`:snaplen`; additive exception data |
| P08-C/D1/D2 | Shared framing, SLL/SLL2, Raw IP, NULL/LOOP full/flow decode; native AF/endian probes | Existing packet transformations and truthful link maps |
| P08-E1 | Exact time/event/ownership design and fixtures | Design only at E1; implemented by E2/E3 |
| P08-E2/E3 | Bounded ordered PCAPNG events, exact time, preserve/lossy/author writer and exclusive atomic publication | `paclo.pcapng/open-source`, `source-info`, `write-pcapng!` |
| Stabilization | Managed native break/close race fix; deterministic documentation/testing of lazy abandonment | Existing ownership APIs; no lazy cancellation invention |
| Performance | PR #55/#56 flow allocation/key reuse; #57 DNS expiry hint; #58 primitive address stores | Internal implementation; no new dependency/options or gate relaxation |

The complete supported function inventory, with positional arity counts, is:

| Namespace | Supported functions (arity counts) |
| --- | --- |
| `paclo.core` | `bpf` 1, `packet-xf` 1, `packets` 1, `reduce-packets` 3, `reduce-packets-report` 3, `start-capture` 1, `capture-packets` 1, `stop-capture!` 1, `capture-stats` 1, `write-pcap!` 2/3, `list-devices` 0; `-main` variadic convenience entrypoint |
| `paclo.stream` | `fan-out` 2/3, `branch` 2, `stats` 1 |
| `paclo.decode-ext` | `register!` 2, `unregister!` 1, `installed` 0, `apply!` 1/2/3 |
| `paclo.flow` | `key` 1/2, `aggregate-rf` 1, `top-n` 2 (second argument is an options map) |
| `paclo.window` | `init` 1, `step` 2, `advance` 2, `finish` 1 |
| `paclo.dns` | `packet-time-us` 1, `packet->event` 1, `init` 1, `step` 2, `advance` 2, `finish` 1 |
| `paclo.pcapng` | `open-source` 1, `source-info` 1, `write-pcapng!` 2/3 |
| Supported annotations | `paclo.proto.dns-ext/annotate-dns` 1, `paclo.proto.tls-ext/annotate-tls-sni` 1 |

Two usage examples previously passed a number to `flow/top-n`; the documented
API requires an options map. They are corrected to `{:n 10}` / `{:n 8}` and
re-executed. Tiny inputs had masked the ineffective numeric argument by falling
back to the default limit. No runtime/API validation change is made here.

All v1.3.0 supported core/stream/decode-ext names and arities remain. This is
source/API inspection plus runtime Var/arglist checks against the published JAR, not proof of universal
behavioral equivalence. `paclo.flow` projection helpers moved to internal
`paclo.flow.project`; they were outside the v1.3 stable namespace list. Generated
`->Capture`/`->Source` constructors are implementation details of opaque handles,
not supported construction APIs. `paclo.pcap`, `parse`, `linktype`, protocol
internals other than the two annotations, stream implementation and PCAPNG
cursor/writer internals remain outside compatibility guarantees.

## Format, decode and lifecycle boundaries

| Path | Preserves/provides | Limits and information loss |
| --- | --- | --- |
| Native `core` input | Owned packet bytes, epoch `:ts-sec`/microsecond component `:ts-usec`, captured/original lengths, native DLT | Installed libpcap governs PCAP/PCAPNG acceptance; normalizes precision to microseconds, loses section/interface/options/opaque data; mixed DLT/snaplen may fail |
| Classic `write-pcap!` | Ordered bytes, selected microseconds, caplen and original len; one explicit DLT/snaplen | Two-argument defaults 1/65536; no sniff/conversion/suffix selection; overwrites incrementally and may leave partial output; no metadata/exact-time round trip or atomic rollback |
| PCAPNG `open-source` | SHB/IDB/EPB/SPB and permitted opaque events, qualified interfaces, ordered owned option octets; mixed orders/LINKTYPEs/snaplens | PCAPNG 1.0 only; obsolete Packet/Secrets blocks rejected; finite ceilings; no live/BPF/seq/reopen; unknown LINKTYPE yields explicit nil DLT |
| PCAPNG `write-pcapng!` | Known semantics, exact ticks/absence and retained ordered octets; bounded loss counts for explicit drops | Preserve default; lossy requires drop categories, author validates explicit context/time; edits need context declaration; no hidden-edit detection, repair, byte-identical copy, append/stream/fsync API |

Exact PCAPNG UTC seconds are `offset + ticks / base^exponent` with unsigned
64-bit ticks, decimal/binary resolution and signed offset. Integer arithmetic
preserves exact values; compatibility microseconds floor submicrosecond time.
SPBs have explicit absent timestamp and omit both compatibility fields. DNS and
Window APIs use integer microseconds, not exact submicrosecond ordering; callers
must choose a policy for missing time. Classic export does not validate nested
exact time; metadata/precision loss must be an intentional application decision.
Older native libpcap readers may expose unsigned post-2038 PCAP seconds as
negative, which the Classic writer rejects; numeric round trips there depend
on installed libpcap, as documented in the writer contract.

Linux/macOS full and flow decoding cover native DLT 1 (Ethernet/VLAN), 113 (SLL),
276 (SLL2), 12 (Raw IP), 0 (NULL) and 108 (LOOP), IPv4/IPv6. Savefile LINKTYPE
101 is mapped to native DLT 12, not accepted as packet DLT 101. NULL accepts a
unique AF in either order; LOOP is big endian; AF 2/24/28/30 only. Container
order/origin OS cannot be inferred from packet maps. SLL addresses are not MAC
pairs; SLL2 interface index is not a PCAPNG interface ID. Other types remain
available raw; explicit unsupported/nil DLT never falls back to Ethernet.
Other OS mappings and Windows support are not established.

Full decode remains best effort: no checksum validation/reassembly and incomplete
headers may produce partial maps or errors. Flow intentionally reads fewer
transport fields and omits bytes/full decode/extra PCAPNG keys. DNS accepts
eligible unfragmented standard UDP/53 packets with at most one question; it is
not TCP DNS, reassembly, mDNS, DoH or a new DNS parser. Flow cardinality, window
retention/groups, pending/retired DNS keys and CLI reports are explicitly bounded;
capacity errors do not silently evict. Finish is not an infinite watermark.

Native bytes are copied at capture but remain mutable and shared by fan-out;
published arrays must be treated as read-only. Synchronous `reduced` stops and
closes; managed capture/branches/PCAPNG sources have explicit single-consumer
ownership. Own handles with `with-open`. A lazy `packets` prefix, consumer error
or reducing xform does not cancel its producer: a full blocking queue may retain
the native handle indefinitely. Issue #40 is closed with this limitation accepted,
not automatic abandonment detection. Managed close waits up to five seconds;
a timeout does not prove resource release, and native/user calls must return.

Native read errors throw `pcap-read-failed`/`pcap-next-ex`, distinct from EOF.
Default propagation and `:pass` valid-prefix/error statistics are separate from
packet decode diagnostics. Existing string errors and schema 1 fields remain;
additional structured fields/stage/reason keywords require tolerant consumers.
PCAPNG has no pass/recovery mode. Reader cleanup preserves primary exception
identity; writer failures preserve the original exception with output/temp/cleanup
information suppressed. Exclusive publication uses Linux renameat2/macOS
renamex_np on supported default filesystems only, failing without fallback.
Unread suffixes are not validated after early stop.

## Compatibility and version decision

[SemVer 2.0.0](https://semver.org/spec/v2.0.0.html) requires minor increments for
compatible added public functionality and major increments for incompatible
public changes. P06/P07/P08 API additions exclude a 1.3.x patch for this bundle.
Plan labels v1.4/v1.5/Later were proposals, not published milestones.

| Candidate | Assessment |
| --- | --- |
| 1.3.1 | Reject for this bundle: adds supported namespaces/functions/options |
| 1.4.0 | Preferred next minor if the documented correctness changes below are accepted within the v1 contract and Java 17 distribution is repaired |
| 1.5.0 | Technically a minor, but unnecessary merely because P06/P07 carried v1.5 planning labels; use only for an explicit release sequencing decision |
| 2.0.0 | Required if the accepted release scope intentionally breaks previously supported behavior, including dropping JDK 17 rather than repairing the artifact; not justified solely by feature count |

The following behavior differences must be in the release migration notes and
accepted by reviewers; **retained function arities do not make these invisible**:

| Change/evidence | Impact and migration | Classification |
| --- | --- | --- |
| P02 timestamp precedence and validation (`pcap/packet-timestamp`, roundtrip tests) | New complete `:ts-*` wins over `:sec/:usec`; partial new pair throws; complete nil/coercible noninteger/negative/out-of-range values now fail; malformed lengths fail. Supply valid complete integer microseconds/lengths and remove conflicting stale fields intentionally. Raw/missing/partial legacy fallback remains. | Correctness/validation changes; callers relying on old coercion/ignored metadata can break |
| P08-B2 framing/snaplen validation (`validate-framing!`, writer tests) | Two-argument non-Ethernet maps and excess caplen now fail instead of emitting mislabeled/inconsistent files. Supply matching native DLT/snaplen; do not erase known metadata to bypass validation. | Intentional rejection of invalid output, not unrestricted two-argument equivalence |
| P05 DLT and P04 diagnostics | Exact whole-map equality/schema consumers see extra keys; unknown explicit types reject instead of Ethernet parsing. Treat additive fields as open and use raw mode for unsupported framing. | Additive data plus correctness correction |
| P08-B1 error propagation | Corrupt files formerly appearing as EOF may now throw. Use `:pass` with error callbacks/report stats only when a failed prefix is explicitly acceptable. | Bug fix with operational impact |
| P06 Flow CLI | Default 100000 unique-flow budget; canonical tie ordering; async errors propagate. Raise explicit bound when appropriate and handle failure. | Observable example-command change |
| P07-B DNS CLI | Correct RTT/mean, strict question matching, QR-oriented client/server grouping, reorder/expiry, full offline EOF, finite limits and overflow exit 5 instead of truncated output. Pair counts/group keys/output volume can change on previously accepted inputs. | Observable semantic migration; not byte-for-byte v1.3 CLI behavior |
| JDK artifact | JDK 21 output cannot load on JDK 17 despite advertised support. | Release blocker below |

A JAR-only probe run outside the checkout under JDK21 confirmed these actual
writer differences against the cached published 1.3.0 artifact:

| Input | Published 1.3.0 | Audited JAR |
| --- | --- | --- |
| Valid legacy `1700000000/123` | Preserves time | Preserves time |
| Both timestamp pairs | Uses legacy pair | Uses capture pair |
| Partial new pair plus complete legacy | Uses legacy pair | Throws partial-new-time error |
| Complete nil/fractional legacy | Clock fallback / coerces fractions | Throws validation error |
| 60 captured bytes, `:len 120` | Writes len 60 | Preserves len 120 |
| Explicit DLT 113 with default writer | Writes Ethernet-labeled file | Throws mismatch error |

The old official CLI policy fixes stdout/stderr and exit codes 1–4, which remain;
new analysis/source/bound failures add exit 5. A consumer assuming only 1–4 or
old client/server grouping needs migration. Historical deprecation promises must
not be rewritten to pretend these changes were already released. Reviewers must
explicitly accept these as correctness/boundedness fixes, or commission a separate
compatible opt-in adjustment; if the chosen scope retains a genuine supported
behavior break, select 2.0.0. This audit does not implement that adjustment or
silently certify unconditional backward compatibility.

## Release blocker: Java 17 distribution

`build.clj` calls `b/javac` without `--release 17`/target configuration.
Publish selects JDK 21. Inspection of locally compiled bindings and the packaged
JAR shows class-file **major 65**, requiring Java 21; Java 17 accepts up to 61, per the
[JVM class-file specification](https://docs.oracle.com/javase/specs/jvms/se17/html/jvms-4.html#jvms-4.1).
The cached published 1.3.0 JAR also contains major 65, so this is a pre-existing
publication/support inconsistency, not a new source API removal.

The macOS ARM64/JDK17 CI job builds its own JAR/classes under JDK17 and runs
source tests. It never consumes the JDK21 Publish artifact. All green source
matrix jobs therefore leave this distribution gap open. The local machine has
JDK21 and JDK13, not JDK17; no local JDK17 runtime pass is claimed.

Required separate correction: retain JDK17 support, compile production classes
to Java17-compatible bytecode using the release build, and run **the same JAR**
without source/Java recompilation on JDK17 and JDK21. Include native offline
reads, both writer paths and all public namespaces/annotations. Recheck every
packaged class version. Preserve all existing gates/thresholds. Do not merely
remove the JDK17 claim or treat its source CI as artifact validation.

## Quality and package evidence

Local host: macOS x86_64, Temurin 21.0.12.1, Clojure 1.12.1, system libpcap.
This is distinct from macOS ARM64 CI. Full commands/results are in the
[work log](work-log.md#2026-10-17-release-readiness-audit-after-p06p08).

| Check | Result |
| --- | --- |
| `doctor` | Pass; real offline read, four packets/438 bytes |
| `check` | Pass: 490 Clojure tests / 19036 assertions, ten JUnit tests, offline smoke |
| Public names/arities | All baseline supported functions/arities retained; static source diff and runtime metadata inspection; behavioral exceptions above |
| Fixture generators | Pass: 28 capture-format, 4 cooked, 3 Raw, 12 NULL/LOOP, 10 PCAPNG contract files; real fixtures and Python wire/heap checks also run in full suite |
| lint/Eastwood | Kondo zero warnings/errors; all 112 Eastwood namespaces, 593 informational warnings and zero exceptions; namespace/format checks pass. Final complete wrapper exits 0, including all 42 Markdown files; intermediate failures/corrections retained in work log |
| Executable docs | All 34 examples pass; 15 example-parser tests, nine link-parser tests (canonical temp path), repository links and cljdoc namespace-load pass |
| Java quality | SpotBugs/CheckStyle/JaCoCo pass; 43.8% line coverage against unchanged 25% gate |
| Performance | Existing gate passes at 452.1 ms, unchanged 1000/1200 ms warning/failure budgets; 27-scenario quick matrix passes in current main CI |
| Package/consumers | JAR builds; contents/POM inspected; three outside-checkout JDK21 consumers pass (all DLTs, DNS/PCAPNG/windows, Flow); JDK17 artifact remains blocked |

Latest main [CI run 38988905927](https://github.com/nantes-rfli/paclo/actions/runs/38988905927)
completed successfully with all 12 jobs. PR #58 final head `9b9b02c` also passed
[run 38955008505](https://github.com/nantes-rfli/paclo/actions/runs/38955008505).
Verified jobs include Linux x64/JDK21, macOS ARM64/JDK17, Linux ARM64/JDK21,
Eastwood, build/Java quality, docs, all three performance shards/results, aggregate
build and informational coverage. These are actual main/PR runs, not inference
from old phase measurements. Final audit-PR CI will be recorded on that PR.

The `build` aggregate explicitly requires build-checks, documentation, performance
shards/results, compatibility matrix and Eastwood. Linux ARM64 is a separate
`arm64-monitor` job, not a `needs` entry; independently require it successful for
release acceptance. Clover coverage is informational (`continue-on-error`);
JaCoCo's 25% line gate is required in build-checks. The synthetic decode/write
performance gate retains 1000/1200 ms warning/failure budgets. The 27 quick-profile
measurements validate completion/counts, not throughput targets. No gate is changed.
No fresh live/NIC, other-platform, cold-cache installation, universal performance
or long production DNS validation is established by these offline checks.

Latest [Dependency Audit run 38428605480](https://github.com/nantes-rfli/paclo/actions/runs/38428605480)
succeeded on 2026-10-13 at `8312d10`. `deps.edn` has no diff from v1.3.0. This is
historical security evidence, not a new CVE scan at the release SHA; recheck or
run the existing workflow before publication, without a bulk dependency update.

## Issues, risks and next priorities

| Item | Assessment | Before/after release |
| --- | --- | --- |
| Java17 artifact | Confirmed distribution/support mismatch | Must fix/verify before stable publication |
| Compatibility/migration decision | Writer and CLI behavior changes above require explicit acceptance and chosen version | Must resolve before naming/tagging the release |
| Issue #37 | Open; PR #57 reviewed and merged as `e444b10`. Repeated actual retired expiry remains O(retired), with measured throughput losses 12.6–38.4%; long representative production-PCAP evidence is missing | Non-blocking follow-up; keep open; correctness/bounds must not be weakened |
| Issue #44 | Open; PR #58 independently reviewed and merged as `752c364`. Repeatable Ethernet Full improvements 9.1–76.1% transformation / 9.6–32.3% native, allocation parity; cooked benefits also retained | Non-blocking; recommend closure after accepting this evidence and remaining JIT/thermal/retention limits |
| Issue #40 | Closed; managed race corrected in merged PR #54, lazy abandonment remains documented/tested | Accepted compatibility limitation; continue ownership guidance |
| Issue #34 | Closed; PR #55/#56 accepted, negative native end-to-end results retained | No release blocker; do not claim universal flow speedup |
| PCAPNG opaque/context and platform limits | Known semantics only; caller declares context edits; atomic primitive/filesystem may reject publication | Ship with explicit existing contract, no unsafe fallback |
| Live/NIC and performance scope | Offline gates and single-host comparisons do not validate sustained NIC targets | Separate measured workflow after release if demanded |

[PR #58 review](https://github.com/nantes-rfli/paclo/pull/58#pullrequestreview-5555216943)
explicitly accepted the implementation while reserving issue-level closure.
This audit finds its investigation/optimization acceptance satisfied, with the
[negative/control results](issue-44-ethernet-performance.md) retained. Closing that issue may acknowledge that limited outcome; it must not claim historical speed
recovery, Flow equivalence/speedup, all hardware or live throughput. The separate
[PR #57 review](https://github.com/nantes-rfli/paclo/pull/57#pullrequestreview-5552073083)
explicitly requires #37 to remain open; its remaining goals are not completed by
this audit. No Issue is closed or commented on here.

P09 remains blocked: no named export/inspection integration workflow is supplied.
The implemented PCAPNG reducible already addresses a concrete composition need;
do not introduce a generic pipeline framework/backend selector. P10 remains
conditional: prioritize #37 production-trace profiling and actual-expiry costs
before speculative buffers/batching/parallel decode/mmap. Any future proposal
needs a measured target shortfall plus ownership/order/cancellation evidence.
Neither is a reason to delay this release once the mandatory conditions pass.

## Recommended release sequence and acceptance

1. Independently review this documentation audit. Merge only after review and
   human approval; preserve historical records and current canonical contract.
2. Make a separate scoped build/consumer PR for the Java17 artifact defect.
   Require unchanged full CI plus identical release-JAR consumers on 17/21.
3. Approve migration scope and version (preferred 1.4.0; major if a supported
   break remains). Prepare a separate release PR: move Unreleased entries into a
   dated version section, align README install/status, API availability labels,
   ROADMAP and development snapshot fallback with the accepted version. Preserve
   unreleased future scope rather than claiming P09/P10 shipped.
4. Validate final main and its candidate JAR/POM: complete Clojure/JUnit, lint and
   Java quality, executable docs, cljdoc loading, real fixtures, unchanged perf
   gate/27 scenarios, all three platforms, JAR contents and independent consumers.
   Require successful Linux ARM64 separately. Check current Dependency Audit;
   triage findings without silently changing dependencies/gates.
5. In a separately authorized release task, run Publish manually from **current
   main** with the approved version and `dry_run=true`. It requires an existing
   dated CHANGELOG heading; it cannot currently run for an unnamed candidate.
   Inspect uploaded JAR/POM/version/SCM/dependencies and checksum. Publish gates
   cover Clojure tests/perf plus build, not all CI; full CI remains a prerequisite.
6. Only after explicit publication authorization, use the existing tag/manual
   publication procedure. A `v*` tag push automatically deploys to Clojars;
   manual `dry_run=false` also deploys. Tag must resolve to the intended main
   ancestor; manual dispatch must equal current main. Never reuse/replace an
   existing version. Verify downloaded Clojars artifact checksum and independent
   consumers, then versioned cljdoc API/doc coverage, before announcing completion.

Package inspection found 41 entries, including all public namespaces, internal
PCAPNG/flow implementation, DNS/TLS annotations and ten native binding classes.
No test/dev directory or fixture corpus is packaged. All ten classes are major
65, confirming the blocker. Maven metadata uses the expected coordinates,
`1.3.0-SNAPSHOT` and SCM tag `v1.3.0-SNAPSHOT` for this unversioned audit build;
its five dependencies exactly match default deps (no CSV/tool/test dependencies).
The POM declares MIT; a standalone LICENSE text is absent from the JAR, as in
existing packaging. Adding that text can be a small packaging follow-up, without
changing the current release verdict. Snapshot SCM tags are placeholders, not
existing release provenance; inspect the actual versioned candidate separately.

`build.clj` currently resolves `PACLO_VERSION`, then matching tag context, then
`1.3.0-SNAPSHOT`; coordinates are `org.clojars.nanto/paclo`. Its POM records MIT,
SCM URL and `v<version>`. Publish sets PACLO_VERSION consistently for JAR/POM;
GitHub Release creation and cljdoc publication verification are separate steps,
not performed by the workflow itself. The current fallback is not the next
stable-version decision. Secrets/deploy credentials and the complete remote
cljdoc build are not exercised by this audit. No Publish dispatch, tag, Clojars
deploy or GitHub Release is performed here.
