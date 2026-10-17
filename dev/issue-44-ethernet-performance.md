# Issue #44: Ethernet decode performance investigation

This independent investigation starts from main
`e444b10ba84513b460916482e1236c202fa27b84` after PR #57 merged.
It concerns full decoding and numeric projection, without changing P06/P07,
source ownership, supported DLTs, dependencies, versions or performance gates.
Issue #44 remains open for independent acceptance review.

## Historical baseline and runner validation

The references are different implementations:

- P08-B2 `4998ddc`: Ethernet/VLAN only; independent full and numeric framing.
- P08-C `9d83bb2`: shared packed framing and SLL/SLL2; full link construction
  separated from IP parsing. Historical evidence reports 416 fewer allocated
  bytes per Ethernet packet and a 4.9–9.8% full throughput cost.
- D2 `ccebcad`: Raw IP and NULL/LOOP are implemented, with strict AF/version
  checks. The Issue's D2 comment describes a separate D1-to-D2 comparison.
- Current main `e444b10`: includes those capabilities, PCAPNG APIs, capture
  lifetime fixes and merged flow/DNS work. None of the DNS follow-up is included
  in this change.

First run the original, unchanged command:

```bash
clojure -M:dev -m paclo.dev.framing-perf 4998ddc 1
```

It succeeds with current main. Both historical and current sources still expose
`unsupported?` and `packet-xf`; one- versus two-argument internal full parsers
are called by their respective historical core. No shim or baseline production
patch is necessary. [The output](issue-44/original-runner.edn) is retained.
Its checksum consumes capture length, so it is insufficient alone to establish
semantic equivalence. The new comparison checks complete decoded values outside
measurement, plus raw identity, absence of bytes/decoded maps from Flow, and
post-run input bytes. These checks complement the existing contract tests.

The [new runner](paclo/dev/ethernet_perf.clj) loads exactly the four requested
historical source files from Git into distinct namespaces, in dependency order.
Only namespace names change. It records SHA-256 of the original sources.
Protocol, capture, extension and runtime dependencies outside these files are
shared from the checkout. Native comparisons deliberately use one current
source-owning `reduce-packets` path with each historical/current `packet-xf`
in `:xform`; they isolate decoding while holding capture implementation fixed.
They are not whole historical-release native benchmarks.

[Baseline run 1](issue-44/baseline-1.edn) and
[reversed run 2](issue-44/baseline-2.edn) retain same-main controls as well as
B2/C/main, with D2 additionally in run 2. Each uses five per-case warmups and
nine alternating 50,000-packet samples; every warmup and measured sample is
retained. Historical allocation differences are reproduced, but absolute values
vary with compiler escape analysis and the reducer/call-site context. Do not
compare numbers from different runners as if they were paired implementation
changes. Throughput differences vary more than the allocation delta.

## Measurement scope and reproducibility

Local environment: macOS 15.4.1 x86_64, Temurin JDK 21.0.12.1, Clojure 1.12.1,
libpcap 1.10.1. Enhanced measurements use a fixed 512 MiB heap and record
runtime/JVM flags, original source hashes and options in their EDN preamble.
The original-runner validation uses its normal default heap/historical schema. No benchmarks run alongside test/lint/package
processes. Early pilot measurements and all negative results are retained.
The first MAC pilot starts while a separate JFR export finishes during startup;
final measurements use serial commands without that activity.

The initial matrix's first Flow cases overlap JIT compilation despite five short
warmups. Its large negative outliers remain recorded. Subsequent comparisons
first warm all 32 protocol/framing shapes, both modes and both implementations,
five times at 10,000 packets/shape. Then each case receives five local warmups
and nine alternating 10,000-packet samples. The second JVM reverses initial
implementation order. The `:prewarm` record distinguishes these runs from
pilots. No sample is selected, removed or replaced. A separate same-source
comparison estimates alias/dispatch/JIT noise.

Counters cover elapsed time, current-thread CPU nanoseconds and allocated bytes,
and process GC count/time over each invocation. GC can be charged to either
adjacent variant and is not an independently attributable packet cost. Per-row
medians and ranges across independent JVM medians are descriptive, not confidence
intervals. Warmup and order remain visible in raw data. Global prewarm visits
references before the working tree; reversal applies to local warmup and
measured order. Neither CPU frequency nor thermal state is pinned on this host. Full parsing still
allocates payload copies, IP/display strings and nested persistent maps; Flow
builds numeric maps and endpoint words without raw bytes or full/link maps.

Reproduce final measurements from this checkout, with other workload processes
finished:

```bash
clojure -J-Xms512m -J-Xmx512m -M:dev -m paclo.dev.ethernet-perf '{:suite :matrix}'
clojure -J-Xms512m -J-Xmx512m -M:dev -m paclo.dev.ethernet-perf '{:suite :matrix :reverse? true}'
clojure -J-Xms512m -J-Xmx512m -M:dev -m paclo.dev.ethernet-perf '{:suite :native}'
clojure -J-Xms512m -J-Xmx512m -M:dev -m paclo.dev.ethernet-perf '{:suite :native :reverse? true}'
clojure -J-Xms512m -J-Xmx512m -M:dev -m paclo.dev.ethernet-perf '{:suite :fixtures}'
clojure -J-Xms512m -J-Xmx512m -M:dev -m paclo.dev.ethernet-perf '{:suite :fixtures :reverse? true}'
```

The matrix contains 128 cases: IPv4/IPv6 × UDP/TCP × 96/1514-byte untagged
Ethernet size × both modes × Ethernet with 0/1/2 VLANs or five other DLTs.
VLANs add four bytes each. The same IP/L4 bytes are placed under native DLT
1/113/276/12/0/108 framing; no benchmark packet header is fabricated by a decoder.
Native has 96 cases across both containers, both versions/protocols/modes and
six DLTs. Generated capture bytes/time/length/DLT are checked by native replay
before measurement. All reads include open/read/copy/close on a warm file cache.
Classic uses the existing native writer; PCAPNG uses a small independent binary
SHB/IDB/EPB encoder in the measurement runner.

Fixture replay uses the first eight valid packets (or the complete smaller file)
from seven real offline fixture files, repeated to 10,000 records in Classic and
PCAPNG: Ethernet DNS/TLS, SLL/SLL2, Raw IP, NULL and LOOP. These prefixes
include DNS/TLS/ICMP and both IP versions. The complete corpus's fragment,
extension, malformed, unsupported and truncation cases are correctness-tested
separately; they are not all represented in the timed valid prefixes. DNS/TLS extension composition remains in the full suite;
performance full mode explicitly uses `:extensions []`.

External actual traffic is the small Wireshark
[SampleCaptures DNS trace](https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures/dns.cap),
already downloaded during Issue #37. Its SHA-256 is
`041eeb6f98bb398f1ee8b09651b5b5a84f6a62639f95bf226f9e7b77355d9f28`;
it is not committed. Read the trace and replay its actual records to 10,000 native Classic
records for paired comparisons. This small trace is not a production distribution.

```bash
curl --fail --location https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures/dns.cap -o /tmp/wireshark-dns.cap
clojure -J-Xms512m -J-Xmx512m -M:dev -m paclo.dev.ethernet-perf '{:trace "/tmp/wireshark-dns.cap" :replay? true}'
clojure -J-Xms512m -J-Xmx512m -M:dev -m paclo.dev.ethernet-perf '{:trace "/tmp/wireshark-dns.cap" :replay? true :reverse? true}'
```

## Bottlenecks and candidate decisions

Full and Flow were profiled separately, outside paired timing. A 2 ms stack
sampler provides a portable, perturbed view; separate JFR execution/allocation/GC
recordings preserve raw events. JFR execution sampling is sparse on this host,
so neither source supplies an exact per-method CPU percentage.

The pre-change Full stack sampler observes reflective `Array.setChar` as the
leaf in 1596/4627 samples (34.5%). MAC/cooked address formatting uses
`aset-char`, which reaches that native reflective primitive setter. It is called
17 times per six-byte MAC: two hex digits per byte plus five separators. Link map/MAC construction
alone takes about 1.06 microseconds in the initial component probe, compared with
about 2.52 microseconds for parsing. Component probes include generic function
and loop overhead and cannot be summed into facade cost.

Accepted: give the local output array the primitive `chars` type and use `aset`
with integer indices. This selects the direct char-array store overload.
AOT/javap inspection confirms three `RT.aset:([CIC)C` calls in the
[after bytecode](issue-44/address-after-bytecode.txt), replacing the `aset-char`
Var calls in the [before bytecode](issue-44/address-before-bytecode.txt). The
array remains private until converted into the same lowercase colon-separated
String. Address lengths, ByteBuffer positioning, field order/content, maps,
DLT/framing, parser logic, exceptions and ownership are unchanged. No cached
packet/address data, lookup table, shared mutable state or packet bytes are added.
The same implementation benefits Ethernet and cooked link addresses.

Flow never uses that address routine. Its initial sampler highlights output
map lookup/construction, `packet-dlt` and VLAN classification. IPv4 words/ports
remain primitive while walking headers, with boxing when publishing persistent
maps. IPv6 adds endpoint vectors/words and the existing transport-walk result.
The direct stores introduce none of these costs.

Shared framing reads bytes at absolute offsets and packs L3 offset/protocol in
one primitive long. Flow does not wrap a ByteBuffer. Full wraps once, positions
it at L3, and reuses it for link addresses after IP parsing; no second packet
buffer or link-intermediate map is introduced. Existing VLAN scans are bounded
by captured length. Numeric `u8/u16/u32/i64` walkers retain primitive arithmetic
until map/vector publication. The generic component probe also boxes its return
values and must not be interpreted as production framing allocation.

Full's facade retains its small tagged success-result map and the existing
IP/L4 maps, legacy display flow key and payload copies. Error/diagnostic maps
are constructed on observed failures; exception reason strings on successful
Flow are constants. Extension configuration is prepared when constructing the
transducer. Removing duplicate Full framing checks or rewriting success-map/
exception handling was not measured in isolation, so none is included.

Rejected candidates, with paired raw output and reproduction patches:

- Inline VLAN `case` in the framing loop: Flow allocation grows 280 → 304
  bytes/packet and throughput declines roughly 34–39% in both pilot JVMs.
  The extra 24 bytes are consistent with boxing from the changed case/loop
  compilation; the measured regression is sufficient to reject it. The
  [patch](issue-44/rejected-case.patch) includes the MAC candidate plus this
  rejected change, for application to main; it is not the delivered code.
- Drop the second presence test in `packet-dlt` after validation: compare
  directly against the MAC-only snapshot, not main. UDP Flow changes +0.9/+6.4%,
  TCP -3.9/+3.9%; Full control rows also move by several percent. Allocation
  stays 280 bytes. This does not show sufficiently consistent benefit to adopt.
  [Patch](issue-44/rejected-dlt.patch) applies to main and includes the MAC change.
- Ethernet-specific full parser, fixed header map constructor, MAC lookup table,
  alternate ByteBuffer/offset walkers and error-path restructuring: not adopted.
  The measured reflective stores provide a simpler local improvement. Existing
  map/payload allocation remains visible; these alternatives lack isolated
  repeatable evidence and would expand the correctness/maintenance surface.

Historical B2 performs the same reflective MAC writes. Therefore this change
addresses a measured bottleneck, not proof that reflective writes were introduced
by P08-C or that they alone explain the historical shared-framing slowdown.
P08-C also removed always-created VLAN transient work and split link construction
from parsing; additional calls/dispatch and JIT layout differ. Full saves 416
bytes at that transition. Source inspection supports those structural differences,
not an exact causal breakdown of its 5–10% historical timing loss.

## Results and practical limits

All 128 transformation cases and 96 native cases complete in two independent
JVMs with identical complete outputs, ownership checks, checksums and zero drops
or errors. The final matrix files contain the global-prewarm record; the first
underwarmed matrix is retained separately as `pilot-matrix.edn`.

The following ranges span all cases and both JVM medians. Allocation deltas are
zero for every final packet-xf pair (Flow: 280 B/packet IPv4, 480 IPv6). Native
deltas are at most 0.0024 B/packet, equivalent to one 24-byte measurement/setup
object per 10k-packet invocation, with no material allocation increase.

| DLT | Full packet-xf throughput change | Full CPU change | Full native throughput change | Flow native throughput change |
| --- | --- | --- | --- | --- |
| Ethernet 1 | +9.1–76.1% | -43.2 to -8.6% | +9.6–32.3% | -5.9 to +10.8% |
| SLL 113 | +3.7–61.2% | -36.0 to -3.6% | +5.1–29.2% | -3.1 to +32.4% |
| SLL2 276 | +3.8–44.6% | -30.2 to -4.4% | +2.8–18.2% | -7.5 to +12.5% |
| Raw IP 12 | -7.1 to +15.2% | -13.1 to +10.4% | -2.6 to +4.4% | -6.1 to +11.4% |
| NULL 0 | -5.1 to +5.5% | -4.6 to +5.3% | -1.9 to +4.6% | -6.8 to +10.5% |
| LOOP 108 | -14.1 to +16.9% | -14.5 to +14.5% | -4.2 to +7.7% | -5.8 to +7.7% |

Positive Full benefits reproduce in every Ethernet, SLL and SLL2 case in both
JVMs. Raw/NULL/LOOP do not call the changed function; their positive and negative
outliers are retained, not presented as improvements or proof of equivalence.
Their native results do not show a repeated large regression. Performance on
other operating systems/hardware is not established by these Mac measurements.

Representative untagged Full transformation cases below show the substantial
absolute run variability as well as the paired benefit. Ranges are across the
two JVMs, in kpps; allocations match before/after within each run.

| Input | Main kpps | Candidate kpps | Allocated B/packet, both variants |
| --- | --- | --- | --- |
| IPv4 UDP-96 | 251.5–252.1 | 356.4–443.8 | 3152–3320 |
| IPv4 TCP-1514 | 200.1–201.5 | 253.2–264.5 | 6112–6224 |
| IPv6 UDP-96 | 120.3–127.6 | 143.8–155.0 | 9032–9200 |
| IPv6 TCP-1514 | 97.6–141.4 | 108.2–166.3 | 11984–12096 |

Actual fixture native replay preserves the benefit: Ethernet DNS Full improves
17.7–24.2% Classic / 20.5–22.9% PCAPNG; TLS Full improves 16.4–22.3% Classic /
13.8–21.7% PCAPNG. SLL/SLL2 fixture Full improves 4.2–10.2% over both containers
and runs. The external actual DNS trace improves 23.7–26.9% for native Full.
Flow, Raw, NULL and LOOP fixture results include negative measurements; all are
in the complete CSV. No universal application or DNS/TLS-extension speedup is
claimed: extensions, reporting, serialization, queues, downstream analysis,
traffic distribution and native I/O can dominate real workflows.

### Flow controls and JIT/order effects

Mixed full/flow matrix Flow ranges from -22.8 to +31.9% on Ethernet. The pilot's
first row reaches -54.0%; neither is hidden. Use separate 50k-packet samples
with `:only-mode :flow`, and compare a snapshot containing exactly the delivered
four sources against the working tree under renamed namespaces. Both isolated
and control suites cover all 64 Flow shapes in two JVMs. Source hashes prove
that the control contains identical implementations.

| Comparison | Ethernet median across cases, JVM 1 / JVM 2 | All-DLT case range |
| --- | --- | --- |
| Main → candidate, Flow only | -3.6% / +0.0% | -21.5 to +25.4% |
| Same candidate → same candidate | +3.3% / +4.3% | -23.5 to +16.9% |

The mixed matrix's first untagged IPv4 UDP Flow case becomes +5.4/+2.8% in
isolation; same-source controls for that case are -5.2/-2.0%. No isolated Flow
case loses more than 10% in both JVMs. This supports rejecting attribution of
the large mixed outliers to the char-store change; it does not prove zero
performance impact in every compilation context. There is no Flow optimization
or throughput-equivalence claim. All its final allocation pairs remain equal.

D2-to-current source review also finds only two core docstring changes in these
four files: the transformation implementation is identical. Its same-JVM timing
differences are therefore another warning against interpreting namespace/JIT
layout changes as causal source regressions. B2-to-C Full's smaller timing cost
reproduces in the initial new runner (about 2.0–5.5% across UDP/TCP medians),
while Flow differences change sign/range across JVMs. These results do not
invalidate the historical P08-C report; they bound this host/run's inference.

### Allocation, GC and retention

JFR and stack profiles locate cost; ThreadMXBean supplies the exact paired
allocation metric. Main-thread Flow allocation samples contain Long, Object[]
and PersistentArrayMap, with no packet byte[] sample in either profile. Full
samples include string byte/char arrays, persistent-map storage/ArraySeq and
HeapByteBuffer, consistent with IP/display formatting, map construction and
existing payload copies. After direct stores, reflective Array.setChar is no
longer among the top 30 sampled leaves; map construction and string/keyword
operations dominate the remaining profile.

Keep JFR weights separate from byte-counter totals: the first main allocation
sample is approximately 1.9 GB in Full and 14.6–14.8 GB in Flow, consistent with
allocation carried from before recording. These single weights exceed the
segment's expected cost and heavily distort weighted class/site rankings.
Summaries preserve every weight plus first/maximum weight, sample counts and
excluded sampler-thread counts. No weight/sample is removed. Do not derive
bytes/packet, allocation percentages or a claimed allocation reduction from
these segmented JFR recordings.

Across the matched Ethernet Full matrix rows (4.32 million measured packets per
variant), GC count/time is 100/91 ms main versus 124/117 ms candidate. Native
Ethernet Full (1.44 million each) is 46/102 ms versus 39/75 ms. Flow matrix GC
is 3/3 ms versus 5/5 ms; native Flow is 15/50 ms versus 8/30 ms. These opposite
movements do not establish a GC benefit or regression. Allocation is unchanged;
collection timing and which adjacent sample pays the pause vary.

The 20k-output forced-GC retained-heap probe estimates Full 1091 → 1117 B/output,
Flow 237 → 237, excluding shared raw input. It holds inputs/results strongly
reachable and checks identity/shape. The roughly 26 B Full difference is a noisy
one-pair heap estimate, not evidence of an added retained field or a precise
memory bound. Output graphs/array/string shapes are unchanged. No RSS/native
retention, sustained soak, large production trace or live/NIC result is claimed.

Initial component probes also contain a boxed countdown. The later probe uses
a primitive countdown, removing approximately 24 B/iteration of instrumentation
allocation. Do not interpret that difference as a production saving. Paired
packet-xf/native counters, rather than these probes, establish allocation parity.

### Raw artifacts and reproduction details

[The complete comparison CSV](issue-44/comparison.csv) contains all 944 pairs:
final cases, historical/same-source controls, both rejected candidates and the
underwarmed pilot. Its `file`/`scenario` columns identify scope, input and mode;
throughput, CPU, allocation and GC before/after remain available per case. All
warmups and nine ordered samples remain in the corresponding EDN files.
The [manifest](issue-44/manifest.json) records exact source/driver/artifact
hashes. The final driver hash identifies reproduction code; the driver evolved
during investigation, and is not asserted to be the historic driver hash of
every pilot. Production hashes remain in each enhanced raw file.

```bash
clojure -M:dev -m paclo.dev.ethernet-perf-summary dev/issue-44/*.edn > /tmp/issue-44-comparison.csv
clojure -J-Xms512m -J-Xmx512m -M:dev -m paclo.dev.ethernet-perf '{:suite :matrix :only-mode :flow :packets 50000}'
clojure -J-Xms512m -J-Xmx512m -M:dev -m paclo.dev.ethernet-perf '{:suite :matrix :only-mode :flow :packets 50000 :reverse? true}'
clojure -J-Xms512m -J-Xmx512m -M:dev -m paclo.dev.ethernet-perf '{:suite :retained}'
clojure -J-Xms512m -J-Xmx512m -M:dev -m paclo.dev.ethernet-perf '{:refs ["e444b10"] :suite :profile :profile-id "e444b10" :jfr "/tmp/before"}'
clojure -J-Xms512m -J-Xmx512m -M:dev -m paclo.dev.ethernet-perf '{:refs [] :suite :profile :jfr "/tmp/after"}'
jfr print --json --stack-depth 8 --events jdk.ObjectAllocationSample,jdk.ExecutionSample,jdk.GarbageCollection /tmp/after-full.jfr > /tmp/after-full.json
python3 dev/script/summarize_ethernet_jfr.py /tmp/after-full.json
```

For same-source controls, copy the four `source-paths` files into a temporary
source tree at their original relative paths, and use its directory as the ref.
The recorded `/tmp/paclo-44-mac` contains main plus `accepted-mac.patch`.
Patches use zero context; apply to unmodified main with
`git apply --unidiff-zero path/to/patch`. All four patches have been checked
against unmodified main. `candidate-mac.patch` preserves the first pilot before
its explanatory comment was added; comments do not change the candidate logic.

## Verification and review handoff

Local required gates pass without changing workflows, dependencies or thresholds:

- `bash dev/script/codex.sh check`: 490 tests / 19036 assertions, ten JUnit
  tests and real native offline smoke; includes existing P06/P07/P08 properties,
  boundary/malformed frames, multi-DLT, PCAP/PCAPNG, fan-out and API contracts.
- `bash dev/script/codex.sh lint`: zero kondo warnings/errors; all 112 Eastwood
  namespaces analyzed, 593 informational warnings, zero exceptions; namespace,
  format and all 41 Markdown files pass. Four real Eastwood failure-exit probes
  pass, including the intentional unanalyzed-namespace failure.
- `bash dev/script/codex.sh perf`: 457.4 ms, unchanged 1000/1200 ms warn/fail.
- All 34 executable documentation examples and local links pass. Capture-format,
  cooked, Raw IP, NULL/LOOP and PCAPNG-contract generators pass `--check`.
- SpotBugs, CheckStyle, JaCoCo and its unchanged 25% line gate pass at 43.8%.
- `package`, JAR resource inspection and two isolated `-Srepro` JAR consumers
  pass outside the checkout. One exercises all six DLTs/full/flow/extensions/
  byte identity; the existing consumer covers exact DNS/snapshots/bounded fan-out,
  PCAPNG and window composition. `prepare` restores development test classes.
- The benchmark rejects an invalid suite with a nonzero exit; every successful
  suite and the 944-row summary command is exercised. All candidate patches
  apply to unmodified main; `git diff --check` passes.

Implementation commit `68ed59adcc3dc738155a7d2fb15d50a87daa5714` is on
[PR #58](https://github.com/nantes-rfli/paclo/pull/58).
Final-head CI evidence for all twelve unchanged jobs is maintained there after
the documentation-only handoff record, avoiding another evidence-commit cycle.
Supported-platform CI establishes correctness/compatibility,
not a live/NIC or cross-platform performance claim. Acceptance and Issue #44
closure remain independent-review decisions; no merge or release is performed.
