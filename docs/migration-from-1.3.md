<!-- markdownlint-disable MD013 -->
# Migration from v1.3.0 to v1.4.0

v1.4.0 is the approved next stable version and is **not published yet**. These
notes describe its candidate behavior, including P01–P08 and merged fixes.
The maintainer approved retaining capture-preserving Writer precedence/strict
validation (D1) and exact bounded DNS aggregation/explicit failures (D2).
These decisions have observable migration effects, including failures on some
formerly accepted inputs; review the checklist below before upgrading.
The [API contract](cljdoc-api-contract.md) specifies the exact rules, and the
[compatibility assessment](../dev/release-compatibility-version.md) retains the
released v1.3.0 comparison. Publication requires separate approval.

## Upgrade checklist

- Audit Writer maps for stale capture timestamps, lengths and DLT metadata.
- Rebaseline DNS RTT values/pair counts and QR-oriented client/server groups.
- Configure finite analysis/report limits and handle every nonzero CLI exit.
- Require complete reports when loss or cancellation is unacceptable.
- Validate the candidate JAR on your runtime; keep published v1.3.0 coordinates
  until v1.4.0 is actually available. See the [release notes](release-notes-1.4.0.md).

## Classic PCAP inputs

Valid byte arrays and plain maps with complete integer `:sec/:usec` continue to
work. Capture maps now preserve `:ts-sec/:ts-usec`, original wire length and
captured length. A complete capture pair wins over legacy keys. Previously,
copying a capture map to the writer could replace its time with the clock and
lose truncation. If intentionally retiming captured data, remove the old capture
pair explicitly; changing only `:sec` does not change the selected time.

This example writes three records and reads their times/lengths back:

<!-- paclo-doc-test: migration-classic-time -->
```clojure
(require '[paclo.core :as core])
(let [file (java.io.File/createTempFile "paclo-migration-" ".pcap")
      legacy {:bytes (byte-array 60) :sec 1700000000 :usec 123}
      captured (assoc legacy :ts-sec 1700000001 :ts-usec 456
                      :caplen 60 :len 120)
      ;; Keep bytes/length/framing; intentionally select a new legacy time.
      retimed (-> captured (dissoc :ts-sec :ts-usec)
                  (assoc :sec 1700000002 :usec 789))]
  (try
    (core/write-pcap! [legacy captured retimed] (.getPath file))
    (core/reduce-packets {:path (.getPath file) :max 3}
                         (fn [rows packet]
                           (conj rows (select-keys packet
                                                   [:ts-sec :ts-usec :caplen :len])))
                         [])
    (finally (.delete file))))
```

A partial capture pair now fails even alongside a complete legacy pair. Complete
selected pairs containing nil, fractions or invalid ranges fail. Missing both
pairs and partial **legacy** pairs still select the clock; do not use that
fallback for measured event time. Require a complete pair at your input boundary.
This example checks writer rejection and then supplies a verified complete pair:

<!-- paclo-doc-test: migration-invalid-time -->
```clojure
(require '[paclo.core :as core])
(let [file (java.io.File/createTempFile "paclo-invalid-time-" ".pcap")
      old-input {:bytes (byte-array 60) :sec 1700000000 :usec 123
                 :ts-sec 1700000001}]
  (try
    {:rejected (try (core/write-pcap! [old-input] (.getPath file)) false
                    (catch clojure.lang.ExceptionInfo e
                      (= "partial :ts-sec/:ts-usec timestamp" (.getMessage e))))
     ;; Only do this when upstream evidence supplies the missing component.
     :verified-time
     (do (core/write-pcap! [(assoc old-input :ts-usec 456)] (.getPath file))
         (core/reduce-packets {:path (.getPath file) :max 1}
                              (fn [_ packet]
                                (reduced (select-keys packet [:ts-sec :ts-usec])))
                              nil))}
    (finally (.delete file))))
```

If the complete legacy pair is intentionally authoritative, explicitly remove
both capture keys before writing, as in the retiming example. Do not remove
metadata indiscriminately or catch every writer failure and retry with “now”.
That can hide corrupt evidence and produce convincing but false RTT/window data.
Explicit `:caplen` must match array length and `:len` must be at least caplen;
selected timestamps/lengths must satisfy the [writer rules](cljdoc-api-contract.md#write-pcap).
Correct the producer or quarantine the record; do not silently clamp lengths or
truncate frames. caplen must fit the selected snaplen, while original len may exceed it.

The two-argument writer still selects Ethernet DLT 1/snaplen 65536. For a cooked
source, use the three-argument form with its actual native DLT, for example
`{:linktype 113 :snaplen 65536}`. Use 12 for Linux/macOS Raw IP packet DLT, not
savefile LINKTYPE 101. Mixed DLTs need separate Classic files or PCAPNG. Do not
erase `:linktype` to bypass mismatch checks. Classic output is incremental and
may be partial after failure; it has no atomic rollback.

## Read errors and data consumers

A malformed native read now raises an error instead of appearing to finish at
EOF. Default to failing the operation. If a valid prefix is explicitly useful,
use `reduce-packets-report` with `:error-mode :pass` and inspect `:stats`/`:error`,
or an error callback. A prefix is not a complete successful capture. Decode
issues are separate: retain string `:decode-error` handling and tolerate new
`:diagnostics` and `:linktype` keys. Prefer selecting known keys over rejecting
all extra fields. Unsupported framing can be read raw; it is not decoded as Ethernet.

## CLI wrappers and analytical results

- **Flow:** row fields/formats and captured-byte totals remain. Equal-score
  ranking/bidirectional orientation may change; don't snapshot arbitrary order.
  Default unique-flow limit is 100000. Set a suitable positive `--max-flows`;
  exhaustion/source failure propagates as a nonzero JVM exit, not DNS code 5.
- **DNS RTT:** native time now yields real millisecond RTT/mean rather than nil
  or truncated means. Strict question-aware matching, retries, expiry and
  quarantine can change pair counts. Rebaseline alerts using known transactions;
  use `--reorder-us`, timeout and reuse horizon for the actual traffic order.
- **DNS QPS:** counts are packets per bucket, including both query and response,
  and bytes are captured bytes. Divide by bucket duration in seconds for QPS.
  Client/server are QR-oriented roles, so response destinations join clients.
  Applications needing source/destination groups should project those addresses
  explicitly with the library. Full offline EOF replaces accidental early caps.
- **Bounds/errors:** old max-buckets could silently truncate; now exact reports
  and empty fills either fit configured finite bounds or fail before stdout.
  DNS usage/input/enum/flag exits remain 1/2/3/4; source/analysis/capacity failures
  use 5. Handle all nonzero exits, not only the old list. Exit 0 with dropped or
  cancelled delivery is possible: require stderr `:complete? true` when completeness
  matters. That flag still does not prove every DNS query has a response.

Formats/positional arguments are retained. Output volume, group keys, matches,
metadata and valid-file success can change. Review the [bounded CLI options](usage.md#bounded-dns-cli-reports-p07-b)
before increasing memory budgets. The approved v1.4.0 policy retains these
correctness and resource bounds; it does not restore silent truncation or guessed pairs.

## Choose the API and output format deliberately

Use `packet-xf` for pure raw/full/flow transformation; `reduce-packets` for owned
synchronous early termination, or `reduce-packets-report` for execution stats.
Use managed `with-open` capture for externally stopped streams and bounded
`stream/fan-out` for consumers. Abandoning a prefix of legacy lazy `packets` does
not close a producer blocked on its queue. Bytes remain mutable and shared;
treat published arrays as read-only.

Use explicit ordered `:extensions [dns-ext/annotate-dns]` for independent full
decode pipelines; `[]` disables hooks. Omission retains dynamic global
registration. Flow keys/aggregates/Top-N use `paclo.flow`; `top-n` takes an
options map such as `{:n 10}`. `paclo.window` and `paclo.dns` provide pure bounded
event-time analysis with explicit advance/finish, not CLI serialization or
implicit clocks. See [usage](usage.md) for runnable compositions.

| Information | Classic `core/write-pcap!` | `paclo.pcapng` event reader/writer |
| --- | --- | --- |
| Packet bytes/captured and original lengths | Yes, validated; one DLT/snaplen | Yes, within supported block contracts |
| Time | Selected integer microseconds; absent time uses clock fallback | Exact ticks/resolution/offset and explicit timestamp absence |
| Multiple sections/interfaces, comments/options | Not retained | Ordered supported metadata/owned octets retained |
| Precision/container identity | No nanosecond/section/byte-identical guarantee | Known semantics, not byte-identical reproduction |
| Publication | Incremental overwrite, may leave partial file | Exclusive atomic publication on supported Linux/macOS filesystems |

Native core PCAPNG reads normalize to microseconds and lose rich metadata.
For that metadata use `pcapng/open-source` with `with-open` and reduction, then
`pcapng/write-pcapng!` preserving events. Authoring and explicitly lossy modes
have different obligations; see [PCAPNG guide](pcapng.md). A `.pcapng` filename
does not switch Classic Writer format. SPB time can be absent: choose a measured
analysis policy instead of converting absence to zero or current time.

JDK 17 and 21 remain supported with Clojure 1.12.x and system libpcap. The v1.4.0
candidate restores JDK17-compatible distributed classes (major 61); the published
v1.3.0 JAR contains major 65 and needs JDK21, or a Java17 source build. Validate the exact JAR
you deploy; a JDK17 source build alone does not validate a JDK21-built artifact.
