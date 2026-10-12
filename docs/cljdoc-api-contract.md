# Public API Contract (v1.x)

This page defines the stable library contract for v1.x.
It is intentionally compact and focused on user-facing namespaces.

## Scope

Public namespaces:

- `paclo.core`
- `paclo.stream`
- `paclo.decode-ext`
- `paclo.proto.dns-ext/annotate-dns` and `paclo.proto.tls-ext/annotate-tls-sni`
  (supported annotation functions; other protocol internals remain excluded)

Internal namespaces (not covered by compatibility guarantees):

- `paclo.pcap`
- `paclo.parse`
- `paclo.proto.*` except the supported annotation functions listed above
- `paclo.stream.impl`

## Packet data contracts

These contracts describe built-in transformations before user extensions and
`:xform`. They share one implementation across `packet-xf`, `packets`, both
synchronous reductions, and managed capture. User functions can replace maps,
remove keys, or change their shape; Paclo does not validate every output packet.
Native captures identify their source link type. Full and flow decoding support
Ethernet (including VLAN tags); other types remain readable as raw packets.
Additional decoders and full PCAPNG metadata/file preservation remain P08.

### Raw capture packets

| Key | Type | Meaning |
| --- | --- | --- |
| `:bytes` | Java `byte[]` | Captured bytes; mutable, not persistent Clojure data |
| `:ts-sec` | integer | Epoch seconds as returned by native libpcap |
| `:ts-usec` | integer | Microsecond component, normally `0..999999` |
| `:caplen` | integer | Captured byte count, equal to array length |
| `:len` | integer | Original wire length; truncation has `:caplen < :len` |
| `:linktype` | nonnegative integer | Native libpcap DLT for this capture handle |

Normal native reads supply all six keys. `packet-xf {}` preserves its input
unchanged, including missing metadata. Metadata is not inferred or repaired by
decoding. Reader timestamp boundaries depend on libpcap; see the
[writer portability note](#write-pcap) for post-2038 seconds. File open, malformed
PCAP records and read failures can throw or terminate according to capture error
policy; they do not necessarily yield a packet map or packet diagnostics.

Fan-out shares the same packet map and byte-array references across branches.
An immutable map does not make its array immutable. Treat published bytes as
read-only; copy explicitly before modifying them:

```clojure
(let [private-bytes (aclone ^bytes (:bytes packet))]
  (aset-byte private-bytes 0 (byte 0))
  (assoc packet :bytes private-bytes))
```

Paclo does not copy every packet for fan-out or diagnostics.

### Link-type dispatch

P05 adds source link-type awareness in `[Unreleased]`; released v1.3.0 does not
detect source link types.

`:linktype` is the numeric value from
[`pcap_datalink`](https://www.tcpdump.org/manpages/pcap_datalink.3pcap.html),
acquired once per capture execution after offline open or live activation and
before `on-ready`. It applies to that handle's packets, including `stop?` and
user `:xform` inputs. Native acquisition failures never default to Ethernet:
negative results throw `ex-info` with `:phase :pcap-datalink`, `:rc` and native
`:err`; native exceptions propagate. The owner closes the handle. Synchronous
and managed setup throw before readiness; lazy capture uses its existing
background `:error-mode` policy. No packet is emitted on acquisition failure.

DLT values are platform libpcap constants, not necessarily the numeric LINKTYPE
stored in a savefile global header (for example DLT_RAW varies by platform).
Do not compare arbitrary savefile LINKTYPE codes directly to `:linktype`.
The supported Linux/macOS fixtures use DLT_EN10MB 1, DLT_LINUX_SLL 113 and
DLT_NULL 0. The actual native value is retained without name conversion.

Full/flow decode accepts explicit integer DLT_EN10MB (1). Explicit non-Ethernet,
unknown, negative, nil or invalid values yield string `:decode-error`
`"unsupported linktype"` and append
`{:stage :decode :reason :unsupported-linktype :linktype value}` (flow uses
`:stage :flow`), without an Ethernet byte location. This check precedes short-frame classification.
Full decode retains raw bytes/metadata, removes stale input `:decoded` and
skips all post-decode hooks. Flow retains capture metadata/linktype and emits
neither bytes nor flow/IP/port fields. Raw mode passes packets through unchanged.

Standalone `packet-xf` cannot detect framing from arbitrary bytes: when the
`:linktype` key is absent, it preserves the legacy Ethernet assumption.
Explicit presence (including nil) is different from absence. A supplied DLT is
trusted as metadata; Paclo does not sniff bytes or convert packet formats.

### Full decode packets

`{:decode? true}` preserves input keys and metadata, adding `:decoded` on parse
success or the existing string `:decode-error` on a thrown decode failure.
Ordinary successful packets omit `:diagnostics`. Existing input keys are retained
except stale `:decoded` on unsupported link types, as specified above;
for example a pre-existing `:decode-error` key prevents extension execution even
when its value is nil. A successful decode does not clear such a key.

The best-effort nested representation is:

| Path | Built-in values |
| --- | --- |
| `:decoded` | Ethernet map: `:type :ethernet`, string MAC `:src`/`:dst`, numeric `:eth`, `:l3` |
| `[:decoded :vlan-tags]` | Vector of maps with `:tpid`, `:pcp`, boolean `:dei`, `:vid`; normally absent without tags |
| `[:decoded :l3]` | IPv4, IPv6, ARP or `{:type :unknown-l3 :eth number}` |
| `[:decoded :l3 :src]`, `:dst` | IP strings for IPv4/IPv6; IPv6 also has `:src-compact`/`:dst-compact` |
| `[:decoded :l3 :protocol]` | IPv4 protocol number; absent for IPv6 |
| `[:decoded :l3 :next-header]` | IPv6 final next-header number, or nil for an incomplete extension chain |
| `[:decoded :l3 :l4]` | TCP/UDP/ICMP map, fragment map or `:unknown-l4` map; absent on ARP/unknown L3 |
| `[:decoded :l3 :l4 :src-port]`, `:dst-port` | Integer TCP/UDP ports; absent on fragments/other L4 |
| `[:decoded :l3 :l4 :payload]` | Usually byte-array; truncated UDP retains the legacy empty vector |
| `[:decoded :l3 :l4 :app]` | Minimal DNS on UDP/53, possibly nil when fewer than 12 DNS bytes; otherwise absent |
| `[:decoded :l3 :flow-key]` | Existing string-address flow map, or nil after an incomplete IPv6 extension chain |

IPv4 includes header fields (`:version`, `:ihl` in bytes, `:total-length`, `:tos`,
`:id`, `:flags-frag`, `:ttl`, `:header-checksum`); IPv6 includes `:version`,
`:traffic-class`, `:flow-label`, `:payload-length`, `:hop-limit`. Both include
boolean `:frag?` and `:frag-offset` (8-byte units, nil without fragmentation).
TCP exposes sequence/acknowledgement numbers, flags, window/checksum,
`:urgent-pointer`, `:header-len` and `:data-len` in bytes. UDP exposes `:length`,
`:checksum`, `:data-len`. ICMP exposes `:icmp-type`, `:code`, `:checksum`, names,
summary and payload. ARP uses `:op`, MAC `:sha`/`:tha` and IPv4 `:spa`/`:tpa`
strings (nil for other protocol types); incomplete ARP can be only `{:type :arp}`.

These are partial parsers, without checksum validation or reassembly. Unknown
Ethertype remains `:unknown-l3` with a diagnostic; unknown L4 protocol remains
`:unknown-l4` with `:proto` and payload and does not itself generate a diagnostic.
Noninitial fragments retain `:ipv4-fragment`/`:ipv6-fragment`, offset and payload.
Truncated UDP retains `:unknown-l4` with `:reason :truncated-udp` and a diagnostic;
incomplete IPv6 extension chains retain nil next-header/flow-key and unknown L4.
Other insufficient headers can throw and produce `:decode-error`. Available
bytes can be parsed even when the declared payload length exceeds capture length.
Diagnostics are not a complete validation or completeness guarantee. Missing
keys, present nil values and explicit unknown keywords have different meanings.
DNS/TLS annotation functions follow the [extension contract](#supported-protocol-annotations).

### Flow projection packets

`{:decode-mode :flow}` normally returns only these flat fields:

| Key | Type / missing value | Meaning |
| --- | --- | --- |
| `:ip-version` | integer 4 or 6 | IP version |
| `:protocol` | integer | IPv4 protocol / IPv6 final next-header number |
| `:src-ip`, `:dst-ip` | unsigned integer `0..4294967295` or two-long vector | IPv4 numeric address / IPv6 `[high-long low-long]` with signed JVM words |
| `:src-port`, `:dst-port` | integer `0..65535` or nil | TCP/UDP ports; nil for other protocols or noninitial fragments |
| `:ts-sec`, `:ts-usec`, `:caplen`, `:len`, `:linktype` | original value or nil | Capture metadata, always present in flow output |

Flow reads only the first four transport bytes needed for ports. It can succeed
where full decode rejects a short TCP/UDP header. It skips supported IPv6 extension
headers with a bounded chain and does not validate all lengths/checksums. Invalid
IP version/header length, short frames/headers, and unsupported Ethertypes return
the five metadata keys plus string `:decode-error` and `:diagnostics`, without
flow fields. ARP is unsupported for flow projection. Neither success nor failure
includes raw `:bytes` or nested `:decoded`. Existing diagnostics are retained.

### Structured diagnostics

P04 adds `:diagnostics` only when an issue is observed: a vector of ordinary EDN
maps, ordered by discovery/execution. Every entry requires keyword `:stage` and
`:reason`. Decode failures retain their prior `:decode-error` text; a best-effort
partial/unsupported decode can have diagnostics and `:decoded` without an error.

| Stage | Reason | Classification |
| --- | --- | --- |
| `:decode`, `:flow` | `:unsupported-linktype` | Explicit link type has no supported decoder; includes `:linktype` |
| `:decode`, `:flow` | `:short-frame` | Fewer than 14 Ethernet bytes (missing full-decode bytes also uses zero available) |
| `:decode`, `:flow` | `:truncated-header` | Known required header bytes are missing |
| `:decode`, `:flow` | `:malformed-packet` | Observed invalid version/header length or invalid IPv6 options; flow also bounds extension chains |
| `:decode`, `:flow` | `:unsupported-ethertype` | Decoder has no implementation for this Ethertype; includes numeric `:ethertype` |
| `:decode`, `:flow` | `:unexpected-failure` | Unclassified exception; no inference from its message |
| `:extension` | `:extension-exception` | Hook threw; includes `:exception-class` and `:message` strings |
| `:extension` | `:extension-non-map` | Hook returned any non-map value, including nil |

When known, `:location` is `{:offset integer :required integer :available integer}`:
zero-based absolute frame byte offset of the required region, its required size,
and available captured bytes in that region/buffer. Units are bytes. Omit it when
no precise region is available. Stages/reasons are additive stable keywords;
consumers should tolerate future values and extra fields. No Throwable, function,
byte-array or native pointer is retained in built-in diagnostics. Diagnostics can
round-trip through `pr-str` / `clojure.edn/read-string`; entire packets containing
byte arrays cannot be assumed to do so.

`:extension-error-mode :ignore|:report` is for full decode only. Omission defaults
to `:ignore`, preserving legacy hook outputs and failure isolation. Explicit use
requires literal `:decode? true`; nil/unknown modes and raw/flow combinations throw
`ex-info` before source open. With `:report`, failures append diagnostics with
zero-based `:index` in selected/global execution order. Failed results are discarded
and later functions receive the preceding map plus diagnostics. Global registration
remains dynamic; arbitrary registry keys are not stored in diagnostics. User hooks
and `:xform` can themselves reshape/remove diagnostics, as with other packet keys.
Capture `:error-mode :throw|:pass` governs source failures separately.

Statistics retain schema version 1 and their existing fields: `:stop-reason`,
`:error`, `:state` where applicable and all counters. `:packets :decode-errors`
counts the existing truthy `:decode-error` after built-in transformation, before
`:xform`; unsupported best-effort decoding and extension diagnostics alone do not
increment it. Unsupported link-type failures do increment it in full/flow mode.
No diagnostic counters are added to reduction, capture or fan-out
statistics. Packet diagnostics are the primary record; reducers can collect them.

## `paclo.core`

### `bpf`

```clojure
(bpf form)
```

- Input: `nil`, string, protocol keyword, or DSL vector
- Output: libpcap BPF filter string (or `nil`)
- Errors: throws `ex-info` for unsupported form/operator/keyword

### `packet-xf`

```clojure
(packet-xf opts)
```

- Input: packet maps, normally including `:bytes`, supplied through ordinary
  Clojure transducer composition
- Options:
  - `:decode? true`: full decode into `:decoded`; if decoding fails,
    return a packet map with `:decode-error`
  - `:decode-mode :flow`: flat numeric flow projection; IPv4 addresses are
    unsigned longs and IPv6 addresses are two-long vectors
  - neither decode option: identity transducer, leaving each packet unchanged
  - `:extensions`: a vector of functions (`fn?`), accepted only with
    `:decode? true`. Key presence matters: `nil`, other collection types and
    non-function elements throw `ex-info` at construction. Raw and flow modes
    reject explicit selection, including `[]`
  - `:extension-error-mode`: full-decode hook failure policy; see
    [structured diagnostics](#structured-diagnostics)
- `:decode?` and `:decode-mode` are mutually exclusive; unsupported
  decode modes and combined options throw `ex-info` at construction
- With full decode, omission of `:extensions` uses the current process-wide
  `paclo.decode-ext` hooks on each packet. `[]` runs none. An explicit vector
  selects exactly its functions in order, retains duplicates, and passes each
  map result to the next function. It is retained as pipeline configuration
  and never merged with or re-read from the global registry
- Functions run only when `:decoded` is present and `:decode-error` is absent.
  Exceptions and non-map results preserve the preceding map; later functions
  still run. Pure functions give deterministic results for the same input and
  explicit selection. Flow mode does not run full-decode extensions
- Output: a transducer, suitable for `comp`, `sequence`, `into`, or
  `transduce`; no capture is opened by constructing it

<!-- paclo-doc-test: api-contract-packet-xf -->

```clojure
(into []
      (comp (packet-xf {:decode-mode :flow})
            (filter #(= 17 (:protocol %)))
            (map :dst-port))
      (packets {:path "test/resources/dns-sample.pcap"}))
```

### `packets`

```clojure
(packets opts)
```

- Input:
  - source: `:path` (offline) or `:device` (live)
  - `:filter`: BPF string / keyword / DSL vector
  - `:decode? true` for full decode, or `:decode-mode :flow` for numeric
    flow projection (they cannot be combined)
  - optional `:extensions` vector with exactly the `packet-xf` contract
  - optional `:xform` transducer, applied after decode and extensions in the built-in
    `packet-xf` transformation
  - capture limits: `:max` (default 100 captured packets),
    `:max-time-ms` (default 10000 ms), and `:idle-max-ms` (default
    3000 ms; continuous idle, mainly live)
  - bounded producer queue: `:queue-cap` (default 1024),
    `:queue-mode :blocking` (default) or `:dropping`,
    and optional `:on-queue-stats`
- Output: lazy sequence of packet maps
- Decode and extension behavior: identical to `packet-xf`; invalid extension
  configuration fails before opening the source
- Termination:
  - offline EOF stops the source, unless a count/time/predicate limit stops
    it first
  - consuming only `(take n ...)` does **not** explicitly cancel the
    background producer or close its source; use synchronous reduction or a
    managed capture for predictable early cleanup
- Errors:
  - throws `ex-info` for invalid `:filter` type
  - libpcap open/filter/capture errors may propagate

### `reduce-packets`

```clojure
(reduce-packets opts rf init)
```

- Input:
  - the same source, filter, decode, transducer, and stopping options as
    `packets`
  - optional `:decode-mode :flow` for a flat low-allocation flow projection
  - a reducing function and initial accumulator
- Output: the completed accumulator
- Behavior:
  - reads and reduces synchronously without a queue or intermediate lazy seq
  - fuses `:xform` into the reducing function
  - honors `reduced` for immediate early termination and source cleanup
  - preserves the compatible `:decode? true` result and extension behavior
  - flow mode returns capture metadata plus numeric source/destination IP,
    protocol, and ports; IPv4 addresses are unsigned longs and IPv6 addresses
    are `[high-long low-long]`
  - `:decode?` and `:decode-mode` cannot be combined
- Errors:
  - throws `ex-info` for invalid `:filter` type
  - honors `:error-mode :throw|:pass` and `:on-error`

### `reduce-packets-report`

```clojure
(reduce-packets-report opts rf init)
```

- Input and processing behavior match `reduce-packets`
- Output: `{:result completed-accumulator :stats execution-stats}`
- Statistics:
  - data-only, schema-versioned map
  - includes source, timing, packet counts, stop reason, and error description
  - `:queue` is `nil` because synchronous reduction has no producer queue
  - live capture includes final portable libpcap counters when available
- Stop reasons include `:max-packets`, `:max-time`, `:idle-timeout`,
  `:predicate`, `:reduced`, `:eof`, and `:error`
- EOF is not equivalent to exhausting the default count of 100 packets:
  large files need explicitly raised count and time limits

### Managed capture

```clojure
(start-capture opts)
(capture-packets capture)
(stop-capture! capture)
(capture-stats capture)
```

- `start-capture`:
  - accepts a live `:device` or offline `:path` plus the compatible filter,
    decode, extension, transducer, stopping, queue, and error options; the capture limit
    and producer queue defaults are the same as for `packets`
  - opens the source and installs BPF synchronously
  - returns an opaque `java.io.Closeable` handle intended for `with-open`
- `capture-packets`:
  - returns one lazy, single-consumer packet stream
  - may be called only once per managed capture
  - must be consumed within the capture's `with-open` scope
- `stop-capture!`:
  - asynchronously requests capture termination
  - is idempotent and safe to call from another thread
- closing the handle:
  - requests termination, abandons queued values, waits for the producer, and
    releases the libpcap handle
  - is idempotent
- `capture-stats`:
  - returns a data-only schema-versioned snapshot during execution or after
    close
  - includes live packet/queue counts while running and final libpcap counters
    after termination
- Managed capture has exactly one direct packet consumer. Compose that stream
  with `paclo.stream/fan-out` when multiple bounded consumers are required.
  Own the capture, fan-out and acquired branch handles together with
  `with-open`, and pass `:cancel!` when fan-out shutdown needs to unblock
  the capture source.

### `write-pcap!`

```clojure
(write-pcap! packets out-path)
```

- Input:
  - `packets`: seq of `byte-array` or packet maps with a required byte-array `:bytes`
  - `out-path`: non-blank output path
- Timestamp selection, in order:
  - A complete `:ts-sec`/`:ts-usec` pair takes precedence, even when legacy values
    conflict or are invalid. A partial new pair throws `ex-info`, even if a
    complete legacy pair is present.
  - When neither new key exists, a complete legacy `:sec`/`:usec` pair is used.
  - Otherwise use current wall-clock time, including raw byte-arrays, maps
    without timestamps, and partial legacy pairs.
- The selected pair must contain integers: epoch seconds in `0..4294967295`
  and microseconds in `0..999999`. Explicit zero is valid. Presence is based on
  keys, so a complete pair containing `nil`, non-integers, or out-of-range values
  throws `ex-info`. Older callers could incidentally coerce some numeric values
  or fall back on `nil`; these invalid complete inputs are now rejected.
- Captured length is the byte-array length. Explicit `:caplen` must equal it.
  Original `:len` is retained when present, otherwise defaults to captured length.
  Explicit lengths must be integers in `0..4294967295`, with `:len >= :caplen`.
  Negative, fractional, `nil`, inconsistent, or overflowing values throw `ex-info`.
  The byte-array itself remains subject to JVM array-size limits.
- Output: preserves packet order, bytes, selected timestamps, captured length,
  and original length, including truncated records. Writes classic Ethernet PCAP
  with snaplen 65536 and microsecond precision. Source global headers, link types,
  snaplen, byte order, and precision are not copied; this is packet metadata
  preservation, not complete source-file preservation or PCAPNG support.
  Packet `:linktype` is ignored by the writer. Saving non-Ethernet bytes under
  its Ethernet header without format conversion cannot produce correct replay.
  Broader output/link-type and complete file round trips remain P08.
- Errors: throws `ex-info` for invalid/missing output path, missing map `:bytes`,
  invalid byte-array inputs, and invalid selected metadata. Native I/O errors retain
  existing behavior; handles and dumpers close when packet processing throws.
- Portability: unsigned seconds fit the PCAP record, but older system libpcap
  readers can expose seconds above `2147483647` as negative (observed with macOS
  system libpcap). Those negative reader values fail writer validation; numeric
  timestamp round trips beyond 2038 depend on the installed libpcap. Paclo does
  not reinterpret native reader timestamps in this change.

Direct packet-map metadata preservation is implemented by P02 in `[Unreleased]`;
released v1.3.0 still requires timestamp adaptation and loses original lengths.

### `list-devices`

```clojure
(list-devices)
```

- Output: sequence like `{:name "en0" :desc "Wi-Fi"}`
- Errors: runtime/libpcap errors may propagate

### `-main`

```clojure
(-main & _)
```

- Behavior: prints repository usage hints for `clojure -M:run`
- Note: convenience entrypoint, not an application runtime API

## `paclo.stream`

### `fan-out`

```clojure
(fan-out source branches)
(fan-out source branches opts)
```

- `source` must be seqable
- `branches` must contain at least two keyword IDs
- every branch config requires `:buffer-mode :blocking|:dropping`
- `:buffer-cap` is a positive integer and defaults to 1024
- optional `:cancel!` releases an externally waiting source during shutdown
- optional `:close-timeout-ms` bounds dispatcher shutdown
- returns an opaque `java.io.Closeable` handle intended for `with-open`
- preserves source order within each branch and shares value references rather
  than copying values

### `branch`

```clojure
(branch fanout branch-id)
```

- returns an opaque `Seqable`, `IReduceInit`, and `java.io.Closeable` handle
- each branch ID may be acquired once and drained by one consumer
- supports `seq`, `reduce`, and `transduce`; a reducer returning
  `reduced` closes that branch early
- closing one branch does not close sibling branches
- `:blocking` avoids branch-local drop but may backpressure all branches
- `:dropping` isolates a slow branch by dropping new values when its buffer is
  full

### `stats`

```clojure
(stats fanout)
```

- returns a data-only schema-version 1 snapshot during or after execution
- records source receipt; branch offer, enqueue, delivery, drop, cancellation,
  and abandonment; buffer depth and backpressure; lifecycle and error fields
- does not include capture/libpcap statistics or application business metrics
- terminal snapshots remain available after close

## `paclo.decode-ext`

### `register!`

```clojure
(register! k f)
```

- Registers hook function `(fn [m] m')` under key `k`
- Re-registering the same key overwrites previous hook and moves it to tail
- Returns `k`

### `unregister!`

```clojure
(unregister! k)
```

- Removes hook by key
- Returns `nil`

### `installed`

```clojure
(installed)
```

- Returns installed hook keys in execution order

### `apply!`

```clojure
(apply! m)
(apply! m extensions)
(apply! m extensions error-mode)
```

- Applies hooks only when `m` is a map with `:decoded` and without `:decode-error`
- Hook behavior:
  - execution order = registration order
  - hook exceptions are swallowed
  - non-map hook return values are ignored
- Returns updated (or original) packet map
- The registry is process-wide; existing transforms consult the installed
  hooks when processing packets. The two-argument arity applies only the
  supplied functions, in their supplied order, with the same eligibility and
  failure policy. Core validates `:extensions` at construction; this lower-level
  function does not validate configuration. The third arity takes `:ignore`
  or `:report`, with nil extensions selecting current global hooks; the two-argument
  arity retains its previous nil-as-empty behavior. Reporting follows the
  [diagnostics contract](#structured-diagnostics).

## Supported protocol annotations

- `paclo.proto.dns-ext/annotate-dns`: ordinary packet-map function adding
  DNS summary and best-effort qname, qtype, qtype-name and qclass fields.
- `paclo.proto.tls-ext/annotate-tls-sni`: ordinary packet-map function adding
  best-effort TLS ClientHello SNI, ALPN and summary, without stream reassembly.
- Unrelated packets pass through unchanged; parsed fields are best-effort and
  omitted when unavailable. Existing protocol `register!` functions install
  these same annotation functions.
- Repository CLI consumers include `:dns-ext` for the DNS namespace; both
  namespaces remain included in the dependency JAR.

Explicit selection and the public annotations are additions in `[Unreleased]`
(P03); released v1.3.0 supports the global registry only.

## Stability notes

- Items above are the v1.x compatibility baseline.
- Backward-compatible additive changes are allowed in v1.x.
- Internal namespace details are intentionally excluded from this contract.
