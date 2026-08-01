# Public API Contract (v1.x)

This page defines the stable library contract for v1.x.
It is intentionally compact and focused on user-facing namespaces.

## Scope

Public namespaces:

- `paclo.core`
- `paclo.stream`
- `paclo.decode-ext`

Internal namespaces (not covered by compatibility guarantees):

- `paclo.pcap`
- `paclo.parse`
- `paclo.proto.*`
- `paclo.stream.impl`

## `paclo.core`

### `bpf`

```clojure
(bpf form)
```

- Input: `nil`, string, protocol keyword, or DSL vector
- Output: libpcap BPF filter string (or `nil`)
- Errors: throws `ex-info` for unsupported form/operator/keyword

### `packets`

```clojure
(packets opts)
```

- Input:
  - source: `:path` (offline) or `:device` (live)
  - `:filter`: BPF string / keyword / DSL vector
  - optional `:decode?`, `:xform`, and additional capture options
  - live queues remain bounded and blocking by default; opt-in
    `:queue-mode :dropping` may be combined with `:queue-cap` and
    `:on-queue-stats`
- Output: lazy sequence of packet maps
- Decode behavior (`:decode? true`):
  - success -> packet includes `:decoded`
  - failure -> packet includes `:decode-error`
  - when `:decoded` exists, `paclo.decode-ext/apply!` is invoked
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
  - honors `reduced` for immediate early termination
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

### Managed capture

```clojure
(start-capture opts)
(capture-packets capture)
(stop-capture! capture)
(capture-stats capture)
```

- `start-capture`:
  - accepts a live `:device` or offline `:path` plus the compatible filter,
    decode, transducer, stopping, queue, and error options
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

### `write-pcap!`

```clojure
(write-pcap! packets out-path)
```

- Input:
  - `packets`: seq of `byte-array` or `{:bytes ... :sec ... :usec ...}` maps
  - `out-path`: non-blank output path
- Output: writes PCAP file; returns writer result
- Errors: throws `ex-info` for invalid/missing output path or invalid packet entry

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
- supports `seq`, `reduce`, and `transduce`
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
```

- Applies hooks only when `m` is a map with `:decoded` and without `:decode-error`
- Hook behavior:
  - execution order = registration order
  - hook exceptions are swallowed
  - non-map hook return values are ignored
- Returns updated (or original) packet map

## Stability notes

- Items above are the v1.x compatibility baseline.
- Backward-compatible additive changes are allowed in v1.x.
- Internal namespace details are intentionally excluded from this contract.
