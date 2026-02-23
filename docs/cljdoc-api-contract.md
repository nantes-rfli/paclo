# Public API Contract (v1.0)

This page defines the stable library contract for v1.0.
It is intentionally compact and focused on user-facing namespaces.

## Scope

Public namespaces:

- `paclo.core`
- `paclo.decode-ext`

Internal namespaces (not covered by compatibility guarantees):

- `paclo.pcap`
- `paclo.parse`
- `paclo.proto.*`

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
- Output: lazy sequence of packet maps
- Decode behavior (`:decode? true`):
  - success -> packet includes `:decoded`
  - failure -> packet includes `:decode-error`
  - when `:decoded` exists, `paclo.decode-ext/apply!` is invoked
- Errors:
  - throws `ex-info` for invalid `:filter` type
  - libpcap open/filter/capture errors may propagate

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

- Items above are the v1.0 compatibility baseline.
- Backward-compatible additive changes are allowed in v1.x.
- Internal namespace details are intentionally excluded from this contract.
