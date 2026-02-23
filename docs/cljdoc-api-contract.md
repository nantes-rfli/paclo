# Public API Contract (for cljdoc / v1.0)

This page defines the library-level contract that is intended to stay stable at v1.0.
It complements the function docstrings and provides one place for arguments, return shapes, and error behavior.

---

## Scope

Public API namespaces:

- `paclo.core`
- `paclo.decode-ext`

Internal namespaces (non-API surface):

- `paclo.pcap`
- `paclo.parse`
- `paclo.proto.*`

---

## `paclo.core`

### `bpf`

Signature:

```clojure
(bpf form)
```

Input contract:

- `nil` => returns `nil`
- `string` => returns the same string
- `keyword` => protocol keyword (`:udp`, `:tcp`, `:icmp`, `:icmp6`, `:arp`, `:ip`, `:ipv4`, `:ip6`, `:ipv6`)
- `vector` => DSL form (`:and`, `:or`, `:not`, `:proto`, host/net/port operators)

Output:

- BPF filter string for libpcap

Errors:

- Throws `ex-info` for unsupported form/operator/keyword
- May throw number parsing errors for invalid port inputs in range/port operators

---

### `packets`

Signature:

```clojure
(packets opts)
```

Core options:

- Source:
  - offline: `{:path "..."}`
  - live: `{:device "..."}`
- Filter:
  - `:filter` accepts BPF string or BPF DSL (`keyword` / `vector`)
- Decode:
  - `:decode? true` annotates each packet with either `:decoded` or `:decode-error`
- Stream transform:
  - `:xform` accepts a transducer and is applied via `sequence`

Passthrough options:

- All additional capture options are passed through to `paclo.pcap/capture->seq`
- Default stop conditions come from `capture->seq` defaults (`:max`, `:max-time-ms`, `:idle-max-ms`)

Output:

- Lazy sequence of packet maps

Decoded packet behavior:

- Parse success => `:decoded` map is attached
- Parse failure => `:decode-error` string is attached
- If `:decoded` is present, `paclo.decode-ext/apply!` is invoked

Errors:

- Throws `ex-info` when `:filter` has an unsupported type
- Capture/open/filter errors from underlying pcap layer may propagate as exceptions

---

### `write-pcap!`

Signature:

```clojure
(write-pcap! packets out-path)
```

Input contract:

- `packets` is a seq of:
  - `byte-array`, or
  - `{:bytes <byte-array> :sec <long> :usec <long>}` (timestamp keys optional)
- `out-path` is required and must be non-blank

Output:

- Returns underlying writer result from `bytes-seq->pcap!` (successful side effect is PCAP file creation)

Errors:

- Throws `ex-info` when output path is missing/blank
- Throws `ex-info` when packet map entries do not contain `:bytes`

---

### `list-devices`

Signature:

```clojure
(list-devices)
```

Output:

- Sequence of maps like `{:name "en0" :desc "Wi-Fi"}`

Errors:

- May propagate environment/libpcap errors depending on runtime platform state

---

### `-main` (repository convenience entrypoint)

Signature:

```clojure
(-main & _)
```

Behavior:

- Prints guidance messages for common repo commands
- This is not an application runtime API and is provided to keep `clojure -M:run` non-failing

---

## `paclo.decode-ext`

### `register!`

Signature:

```clojure
(register! k f)
```

Input contract:

- `k`: hook key (typically namespaced keyword)
- `f`: `(fn [m] m')` where `m` is a packet map

Behavior:

- Registers hook in execution order
- Re-registering the same key overwrites previous hook and moves it to tail

Output:

- Returns `k`

---

### `unregister!`

Signature:

```clojure
(unregister! k)
```

Behavior:

- Removes hook identified by key

Output:

- Returns `nil`

---

### `installed`

Signature:

```clojure
(installed)
```

Output:

- Sequence of installed hook keys in execution order

---

### `apply!`

Signature:

```clojure
(apply! m)
```

Execution guard:

- Hooks are applied only when:
  - `m` is a map
  - `:decoded` exists
  - `:decode-error` is absent

Hook behavior:

- Hooks run in registration order
- Hook exceptions are swallowed (packet processing continues)
- Non-map hook return values are ignored and previous map is kept

Output:

- Updated packet map (or original map if not applicable)

---

## Stability Notes

- The function names and behavior above are the v1.0 freeze target.
- Additive options are allowed after v1.0 if they are backward compatible.
- Internal namespace details are not covered by this contract.
