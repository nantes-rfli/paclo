# Migration Guide: 0.4 -> 1.0

This guide summarizes what to check when moving from `v0.4.x` to `v1.0.0`.

## Scope

- Library API (`paclo.core`, `paclo.decode-ext`)
- Official CLI examples (`pcap-filter`, `pcap-stats`, `flow-topn`, `dns-qps`, `dns-topn`)
- Runtime/CI compatibility expectations

## Quick checklist

- [ ] Use only public namespaces:
  - `paclo.core`
  - `paclo.decode-ext`
- [ ] Stop depending on internal namespaces (`paclo.pcap`, `paclo.parse`, `paclo.proto.*`)
- [ ] Run on `Clojure 1.12.x` (official support baseline)
- [ ] If you wrap CLI commands, handle exit codes `1/2/3/4` explicitly
- [ ] Re-run your smoke tests with `clojure -M:test`

## What changed from 0.4

### 1) Public API boundary is now explicit

The public/stable API surface is fixed to:

- `paclo.core`: `bpf`, `packets`, `write-pcap!`, `list-devices`
- `paclo.decode-ext`: `register!`, `unregister!`, `installed`, `apply!`

Internal namespaces remain usable for local experiments, but they are out of compatibility guarantees in `v1.0+`.

### 2) Compatibility policy tightened

- Official Clojure support is `1.12.x`.
- Compatibility matrix target is JDK `17/21`, macOS/Linux, x86_64/arm64
  (arm64 is monitored in CI and may become a required gate later).

If you are still pinned to Clojure `1.11.x`, upgrade first.

### 3) CLI error contract is fixed

For official CLI commands, the shared error exit codes are:

- `1`: missing required args / usage
- `2`: input file not found
- `3`: invalid enum value (group/mode/metric/format)
- `4`: invalid flag/value

Normal output is emitted to `stdout`; diagnostics and warnings go to `stderr`.

### 4) `clojure -M:run` behavior

`clojure -M:run` is kept as a convenience entrypoint and prints usage guidance.
It is not an app runtime API.

## Suggested migration steps

1. Search for internal namespace usage:

```bash
rg -n "paclo\\.(pcap|parse|proto)" src test dev
```

1. Replace direct internal calls with public API where possible:

```clojure
;; before (internal)
(require '[paclo.pcap :as p])

;; after (public)
(require '[paclo.core :as core])
```

1. Validate CLI wrappers/scripts against exit code contract:

```bash
clojure -M:dev -m examples.pcap-stats
echo $?   # expect 1
```

1. Run full regression tests:

```bash
clojure -M:test
```

## Deprecation timeline policy (v1.0+)

- `v1.x`: backward-compatible additions are allowed.
- Any future deprecation must be announced before removal.
- Breaking removals are planned no earlier than the next major (`v2.0.0`).
