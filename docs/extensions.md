# Decode Extensions

`paclo.decode-ext` lets you annotate or transform decoded packets immediately after decode,
without changing the base parser (`parse/packet->clj`).

## How hooks work

- A hook is a function `m -> m'` where `m` is a packet map from `(packets {:decode? true ...})`.
- Hooks run only when `:decoded` exists and `:decode-error` is absent.
- Hooks run in registration order.
- Re-registering the same key overwrites the previous function and moves it to the tail.
- Hook exceptions are swallowed; packet processing continues.
- Only map return values are applied; non-map returns are ignored.

## Stability notes (v1.0 contract)

- Hook signature (`m -> m'`) is stable.
- `register!`, `unregister!`, `installed`, and `apply!` behavior is part of the public API contract.
- Hook failures are isolated by design.

```clojure
(require '[paclo.decode-ext :as dx])

(dx/register! ::my-hook
  (fn [m]
    (if (= :udp (get-in m [:decoded :l3 :l4 :type]))
      (assoc-in m [:decoded :note] "hello-udp")
      m)))

(dx/unregister! ::my-hook)
(dx/installed)
```

## Explicit selection per pipeline

Full decode runs extensions before the user `:xform`, through the same
`packet-xf` transformation used by `packets`, `reduce-packets`,
`reduce-packets-report`, and managed `start-capture` / `capture-packets`.

- Omit `:extensions` to use the current global registry on each packet.
  Registering or unregistering after constructing a transducer affects it.
- Supply `:extensions []` to run no extensions, including global hooks.
- Supply a vector of functions to select exactly those functions in order.
  Duplicates run repeatedly; each map result feeds the next function.
  The vector is retained when the pipeline is constructed. Global registration
  changes do not affect an explicit pipeline, and unregistered functions work.
- The vector and every element (`fn?`) are validated at construction. Explicit
  `nil`, lists, maps, keywords, strings and non-function elements throw `ex-info`.
  Explicit selection requires `:decode? true`; raw and `:decode-mode :flow`
  reject it, even for an empty vector, before source open.
- Extensions run only when `:decoded` is present and `:decode-error` is absent.
  Exceptions and non-map results, including `nil`, preserve the preceding map.
  Later functions continue. This is the same failure isolation as global hooks;
  the default `:extension-error-mode :ignore` preserves these outputs.
  Opt into `:report` to append EDN diagnostics for exceptions/non-map results,
  with zero-based indices in execution order (also for global hooks).
  See the [canonical diagnostics contract](cljdoc-api-contract.md#structured-diagnostics)
  and [executable example](usage.md#packet-contracts-and-diagnostics).
  Existing decode-error counters and capture `:error-mode` remain separate.

The supported ordinary annotation functions are `dns-ext/annotate-dns` and
`tls-ext/annotate-tls-sni`. Existing `register!` functions install those same
functions. DNS retains summary and best-effort question fields; TLS retains
best-effort SNI and ALPN without TCP reassembly. Both leave unrelated packets
unchanged and can be called directly without registering. When the selected
functions are pure, the same input and vector produce deterministic output.

<!-- paclo-doc-test: extensions-ordered-selection -->

```clojure
(require '[paclo.core :as core]
         '[paclo.proto.dns-ext :as dns-ext]
         '[paclo.proto.tls-ext :as tls-ext])

(let [note (fn [m] (update m :steps (fnil conj []) :annotated))]
  (core/reduce-packets
   {:path "test/resources/dns-sample.pcap"
    :decode? true
    :extensions [dns-ext/annotate-dns tls-ext/annotate-tls-sni note note]
    :xform (map #(vector (:steps %)
                        (get-in % [:decoded :l3 :l4 :app :summary])))}
   conj []))
```

These APIs are additions in `[Unreleased]` (P03); v1.3.0 uses global hooks.

## Independent fan-out branches

Distribute raw packets and apply a separate `packet-xf` in each consumer.
Blocking branches must drain concurrently; each consumer owns its branch.
The finite input below contains DNS and TLS PCAP data:

<!-- paclo-doc-test: extensions-fan-out -->

```clojure
(require '[paclo.core :as core]
         '[paclo.stream :as stream]
         '[paclo.proto.dns-ext :as dns-ext]
         '[paclo.proto.tls-ext :as tls-ext])

(let [raw (concat (core/packets {:path "test/resources/dns-sample.pcap"})
                  (core/packets {:path "test/resources/tls-sni-alpn-sample.pcap"}))]
  (with-open [fanout (stream/fan-out
                     raw {:dns {:buffer-mode :blocking :buffer-cap 1}
                          :tls {:buffer-mode :blocking :buffer-cap 1}})
              dns-branch (stream/branch fanout :dns)
              tls-branch (stream/branch fanout :tls)]
    (let [dns-result (future
                       (into [] (core/packet-xf
                                 {:decode? true :extensions [dns-ext/annotate-dns]})
                             dns-branch))
          tls-result (future
                       (into [] (core/packet-xf
                                 {:decode? true :extensions [tls-ext/annotate-tls-sni]})
                             tls-branch))]
      (try
        {:dns @dns-result :tls @tls-result}
        (finally
          (future-cancel dns-result)
          (future-cancel tls-result))))))
```

Packet byte arrays are mutable and shared across branches. Treat published
bytes as read-only; these annotations do not mutate them. For a managed source,
own capture, fan-out, and branches together with `with-open` and use `:cancel!`
to unblock the source as described in the [usage guide](usage.md#bounded-fan-out-v13).
The fan-out buffering, cancellation and single-consumer contracts are unchanged.

## Example: DNS summary hook

```clojure
(require '[paclo.proto.dns-ext :as dns-ext])

(dns-ext/register!)
;; Adds [:decoded :l3 :l4 :app :summary] to DNS packets
```

Repository-local CLI runs that use DNS extension should include `:dns-ext`:

```bash
clojure -M:dev:dns-ext -m examples.dns-topn test/resources/dns-sample.pcap
```

When Paclo is consumed as a dependency artifact, `paclo.proto.dns-ext` is included.

## Example: TLS ClientHello SNI hook

Extract SNI from TLS ClientHello on a best-effort basis (single-segment, no stream reassembly).

```clojure
(require '[paclo.core :as core]
         '[paclo.proto.tls-ext :as tls-ext])

(tls-ext/register!)

(into []
  (comp
    (filter #(= :tls (get-in % [:decoded :l3 :l4 :app :type])))
    (map #(select-keys (get-in % [:decoded :l3 :l4 :app]) [:sni :summary])))
  (core/packets {:path "tls-sample.pcap"
                 :filter "tcp and port 443"
                 :decode? true}))
```

CLI example:

```bash
clojure -M:dev -m examples.tls-sni-scan tls-sample.pcap 'tcp and port 443' 10 jsonl
```

## Best practices

- Use namespaced keywords for hook keys (for example `:my.ns/hook`).
- Keep hooks side-effect free unless explicitly intended.
- If a hook has fragile external dependencies, handle failures inside the hook body.

## Limitations

- TLS SNI extraction is best-effort and does not perform TCP stream reassembly.
- No SNI in ClientHello means no annotation is added.

Full decode skips all extension hooks when an explicit `:linktype` is unsupported,
including global registration and explicit `:extensions` with either error mode.
Raw reads still expose those bytes and their native DLT. See the
[link-type dispatch contract](cljdoc-api-contract.md#link-type-dispatch).
