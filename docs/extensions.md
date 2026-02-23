# Decode Extensions (Post-Decode Hooks)

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

`paclo.core/packets` calls `decode-ext/apply!` when `:decode? true` is set, so every decoded packet
passes through installed hooks.

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
