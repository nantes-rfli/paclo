# Paclo Usage Guide

This page walks through the essential tasks for using Paclo as a PCAP toolkit in Clojure and explains the library’s structure.

## Architecture at a glance
- **JNI-free binding**: Paclo uses `jnr-ffi`/`jnr-constants` to call `libpcap` without JNI headers. This keeps builds simple and portable.
- **Core namespaces**:
  - `paclo.pcap` – thin wrappers around libpcap (open live/offline, dump, capture loop).
  - `paclo.parse` – byte-level parsing to Clojure maps (Ethernet/IP/TCP/UDP/ICMP).
  - `paclo.core` – user-facing API that ties capture, decode, BPF DSL, and writing together.
  - `paclo.decode-ext` – hook system for post-decode annotations (e.g., DNS/TLS SNI).
- **Data-first design**: decoded packets are plain maps; undecodable packets carry `:decode-error`.
- **Lazy / streaming**: capture functions return lazy seqs or accept transducers (`:xform`) for early filtering/mapping.

## Quick start (offline)
```clojure
(require '[paclo.core :as core])

;; Read packets from file, no decode
(->> (core/packets {:path "sample.pcap"})
     (take 3) doall)

;; Read & decode, keep only summary fields
(->> (core/packets {:path "resources/dns-sample.pcap" :decode? true})
     (map #(select-keys % [:caplen :decoded :decode-error]))
     (take 2) doall)
```

## Live capture with BPF DSL
```clojure
(require '[paclo.core :as core])

(->> (core/packets {:device "en0"
                    :filter (core/bpf [:and [:udp] [:port 53]])
                    :timeout-ms 50})
     (take 10) doall)
```

## Writing PCAP
```clojure
(require '[paclo.core :as core])

(core/write-pcap! [(byte-array (repeat 60 (byte 0)))
                   {:bytes (byte-array (repeat 60 (byte -1)))
                    :sec 1700000000 :usec 123456}]
                  "out.pcap")
```

## BPF DSL examples
```clojure
(core/bpf [:and [:ipv6] [:udp] [:dst-port-range 8000 9000]])
;; => "(ip6) and (udp) and (dst portrange 8000-9000)"

(core/bpf [:and [:net "10.0.0.0/8"] [:not [:port 22]]])
;; => "(net 10.0.0.0/8) and (not (port 22))"
```

## Decode hooks (extensions)
```clojure
(require '[paclo.decode-ext :as dx]
         '[paclo.proto.dns-ext :as dns-ext])

(dns-ext/register!) ; adds DNS summaries to decoded packets

(->> (core/packets {:path "resources/dns-sample.pcap"
                    :decode? true})
     (take 1) doall)
```
See `docs/extensions.md` for how to write your own hook (e.g., TLS SNI).

## Error handling
- `:decode? true` never throws on parse failure; packets carry `:decode-error`.
- Live capture options: `:timeout-ms`, `:idle-max-ms`, `:error-mode` (`:throw` or `:pass`), and `:stop?` predicate for early stop.
- When writing PCAP, invalid records raise exceptions immediately.

## Performance tips
- Use `:xform` transducers on `packets` to filter/map early (reduces allocations).
- Prefer BPF at libpcap level for coarse filtering; use `:xform` for fine-grained logic.
- For large captures, consume with `transduce` or `into []` to control realization.

## Sample data
- `resources/dns-sample.pcap` – sanitized DNS trace used in tests.
- `sample.pcap` / `out-test.pcap` / `out.pcap` – small fixtures for examples and docs.
- CLI examples in `dev/examples` accept custom input PCAPs; see README “Run the examples”.

## Reference & further reading
- API docs: https://cljdoc.org/d/io.github.nantes-rfli/paclo/CURRENT
- Roadmap: ./ROADMAP.md
- Decode extensions: ./extensions.md
