# Paclo Usage Guide

This guide covers the minimal concepts and common workflows for Paclo.
For installation and CLI entry examples, start from `README.md`.

## Mental model

- `paclo.core` is the user-facing API.
- `packets` returns lazy packet maps from a file (`:path`) or device (`:device`).
- `bpf` converts a small Clojure DSL to BPF strings.
- `write-pcap!` writes byte records back to a PCAP file.
- Optional decode hooks (`paclo.decode-ext`) annotate decoded packets.

## Quick start (offline)

```clojure
(require '[paclo.core :as core])

(->> (core/packets {:path "test/resources/dns-sample.pcap"
                    :decode? true})
     (map #(select-keys % [:caplen :decoded :decode-error]))
     (take 2)
     doall)
```

## Quick start (live capture)

```clojure
(require '[paclo.core :as core])

(->> (core/packets {:device "en0"
                    :filter (core/bpf [:and [:udp] [:port 53]])
                    :timeout-ms 50})
     (take 10)
     doall)
```

## Write PCAP

```clojure
(require '[paclo.core :as core])

(core/write-pcap! [(byte-array (repeat 60 (byte 0)))
                   {:bytes (byte-array (repeat 60 (byte -1)))
                    :sec 1700000000
                    :usec 123456}]
                  "out.pcap")
```

## BPF DSL (examples)

```clojure
(core/bpf [:and [:ipv6] [:udp] [:dst-port-range 8000 9000]])
;; => "(ip6) and (udp) and (dst portrange 8000-9000)"

(core/bpf [:and [:net "10.0.0.0/8"] [:not [:port 22]]])
;; => "(net 10.0.0.0/8) and (not (port 22))"
```

## Decode hooks

```clojure
(require '[paclo.core :as core]
         '[paclo.proto.dns-ext :as dns-ext])

(dns-ext/register!)

(->> (core/packets {:path "test/resources/dns-sample.pcap"
                    :decode? true})
     (take 1)
     doall)
```

See `docs/extensions.md` for hook contract and TLS/DNS extension notes.

## CLI workflows

Paclo ships practical CLI examples under `dev/examples`.
Use `README.md` as the command index, and use this guide for API behavior.

## Error model

- `:decode? true` does not throw on parse failure.
- Decode failures are represented as `:decode-error` in each packet map.
- Invalid API inputs (for example unsupported `:filter` type) throw `ex-info`.
- Lower-level libpcap open/filter/capture errors may propagate as exceptions.

## Performance tips

- Use BPF for coarse filtering as early as possible.
- Use `:xform` transducers in `packets` for early map/filter and lower allocation.
- For large traces, prefer `transduce` or bounded realization over full materialization.

## References

- API docs (cljdoc): <https://cljdoc.org/d/org.clojars.nanto/paclo/CURRENT>
- Public API contract: `./cljdoc-api-contract.md`
- Decode extensions: `./extensions.md`
- Roadmap: `./ROADMAP.md`
