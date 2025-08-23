# Paclo

Paclo is a Clojure library for packet capture (pcap) input/output and filtering.  
It provides a Clojure-friendly API for reading, writing, and filtering packets with BPF DSL support.

## Quick Start

```clojure
(require '[paclo.core :as core])

;; Capture 10 UDP/53 packets
(->> (core/packets {:device "en0"
                    :filter (core/bpf [:and [:udp] [:port 53]])
                    :timeout-ms 50})
     (take 10) doall)
```

### List devices (human-friendly on macOS)

```clojure
(require '[paclo.core :as core])
(core/list-devices)
;; => [{:name "en0" :desc "Wi-Fi"} {:name "lo0" :desc "Loopback"} ...]
```

### BPF DSL examples (extended)

```clojure
(core/bpf [:and [:ipv6] [:udp] [:dst-port-range 8000 9000]])
;; => "(ip6) and (udp) and (dst portrange 8000-9000)"

(core/bpf [:and [:net "10.0.0.0/8"] [:not [:port 22]]])
;; => "(net 10.0.0.0/8) and (not (port 22))"
```


## Documentation

* [AI\_HANDOFF.md](./AI_HANDOFF.md) — 開発・引き継ぎ手順
* [docs/ROADMAP.md](./docs/ROADMAP.md) — ロードマップと進捗
