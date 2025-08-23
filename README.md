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

## Documentation

* [AI\_HANDOFF.md](./AI_HANDOFF.md) — 開発・引き継ぎ手順
* [docs/ROADMAP.md](./docs/ROADMAP.md) — ロードマップと進捗
