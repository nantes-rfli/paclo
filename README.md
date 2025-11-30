# Paclo

[![cljdoc](https://cljdoc.org/badge/io.github.nantes-rfli/paclo)](https://cljdoc.org/d/io.github.nantes-rfli/paclo/CURRENT)
[![Clojars Project](https://img.shields.io/clojars/v/io.github.nantes-rfli/paclo.svg)](https://clojars.org/io.github.nantes-rfli/paclo)

> ※ Clojars 公開前は暫定表示です。公開後に自動で有効化されます。

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

### Run the examples

Development examples live under `dev/examples` and are loaded via the `:dev` alias.

```bash
clojure -M:dev -m examples.bench
clojure -M:dev -m examples.dns-summary path/to/trace.pcap
clojure -M:dev -m examples.ping
clojure -M:dev -m examples.pcap-filter in.pcap out.pcap 'udp and port 53' 60
clojure -M:dev -m examples.flow-topn in.pcap 'udp and port 53' 10
clojure -M:dev -m examples.dns-rtt in.pcap 'udp and port 53' 20
clojure -M:dev -m examples.dns-rtt in.pcap 'udp and port 53' 50 stats
clojure -M:dev -m examples.dns-rtt in.pcap 'udp and port 53' 50 qstats p95
```

> **Note:** If you’re stuck on an older CLI setup and cannot use `:dev`, you can temporarily run examples via `load-file`. See **AI\_HANDOFF.md** for the workaround. Newer setups should prefer `-M:dev -m`.

### DNS RTT with endpoint filters

Compute DNS transaction RTTs and summarize by pairs/stats/qstats.  
You can filter by endpoint prefix (`--client` / `--server`), where the prefix is `IP` or `IP:PORT`.

```bash
# Pairs (default), all servers
clojure -Srepro -M:dev -m examples.dns-rtt in.pcap

# Pairs, only server 1.1.1.1:53
clojure -Srepro -M:dev -m examples.dns-rtt in.pcap 'udp and port 53' 50 pairs _ edn _ --server 1.1.1.1:53

# Qname stats, JSONL output, only client 192.168.4.28, sort by p95
clojure -Srepro -M:dev -m examples.dns-rtt in.pcap 'udp and port 53' 20 qstats p95 jsonl --client 192.168.4.28
```

**Notes**

* `--client/-c` / `--server/-s` は**前方一致**（`192.168.4.28` や `1.1.1.1:53` など）
* `alert%`（例: `2.5`）を与えると、NXDOMAIN+SERVFAIL がその割合を超えた時に `stderr` に `WARNING` を出力
* RTT は PCAP にタイムスタンプが無い場合は計算されません（`with-rtt: 0`）

### pcap-stats (EDN / JSONL)

```bash
# Basic stats (EDN)
clojure -Srepro -M:dev -m examples.pcap-stats in.pcap

# With BPF, topN=10, JSONL output
clojure -Srepro -M:dev -m examples.pcap-stats in.pcap 'udp and port 53' 10 jsonl
```

### flow-topn (EDN / JSONL)

```bash
# Top flows (bidir, sort by bytes), JSONL output
clojure -Srepro -M:dev -m examples.flow-topn in.pcap 'udp and port 53' 10 bidir bytes jsonl
```

### pcap-filter (EDN / JSONL meta)

```bash
# Filter + write out (EDN meta printed to stdout)
clojure -Srepro -M:dev -m examples.pcap-filter in.pcap out.pcap

# With BPF and JSONL meta
clojure -Srepro -M:dev -m examples.pcap-filter in.pcap out-dns.pcap 'udp and port 53' 0 jsonl
```

### TLS SNI scan (EDN / JSONL)

Extract Server Name Indication (SNI) from TLS ClientHello (best-effort; single-segment only).

```bash
# Top 50 SNI over port 443
clojure -Srepro -M:dev -m examples.tls-sni-scan in.pcap

# With BPF, topN=10, JSONL
clojure -Srepro -M:dev -m examples.tls-sni-scan in.pcap 'tcp and port 443' 10 jsonl
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

* [docs/README.md](./docs/README.md) — Documentation index (user guide, extensions, roadmap)

## Install

> まずは **Git 依存**で使えます（Clojars 配布は後日）。  
> 安定化後に Clojars へ公開したら、ここに Clojars 用の記述を追記します。

**deps.edn**

```edn
{:deps
 {io.github.nantes-rfli/paclo
  {:git/url "https://github.com/nantes-rfli/paclo.git"
   ;; 安定版を使う場合はタグを指定（v0.2.0 リリース）
   :git/tag "v0.2.0"
   :git/sha "a1bbb263b22956001ef8e100061bcbfc7b1b2ec7"}}}
````

**require 一文**

```clojure
(require '[paclo.core :as core])
```

---

## Supported Environments

* OS: macOS（Intel Mac で動作確認）
* JDK: Temurin/Oracle/OpenJDK 21+ 推奨
* libpcap: システム標準（macOS 標準の `pcap` でOK）

---

## Error Handling (decode?)

`(core/packets {:decode? true ...})` のとき、デコード失敗でも例外は投げません。
各要素に以下のいずれかが付与されます。

* `:decoded` … デコード成功時の構造化マップ
* `:decode-error` … 失敗時のエラーメッセージ（例: フレームが短い、未対応など）

---

## Documentation / Badges（準備）

公開後に以下を掲示します（Clojars/cljdoc 公開時に URL を差し替え）

* cljdoc: `[![cljdoc](https://cljdoc.org/badge/io.github.nantes-rfli/paclo)](https://cljdoc.org/d/io.github.nantes-rfli/paclo/CURRENT)`
* Clojars: `[![Clojars Project](https://img.shields.io/clojars/v/io.github.nantes-rfli/paclo.svg)](https://clojars.org/io.github.nantes-rfli/paclo)`

---

## FAQ

**Q. ライブキャプチャが Permission denied になります**  
A. Linux/macOS では root 権限や特権付与が必要です。`sudo` または libpcap の権限設定をご確認ください。

**Q. パフォーマンスはどの程度ですか？**  
A. 数十万パケット程度であれば REPL 内で問題なく処理できます。大規模処理は `:xform` で早期フィルタ/マップを推奨します。

**Q. `:decode? true` の挙動は？**  
A. デコードに失敗しても例外は投げず、各要素に `:decode-error` が付与されます。

# fresh clone の場合は最初に Java をコンパイル

clojure -T:build javac
