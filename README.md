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

## Install

> まずは **Git 依存**で使えます（Clojars 配布は後日）。  
> 安定化後に Clojars へ公開したら、ここに Clojars 用の記述を追記します。

**deps.edn**

```edn
{:deps
 {io.github.nantes-rfli/paclo
  {:git/url "https://github.com/nantes-rfli/paclo.git"
   ;; リリースタグ作成後は :git/tag 推奨。ひとまず main の最新を固定したい場合は :git/sha を指定。
   :git/sha "dc1a3c6"}}}
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
