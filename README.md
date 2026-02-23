<!-- markdownlint-disable MD013 -->
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

| Example | What it shows | Formats | Typical command |
| --- | --- | --- | --- |
| bench | PCAP read perf smoke | edn | `clojure -M:dev -m examples.bench` |
| dns-summary | DNS summary rows | edn/jsonl | `clojure -M:dev:dns-ext -m examples.dns-summary trace.pcap` |
| ping | Minimal capture loop | edn | `clojure -M:dev -m examples.ping` |
| pcap-filter | Filter + write, meta to stdout | edn/jsonl | `clojure -M:dev -m examples.pcap-filter in.pcap out.pcap 'udp and port 53' 60 jsonl --async` |
| flow-topn | Top flows (unidir/bidir, packets/bytes) | edn/jsonl | `clojure -M:dev -m examples.flow-topn in.pcap 'udp and port 53' 10 --async` |
| dns-rtt | RTT pairs/stats/qstats, endpoint filters | edn/jsonl | `clojure -M:dev:dns-ext -m examples.dns-rtt in.pcap 'udp and port 53' 50 stats --async` |
| tls-sni-scan | TLS ClientHello SNI top-N | edn/jsonl | `clojure -M:dev -m examples.tls-sni-scan in.pcap 'tcp and port 443' 10 jsonl` |

- DNS 例（dns-summary / dns-rtt）はリポ clone 実行時のみ `-M:dev:dns-ext` が必要。ライブラリ利用時は JAR に同梱済みで `require` だけで OK。
- 省略可能な引数は `_` でスキップできます（例: `... _ _ stats jsonl`）。
- すべての例で `<format>` は `edn` / `jsonl` を受け付け、指定が無ければ `edn` です。
- DNS の同梱サンプル: `test/resources/dns-sample.pcap`（4 pkt）, `test/resources/dns-synth-small.pcap`（10 pkt synthetic）。CLI の動作確認に使えます。

オプション依存（必要な人だけ alias で追加）

- CSV: `-A:csv`（`org.clojure/data.csv`）で CSV 出力ユースケースを軽く試せます。デフォルト依存には含めていません。
- Parquet / DuckDB: 未同梱。必要になったら別 alias を追加して opt-in する方針です。

#### dns-ext alias クイックチェック

```bash
# 開発環境で DNS 拡張をロードできるか確認（依存追加は不要）
clojure -M:dev:dns-ext -e "(require 'paclo.dns.decode) (println :dns-ext-ok)"
```

- 成功すると `:dns-ext-ok` が表示されます。失敗する場合は `:dev` alias のパスに `extensions/dns/src` が含まれているか `deps.edn` を確認してください。
- examples の実行は `-M:dev:dns-ext` を先頭に付けるだけで OK です（JAR 利用時は不要）。

#### REPL turnaround (sample)

- 2025-12-03 `examples.pipeline-bench test/resources/dns-sample.pcap`
  - `decode?=false` 4 pkt / 11.1ms, `decode?=true` 4 pkt / 13.3ms（ローカル開発機、:xform=drop<60B）
  - 計測コマンド例: `clojure -M:dev -m examples.pipeline-bench test/resources/dns-sample.pcap`
    / `... "" "" /tmp/pipeline-out.pcap true`
- 2025-12-04 `examples.pipeline-bench /tmp/paclo-mid-50k.pcap`（合成 PCAP 50k pkt, caplen≈74B）
  - `decode?=false` 50k pkt / 273.7ms, `decode?=true` 50k pkt / 879.9ms（ローカル開発機、:xform=drop<60B）
  - PCAP は `make-synth-pcap` でローカル生成（非同梱）
  - ベンチ例: `clojure -M:dev -m examples.pipeline-bench /tmp/paclo-mid-50k.pcap "" 50000 /tmp/paclo-mid-50k-out.pcap true`
- 合成PCAP生成スクリプト（再現用）: `clojure -M:dev -m make-synth-pcap /tmp/paclo-mid-50k.pcap 50000 74`
- 2025-12-03 `examples.pipeline-bench /tmp/bench-100k.pcap`（合成 PCAP, 100k pkt, caplen≈74B）
  - `decode?=false` 100k pkt / 398.5ms, `decode?=true` 100k pkt / 1291.7ms（ローカル開発機）
  - 生成: `make-synth-pcap` でローカル合成（非同梱）
  - ベンチ: `clojure -M:dev -m examples.pipeline-bench /tmp/bench-100k.pcap "" 100000 /tmp/pipeline-bench-out.pcap true`

Bench summary (xform=drop<60B, same machine)

| sample | packets | decode?=false | decode?=true | note |
| --- | ---: | ---: | ---: | --- |
| dns-sample | 4 | 11.1ms | 13.3ms | bundled PCAP |
| synth-mid | 1,000 | 36.2ms | 76.2ms | make-synth-pcap 74B |
| synth-50k | 50,000 | 273.7ms | 879.9ms | make-synth-pcap 74B |
| synth-100k | 100,000 | 398.5ms | 1291.7ms | make-synth-pcap 74B |

計測環境: macOS 14.4 / Intel i7-8700B 3.20GHz / JDK 21 / :xform=drop<60B 共通。

> **Note:** If you’re stuck on an older CLI setup and cannot use `:dev`, you can temporarily run
> examples via `load-file`. Newer setups should prefer `-M:dev -m`.

### DNS RTT with endpoint filters

Compute DNS transaction RTTs and summarize by pairs/stats/qstats.  
You can filter by endpoint prefix (`--client` / `--server`), where the prefix is `IP` or `IP:PORT`.

```bash
# Pairs (default), all servers
clojure -Srepro -M:dev:dns-ext -m examples.dns-rtt in.pcap

# Pairs, only server 1.1.1.1:53
clojure -Srepro -M:dev:dns-ext -m examples.dns-rtt in.pcap 'udp and port 53' 50 pairs _ edn _ --server 1.1.1.1:53

# Qname stats, JSONL output, only client 192.168.4.28, sort by p95
clojure -Srepro -M:dev:dns-ext -m examples.dns-rtt in.pcap 'udp and port 53' 20 qstats p95 jsonl --client 192.168.4.28

# Opt-in async (backpressure/drop/cancel demo). Defaults: buffer=1024, mode=buffer
clojure -Srepro -M:dev:dns-ext -m examples.dns-rtt in.pcap 'udp and port 53' 50 stats edn --async --async-buffer 1024
clojure -Srepro -M:dev:dns-ext -m examples.dns-rtt in.pcap 'udp and port 53' 50 stats edn --async --async-mode dropping --async-timeout-ms 1000

サンプル PCAP: `test/resources/dns-sample.pcap`（4pkt, query/response x2）、`test/resources/dns-synth-small.pcap`（10pkt, query-only 合成）、`test/resources/tls-sni-sample.pcap`（SNI=example.com）、`test/resources/tls-sni-alpn-sample.pcap`（SNI=example.com, ALPN=h2,http/1.1）、`test/resources/tls-sni-h3-sample.pcap`（SNI=example.com, ALPN=h3）。
参考: ALPN 複合例として `test/resources/tls-sni-alpn-h3mix-sample.pcap`（h3,h2,http/1.1）も同梱。

### DNS Top-N (v0.4)

DNS 指標のランキングを EDN/JSONL/CSV で出力。group によって集計キーを切替え、SNI / ALPN 集計も可能です。

```bash
# 既定 (rcode top20, edn)
clojure -M:dev:dns-ext -m examples.dns-topn test/resources/dns-sample.pcap

# qname suffix で CSV 出力、punycode を Unicode 化
clojure -M:dev:dns-ext -m examples.dns-topn test/resources/dns-sample.pcap _ 10 qname-suffix csv --punycode-to-unicode

# SNI ランキング（TLS BPF 既定: tcp and port 443）
clojure -M:dev:dns-ext -m examples.dns-topn in.pcap _ 20 sni edn --sni-bpf "tcp and port 443"

# ALPN の第一候補をランキング（デフォルト挙動）
clojure -M:dev:dns-ext -m examples.dns-topn in.pcap _ 20 alpn edn

# ALPN をすべて結合して監査したい場合
clojure -M:dev:dns-ext -m examples.dns-topn in.pcap _ 20 alpn edn _ --alpn-join

# opt-in async（drop/cancelデモ）
clojure -M:dev:dns-ext -m examples.dns-topn in.pcap _ 20 rcode edn --async --async-buffer 1024 --async-mode dropping --async-timeout-ms 1000
```

|引数|省略時|説明|
|---|---|---|
|`<pcap>`|必須|入力 PCAP|
|`<bpf>`|`udp and port 53`（group=sni 時は `tcp and port 443`）|BPF 文字列|
|`<topN>`|20|表示上限|
|`<group>`|rcode|`rcode` / `rrtype` / `qname` / `qname-suffix` / `client` / `server` / `sni` / `alpn`|
|`<format>`|edn|`edn` / `jsonl` / `csv`|
|`<metric>`|count|`count` / `bytes`|
|`--punycode-to-unicode`|-|qname を Unicode に正規化（失敗時は元のラベルを使用）|
|`--log-punycode-fail`|-|punycode 変換失敗を stderr に WARN ログする|
|`--sni-bpf`|tcp and port 443|SNI/ALPN 集計時の BPF を上書き|
|`--alpn-join`|-|ALPN を全てカンマ結合（デフォルトは「先頭のみ」＝優先度トップを採用）|
|`--async*`|off|既存 async フラグ（buffer/mode/timeout）|

### DNS QPS (v0.4)

時間粒度で DNS トラフィックを集計（count/bytes）。bucket 毎に key（rcode/rrtype/qname...）で分けて出力。

```bash
clojure -M:dev:dns-ext -m examples.dns-qps test/resources/dns-sample.pcap

# qname で 200ms バケット、max-buckets=1000（per-key補完と warn 閾値を低めに設定）
clojure -M:dev:dns-ext -m examples.dns-qps in.pcap _ 200 qname edn --max-buckets 100000 --warn-buckets-threshold 50000 --emit-empty-per-key

# JSONL で出力（async drop デモ）
clojure -M:dev:dns-ext -m examples.dns-qps in.pcap _ 500 rrtype jsonl --async --async-mode dropping --async-buffer 256
```

|引数|省略時|説明|
|---|---|---|
|`<pcap>`|必須|入力 PCAP|
|`<bpf>`|`udp and port 53`|BPF 文字列|
|`<bucket-ms>`|1000|バケット幅 (ms)|
|`<group>`|rcode|`rcode` / `rrtype` / `qname` / `qname-suffix` / `client` / `server`|
|`<format>`|edn|`edn` / `jsonl` / `csv`|
|`--punycode-to-unicode`|-|qname を Unicode に正規化|
|`--log-punycode-fail`|-|punycode 変換失敗を stderr に WARN で記録|
|`--emit-empty-buckets`|-|バケット欠損も 0 行として出力（key=:_all で補完）|
|`--emit-empty-per-key`|-|各 key × バケットを 0 で補完（行数増に注意、max-buckets で上限）|
|`--max-buckets`|200000|出力行数の上限（メモリ保護、per-key 補完時に特に有効）|
|`--warn-buckets-threshold`|100000|警告を出す行数閾値（emit-empty-per-key 併用時に有効）|
|`--log-punycode-fail`|-|punycode 変換失敗を stderr に WARN ログする|
|`--async*`|off|既存 async フラグ（buffer/mode/timeout）|

参考: `--emit-empty-per-key --max-buckets 100000 --warn-buckets-threshold 50000` のように併用すると、長時間走る集計でも行数膨張を見逃しにくい。短時間・小 PCAP（<=1k 行想定）では既定の 100k で十分。目安: 10万行 ≈ 数百 ms、50万行 ≈ 数秒（環境依存）。

ベンチ目安（macOS 14.4 / i7-8700B / JDK21）

|sample|pkts|bucket-ms|decode?|elapsed-ms|
|---|---:|---:|---|---:|
|dns-synth-small.pcap (同梱)|10|1000|true|≈16.2|

### 依存脆弱性スキャン（NVD）

- GitHub Actions の `Dependency Audit` ワークフローで `secrets.NVD_API_TOKEN` を用いて定期実行します。
- ローカルで再現する場合は `NVD_API_TOKEN=<token> clojure -M:nvd dev/nvd-clojure.edn "$(clojure -Spath -A:dev:dns-ext)"` を実行してください。

|引数|省略時|説明|
|---|---|---|
|`<in.pcap>`|必須|入力 PCAP|
|`<bpf>`|`udp and port 53`|BPF 文字列|
|`<topN>`|50|pairs/qstats の上限行数|
|`<mode>`|pairs|`pairs` / `stats` / `qstats`|
|`<metric>`|pairs|`pairs` / `with-rtt` / `p50` / `p95` / `p99` / `avg` / `max`|
|`<format>`|edn|`edn` or `jsonl`|
|`<alert%>`|なし|NXDOMAIN+SERVFAIL 率の閾値（例: `2.5`）|
|`--client` / `-c`|なし|送信元/宛先プレフィックスフィルタ（前方一致）|
|`--server` / `-s`|なし|送信元/宛先プレフィックスフィルタ（前方一致）|

### Notes

- `--client/-c` / `--server/-s` は**前方一致**（`192.168.4.28` や `1.1.1.1:53` など）
- `alert%`（例: `2.5`）を与えると、NXDOMAIN+SERVFAIL がその割合を超えた時に `stderr` に `WARNING` を出力
- RTT は PCAP にタイムスタンプが無い場合は計算されません（`with-rtt: 0`）

### pcap-stats (EDN / JSONL)

|引数|省略時|説明|
|---|---|---|
|`<in.pcap>`|必須|入力 PCAP|
|`<bpf>`|なし|BPF 文字列（例: `udp and port 53`）|
|`<topN>`|5|上位件数（src/dst）|
|`<format>`|edn|`edn` or `jsonl`|

```bash
# Basic stats (EDN)
clojure -Srepro -M:dev -m examples.pcap-stats in.pcap

# With BPF, topN=10, JSONL output
clojure -Srepro -M:dev -m examples.pcap-stats in.pcap 'udp and port 53' 10 jsonl

# Opt-in async (backpressure/drop demo). Defaults: buffer=1024, mode=buffer
clojure -Srepro -M:dev -m examples.pcap-stats in.pcap '_' '_' edn --async --async-buffer 1024
clojure -Srepro -M:dev -m examples.pcap-stats in.pcap '_' '_' edn --async --async-mode dropping --async-timeout-ms 1000

# Sample output (EDN)
{:packets 1234, :bytes 98765, :caplen {:avg 80.1, :min 42, :max 1514},
 :proto {:l3 {:ipv4 1200}, :l4 {:tcp 900, :udp 300}},
 :top {:src [{:key "10.0.0.1" :count 200}], :dst [{:key "8.8.8.8" :count 150}]}}
```

### flow-topn (EDN / JSONL)

|引数|省略時|説明|
|---|---|---|
|`<in.pcap>`|必須|入力 PCAP|
|`<bpf>`|`udp or tcp`|BPF 文字列|
|`<topN>`|10|上位フロー件数|
|`<mode>`|unidir|`unidir`（片方向）/ `bidir`（双方向まとめ）|
|`<metric>`|packets|`packets` or `bytes`|
|`<format>`|edn|`edn` or `jsonl`|

```bash
# Top flows (bidir, sort by bytes), JSONL output
clojure -Srepro -M:dev -m examples.flow-topn in.pcap 'udp and port 53' 10 bidir bytes jsonl

# Opt-in async (backpressure/cancel demo). Defaults: buffer=1024, mode=buffer
clojure -Srepro -M:dev -m examples.flow-topn in.pcap 'udp or tcp' 10 bidir bytes edn --async --async-buffer 1024
clojure -Srepro -M:dev -m examples.flow-topn in.pcap 'udp or tcp' 10 bidir bytes edn --async --async-mode dropping --async-timeout-ms 1000
# 例: 合成DNS 25k pkt, buffer=64, dropping → flows=2 (DNSクエリ/レス), dropped=0
# 例: 同ファイル timeout=1000ms → flows=0, cancelled=true（途中停止デモ）
# 例: 実PCAP(20k pkt, UDP多め), buffer=64, dropping → flows=10, dropped=0, cancelled=false

# Sample output (EDN)
[{:flow {:proto :udp, :src "10.0.0.1:5353", :dst "224.0.0.251:5353"}
  :packets 320 :bytes 18320}
 {:flow {:proto :tcp, :src "10.0.0.1:443", :dst "10.0.0.2:53422"}
  :packets 210 :bytes 14000}]
```

### pcap-filter (EDN / JSONL meta)

```bash
# Filter + write out (EDN meta printed to stdout)
clojure -Srepro -M:dev -m examples.pcap-filter in.pcap out.pcap

# With BPF and JSONL meta
clojure -Srepro -M:dev -m examples.pcap-filter in.pcap out-dns.pcap 'udp and port 53' 0 jsonl

# Opt-in async (backpressure/cancel demo). Defaults: buffer=1024, mode=buffer
clojure -Srepro -M:dev -m examples.pcap-filter in.pcap out.pcap --async --async-buffer 1024 --async-mode buffer
clojure -Srepro -M:dev -m examples.pcap-filter in.pcap out.pcap --async --async-mode dropping --async-timeout-ms 1000

# Long PCAP で背圧/ドロップを観察（値は環境依存）
clojure -Srepro -M:dev -m examples.pcap-filter /tmp/large.pcap /tmp/out.pcap --async --async-mode dropping --async-buffer 16
# => メタの :async-dropped/:async-cancelled? や stderr ログで挙動を確認
# 例: 合成DNS 25k pkt, buffer=16, dropping → async-dropped≈14k (drop-pct≈56%)
# 例: 実PCAP(20k pkt, home LAN), buffer=16, dropping → async-dropped=11750 (drop-pct≈58.75%)
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

## Public API Surface (v1.0 freeze target)

v1.0 で後方互換を保証する公開面は、以下を基準にします。

| Namespace | Public functions | Notes |
| --- | --- | --- |
| `paclo.core` | `bpf`, `packets`, `write-pcap!`, `list-devices` | メインの利用者向け API |
| `paclo.decode-ext` | `register!`, `unregister!`, `installed`, `apply!` | decode 拡張フック API |

- `paclo.pcap` / `paclo.parse` / `paclo.proto.*` は内部 namespace として扱います。
- `clojure -M:run` はライブラリ利用ガイドを表示する補助エントリポイントです。

## Documentation

- [docs/README.md](./docs/README.md) — Documentation index (user guide, extensions, roadmap)
- [docs/cljdoc-api-contract.md](./docs/cljdoc-api-contract.md) — Public API contract synced for cljdoc/v1.0
- [docs/migration-0.4-to-1.0.md](./docs/migration-0.4-to-1.0.md) — Migration checklist and compatibility notes for v1.0

## Install

> まずは **Git 依存**で使えます（Clojars 配布は後日）。  
> 安定化後に Clojars へ公開したら、ここに Clojars 用の記述を追記します。

### deps.edn

```edn
{:deps
 {io.github.nantes-rfli/paclo
 {:git/url "https://github.com/nantes-rfli/paclo.git"
   ;; 安定版を使う場合はタグを指定（v0.4.0 リリース）
   :git/tag "v0.4.0"
   :git/sha "bd969d4bab5431f2e0936bcc3ffc78871f21f5ee"}}}
````

### require 一文

```clojure
(require '[paclo.core :as core])
```

---

## Compatibility Matrix (v1.0 target)

| Layer | Supported | CI gate (2026-02-23) | Notes |
| --- | --- | --- | --- |
| Clojure | `1.12.x` | 互換性ジョブで必須（Linux/JDK21, macOS/JDK17） | `deps.edn` 基準は `1.12.1` |
| JDK | `17`, `21` | 互換性ジョブで両方必須 | build/coverage でも追加検証 |
| OS | macOS, Linux | 互換性ジョブで両方必須 | macOS は `macos-latest` ラベルを使用 |
| CPU | x86_64, arm64 | x86_64 は Linux 互換性ジョブで必須、arm64 は専用ジョブで required | arm64 は `ubuntu-24.04-arm` |
| Babashka | `1.12.x` | CI で `bb --version` を実行 | CLI 補助スクリプト向け |
| libpcap | システム標準版 | Linux CI は `libpcap-dev` 導入 | macOS は標準 `pcap` |

- Java ソースを変更したら `clojure -T:build javac` で `target/classes` を再生成してください。
- 性能ゲートは `clojure -M:perf-gate` で実行し、`warn=1000ms / fail=1200ms` を初期閾値として運用します。
- Clojure deps キャッシュは `runner.arch` 分離で運用し、x64/arm64 間の復元混在を防止します。

---

## Error Handling (decode?)

`(core/packets {:decode? true ...})` のとき、デコード失敗でも例外は投げません。
各要素に以下のいずれかが付与されます。

- `:decoded` … デコード成功時の構造化マップ
- `:decode-error` … 失敗時のエラーメッセージ（例: フレームが短い、未対応など）

---

## Documentation / Badges（準備）

公開後に以下を掲示します（Clojars/cljdoc 公開時に URL を差し替え）

- cljdoc: `[![cljdoc](https://cljdoc.org/badge/io.github.nantes-rfli/paclo)](https://cljdoc.org/d/io.github.nantes-rfli/paclo/CURRENT)`
- Clojars: `[![Clojars Project](https://img.shields.io/clojars/v/io.github.nantes-rfli/paclo.svg)](https://clojars.org/io.github.nantes-rfli/paclo)`

---

## FAQ

**Q. ライブキャプチャが Permission denied になります**  
A. Linux/macOS では root 権限や特権付与が必要です。`sudo` または libpcap の権限設定をご確認ください。

**Q. パフォーマンスはどの程度ですか？**  
A. 数十万パケット程度であれば REPL 内で問題なく処理できます。大規模処理は `:xform` で早期フィルタ/マップを推奨します。

**Q. `:decode? true` の挙動は？**  
A. デコードに失敗しても例外は投げず、各要素に `:decode-error` が付与されます。

## fresh clone の場合は最初に Java をコンパイル

clojure -T:build javac
