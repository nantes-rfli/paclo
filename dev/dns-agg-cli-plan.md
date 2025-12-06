# DNS 集計 CLI 設計メモ（Phase E 草案）

v0.4 / P2 の着手用たたき台。2025-12-12 までに CLI 仕様を確定する。

## 目的

- DNS トラフィックを即時集計できる babashka/sci CLI を 1–2 本追加し、EDN/JSONL/CSV で一貫出力する。
- 既存 async オプション（`--async`/`--async-buffer`/`--async-mode`/`--async-timeout-ms`）を共有し、examples の UX を揃える。
- `:dns-ext` alias で自己完結（追加依存は README/CI で明示）。

## CLI 仕様（決定済み / 実装着手）

### dns-topn（ランキング, 実装中）

- 目的: rcode / rrtype / qname / SNI などで上位を集計し、DNS 健全性・ホスト分布を把握。
- 呼び出し: `clojure -M:dev:dns-ext -m examples.dns-topn <pcap> [bpf] [topN] [group] [format] [metric] ...`
- 既定値: `bpf="udp and port 53"`, `topN=20`, `group=rcode`, `format=edn`, `metric=count`。
- group: `rcode | rrtype | qname | qname-suffix | client | server | sni`（SNI は TLS SNI 拡張あり時のみ）。
- metric: `count | bytes`（qps は切り出し済みの dns-qps に委任）。
- 出力: `{ :key <kw/str> :count <long> :bytes <long> :pct <double> }`。csv は `key,count,bytes,pct` で RFC4180 風 quoting。
- async: buffer/mode/timeout を実装済み（dropping で drop カウント、timeout で cancel）。
- punycode: `--punycode-to-unicode` で qname を Unicode へ変換（失敗時は元のラベル）。`--log-punycode-fail` で WARN を stderr に出力。
- SNI: group=sni 時は BPF 既定を `tcp and port 443` に切替え。`--sni-bpf` で上書き可。サンプル `test/resources/tls-sni-sample.pcap` 追加。

### dns-qps（タイムシリーズ, 実装中）

- 目的: rcode/rrtype/qname で時間粒度のカウント/bytes をバケット集計し、スパイク検知に使う。
- 呼び出し: `clojure -M:dev:dns-ext -m examples.dns-qps <pcap> [bpf] [bucket-ms] [group] [format] ...`
- 既定値: `bpf="udp and port 53"`, `bucket-ms=1000`, `group=rcode`, `format=edn`。
- 出力: `{ :t <epoch-ms> :key <kw/str> :count <long> :bytes <long> }`（EDN/JSONL/CSV）。
- バケット: `t_ms` は ts-sec 優先、ts-usec が絶対値の場合は usec/1e3 を採用。
- オプション: `--emit-empty-buckets` で欠損バケットを `{:key :_all :count 0 :bytes 0}` で埋める。`--emit-empty-per-key` で各 key × バケットを 0 で補完（max-buckets で上限、超過時は truncate 記録し WARN）。`warn-buckets-threshold` をフラグで調整可能（デフォルト 100k）。
- async: buffer/mode/timeout 実装済み（dropping/cancel カウント）。
- punycode: `--punycode-to-unicode` で qname 正規化。

## テスト方針

- `test/examples/` にスモークテスト追加：
  - topn: デフォルト（rcode）と CSV 出力のヘッダを確認、meta の async? が false であることを確認。
  - qps: 小 PCAP でバケットが生成されることと `bucket-ms` の既定値を確認。
- サンプル PCAP: `test/resources/dns-sample.pcap`（既存 4pkt）＋ `dns-synth-small.pcap`（10pkt, query-only）をゴールデン参照。必要なら `dev/make_synth_pcap.clj` で生成手順を README に追記。

## CI / 依存

- `:dns-ext` alias を README と同じ手順でロード確認 (`clojure -M:dev:dns-ext -e "(require 'paclo.proto.dns-ext)"`).
- babashka 1.12.212 前提で CI も version check を追加（lint/test と同列）。
- eastwood/nvd: Phase F〜G で `clojure -M:dev:lint -m eastwood` / `clojure -M:nvd` を `:dns-ext` 経由でも通す。

## 未決事項（残件）

- ALPN 集計: group=:alpn を追加（デフォルトは先頭 ALPN、`--alpn-join` で全 ALPN をカンマ結合）。サンプル PCAP: `test/resources/tls-sni-alpn-sample.pcap`（h2,http/1.1）、`test/resources/tls-sni-h3-sample.pcap`（h3）、`test/resources/tls-sni-alpn-h3mix-sample.pcap`（h3,h2,http/1.1）。
