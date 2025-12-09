# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- DNS 集計 CLI `examples.dns-topn` / `examples.dns-qps`（EDN/JSONL/CSV、async/drop/cancel、qname punycode 正規化、SNI/ALPN 集計、empty-bucket 補完）。
- TLS サンプル PCAP を追加（`tls-sni-sample.pcap`, `tls-sni-alpn-sample.pcap`, `tls-sni-h3-sample.pcap`, `tls-sni-alpn-h3mix-sample.pcap`）し、スモークテストを拡充。
- DNS QPS ベンチ目安を README/ROADMAP に追記（dns-synth-small 10pkt, bucket=1000, decode?=true, ≈16.2ms）。
- CI: build ジョブに dns-ext smoke（`examples.dns-topn`）と cljdoc ドライランを追加予定（Phase F）。

### Fixed
- `dns-qps` に `--log-punycode-fail` を追加し、README/ヘルプと実装の不整合を解消。punycode decode 失敗を WARN として標準エラーに出力。

### Notes
- Eastwood は `-M:eastwood:dns-ext`（+ data.xml 追加）で完走。警告は boxed-math/performance/reflection のみ。
- nvd-clojure は GitHub Actions `Dependency Audit` で `secrets.NVD_API_TOKEN` を用いて実行。ローカル再現は `NVD_API_TOKEN` を設定して `clojure -M:nvd dev/nvd-clojure.edn "$(clojure -Spath -A:dev:dns-ext)"`。
- 2025-12-09 時点のローカル nvd-clojure 実行は `NVD_API_TOKEN` 未設定で失敗（要トークン設定）。

## [0.3.0] - 2025-12-05

### Added
- TLS ClientHello SNI/ALPN decode extension (`paclo.proto.tls-ext`) and example `examples.tls-sni-scan` (EDN/JSONL).
- REPL pipeline benchmark sample numbers for small / mid (50k) / large (100k) synthetic PCAPs.
- Synthetic PCAP generator `make-synth-pcap` to reproduce benchmark inputs (count/caplen configurable).
- Property test to assert decode_ext isolates exceptions yet keeps later hooks running.
- decode_ext ガード（`:decoded` が無い/`:decode-error` がある場合は hook をスキップ）とカバレッジ追加。
- `examples.pcap-filter` の JSONL メタ出力スモークテスト。
- examples: `pcap-filter` / `flow-topn` / `pcap-stats` / `dns-rtt` に opt-in の `--async`（背圧/ドロップ/タイムアウトデモ）を追加。

### Docs
- `docs/extensions.md` stability notes for decode_ext hooks (map-only apply, exception isolation, API compatibility).
- Roadmap updated to reflect Phase B progress and outstanding tasks; mid-size REPL turnaround numbers added; proto-dns split draft added (`dev/proto-dns-split-plan.md`).
- README REPL turnaround section now lists small/mid/large pipeline-bench samples.
- Examples docs/help text aligned (`dns-summary` alias hint, `tls-sni-scan` formats/tips) に加え、EDN/JSONL 共通フラグと `_` スキップの説明を整理。
- `docs/extensions.md` を v0.3 安定化注記に更新（適用条件ガードを明文化）。
- README に async オプションの opt-in 用例と長尺 PCAP での背圧/ドロップ観察手順を追記（pcap-filter / flow-topn / pcap-stats / dns-rtt）。ROADMAP に core.async 進捗を反映。

### Fixed
- `examples.dns-summary` help text now references the required `:dns-ext` alias.
- `examples.tls-sni-scan` accepts skipped optional args via `_` and emits consistent format errors.
- BPF arg `_` now correctly treated as "unset" in `examples.pcap-filter` / `flow-topn` / `pcap-stats` to match Usage tips.


## Versioning / SemVer

This project follows [SemVer](https://semver.org/).
Until **v1.0.0**, **minor versions may include breaking changes**.
Patch versions never do.

## [0.2.0] - 2025-08-24

### Added

- `:xform` transducer support in `core/packets`.
- BPF DSL extensions: `:proto` (`:ip/:ipv4/:ip6/:ipv6`), `:src-net/:dst-net`, `:port-range` variants.
- `core/list-devices` facade and minimal test.
- Golden PCAP round-trip tests and error propagation tests.

### Changed

- Documentation: added roadmap and README Quick Start.

### Fixed

- Stabilized AI_HANDOFF generation and primary links (ROADMAP added).
