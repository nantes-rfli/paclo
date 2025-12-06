# Paclo Roadmap

Paclo ライブラリの方向性・リリース計画・直近タスクをまとめたロードマップです。フェーズ単位の目的と受け入れ条件を明確にし、進捗を簡潔に追える形で管理します。開発フローや環境手順は `README.md` を参照してください。

---

## 北極星（North Star）

「PCAPを *Clojureのデータ処理* に自然合流させる、最小で快適なパケット処理ライブラリ」

- Data-first（EDN/マップ/seq/transducer）
- 小さなコア + 拡張モジュール
- REPLで反復が速い（ホットスワップ、軽依存）
- tcpdump / Wireshark とは競合せず“つなぐ”

---

## リリース全体像

- **v0.2 (完了)** — OSS-ready の土台: `:xform` 対応、BPF DSL 拡張、L2/L3/L4 最小デコード、Golden PCAP、CI 安定化、最低限の README/CHANGELOG。
- **v0.3 (完了 / P1, 2025-12-05)** — 「Clojure らしい data-first 体験」を可視化。decode 拡張点の安定化、examples の一貫性、REPL ラウンドトリップの速さを示す
  （proto-dns は :dns-ext alias で提供継続）。
- **v0.4 (計画 / P2)** — 「DNS 集計・軽量可観測」ユースケースにフォーカスし、学習/運用の両方ですぐ使える CLI と例を強化。
- **v1.0 (計画 / P3)** — 破壊的変更を収束させ、コア責務を固定し安定宣言。

---

## 最新ステータス: v0.3 / P1 完了（2025-12-05）

### 目的（P1）

pcap を REPL・seq・EDN にそのまま流し込める「data-first / REPL 快速」を体感できるリリースにする。

### UX 指標

- 小サイズ pcap で decode→xform→出力確認を 3–5 秒以内に往復できる
- EDN/JSONL 出力が diff/grep しやすい一貫性を保つ
- 不要コピーを避けた pipeline で GC を抑制

### 受け入れ条件（達成済み）

- [x] REPL ワークフロー指標と計測サンプルを README/ROADMAP に掲載
- [x] `decode_ext` API を後方互換で安定化し、DNS + 追加 1 拡張（TLS SNI）を同 API で動作
- [x] `pcap-filter` / `pcap-stats` / `flow-topn` / `dns-rtt` が共通フラグで EDN/JSONL 切替し、エラー表示が README と一致
- [x] スモークテスト（examples）＋ decode 拡張の最小ゴールデン or プロパティテストを追加
- [x] Docs 整備（README examples 一覧化、extensions.md 安定化注記、CHANGELOG 0.3.0）

### フェーズ進行状況

- [x] Phase A — pipeline 最適化 PoC、`pcap-stats` / `flow-topn` README 補強（完了: 2025-12-03）
- [x] Phase B — decode 拡張 API 安定化、TLS SNI 拡張、proto-dns 切り出し検討メモ作成（完了: 2025-12-04、現方針は同リポ alias 維持）
- [x] Phase C — core.async オプション実装（opt-in）、examples スモークテスト拡充、エラー整形統一（完了: 2025-12-05）
- [x] Phase D — ドキュメント仕上げ、CHANGELOG 0.3.0 反映、`v0.3.0` タグ作成（完了: 2025-12-05）

### Phase C / D 成果（完了）

- examples 4 本に `--async`/`--async-buffer`/`--async-mode`/`--async-timeout-ms` を追加し、同期/非同期の出力一致スモークを
  `test/examples/smoke_test.clj` に追加
- 長尺/キャンセル挙動: async timeout=0 / dropping buffer などでドロップ・キャンセルを検証するスモークを追加（flow-topn / dns-rtt / pcap-filter）
- README に async オプションの opt-in 手順と観察例を追記、ROADMAP 反映、CHANGELOG 0.3.0 公開
- `git tag v0.3.0` 済み（2025-12-05）

### 進捗サマリ（2025-12-05 時点）

- TLS SNI 拡張実装・テスト・例への統合を完了し、`docs/extensions.md` に使用/制約を追記
- decode_ext の安定化ドラフト `dev/decode-ext-api-plan.md` と proto-dns 分離計画ドラフト `dev/proto-dns-split-plan.md` を作成
  （現方針は alias 維持だが検討記録として保持）
- REPL 指標（小/中/大）を取得し README/ROADMAP に反映、ベースラインを最新化
- examples 4 本のフォーマット/エラー整形を共通化し、`pcap-filter` JSONL メタ出力のスモークテストを追加
- async オプションの opt-in 実装とスモークテストを整備し、CHANGELOG/README/ROADMAP を v0.3.0 内容に同期

---

## パフォーマンスベースライン（記録用）

- 2025-12-04 合成 PCAP `/tmp/paclo-mid-50k.pcap` (50k pkt, caplen≈74B, :xform drop<60B)
  - decode?=false: 273.7ms / decode?=true: 879.9ms
- 2025-12-03 合成 PCAP `/tmp/bench-100k.pcap` (100k pkt, caplen≈74B)
  - decode?=false: 398.5ms / decode?=true: 1291.7ms
- 2025-12-03 小サンプル `test/resources/dns-sample.pcap` (4 pkt)
  - decode?=false: 11.1ms / decode?=true: 13.3ms
- 2025-12-02 合成 100k pkt + 小サンプル（参考値）
  - decode?=false: 0.37s（50k pkt after drop） / decode?=true: 1.36s
  - 小サンプル 7.9ms

---

## v0.4 / P2 計画（DNS 集計ユースケース）

### 目的（P2）

DNS トラフィックを EDN/JSONL/CSV へ即時集計し、軽量な可観測性/セキュリティ用途にそのまま使えるツールキットを提供する。

### スコープ

- 必須: DNS 指向の集計/ランキング CLI（babashka/sci ベース）を 1–2 本追加（例: qps/rcode/rrtype top-n, SNI/host 集計）。
- 必須: `paclo-proto-dns` は同リポの `:dns-ext` alias として維持し、依存/ビルド時間を抑えたまま使いやすさを改善（README に alias 使い方を明示）。
- 必須: examples を DNS 集計に寄せた形で拡充（既存 `dns-rtt` を再利用しつつ、新 CLI と共通フラグを揃える）。
- 必須: 出力フォーマットを EDN/JSONL/CSV で統一し、メタデータ（drop/cancel/async 状態）を継承。
- 任意: Parquet/duckdb への連携サンプルを 1 本（サイズ次第で後方互換を崩さない範囲）。
- 非スコープ: 重い可視化 UI、フル DPI 自動解析、ストリーム処理基盤への統合。

### 受け入れ条件（Done 定義）

- [ ] `paclo-proto-dns` が `:dns-ext` alias で一貫して動作し、README にセットアップ/依存手順が明示されている。
- [ ] DNS 集計 CLI（bb/sci）が `--async` 系フラグを含め examples と一貫し、サンプル PCAP で動作確認済み。
- [ ] DNS 集計用のスモーク/ゴールデンテストを追加（小 PCAP 同梱）。
- [ ] README/ROADMAP/CHANGELOG に v0.4 内容と使い方を反映し、最新ベンチまたは目安を 1 件掲載。
- [ ] 依存・セキュリティチェック（eastwood/nvd）を実行し、クリティカルなしであることを明記。

### 着手前の準備（進行中）

- [x] 方針: `paclo-proto-dns` は同リポで `:dns-ext` alias として維持
- [x] dns-ext ロード確認コマンドを README に追記（`clojure -M:dev:dns-ext -e ...`）
- [x] DNS 用サンプル PCAP の最小セットを整理（同梱: `dns-sample.pcap` 4pkt, `dns-synth-small.pcap` 10pkt synthetic）
- [x] babashka ポリシー: 最新安定版へ追従（現在 1.12.212 で確認済み）。CI でも `bb --version` をチェックする方針。
- [x] CSV/Parquet/duckdb 方針: CSV は `:csv` alias のみ追加（デフォルト非依存）。Parquet/duckdb は未同梱の任意オプションとして
  README/ROADMAP に明記し、必要時に alias で opt-in する。

### マイルストン

- Phase E (計画確定) — 2025-12-12: DNS 集計の指標と出力項目を固め、CLI コマンド仕様を決定。`:dns-ext` alias の依存/起動確認を整備。
- Phase F (実装/テスト) — 2025-12-22: CLI 実装、examples 追従、スモーク/ゴールデンテスト追加。`:dns-ext` alias での CI（lint+tests+cljdoc）を green に。
- Phase G (ドキュメント/リリース準備) — 2026-01-05: README/ROADMAP/CHANGELOG 反映、ベンチ結果掲載、リリース候補タグ `v0.4.0-rc` 作成。

### Phase E 着手メモ（2025-12-05 更新）

- DNS 集計 CLI を `dev/examples/dns_topn.clj` / `dev/examples/dns_qps.clj` に実装中
  （async/drop/cancel、punycode opt-in + warn、max-buckets/warn-buckets-threshold、empty-bucket 補完、
   SNI/ALPN 集計、SNI BPF 切替）。SNI/ALPN サンプル `test/resources/tls-sni-sample.pcap`
  / `tls-sni-alpn-sample.pcap` を追加。設計は `dev/dns-agg-cli-plan.md` に反映。
- サンプル PCAP は既存 `dns-sample.pcap` + `dns-synth-small.pcap` をゴールデン候補とし README に記載。
  必要に応じて `dev/make_synth_pcap.clj` で生成（dns-synth-small は同梱）。
- 決定事項: CSV は RFC4180 風 quoting（" と , ; 改行で quote）、qname は lower + trailing dot 削除。
  SNI 集計は `dns-topn` の group オプションとして含める（別 BPF 指定は将来検討）。
- 残件: punycode 対応の要否、async の実動実装、dns-qps の空洞バケット出力オプション、SNI 用デフォルト BPF 指定。

### リスクと緩和

- PCAP サンプル不足 → `make-synth-pcap` を DNS 用に拡張し、小/中サイズのゴールデンを生成して同梱。
- alias 経由の依存抜け/初期化漏れ → README に `:dns-ext` の追加依存と起動例を明記し、CI で alias パスを走らせる。
- CSV/Parquet 追加による依存増 → CSV は標準出力のみ、Parquet は任意オプションとしデフォルト依存に含めない。

---

## v1.0 に向けたスコープ確定（P3）

- コア責務: PCAP 入出力 + BPF + 遅延処理 + L2/L3/L4 最小デコード
- 上位プロトコル・統計・可視化は別モジュールで提供
- API 安定化宣言（Spec/malli 型ヒントは任意）
- v1.0 タグ公開で破壊的変更を凍結

---

## モジュール分割方針

- paclo-core — コア（必須）
- paclo-proto-dns — 上位プロトコル例（同リポで `:dns-ext` alias 提供）
- paclo-cli — 最小 CLI
- paclo-examples — サンプル集
- [ ] CSV/Parquet オプションの依存戦略を決定（デフォルト依存に含めない方針の確認）
- [x] CSV 用の軽量 alias `:csv` を追加（`org.clojure/data.csv`）。Parquet/duckdb はデフォルト依存に含めず、今後の任意オプションで検討。
