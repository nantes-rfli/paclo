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
- **v0.4 (完了 / P2, 2025-12-10)** — 「DNS 集計・軽量可観測」ユースケースにフォーカスし、学習/運用の両方ですぐ使える CLI と例を強化。
- **v1.0 (計画 / P3)** — 破壊的変更を収束させ、コア責務を固定し安定宣言。

---

## 最新ステータス: v0.4 / P2 完了（2025-12-10）

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

### 進捗サマリ（2025-12-10 時点）

- TLS SNI 拡張実装・テスト・例への統合を完了し、`docs/extensions.md` に使用/制約を追記
- decode_ext の安定化ドラフト `dev/decode-ext-api-plan.md` と proto-dns 分離計画ドラフト `dev/proto-dns-split-plan.md` を作成
  （現方針は alias 維持だが検討記録として保持）
- REPL 指標（小/中/大）を取得し README/ROADMAP に反映、ベースラインを最新化
- examples 4 本のフォーマット/エラー整形を共通化し、`pcap-filter` JSONL メタ出力のスモークテストを追加
- async オプションの opt-in 実装とスモークテストを整備し、CHANGELOG/README/ROADMAP を v0.3.0 内容に同期
- CI は dns-ext smoke / cljdoc dry-run を含め green（2025-12-10 時点）。Dependency Audit（nvd-clojure）が
  GA でクリティカルなし。`v0.4.0-rc` から `v0.4.0` をタグ発行。

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

## v0.4 / P2 完了（DNS 集計ユースケース）

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

- [x] `paclo-proto-dns` が `:dns-ext` alias で一貫して動作し、README にセットアップ/依存手順が明示されている。
- [x] DNS 集計 CLI（bb/sci）が `--async` 系フラグを含め examples と一貫し、サンプル PCAP で動作確認済み。
- [x] DNS 集計用のスモーク/ゴールデンテストを追加（小 PCAP 同梱）。
- [x] README/ROADMAP/CHANGELOG に v0.4 内容と使い方を反映し、最新ベンチまたは目安を 1 件掲載。
- [x] 依存・セキュリティチェック（eastwood/nvd）を実行し、クリティカルなしであることを明記。
  - 2025-12-10: GitHub Actions "Dependency Audit"（nvd-clojure）を `NVD_API_TOKEN` 設定付きで実行し、クリティカル CVE なしを確認。

### 着手前の準備（進行中）

- [x] 方針: `paclo-proto-dns` は同リポで `:dns-ext` alias として維持
- [x] dns-ext ロード確認コマンドを README に追記（`clojure -M:dev:dns-ext -e ...`）
- [x] DNS 用サンプル PCAP の最小セットを整理（同梱: `dns-sample.pcap` 4pkt, `dns-synth-small.pcap` 10pkt synthetic）
- [x] babashka ポリシー: 最新安定版へ追従（現在 1.12.212 で確認済み）。CI でも `bb --version` をチェックする方針。
- [x] CSV/Parquet/duckdb 方針: CSV は `:csv` alias のみ追加（デフォルト非依存）。Parquet/duckdb は未同梱の任意オプションとして
  README/ROADMAP に明記し、必要時に alias で opt-in する。

### マイルストン

- Phase E (計画確定) — 2025-12-12: DNS 集計の指標と出力項目を固め、CLI コマンド仕様を決定。`:dns-ext` alias
  の依存/起動確認を整備。 **状態: 完了 (2025-12-09)**
- Phase F (実装/テスト) — 2025-12-22: CLI 実装、examples 追従、スモーク/ゴールデンテスト追加。`:dns-ext` alias での
  CI（lint+tests+cljdoc）を green に。**状態: 完了 (2025-12-10: CI green / cljdoc dry-run / dns-topn smoke 反映、
  NVD は GA Dependency Audit でクリティカルなし)**
- Phase G (ドキュメント/リリース準備) — 2026-01-05: README/ROADMAP/CHANGELOG 反映、ベンチ結果掲載、リリース候補タグ `v0.4.0-rc` 作成。
  **状態: 完了 (2025-12-10: `v0.4.0-rc` → `v0.4.0` タグ発行)**

### Phase E メモ（2025-12-09 更新 / 完了）

- `dns-topn` / `dns-qps` を実装済み（punycode opt-in+warn, async/drop/cancel, empty-bucket 補完, SNI/ALPN 集計, RFC4180 CSV）。
  SNI/ALPN サンプル `tls-sni-sample.pcap` / `tls-sni-alpn-sample.pcap` / `tls-sni-h3[-mix]-sample.pcap` を同梱し、スモークテスト追加。
- ALPN 集計仕様を確定（group=:alpn、デフォルトは先頭のみ採用、`--alpn-join` で全 ALPN を結合）し、サンプル PCAP と smoke テストを整備済み。
- `dns-qps` に `--log-punycode-fail` を追加し README/Usage を同期。qname 正規化は toASCII で検証して warn を stderr 出力。
- スモークテストを `test/examples/smoke_test.clj` に拡充（csv ヘッダ、punycode warn）し、`clojure -M:test` は 2025-12-09 時点で green。
- v0.4 ベンチ目安を追加: `dns-qps` on `dns-synth-small.pcap` (10 pkt, bucket=1000, decode?=true)
  で elapsed ≈ 16.2ms（macOS 14.4 / i7-8700B / JDK21）。
- eastwood は `-M:eastwood:dns-ext` + data.xml 追加で完走（警告は boxed-math 等のみ）。
  nvd は GitHub Actions `Dependency Audit`（secrets.NVD_API_TOKEN）で実行予定。ローカル実行時は同トークンを
  `NVD_API_TOKEN` に設定する。

### Phase F 進行中メモ（2025-12-10 更新）

- CI 拡張: `dns-topn` の最小 smoke (`clojure -M:dev:dns-ext -m examples.dns-topn test/resources/dns-sample.pcap`) を
  `ci.yml` build ジョブに追加（2025-12-09 適用済み）。
- CI 拡張: cljdoc ドライランを追加し、`:dns-ext` 経路でも壊れないことを確認（`cljdoc.doc-tree` の require を CI で実施、2025-12-09 適用済み）。
- セキュリティ: GitHub Actions "Dependency Audit" で `clojure -M:nvd dev/nvd-clojure.edn "$(clojure -Spath -A:dev:dns-ext)"`
  を実行し、クリティカル CVE なしを確認（2025-12-10）。
- ドキュメント: README/CHANGELOG を CI 変更と NVD 結果に同期。

#### CI トラブルシュート（2025-12-10）

- `cljdoc/cljdoc-action@v1` が解決できず CI 失敗 → cljdoc CLI (`cljdoc.main` require) を直接呼び出す形に切替。
- coverage ジョブで JDK21/17 + cloverage がネイティブクラッシュする事象 → coverage ジョブを Temurin 17 固定 + continue-on-error に緩和。

### リスクと緩和

- PCAP サンプル不足 → `make-synth-pcap` を DNS 用に拡張し、小/中サイズのゴールデンを生成して同梱。
- alias 経由の依存抜け/初期化漏れ → README に `:dns-ext` の追加依存と起動例を明記し、CI で alias パスを走らせる。
- CSV/Parquet 追加による依存増 → CSV は標準出力のみ、Parquet は任意オプションとしデフォルト依存に含めない。

---

## v1.0 / P3 着手計画（API 安定化・凍結）

### 目的（P3）

paclo-core の責務と API を 1.0 で凍結し、以後の変更を後方互換に限定できる状態を作る。破壊的変更は P3 内で完了させ、以降は deprecation ポリシーに従う。

### P3 スコープ

- 必須: コア API/CLI/BPF DSL の安定化（`decode` / `decode-ext` / `xform` / CLI 共通フラグ / BPF DSL）、エラー/ログ契約の文書化
- 必須: 互換性マトリクス確定（JDK/LTS、Clojure/bb バージョン、OS）、サポート方針とテスト対象を明記
- 必須: 回帰セット常設（ゴールデン PCAP、property/quickcheck、性能バジェット、async 経路スモーク、CLI 出力スナップショット）を CI に組み込み
- 必須: Migration ガイド作成（0.4→1.0 の破壊的変更一覧 / 代替手順 / deprecation タイムライン）
- 任意: コアの malli/spec ヒントと cljdoc での型/契約閲覧性改善（コード本体は opt-in ヒント）
- 非スコープ: 新規上位プロトコル追加、重い可視化/UI、ストリーミング基盤連携、依存を膨らませる新機能

### P3 受け入れ条件（Done 定義）

- [x] コア API/CLI/BPF DSL の契約を README + cljdoc に明文化し、破壊的変更は P3 内で完了
- [x] 互換性マトリクス（JDK17/21、Clojure 1.12.x、babashka 1.12.x、macOS/Linux x86_64/arm64）を
  README に掲載し、CI は初期セット（JDK17/macOS runner, JDK21/Linux x86_64）を必須で回す
- [x] 回帰セット: ゴールデン PCAP（小/中）+ property/quickcheck + async 経路スモーク +
  CLI 出力スナップショットを CI 常設、性能バジェット
  （mid-50k pcap decode?=true ≤ 1.0s をハード上限）を閾値化
- [x] セキュリティ/静的解析: eastwood / clj-kondo / nvd を定常実行し、クリティカル CVE なしを記録
- [ ] リリース成果物: CHANGELOG 1.0.0、Migration Guide (0.4→1.0)、cljdoc 公開、`v1.0.0` タグ発行

### ドキュメント計画（ユーザ導線を固定）

- README: v1.0 向けに再構成（クイックスタート + 公開API早見表 + CLI 早見表 + BPF DSL ミニ表）。破壊的変更は入れず導線を整理。
- cljdoc: 公開 API 詳細（シグネチャ、オプション、返却スキーマ、例外、BPF DSL 構文、CLI 出力スキーマ）を充実させ README からリンク。
- docs/ 配下: 補足ドキュメントの置き場として維持。例: extensions.md、リリース手順、ベンチ記録、ADR、API 詳細の草案。
- Migration Guide: 0.4→1.0 の差分と非推奨→削除のタイムラインを明文化。

### 公開 API リスト確定（宣言する範囲）

- ライブラリ: `paclo.core` の公開関数（decode / decode-ext / xform / 付随ヘルパ）とオプション・戻り値キーを固定。内部 NS は非公開明示。
- CLI: 公式サポートコマンド（pcap-filter / pcap-stats / flow-topn / dns-qps / dns-topn）のフラグ・exit code・出力フィールドを固定。
- BPF DSL: サポート構文・演算子セット・エラー挙動をリスト化し「公式仕様」として凍結。

### 互換性と品質ゲート

- 互換性マトリクス宣言（JDK17/21、Clojure 1.12.x、bb 1.12.x、macOS/Linux x86_64/arm64）と
  CI 軸を固定。初期は JDK17/macOS runner + JDK21/Linux x86_64 を必須にし、arm64 は将来追加候補。
- 回帰セット常設（ゴールデン PCAP 小/中 + property/quickcheck + async スモーク + CLI スナップショット）。
- 性能バジェットを CI で閾値化（mid-50k pcap decode?=true を
  warn=1.0s / fail=1.2s の二段階で運用）。
- セキュリティ/静的解析（nvd, eastwood, clj-kondo, cljdoc）をリリースゲートに組み込み。

### マイルストン案

- Phase H (API 凍結設計) — 日付未定（個人開発のため柔軟運用）。破壊的変更リスト確定、公開 API リスト草案、互換性マトリクスと性能バジェット決定。**状態: 完了 (2026-02-23)**
- Phase I (回帰性・互換性強化) — 日付未定。回帰セット/CI 行列/性能バジェット実装、CLI/BPF エラー契約のテスト化。**状態: 進行中 (2026-02-23)**
- Phase J (リリース準備) — 日付未定。README 再構成、cljdoc 詳細反映、Migration Guide、リリースゲート実行、`v1.0.0-rc` → `v1.0.0`。

### Phase H 着手ログ（2026-02-23）

- [x] 公開 API / CLI / BPF DSL / 互換性マトリクスの初期棚卸しを作成（`docs/v1-phase-h-freeze-draft.md`）
- [x] 破壊的変更リストを確定（`docs/v1-phase-h-freeze-draft.md` に判断を記録）
- [x] 互換性マトリクスの最終決定（Clojure 1.12.x を公式サポートとして固定）
- [x] 互換性マトリクス準拠の CI ジョブを追加（Linux/JDK21 + macOS/JDK17）
- [x] arm64 ジョブを追加（`ubuntu-24.04-arm`、2026-02-23 に `continue-on-error` 解除で required 化）
- [x] 性能バジェットの CI 閾値化方針を確定（warn=1.0s / fail=1.2s）
- [x] `clojure -M:run` エラーを解消（`paclo.core/-main` を追加しガイド表示に統一）
- [x] cljdoc 向け API 契約（引数・返却・例外）の同期ドラフトを追加（`docs/cljdoc-api-contract.md`）
- [x] CLI 出力スナップショット/終了コードテストを追加
  （`test/examples/cli_contract_test.clj`）

### Phase I 進捗ログ（2026-02-23）

- [x] arm64 必須ゲート化の判定基準を確定（14日 success>=95%、flake<5%、x86_64比1.5x 以内、昇格手順）
  （`docs/v1-phase-h-freeze-draft.md`）
- [x] 14日観測を待たず arm64 required 化を先行（リリース優先の例外運用）
  （`.github/workflows/ci.yml`）
- [x] arm64 required 安定化として `pcap-loop-test` を非ゲート観測へ分離
  （`.github/workflows/ci.yml`）
- [x] `pcap-loop-test` の `PointerByReference` 反射代入を除去し、
  arm64 required の unit tests を `clojure -M:test` に再統合
  （`.github/workflows/ci.yml`, `test/paclo/pcap_loop_test.clj`）
- [x] BPF エラー契約テストを強化（`ex-data` を含む未知 proto/op/unsupported form を固定化）
  （`test/paclo/core_bpf_test.clj`）
- [x] `core/packets` の `invalid :filter` 例外契約をテスト化（メッセージ + `ex-data`）
  （`test/paclo/core_unit_test.clj`）
- [x] Migration Guide 0.4→1.0 の初版を追加（差分、移行手順、deprecation 方針）
  （`docs/migration-0.4-to-1.0.md`）

### Phase J 進捗ログ（2026-02-23）

- [x] `v1.0.0-rc` リリースチェックリストの初版を追加（ローカルゲート/CIゲート/タグ手順）
  （`docs/release-v1-rc-checklist.md`）
- [x] `v1.0.0-rc` ローカルゲートを実行し全コマンド成功を確認
  （`clojure -M:test`, `clojure -M:eastwood`, `clj-kondo --lint src test dev`, `clojure -M:perf-gate`,
   `clojure -M:dev:dns-ext -m examples.dns-topn test/resources/dns-sample.pcap`, `cljdoc.doc-tree` load）
- [x] arm64 昇格判定の定期レポート workflow を追加（`workflow_dispatch` + weekly schedule）
  （`.github/workflows/arm64-promotion-report.yml`）
- [x] arm64 昇格判定のローカル集計スクリプトを追加（`gh` API 経由）
  （`dev/script/arm64_promotion_report.sh`）
- [x] 最新 CI / Dependency Audit の green を確認（`gh run list`）
  （CI: `22295071881` success, Dependency Audit: `21812860426` success）
- [x] `CHANGELOG.md` に `## [1.0.0-rc] - 2026-02-23` を追加
  （`CHANGELOG.md`）
- [ ] arm64 promotion 判定を再計測し、基準未達を継続確認
  （`dev/script/arm64_promotion_report.sh 14 0.95 0.05 1.5`:
   `sample_count=7`, `window_covered=false`, `success_rate=0.714`, `max_duration_ratio=2.104`,
   `eligible_for_required_gate=false`）

### リスクと緩和（P3）

- API 凍結漏れ: PR テンプレに契約チェックリストを追加し、公開 API 変更はレビュー必須。
- 性能劣化: 性能バジェット逸脱で CI red、原因追跡を必須化。
- 依存脆弱性: nvd をリリースゲートに据え、CVE 例外は ADR 化して合意の上でのみ許可。

---

## モジュール分割方針

- paclo-core — コア（必須）
- paclo-proto-dns — 上位プロトコル例（同リポで `:dns-ext` alias 提供）
- paclo-cli — 最小 CLI
- paclo-examples — サンプル集
- [x] CSV/Parquet オプションの依存戦略を決定（デフォルト依存に含めない方針の確認）
  - 方針: CSV は `:csv` alias のみ追加しデフォルト非依存、Parquet/duckdb は任意オプションとして今後もデフォルトに含めない。
- [x] CSV 用の軽量 alias `:csv` を追加（`org.clojure/data.csv`）。Parquet/duckdb はデフォルト依存に含めず、今後の任意オプションで検討。
