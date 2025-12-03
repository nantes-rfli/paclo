# Paclo Roadmap

本ドキュメントは Paclo ライブラリのロードマップです。  
フェーズごとの目標・タスク・進捗を一覧できる形で管理します。  
開発フローや環境手順は README を参照してください。

---

## 北極星（North Star）

「PCAPを *Clojureのデータ処理* に自然合流させる、最小で快適なパケット処理ライブラリ」

- Data-first（EDN/マップ/seq/transducer）
- 小さなコア + 拡張モジュール
- REPLで反復が速い（ホットスワップ、軽依存）
- tcpdump / Wireshark とは競合せず“つなぐ”

---

## フェーズ構成

### P0: 基盤を OSS-ready に（v0.2）

**目的**: 最小価値の安定提供と外部利用の障壁ゼロ化  

- [x] `:xform` 実装（transducer対応）
- [x] BPF DSL `:proto/:net/:not` 拡張
- [x] L2/L3/L4 最小デコード（Ethernet/IPv4/IPv6/TCP/UDP/ICMP）
- [x] Golden PCAP & 往復テスト
- [x] `list-devices` のファサード + 最小テスト
- [x] README: cljdoc バッジ追加
- [x] README: install/require 一文
- [x] README: サポート環境（macOS/Intel, JDK, libpcap）
- [x] README: :decode? の失敗時ふるまいを明記
- [x] CHANGELOG 初版 / SemVer 宣言
- [x] CI ビルド安定化（main ブランチ green 確認で完了）

---

### P1: Clojureらしい処理体験（v0.3）

**目的**: North Star の「data-first / REPL 快速」を v0.3 で可視化し、pcap を REPL・seq・EDN に
そのまま流し込める体験を前面に出す。

#### UX指標

- REPL 往復（小 pcaps）3–5 秒以内で decode → xform → 出力を確認できる
- EDN/JSONL 出力の一貫性（diff/grep 即応）
- ゼロコピー志向で不要コピー・GC を抑える pipeline

#### スコープ

- 必須: pipeline 最適化（`packets → :xform → write-pcap!`）、decode 拡張点 API 安定化、
  DNS デコードを `paclo-proto-dns` として分離、Cookbook/例集の充実
- 任意: core.async オプション（背圧・キャンセル例付き）
- 非スコープ: 可視化 UI や重い統計処理（P2 以降で検討）

#### 受け入れ条件（Done 定義）

- [ ] REPL ワークフロー指標を README/ROADMAP に明記し、計測結果サンプルを 1 件掲載
- [ ] `decode_ext` API が破壊的変更なしで安定化し、DNS + 追加 1 拡張
  （例: TCP 概要 or TLS SNI）が同 API で動作
- [ ] examples（`pcap-filter` / `pcap-stats` / `flow-topn` / `dns-rtt`）が共通フラグで
  EDN/JSONL 切替でき、エラー表示が README と一致
- [ ] スモークテスト（examples）＋ decode 拡張の最小ゴールデン or プロパティテストを
  1 本追加
- [ ] Docs: README “Run the examples” の一覧化、extensions.md に安定化注記、
  CHANGELOG に 0.3.0 を追記

### ベースライン（計測メモ）

- 2025-12-02 `examples.pipeline-bench`（macOS, local tmp PCAP）
  - `decode?=false` 100k pkt → drop<60B で 50k pkt / 約 0.37s
  - `decode?=true` 100k pkt → 50k pkt / 約 1.36s
  - 小サンプル `test/resources/dns-sample.pcap` 4 pkt / 約 7.9ms
- 2025-12-03 `examples.pipeline-bench`（小サンプル `test/resources/dns-sample.pcap`）
  - `decode?=false` 4 pkt / 11.1ms （フィルタなし、:xform drop<60B）
  - `decode?=true`  4 pkt / 13.3ms （同条件、出力 `/tmp/pipeline-out.pcap`）
  - 条件: ローカル開発機（詳細スペックは未記録）
- 2025-12-03 `examples.pipeline-bench`（合成 PCAP `/tmp/bench-100k.pcap` 100k pkt, caplen≈74B）
  - `decode?=false` 100k pkt / 432.5ms
  - `decode?=true`  100k pkt / 1754.8ms
  - 条件: ローカル開発機、:xform drop<60B（デフォルト）。入力 PCAP はローカル生成（リポジトリ未同梱）。

### フェーズ分割

- [x] Phase A: pipeline 最適化 PoC、`pcap-stats` / `flow-topn` の README 補強（完了: 2025-12-03）
- [ ] Phase B: decode 拡張 API 安定化、追加拡張 1 本（TLS SNI）、
  `paclo-proto-dns` 切り出し計画（進行中）
- [ ] Phase C: core.async オプション（任意）、examples スモークテスト、エラー整形の統一
- [ ] Phase D: ドキュメント仕上げ、CHANGELOG 更新、`v0.3.0` タグ準備

---

### P2: ユースケース特化（v0.4）

#### 候補ユースケース（1つ選ぶ）

- 教育/検証用ラボ
- 軽量セキュリティ（DNS集計）
- データ前処理（pcap→EDN/CSV/Parquet 変換）

#### 成果

- examples/ ディレクトリ充実
- プチ CLI（babashka/sci）
- ミニベンチマーク

---

### P3: 1.0 に向けたスコープ確定

**目的**: 破壊的変更の収束と責務の明文化  

- CORE = PCAP入出力 + BPF + 遅延処理 + L2/L3/L4最小デコード  
- 上位プロトコルや統計/可視化は別モジュール  
- API 安定化宣言、Spec/malli 型ヒントは任意  
- v1.0 タグ公開

---

## モジュール分割方針

- paclo-core … コア（必須）
- paclo-proto-dns … 上位プロトコル例（別モジュール、別repoに切り出し）
- paclo-cli … 最小 CLI
- paclo-examples … サンプル集

---

## リリース目安

- v0.2 = CORE + :xform + BPF拡張 + L2/3/4最小 + Docs  
- v0.3 = decode拡張点 + proto-dns + examples + (任意) core.async  
- v1.0 = スコープ固定・破壊変更収束・安定宣言

## P1 Improvement Track (v0.3.0)

**目的**: P1 のスコープを実務タスクに落とし込み、例（examples）とエラーハンドリングを
「小さく強く」仕上げる。

**完了条件**（上記受け入れ条件と対応）:

- [ ] REPL 計測結果を 1 例残し、指標を明文化
- [ ] examples 4 本が共通フラグで EDN/JSONL 切替し、Usage/エラー文言が一致
- [ ] `decode_ext` API 安定化 + DNS 以外の拡張 1 本追加
- [ ] スモークテストと decode 拡張の最小ゴールデン/プロパティいずれか 1 本
- [ ] Docs 仕上げ（README examples 一覧化、extensions.md 安定化注記、CHANGELOG 0.3.0）

**段階**:

- **Phase A** (完了 2025-12-03): `dns-rtt` に client/server フィルタ、
  `pcap-stats` / `flow-topn` の README 追記、pipeline ベンチで REPL 往復のベースライン取得
- **Phase B** (進行中): TLS SNI 拡張を examples へ統合済み。
  decode_ext API の安定化方針ドラフトあり。
  `paclo-proto-dns` 分離計画ドラフトは未作成。
  残: 計測掲載/ドキュメント整備/追加テスト/分離計画の明文化。
- **Phase C**: examples スモークテスト、エラー整形統一、core.async オプション（任意）
- **Phase D**: ドキュメント仕上げ & `v0.3.0` タグ

### Phase B の初期タスクリスト（着手用）

- [x] 追加 decode 拡張は TLS SNI（ClientHello限定・再組立なし）で進行。
  理由: DNS 拡張と並べて上位レイヤを示せる、追加依存なしで data-first 価値が高い。
  完了 2025-12-03（期限: 2025-12-10）
- [x] `decode_ext` API の安定化案ドラフト（互換性/エラー方針）作成 →
  `dev/decode-ext-api-plan.md`（完了: 2025-12-03）
- [x] 追加拡張の最小実装とサンプル: `paclo.proto.tls-ext` で ClientHello から SNI/ALPN を付与。
  サンプル CLI `dev/examples/tls_sni_scan.clj` を追加し、EDN/JSONL 両対応で集計可能
  （完了: 2025-12-03）。
- [x] `paclo-proto-dns` モジュールの切り出し作業計画: `dev/proto-dns-split-plan.md`
  にドラフト作成（2025-12-03）。

### Phase B 進捗（2025-12-03 時点）

- 完了: TLS SNI 拡張を実装・検証。`src/paclo/proto/tls_ext.clj` に SNI/ALPN/summary 付与、
  `test/paclo/tls_ext_test.clj` で境界ケースをカバー。
- 完了: Examples への統合。`dev/examples/tls_sni_scan.clj` で EDN/JSONL 切替・TopN 集計を提供。
  `docs/extensions.md` に使用方法と制約を追記済み。
- 完了: decode_ext API 安定化ドラフトを `dev/decode-ext-api-plan.md` に作成。
  非破壊ルール/実行条件/例外方針を記載。`dx/with-hooks` は要否検討のまま保留。
- 完了: `paclo-proto-dns` 分離計画ドラフトを `dev/proto-dns-split-plan.md` に作成
  （別リポジトリ化・依存・公開手順）。
- 完了: DNS 拡張を `:dns-ext` alias 経由のオプション扱いに整理（同リポ・単一アーティファクトのまま）。
- 未了: REPL 指標/計測結果の公開、decode_ext 追加テスト
  （フック順序・非 map 戻り値無害化等）、
  examples 共通フラグ/エラー整形の統一、CHANGELOG/README 仕上げ。
- 未了: REPL 指標/計測結果の公開（中〜大規模サンプル）、decode_ext 追加テスト
  （順序保証のプロパティなど）、
  examples 共通フラグ/エラー整形の統一、CHANGELOG/README 仕上げ。

次のアクション（Phase C に持ち越し予定のものも含む）

- `paclo-proto-dns` 分離計画ドラフトを作成して Phase B をクローズ可能な状態にする。
- REPL ワークフロー計測値を README/ROADMAP に掲載（例: 小 PCAP での decode 有無の往復時間）。
- decode_ext のスモーク/プロパティテスト追加
  （フック順序・例外無害化・非 map 戻り値無視を確認）。
- examples 4 本のフラグ/Usage/エラー整形を統一し、`pcap-filter` JSONL メタの挙動も
  smoke で確認。
- Docs 仕上げ（extensions.md 安定化注記、README examples 一覧整形、CHANGELOG 0.3.0 追記）。
