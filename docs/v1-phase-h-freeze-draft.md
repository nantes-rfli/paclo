# v1.0 / Phase H API Freeze Draft (2026-02-23)

このドキュメントは P3 Phase H（API 凍結設計）の着手メモです。
目的は、1.0 で固定する契約を「実装の現状」と「未決定事項」に分けて棚卸しし、Phase I の実装対象を明確化することです。

---

## 1. Phase H 着手ステータス

- [x] 公開 API（`paclo.core` / `paclo.decode-ext`）の棚卸し
- [x] 公式 CLI 5 コマンドの引数・終了コード・出力契約の棚卸し
- [x] BPF DSL のサポート構文を一覧化
- [x] 互換性マトリクスと CI 実装の差分を明文化
- [x] 破壊的変更リストの最終確定
- [~] README / cljdoc への契約反映（README は反映済み、cljdoc は未反映）

---

## 2. 公開 API 凍結ドラフト

### 2.1 `paclo.core`（凍結候補）

- `bpf`
  - 署名: `(bpf form)`
  - 返却: BPF 文字列または `nil`
  - 受理入力:
    - `nil`
    - 文字列（そのまま返す）
    - キーワード（`:udp` `:tcp` `:icmp` `:icmp6` `:arp` `:ip` `:ipv4` `:ip6` `:ipv6`）
    - DSL ベクタ（後述「4. BPF DSL」）
  - 例外: 未知のキーワード/演算子/型で `ex-info`
- `packets`
  - 署名: `(packets opts)`
  - 返却: packet map の lazy seq
  - `opts` の主要契約:
    - 入力元は `:path` または `:device` のいずれか（両方は不可）
    - `:filter` は `string | keyword | vector | nil`
    - `:decode? true` で `:decoded` または `:decode-error` を付与
    - `:xform` は `(sequence xform stream)` と同等に適用
  - 実装上の注意:
    - `capture->seq` のデフォルト停止条件（`:max 100` / `:max-time-ms 10000` / `:idle-max-ms 3000`）を継承
    - `:decoded` がある要素には `decode-ext/apply!` を適用
- `write-pcap!`
  - 署名: `(write-pcap! packets out)`
  - 入力: `byte-array` または `{:bytes ... :sec ... :usec ...}` の seq
  - 挙動: `out` へ PCAP 書き込み。`out` が空なら `ex-info`
- `list-devices`
  - 署名: `(list-devices)`
  - 返却: `{:name "...", :desc "..."}` の seq

### 2.2 `paclo.decode-ext`（凍結候補）

- `register! [k f]`: hook を登録（同キー再登録は上書き＋末尾へ）
- `unregister! [k]`: hook を削除
- `installed []`: 登録キー列を返す
- `apply! [m]`: 条件付きで hook を順適用
  - 実行条件: `m` が map、`m` に `:decoded` があり `:decode-error` が無い
  - hook 例外は握りつぶし、元の map を継続
  - hook の返り値が map 以外なら無視

### 2.3 非公開境界（1.0 で明示する対象）

- `paclo.pcap` / `paclo.parse` / `paclo.proto.*` は内部実装 namespace 扱い
- 1.0 では `paclo.core` と `paclo.decode-ext` を公開 API 面として明示する

---

## 3. 公式 CLI 契約ドラフト

対象コマンド:

- `examples.pcap-filter`
- `examples.pcap-stats`
- `examples.flow-topn`
- `examples.dns-qps`
- `examples.dns-topn`

共通終了コード（`examples.common` 由来）:

- `1`: 必須引数不足（usage）
- `2`: 入力 PCAP 不在
- `3`: 列挙値バリデーションエラー（group/mode/metric/format など）
- `4`: フラグ/数値引数の不正

共通出力契約:

- 正常系の主データは stdout（`edn` / `jsonl` / `csv`）
- 実行メタ情報や warning は stderr
- 例外未捕捉の異常終了は JVM の終了コードに依存（Phase I で統一方針を決める）

---

## 4. BPF DSL 凍結ドラフト（`paclo.core/bpf`）

論理演算:

- `[:and expr ...]`
- `[:or expr ...]`
- `[:not expr]`

プロトコル:

- `:udp` `:tcp` `:icmp` `:icmp6` `:arp`
- `:ip` `:ipv4` `:ip6` `:ipv6`
- `[:proto <keyword>]`

アドレス:

- `[:host "..."]`
- `[:src-host "..."]`
- `[:dst-host "..."]`
- `[:net "..."]`
- `[:src-net "..."]`
- `[:dst-net "..."]`

ポート:

- `[:port N]`
- `[:src-port N]`
- `[:dst-port N]`
- `[:port-range A B]`
- `[:src-port-range A B]`
- `[:dst-port-range A B]`

エラー挙動:

- 未知演算子/未対応型は `ex-info`
- 数値変換不能なポート引数は `NumberFormatException` 起点で失敗

---

## 5. 互換性マトリクス（決定）

P3 目標（ROADMAP）:

- JDK: 17 / 21
- Clojure: 1.12.x
- Babashka: 1.12.x
- OS: macOS / Linux（x86_64, arm64）

2026-02-23 時点の実装状況:

- `deps.edn` の基準 Clojure は `1.12.1`
- 互換性マトリクス用 CI ジョブで Linux/JDK21 と macOS-latest/JDK17 を必須化
- JDK17 は互換性ジョブで必須、coverage ジョブでも追加検証
- macOS 軸は `macos-latest` で運用（runner 世代は GitHub 側で管理）
- arm64 は `ubuntu-24.04-arm` で CI ジョブを導入済み（2026-02-23 に `continue-on-error` を解除して必須ゲート化）

arm64 必須ゲート化の判定基準（2026-02-23 確定）:

- 連続 14 日以上、`arm64-monitor` が 95% 以上 success（workflow run 単位）
- 同期間で flaky retry（rerun）依存が 5% 未満
- 失敗原因が infra（runner/network）ではなくテスト実装起因の場合、修正 PR が 72 時間以内にマージされている
- `clojure -M:test` / `dns-ext smoke` / `perf-gate` の arm64 実行時間が x86_64 比 1.5 倍以内
- 昇格手順: `continue-on-error` を解除し、`compatibility-matrix` に arm64 required job を追加して 1 週間観測
- 例外運用（2026-02-23）: リリース優先で 14 日観測を待たず `arm64-monitor` を required 化。観測継続し、基準未達が続く場合は閾値/構成を再調整する

---

## 6. 性能バジェット（決定）

基準値（既存ベースライン）:

- `mid-50k` 合成 PCAP（`decode?=true`）: `879.9ms`（2025-12-04 記録）

1.0 向け運用値:

- hard fail: `<= 1.2s`
- warning: `> 1.0s`

備考:

- `clojure -M:perf-gate` を追加し、CI で上記閾値を実行時チェックする

---

## 7. 破壊的変更判断（確定）

- 決定 A: Clojure の公式サポートは `1.12.x` に固定
  - 理由: 現行 `deps.edn` が `1.12.1` を基準としており、宣言と実装を一致させるため
  - 影響: 旧記載の `1.11.x` は v1.0 の公式保証対象から外す
- 決定 B: CLI 終了コードは `1/2/3/4` を固定し、予期しない例外の統一コード導入は Phase I へ送る
  - 理由: 既存利用への影響を抑えつつ、テスト整備と同時に導入した方が安全なため
- 決定 C: `clojure -M:run` は廃止せず、`paclo.core/-main` を追加してガイド表示に統一
  - 理由: 既存 alias 互換を保ったまま実行時エラーを解消できるため

---

## 8. Phase I への引き継ぎタスク

- [x] README に公開 API 早見表と互換性マトリクスを追加
- [x] cljdoc 向け API 契約（引数・返却・例外）を同期（`docs/cljdoc-api-contract.md`）
- [x] CI に互換性マトリクス準拠ジョブを追加（Linux/JDK21 + macOS/JDK17）
- [x] 性能ゲート（mid-50k）を CI に追加（`clojure -M:perf-gate`）
- [x] arm64 必須ゲート化の判定基準を確定（成功率/flake率/時間比/昇格手順）
- [x] arm64 ジョブを required 化（`continue-on-error` 解除、2026-02-23）
- [ ] required 化後の観測実績を蓄積し、判定基準との乖離をレビュー（必要なら閾値/構成見直し）
- [x] CLI 出力スナップショットと終了コードテストを追加
  （`test/examples/cli_contract_test.clj`, `test/resources/cli_snapshots.edn`）
