# paclo-proto-dns 分離ドラフト（Phase B 未了タスク）

## 目的
- `paclo.proto.dns-ext` を別リポジトリ `paclo-proto-dns` に切り出し、core を最小化しつつ拡張例を独立配布できるようにする。

## スコープ
- 移設対象: `src/paclo/proto/dns_ext.clj` と対応テスト（`test/paclo/dns_ext_test.clj`）、DNS 用 test resources（pcap/golden）。
- paclo 本体: optional dependency として `io.github.paclo/paclo-proto-dns` を参照（:dev/:test で有効化）。
- 公開: Clojars `io.github.paclo/paclo-proto-dns` v0.1.0（プレリリース扱い）。

## 作業ステップ案
1) 新リポジトリ作成（GitHub: paclo-proto-dns）。LICENSE/README/cljdoc バッジ雛形。
2) コード移設: 現行ファイルを `src/paclo/proto/dns_ext.clj` と同パスでコピー。test/resources も移動しパス修正。
3) deps.edn: minimal deps（paclo-core 依存、test 用に `clojure.test`、`pcap` リソース読込）。
4) CI: clj -T:build test + cljdoc（GitHub Actions）。
5) Clojars: `0.1.0` リリース（playground 位置づけ）。
6) paclo 本体: deps.edn に `:lib io.github.paclo/paclo-proto-dns {:mvn/version "0.1.0"}` を optional で追加。
7) docs: `docs/extensions.md` に外部モジュールとしての使い方を追記、ROADMAP/CHANGELOG に分離済みを明記。

## 留意事項
- API 互換性: `register!/unregister!/installed` を維持。戻り値/エラーポリシーは decode_ext 安定化方針に従う。
- サンプル: `dev/examples/dns_summary.clj` は新モジュールを require する形に調整。
- リリースキー管理: Clojars デプロイ鍵を新リポジトリのシークレットに追加。

## マイルストン案
- 2025-12-10: リポジトリ雛形 + コード移設 + CI スモーク通過
- 2025-12-15: Clojars 0.1.0 プレリリース + cljdoc 公開
- 2025-12-17: paclo 本体に optional 依存を追加し、ドキュメントを更新
