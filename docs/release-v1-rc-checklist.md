# v1.0.0-rc Release Checklist

`v1.0.0-rc` を作る前に実行する最小チェックリストです。
目的は「契約凍結の逸脱」「互換性劣化」「性能後退」を rc タグ前に確実に検出することです。

## 1. Preconditions

- [ ] `docs/cljdoc-api-contract.md` が最新実装と一致している
- [ ] `docs/migration-0.4-to-1.0.md` が最新の差分を反映している
- [ ] `CHANGELOG.md` に `1.0.0-rc` 向け差分を記載済み
- [ ] `docs/ROADMAP.md` の P3 進捗が実態と一致している

## 2. Local gates

リポジトリルートで実行:

```bash
clojure -M:test
clojure -M:eastwood
clj-kondo --lint src test dev
clojure -M:perf-gate
clojure -M:dev:dns-ext -m examples.dns-topn test/resources/dns-sample.pcap
clojure -Sdeps '{:deps {cljdoc/cljdoc {:mvn/version "0.0.1315-c9e9a7e"}}}' -M -e "(require 'cljdoc.doc-tree) (println :cljdoc-loaded)"
```

確認項目:

- [ ] 全コマンドが成功
- [ ] `perf-gate` が warn/fail 閾値を超えていない
- [ ] CLI スモークの出力/終了コード契約に差分がない

## 3. CI gates

- [ ] `CI` workflow が `main/master` 上で green
- [ ] `Dependency Audit`（nvd-clojure）が green、critical CVE なし
- [ ] `arm64-monitor` が継続的に成功
- [ ] `Arm64 Promotion Report` が基準を満たす
  - 14日 coverage
  - success >= 95%
  - rerun rate < 5%
  - arm64/x64 job duration ratio <= 1.5

ローカル確認（`gh` + API 経由）:

```bash
dev/script/arm64_promotion_report.sh 14 0.95 0.05 1.5
```

手動実行コマンド（GitHub Actions 画面の `workflow_dispatch` でも可）:

```text
workflow: Arm64 Promotion Report
inputs : lookback_days=14, min_success_rate=0.95, max_rerun_rate=0.05, max_duration_ratio=1.5, enforce=true
```

## 4. Release artifacts

- [ ] README の公開 API / 互換性マトリクス / install 例が最新
- [ ] docs index (`docs/README.md`) に必要ドキュメントリンクが揃っている
- [ ] `CHANGELOG.md` に `## [1.0.0-rc] - YYYY-MM-DD` を追加
- [ ] 必要なら ADR/設計メモを `docs/` に追記

## 5. Tagging and publish

```bash
git tag v1.0.0-rc
git push origin v1.0.0-rc
```

- [ ] タグ作成後、GitHub Releases 下書きを作成
- [ ] リリースノートに migration link を含める
- [ ] cljdoc 反映を確認

## 6. Post-tag verification

- [ ] `deps.edn` の git/tag + sha でサンプルが再現できる
- [ ] Quick Start がクリーン環境で動作する
- [ ] 既知の制約（arm64 required 化前提など）をリリースノートで明示
