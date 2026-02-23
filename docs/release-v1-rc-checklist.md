# v1.0.0-rc Release Checklist

`v1.0.0-rc` を作る前に実行する最小チェックリストです。
目的は「契約凍結の逸脱」「互換性劣化」「性能後退」を rc タグ前に確実に検出することです。

## 1. Preconditions

- [x] `docs/cljdoc-api-contract.md` が最新実装と一致している（確認日: 2026-02-23）
- [x] `docs/migration-0.4-to-1.0.md` が最新の差分を反映している（確認日: 2026-02-23）
- [x] `CHANGELOG.md` に `1.0.0-rc` 向け差分を記載済み（追加日: 2026-02-23）
- [x] `docs/ROADMAP.md` の P3 進捗が実態と一致している（更新日: 2026-02-23）

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

- [x] 全コマンドが成功（実行日: 2026-02-23）
- [x] `perf-gate` が warn/fail 閾値を超えていない（679.6ms / warn=1000ms / fail=1200ms）
- [x] CLI スモークの出力/終了コード契約に差分がない

直近実行ログ（2026-02-23, local）:

- `clojure -M:test` => 185 tests / 504 assertions / 0 failures / 0 errors
- `clojure -M:eastwood` => Warnings 12 / Exceptions 0（exit 0）
- `clj-kondo --lint src test dev` => errors 0 / warnings 0
- `clojure -M:dev:dns-ext -m examples.dns-topn test/resources/dns-sample.pcap` => success
- `clojure -Sdeps ... cljdoc.doc-tree` => `:cljdoc-loaded`

## 3. CI gates

- [x] `CI` workflow が `main/master` 上で green（run: `22296353769`, 2026-02-23）
- [x] `Dependency Audit`（nvd-clojure）が green、critical CVE なし（run: `21812860426`, 2026-02-09）
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

直近ローカル集計（2026-02-23）:

- `sample_count=7`, `window_covered=false`
- `success_rate=0.714`, `rerun_rate=0.0`, `max_duration_ratio=2.104`
- `eligible_for_required_gate=false`

## 4. Release artifacts

- [x] README の公開 API / 互換性マトリクス / install 例が最新（確認日: 2026-02-23）
- [x] docs index (`docs/README.md`) に必要ドキュメントリンクが揃っている（確認日: 2026-02-23）
- [x] `CHANGELOG.md` に `## [1.0.0-rc] - YYYY-MM-DD` を追加（2026-02-23）
- [ ] 必要なら ADR/設計メモを `docs/` に追記

## 5. Tagging and publish

```bash
git tag v1.0.0-rc.1
git push origin v1.0.0-rc.1
```

- [x] タグ作成後、GitHub Releases 下書きを作成
- [x] リリースノートに migration link を含める
- [ ] cljdoc 反映を確認

実施結果（2026-02-23）:

- [x] タグ作成後、GitHub Releases 下書きを作成
  - `v1.0.0-rc` (draft, prerelease): `https://github.com/nantes-rfli/paclo/releases/tag/untagged-9ee36cae8a3a2f602c7d`
  - `v1.0.0-rc.1` (draft, prerelease): `https://github.com/nantes-rfli/paclo/releases/tag/untagged-76e380af67cd9531a365`
- [x] `v1.0.0-rc.1` を publish（pre-release 公開）
  - 公開 URL: `https://github.com/nantes-rfli/paclo/releases/tag/v1.0.0-rc.1`
- [x] リリースノートに migration link を含める
- [ ] cljdoc 反映を確認（公開反映待ち）

## 6. Post-tag verification

- [x] `deps.edn` の git/tag + sha でサンプルが再現できる
- [x] Quick Start がクリーン環境で動作する
- [x] 既知の制約（arm64 required 化前提など）をリリースノートで明示

## 7. v1.0.0 finalization

- [x] `CHANGELOG.md` に `## [1.0.0] - 2026-02-23` を追加
- [x] `v1.0.0` タグを作成して push
- [x] `v1.0.0` Release を公開（latest）
- [x] Clojars publish 自動化を追加（`Publish` workflow + `:deps-deploy`）
- [ ] cljdoc 公開反映を確認

実施結果（2026-02-23）:

- `v1.0.0` release URL: `https://github.com/nantes-rfli/paclo/releases/tag/v1.0.0`
- Clojars publish は `.github/workflows/publish.yml` で実行可能（必須 secrets: `CLOJARS_USERNAME`, `CLOJARS_PASSWORD`）
- cljdoc: `https://cljdoc.org/d/org.clojars.nanto/paclo/CURRENT` は Clojars publish 後に確認継続

実施結果（2026-02-23）:

- [x] `deps.edn` の git/tag + sha でサンプルが再現できる
  - `v1.0.0-rc` (`0ff30ec`) では `ClassNotFoundException: paclo.jnr.PcapHeader`
  - `v1.0.0-rc.1` (`92219f8`) では `clojure -X:deps prep` 後に `(require '[paclo.core :as core])` + `(core/bpf :udp)` が成功
- [x] Quick Start がクリーン環境で動作する
  - 手順: `git clone --branch v1.0.0-rc.1` → `clojure -T:build javac` → README 相当コマンド実行成功
- [x] 既知の制約（arm64 required 化前提など）をリリースノートで明示
