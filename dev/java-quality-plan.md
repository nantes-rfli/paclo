# Java 側品質向上ロードマップ（JNR バインディング）

Paclo の Java/JNR 層（約120行）向けに、段階的で軽量な品質向上を行う計画。
進捗はタスクリストで管理する。

## フェーズ概要

- **Phase 1: 必須基盤**
  - JUnit 5 を導入し、実 PCAP を使ったスモークテストを追加（`pcap_open_offline`→`pcap_next_ex`→`PcapHeader`）。
  - リソース安全化: `PcapHandle`/`BpfProgram` を `AutoCloseable` 化し、try-with-resources で `pcap_close`/`pcap_freecode` を強制。
  - 例外統一: 失敗時に `pcap_geterr` を含む `IllegalStateException` を投げるユーティリティを整備。
  - コンパイラオプション強化: `-Xlint:all -Werror` を build alias に追加。
  - Javadoc 最小セット: 公開 API のみ対象。

- **Phase 2: 静的解析（必要に応じて）**
  - SpotBugs（Nullness/Bad practice/Performance コア）を追加し、誤検知は抑制コメントで明示。
  - CheckStyle（任意・最小ルール）を適用。
  - CI 統合: Java 用ワークフローで libpcap をインストールし、ビルド＋ SpotBugs/CheckStyle を実行。

- **Phase 3: 将来拡張**
  - JaCoCo で statement カバレッジを軽く確認（緩めの閾値）。
  - Javadoc 自動生成（警告ゼロ維持が目的）。
  - OS/arch 依存性の明文化またはランタイム判定の実装。

## タスクリスト（進捗管理）

- [x] Phase 1: JUnit 5 導入と実 PCAP スモークテスト追加
- [x] Phase 1: `PcapHandle`/`BpfProgram` の `AutoCloseable` 化と try-with-resources 対応
- [x] Phase 1: 例外メッセージ統一（`pcap_geterr` 取得ユーティリティ）
- [x] Phase 1: コンパイラオプション `-Xlint:all -Werror` を build alias に追加
- [x] Phase 1: 公開 API への最小 Javadoc 付与
- [x] Phase 2: SpotBugs 導入と警告ゼロ確認
- [x] Phase 2: CheckStyle 最小ルール導入（必要なら）
- [x] Phase 2: CI に Java ジョブ追加（libpcap インストール＋テスト/解析）
- [x] Phase 3: JaCoCo 設定と閾値設定
- [x] Phase 3: Javadoc 自動生成パイプライン
- [x] Phase 3: OS/arch 依存性の明文化またはランタイム判定実装

## 開発者向けコマンド一覧

| 用途 | コマンド | 出力/閾値 | 備考 |
| --- | --- | --- | --- |
| Java テスト | `clojure -T:build javac-test && clojure -M:junit` | target/classes, test-classes | `out-dns.pcap` を使用 |
| SpotBugs | `clojure -M:spotbugs -m paclo.dev.spotbugs` | `target/spotbugs.xml` | 依存を auxclasspath に渡し、欠落クラス警告を抑制 |
| CheckStyle | `clojure -M:checkstyle -m paclo.dev.checkstyle` | `target/checkstyle.xml` | ルールは最小セット |
| JaCoCo 計測 | `clojure -M:jacoco -m paclo.dev.jacoco` | `target/jacoco.xml`, `target/jacoco-html` | JUnit をエージェント付きで実行 |
| JaCoCo Gate | `clojure -T:build jacoco-gate` | 閾値 `JACOCO_MIN_LINE` (デフォ25% 通過) | 失敗で非ゼロ終了 |
| Javadoc | `clojure -T:build javadoc` | `target/javadoc` | 生成のみ |
| VSCode 参照修正 | ウィンドウ再読込 | — | `.vscode/settings.json` で JNR/ASM/JUnit を参照 |
| 依存/環境 | libpcap インストール | — | macOS: Homebrew, CI: `apt install libpcap-dev` |
