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
- [ ] Phase 2: SpotBugs 導入と警告ゼロ確認
- [ ] Phase 2: CheckStyle 最小ルール導入（必要なら）
- [ ] Phase 2: CI に Java ジョブ追加（libpcap インストール＋テスト/解析）
- [ ] Phase 3: JaCoCo 設定と閾値設定
- [ ] Phase 3: Javadoc 自動生成パイプライン
- [ ] Phase 3: OS/arch 依存性の明文化またはランタイム判定実装

## メモ

- Mockito は当面不要（ネイティブ呼び出し中心のため）。必要になれば最小限で追加。
- libpcap は CI/ローカルともに必須。macOS 開発環境では Homebrew、CI では apt でインストール。
- 誤検知抑制はコメントで理由を残す（ボーイスカウトルール）。
- VSCode での Java 参照エラー対策として、`.vscode/settings.json` に JNR/ASM の M2 リポジトリ glob を追加済み。再読込すると赤警告が消える。
- Java テスト実行: `clojure -T:build javac-test` でコンパイル後、`clojure -M:junit` で JUnit 実行（`out-dns.pcap` を使用）。
