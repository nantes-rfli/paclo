# Paclo Roadmap

本ドキュメントは Paclo ライブラリのロードマップです。  
フェーズごとの目標・タスク・進捗を一覧できる形で管理します。  
開発フローや環境手順は [AI_HANDOFF.md](../AI_HANDOFF.md) を参照してください。

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
- [ ] L2/L3/L4 最小デコード（Ethernet/IPv4/IPv6/TCP/UDP/ICMP）
- [x] Golden PCAP & 往復テスト
- [ ] README 整備（cljdoc バッジ, クイックスタート）
- [ ] CHANGELOG 初版 / SemVer 宣言
- [ ] CI ビルド安定化（Java クラス）
- [x] `list-devices` のファサード + 最小テスト

---

### P1: Clojureらしい処理体験（v0.3）
**目的**: d)「Clojureならでは」の体験を前面に  
- [ ] pipeline 最適化（`packets → :xform → write-pcap!`）
- [ ] core.async オプション（任意）
- [ ] デコード拡張点（multimethod or 登録API）
- [ ] DNS デコードを別モジュール（`paclo-proto-dns`）
- [ ] Cookbook 例集 / 性能目安公開

---

### P2: ユースケース特化（v0.4）
**候補ユースケース（1つ選ぶ）**
- 教育/検証用ラボ
- 軽量セキュリティ（DNS集計）
- データ前処理（pcap→EDN/CSV 変換）

**成果**  
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
- paclo-proto-dns … 上位プロトコル例（別モジュール）
- paclo-cli … 最小 CLI
- paclo-examples … サンプル集

---

## リリース目安
- v0.2 = CORE + :xform + BPF拡張 + L2/3/4最小 + Docs  
- v0.3 = decode拡張点 + proto-dns + examples + (任意) core.async  
- v1.0 = スコープ固定・破壊変更収束・安定宣言
