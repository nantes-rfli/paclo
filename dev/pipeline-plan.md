# Pipeline PoC Notes (Phase A)

目的: v0.3 で「pcap → :xform → write-pcap!」の REPL 往復を 3–5s 以内に収めるための着火点。ここでは着手アイデアと計測観点だけをまとめ、実装は Phase B で行う。

## 計測観点
- REPL 1 ラウンド時間（pcap 読み+transform+write）。小/中 PCAP の 2 ケースを継続計測。
- GC 圧: `-Xlog:gc` か `jstat` で pause/alloc をざっくり見る（必要なら Phase B）。
- コピー回数: `:bytes` をそのまま流せているか（decode?=false/true 両方）。

## 既存ベースライン（2025-12-02）
- decode?=false, 100k pkt → drop<60B で 50k pkt / ~0.37s
- decode?=true, 100k pkt → 50k pkt / ~1.36s
- dns-sample (4 pkt) → ~7.9ms

## 改善アイデア（Phase B で検証）
1) 受信側
   - `packets` 内部での `:max` chunk を可変にして I/O → decode のバッチを広げる（ヒープ滞留と相談）。
   - decode?=false パスでは map 生成を避け、{:bytes ...} だけの軽量形に落とすオプションを検討。
2) 変換（:xform）
   - transducer で `select-keys` する箇所を、必要キー固定の小 fn に置き換え（persist 量を抑制）。
   - 事前に `volatile` でカウンタを渡し、副作用を reduce 1 回に集約する例を追加ベンチ。
3) 書き出し
   - write-pcap! が受け取るシーケンスを chunked で渡し、`pcap/bytes-seq->pcap!` 側で small-buffer reuse を検証。
4) JVM チューニング
   - REPL 作業用に `-J-XX:+UseZGC` / `-J-XX:+UseG1GC` / `-J-XX:+PerfDisableSharedMem` など簡易オプションの比較を1回だけ実測。

## すぐ着手できる小タスク
- pipeline-bench に `--gc-log <path>` 追加（Phase BでOK）。
- decode?=true の場合だけ `select-keys` をやめ、:decoded を残したまま pass-through する試験実装を branch で試す。

## 完了判定 (Phase A)
- ベースラインを Roadmap に記録済み ✔
- 改善アイデアと計測観点をメモ化 ✔
- 次フェーズの ToDo を明示 ✔
