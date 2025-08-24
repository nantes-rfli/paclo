# AI_HANDOFF (auto-generated)

このファイルは自動生成されています。直接編集しないでください。  
更新する場合は `script/make-ai-handoff.sh` を修正してください。

- commit: bbd8a84
- generated: 2025-08-24 12:01:19 UTC

## Primary docs（必読）

- リポジトリ: https://github.com/nantes-rfli/paclo （branch: main）
- AI_HANDOFF.md（このファイルの raw）  
  https://raw.githubusercontent.com/nantes-rfli/paclo/refs/heads/main/AI_HANDOFF.md
- ロードマップ: docs/ROADMAP.md  
  https://raw.githubusercontent.com/nantes-rfli/paclo/refs/heads/main/docs/ROADMAP.md

## How to run

`clj -M:test` / `clj -T:build jar`

## Notes

- IPv6 HBH / Destination Options の HdrExtLen は **(n+1)\*8 バイト（総ヘッダ長）**。  
  テストベクタ作成時は NextHdr/HdrExtLen の 2 バイトを除いた *オプション領域長* が (総長-2) に厳密一致するように Pad1/PadN で調整すること。
- Ethernet VLAN (802.1Q/802.1ad) を自動ではぎ、最終 Ethertype で L3 を解釈します。  
  VLAN 情報はトップレベルの `:vlan-tags` ベクタ（`{:tpid :pcp :dei :vid}`）に入ります。
- `capture->seq` は **:stop?**（任意条件で即停止）と **:error-mode**（:throw|:pass）のオプションがあります。

## Samples

```clojure
;; 任意条件で停止（UDP/53 のパケットを見つけたら止める）
(require '[paclo.pcap :as p] '[paclo.parse :as parse])
(def s (p/capture->seq {:device "en0" :filter "udp port 53"
                        :timeout-ms 50 :idle-max-ms 10000 :max-time-ms 15000
                        :stop? (fn [pkt]
                                 (let [m (parse/packet->clj (:bytes pkt))
                                       l4 (:l4 (:l3 m))]
                                   (and (= :udp (:type l4))
                                        (or (= 53 (:src-port l4)) (= 53 (:dst-port l4))))))})))
(take 1 s)

;; 背景例外をスキップして継続（ログは :on-error で通知）
(def s2 (p/capture->seq {:device "en0" :filter "udp and and"  ; わざと不正
                         :timeout-ms 50 :error-mode :pass
                         :on-error (fn [ex] (println "BG error:" (.getMessage ex)))}))
(take 5 s2)
```
```clojure
;; ICMPv6 Time Exceeded（hex→parse→要約）。:type-name/:code-name/:summary が付与されます。
(require '[paclo.dev :as d])
(-> "00 11 22 33 44 55 66 77 88 99 AA BB 86 DD
     60 00 00 00 00 08 3A 40
     20 01 0D B8 00 00 00 00 00 00 00 00 00 00 00 01
     20 01 0D B8 00 00 00 00 00 00 00 00 00 00 00 02
     03 00 00 00 00 00 00 00"
    d/parse-hex d/summarize)

;; VLAN (802.1Q, VID=100) の例。:vlan-tags に [ {:tpid 0x8100 :pcp 0 :dei false :vid 100} ] が入ります。
(-> "FF FF FF FF FF FF 00 00 00 00 00 01 81 00 00 64 08 00
     45 00 00 30 00 02 00 00 40 11 00 00
     C0 A8 01 64 08 08 08 08
     13 88 00 35 00 18 00 00
     00 3B 01 00 00 01 00 00 00 00 00 00 00 00 00 00"
    d/parse-hex d/summarize)
```

### paclo.core quick samples
```clojure
(require '[paclo.core :as core])

;; Offline decode (safe: adds :decode-error instead of throwing)
(->> (core/packets {:path "out-test.pcap" :decode? true})
     (map #(select-keys % [:caplen :decode-error]))
     (take 2)
     doall)

;; Live with DSL
(->> (core/packets {:device "en0"
                    :filter (core/bpf [:and [:udp] [:port 53]])
                    :timeout-ms 50})
     (take 10)
     doall)

;; Write PCAP from bytes (for tests/repro)
(core/write-pcap! [(byte-array (repeat 60 (byte 0)))
                   {:bytes (byte-array (repeat 60 (byte -1)))
                    :sec 1700000000 :usec 123456}]
                  "out-sample.pcap")
```

## Files

### script/make-ai-handoff.sh
````bash
#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# Paclo: AI_HANDOFF.md generator
# -----------------------------------------------------------------------------
# - Generates AI_HANDOFF.md in a deterministic, readable Markdown layout.
# - Keeps a single "truth" with primary links (repo, AI_HANDOFF raw, ROADMAP).
# - Avoids brittle escaping by using small, consistent heredocs.
# =============================================================================

out="AI_HANDOFF.md"
rev="$(git rev-parse --short HEAD 2>/dev/null || echo 'unknown')"
date="$(date -u '+%Y-%m-%d %H:%M:%S UTC')"

emit_file () {
  # Usage: emit_file <lang> <path>
  local lang="$1"; shift
  local path="$1"; shift
  echo '```'"${lang}" >> "${out}"
  cat "${path}"         >> "${out}"
  echo '```'            >> "${out}"
  echo                  >> "${out}"
}

emit_section_header () {
  # Usage: emit_section_header <title>
  local title="$1"; shift
  echo "## ${title}" >> "${out}"
  echo                >> "${out}"
}

# Reset file
: > "${out}"

# -----------------------------------------------------------------------------
# Header
# -----------------------------------------------------------------------------
cat >> "${out}" <<EOF
# AI_HANDOFF (auto-generated)

このファイルは自動生成されています。直接編集しないでください。  
更新する場合は \`script/make-ai-handoff.sh\` を修正してください。

- commit: ${rev}
- generated: ${date}

EOF

# -----------------------------------------------------------------------------
# Primary docs
# -----------------------------------------------------------------------------
emit_section_header "Primary docs（必読）"

cat >> "${out}" <<'EOF'
- リポジトリ: https://github.com/nantes-rfli/paclo （branch: main）
- AI_HANDOFF.md（このファイルの raw）  
  https://raw.githubusercontent.com/nantes-rfli/paclo/refs/heads/main/AI_HANDOFF.md
- ロードマップ: docs/ROADMAP.md  
  https://raw.githubusercontent.com/nantes-rfli/paclo/refs/heads/main/docs/ROADMAP.md
EOF
echo >> "${out}"

# -----------------------------------------------------------------------------
# How to run
# -----------------------------------------------------------------------------
emit_section_header "How to run"
cat >> "${out}" <<'EOF'
`clj -M:test` / `clj -T:build jar`
EOF
echo >> "${out}"

# -----------------------------------------------------------------------------
# Notes
# -----------------------------------------------------------------------------
emit_section_header "Notes"
cat >> "${out}" <<'EOF'
- IPv6 HBH / Destination Options の HdrExtLen は **(n+1)\*8 バイト（総ヘッダ長）**。  
  テストベクタ作成時は NextHdr/HdrExtLen の 2 バイトを除いた *オプション領域長* が (総長-2) に厳密一致するように Pad1/PadN で調整すること。
- Ethernet VLAN (802.1Q/802.1ad) を自動ではぎ、最終 Ethertype で L3 を解釈します。  
  VLAN 情報はトップレベルの `:vlan-tags` ベクタ（`{:tpid :pcp :dei :vid}`）に入ります。
- `capture->seq` は **:stop?**（任意条件で即停止）と **:error-mode**（:throw|:pass）のオプションがあります。
EOF
echo >> "${out}"

# -----------------------------------------------------------------------------
# Samples
# -----------------------------------------------------------------------------
emit_section_header "Samples"

cat >> "${out}" <<'EOF'
```clojure
;; 任意条件で停止（UDP/53 のパケットを見つけたら止める）
(require '[paclo.pcap :as p] '[paclo.parse :as parse])
(def s (p/capture->seq {:device "en0" :filter "udp port 53"
                        :timeout-ms 50 :idle-max-ms 10000 :max-time-ms 15000
                        :stop? (fn [pkt]
                                 (let [m (parse/packet->clj (:bytes pkt))
                                       l4 (:l4 (:l3 m))]
                                   (and (= :udp (:type l4))
                                        (or (= 53 (:src-port l4)) (= 53 (:dst-port l4))))))})))
(take 1 s)

;; 背景例外をスキップして継続（ログは :on-error で通知）
(def s2 (p/capture->seq {:device "en0" :filter "udp and and"  ; わざと不正
                         :timeout-ms 50 :error-mode :pass
                         :on-error (fn [ex] (println "BG error:" (.getMessage ex)))}))
(take 5 s2)
```
```clojure
;; ICMPv6 Time Exceeded（hex→parse→要約）。:type-name/:code-name/:summary が付与されます。
(require '[paclo.dev :as d])
(-> "00 11 22 33 44 55 66 77 88 99 AA BB 86 DD
     60 00 00 00 00 08 3A 40
     20 01 0D B8 00 00 00 00 00 00 00 00 00 00 00 01
     20 01 0D B8 00 00 00 00 00 00 00 00 00 00 00 02
     03 00 00 00 00 00 00 00"
    d/parse-hex d/summarize)

;; VLAN (802.1Q, VID=100) の例。:vlan-tags に [ {:tpid 0x8100 :pcp 0 :dei false :vid 100} ] が入ります。
(-> "FF FF FF FF FF FF 00 00 00 00 00 01 81 00 00 64 08 00
     45 00 00 30 00 02 00 00 40 11 00 00
     C0 A8 01 64 08 08 08 08
     13 88 00 35 00 18 00 00
     00 3B 01 00 00 01 00 00 00 00 00 00 00 00 00 00"
    d/parse-hex d/summarize)
```
EOF
echo >> "${out}"

cat >> "${out}" <<'EOF'
### paclo.core quick samples
```clojure
(require '[paclo.core :as core])

;; Offline decode (safe: adds :decode-error instead of throwing)
(->> (core/packets {:path "out-test.pcap" :decode? true})
     (map #(select-keys % [:caplen :decode-error]))
     (take 2)
     doall)

;; Live with DSL
(->> (core/packets {:device "en0"
                    :filter (core/bpf [:and [:udp] [:port 53]])
                    :timeout-ms 50})
     (take 10)
     doall)

;; Write PCAP from bytes (for tests/repro)
(core/write-pcap! [(byte-array (repeat 60 (byte 0)))
                   {:bytes (byte-array (repeat 60 (byte -1)))
                    :sec 1700000000 :usec 123456}]
                  "out-sample.pcap")
```
EOF
echo >> "${out}"

# -----------------------------------------------------------------------------
# Files (embedded)
# -----------------------------------------------------------------------------
emit_section_header "Files"

# The generator script itself (use 4 backticks to avoid closing fences confusion)
echo "### script/make-ai-handoff.sh" >> "${out}"
echo '````bash' >> "${out}"
cat "script/make-ai-handoff.sh" >> "${out}" || true
echo '````' >> "${out}"
echo >> "${out}"

# Other important files
for pair in \
  "clojure:src/paclo/parse.clj" \
  "clojure:src/paclo/pcap.clj" \
  "clojure:src/paclo/core.clj" \
  "clojure:src/paclo/dev.clj" \
  "java:src-java/paclo/jnr/PcapLibrary.java" \
  "clojure:test/paclo/parse_test.clj" \
  "clojure:test/paclo/core_test.clj" \
  "clojure:test/paclo/list_devices_test.clj" \
  "clojure:test/paclo/golden_test.clj" \
  "clojure:test/paclo/test_util.clj" \
  "edn:.clj-kondo/config.edn"
do
  lang="${pair%%:*}"
  path="${pair#*:}"
  if [[ -f "${path}" ]]; then
    echo "### ${path}" >> "${out}"
    emit_file "${lang}" "${path}"
  fi
done

# Also embed the CI workflow so it is always carried in the handoff
if [[ -f ".github/workflows/ci.yml" ]]; then
  echo "### .github/workflows/ci.yml" >> "${out}"
  emit_file "yaml" ".github/workflows/ci.yml"
fi

# -----------------------------------------------------------------------------
# 整形運用ポリシー
# -----------------------------------------------------------------------------
emit_section_header "整形運用ポリシー（2025-08 更新）"
cat >> "${out}" <<'EOF'
**現在の方針: 保存時整形 OFF + CLI 一本化**

- VS Code 保存時整形: 無効化  
- 整形は必ずコミット前に CLI (`script/fmt.sh`) で実施  
- CI (`clojure-lsp format --dry`) と完全一致  

理由: Calva 保存時整形で `dns-min` などが崩れるため。  
CLI 実行時は問題なし → 保存時整形を切り、CLI に統一。  

将来保存時整形を復活させたい場合は、Calva整形ではなく  
**VS Code → clojure-lsp (LSP フォーマット)** への切替を推奨。
EOF
echo >> "${out}"

# Settings snapshots
cat >> "${out}" <<'EOF'
### .vscode/settings.json
```json
EOF
if [[ -f ".vscode/settings.json" ]]; then
  if command -v jq >/dev/null 2>&1; then
    jq -S . .vscode/settings.json >> "${out}"
  else
    cat .vscode/settings.json >> "${out}"
  fi
else
  echo "// (not found: .vscode/settings.json)" >> "${out}"
fi
echo '```' >> "${out}"
echo >> "${out}"

cat >> "${out}" <<'EOF'
### .lsp/config.edn
```edn
EOF
if [[ -f ".lsp/config.edn" ]]; then
  cat .lsp/config.edn >> "${out}"
else
  echo ";; (not found: .lsp/config.edn)" >> "${out}"
fi
echo '```' >> "${out}"
echo >> "${out}"

cat >> "${out}" <<'EOF'
### .editorconfig
```
EOF
if [[ -f ".editorconfig" ]]; then
  cat .editorconfig >> "${out}"
else
  echo "# (not found: .editorconfig)" >> "${out}"
fi
echo '```' >> "${out}"
echo >> "${out}"

# -----------------------------------------------------------------------------
# Environment snapshot
# -----------------------------------------------------------------------------
emit_section_header "Environment snapshot"
{
  echo '```'
  echo "git commit: $(git rev-parse --short=12 HEAD 2>/dev/null || echo N/A)"
  echo "branch: $(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo N/A)"
  echo "java: $(java -version 2>&1 | head -n1)"
  echo "clojure: $(clojure -M -e '(println (clojure-version))' 2>/dev/null || echo N/A)"
  echo "clojure-lsp: $(clojure-lsp --version 2>/dev/null || echo N/A)"
  echo "clj-kondo: $(clj-kondo --version 2>/dev/null || echo N/A)"
  echo "os: $(uname -a)"
  echo '```'
} >> "${out}"
echo >> "${out}"

# -----------------------------------------------------------------------------
# Developer bootstrap
# -----------------------------------------------------------------------------
emit_section_header "Developer bootstrap (git hooks)"
cat >> "${out}" <<'EOF'
このリポジトリでは共有フックを使用します。クローンしたら一度だけ以下を実行してください。

```bash
git config core.hooksPath .githooks
```
EOF
echo >> "${out}"

echo "Wrote ${out}"
````

### src/paclo/parse.clj
```clojure
(ns paclo.parse
  (:require
   [clojure.string :as str])
  (:import
   [java.nio ByteBuffer ByteOrder]))

(declare l4-parse)
(declare maybe-attach-dns)

(defn- u8  [^ByteBuffer b] (bit-and (.get b) 0xFF))
(defn- u16 [^ByteBuffer b] (bit-and (.getShort b) 0xFFFF))
(defn- u32 [^ByteBuffer b] (bit-and (.getInt b) 0xFFFFFFFF))

(defn- mac [^ByteBuffer b]
  (format "%02x:%02x:%02x:%02x:%02x:%02x"
          (u8 b) (u8 b) (u8 b) (u8 b) (u8 b) (u8 b)))

(def ETH-IPv4 0x0800)
(def ETH-IPv6 0x86DD)
(def ETH-ARP  0x0806)

(def ETH-VLAN-8100 0x8100)  ;; 802.1Q
(def ETH-VLAN-88A8 0x88A8)  ;; 802.1ad (QinQ outer)
(def ETH-VLAN-9100 0x9100)  ;; 追加TPID（環境による）
(def ETH-VLAN-9200 0x9200)
(def ^:private VLAN-TPIDs #{ETH-VLAN-8100 ETH-VLAN-88A8 ETH-VLAN-9100 ETH-VLAN-9200})

(defn- ipv4-addr [^ByteBuffer b]
  (format "%d.%d.%d.%d" (u8 b) (u8 b) (u8 b) (u8 b)))

(defn- ipv6-addr [^ByteBuffer b]
  ;; 簡易表記。ゼロ圧縮はしていない（後で最適化可）
  (format "%x:%x:%x:%x:%x:%x:%x:%x"
          (u16 b) (u16 b) (u16 b) (u16 b)
          (u16 b) (u16 b) (u16 b) (u16 b)))

;; IPv6: 8ワード読み取り（u16×8）
(defn- ipv6-addr-words ^clojure.lang.IPersistentVector [^ByteBuffer b]
  (vector (u16 b) (u16 b) (u16 b) (u16 b)
          (u16 b) (u16 b) (u16 b) (u16 b)))

(defn- ipv6-full-str [ws]                   ;; 非圧縮（既存の ipv6-addr と同等の見た目）
  (clojure.string/join ":" (map #(format "%x" %) ws)))

(defn- ipv6-compress-str
  "RFC5952に準拠した簡易圧縮: 0の最長連続（長さ>=2）を :: に。
   先頭/末尾/全ゼロ も自然に処理。"
  [ws]
  (let [n (count ws)
        ;; 最長0連続を探索（>=2のみ）
        [best-i best-len]
        (loop [i 0 cur-i nil cur-len 0 best-i nil best-len 0]
          (if (= i n)
            ;; ループ終了時、直前の連続が最長なら更新
            (let [[best-i best-len]
                  (if (and cur-i (>= cur-len 2) (> cur-len best-len))
                    [cur-i cur-len] [best-i best-len])]
              [best-i best-len])
            (let [z? (zero? (nth ws i))]
              (cond
                z?
                (recur (inc i)
                       (or cur-i i)
                       (inc cur-len)
                       best-i best-len)

                ;; 連続0が途切れた
                :else
                (let [[best-i best-len]
                      (if (and cur-i (>= cur-len 2) (> cur-len best-len))
                        [cur-i cur-len] [best-i best-len])]
                  (recur (inc i) nil 0 best-i best-len))))))]
    (if (>= best-len 2)
      (let [before (subvec ws 0 best-i)
            after  (subvec ws (+ best-i best-len) n)
            hexs   (fn [v] (map #(Integer/toHexString (int %)) v))
            s-before (clojure.string/join ":" (hexs before))
            s-after  (clojure.string/join ":" (hexs after))]
        (cond
          (and (empty? before) (empty? after)) "::"
          (empty? before)      (str "::" s-after)
          (empty? after)       (str s-before "::")
          :else                (str s-before "::" s-after)))
      ;; 圧縮対象ナシ
      (clojure.string/join ":" (map #(Integer/toHexString (int %)) ws)))))

;; 安全ヘルパ: 現在位置から len バイト分だけ読める ByteBuffer を作る
(defn- limited-slice ^ByteBuffer [^ByteBuffer b ^long len]
  (when (and (<= 0 len) (<= len (.remaining b)))
    (doto (.duplicate b)
      (.limit (+ (.position b) len)))))

;; 残りを byte[] でコピー（payloadを地味に見たい時用）
(defn- remaining-bytes ^bytes [^ByteBuffer b]
  (let [dup (.duplicate b)
        arr (byte-array (.remaining dup))]
    (.get dup arr)
    arr))

;; 残りバイト数（ByteBufferを消費せずに測る）
(defn- remaining-len ^long [^ByteBuffer b]
  (.remaining (.duplicate b)))

(defn- make-flow-key
  "L3の src/dst と L4の src/dst port から5タプルマップを作る。
   TCP/UDP以外はポートが無いので proto/ipだけの簡易キーにする。"
  [{:keys [src dst protocol next-header] :as l3} l4]
  (let [proto (or protocol next-header)]   ;; IPv4は :protocol, IPv6は :next-header
    (case proto
      6  {:proto :tcp  :src-ip src :src-port (:src-port l4) :dst-ip dst :dst-port (:dst-port l4)}
      17 {:proto :udp  :src-ip src :src-port (:src-port l4) :dst-ip dst :dst-port (:dst-port l4)}
      1  {:proto :icmp :src-ip src :dst-ip dst}
      58 {:proto :icmp6 :src-ip src :dst-ip dst}
      {:proto proto :src-ip src :dst-ip dst})))

;; ------------------------------------------------------------
;; IPv6 Options (HBH / Destination Options) の TLV 検証
;; - 呼び出し時点で NextHdr/HdrExtLen の 2B は既に読み終えている前提
;; - len バイト分のオプション領域を、Pad1/PadN/任意TLV として走査
;; - 過走/途切れが無ければ true を返す
;; ------------------------------------------------------------
(defn- valid-ipv6-options-tlv?
  [^ByteBuffer b ^long len]
  (if-let [opt (limited-slice b len)]
    (loop []
      (if (zero? (.remaining opt))
        true
        (let [t (u8 opt)]
          (if (= t 0) ;; Pad1 (1 byte)
            (recur)
            (if (zero? (.remaining opt)) ;; 長さフィールドが読めない
              false
              (let [l (u8 opt)]
                (if (> l (.remaining opt)) ;; value が足りない（過走）
                  false
                  (do
                    (.position opt (+ (.position opt) l)) ;; value を飛ばす
                    (recur)))))))))
    false))

(defn- arp [^ByteBuffer b]
  (when (<= 8 (.remaining b))                             ;; 最低限の固定部
    (let [htype (u16 b) ptype (u16 b)
          hlen  (u8 b)  plen  (u8 b)
          oper  (u16 b)]
      (when (<= (+ (* 2 hlen) (* 2 plen)) (.remaining b))
        (let [sha (byte-array hlen) _ (.get b sha)
              spa (byte-array plen) _ (.get b spa)
              tha (byte-array hlen) _ (.get b tha)
              tpa (byte-array plen) _ (.get b tpa)]
          {:type :arp
           :op   (case oper 1 :request 2 :reply oper)
           :sha  (format "%02x:%02x:%02x:%02x:%02x:%02x"
                         (aget sha 0) (aget sha 1) (aget sha 2)
                         (aget sha 3) (aget sha 4) (aget sha 5))
           :spa  (when (= ptype ETH-IPv4)
                   (format "%d.%d.%d.%d"
                           (bit-and 0xFF (aget spa 0))
                           (bit-and 0xFF (aget spa 1))
                           (bit-and 0xFF (aget spa 2))
                           (bit-and 0xFF (aget spa 3))))
           :tha  (format "%02x:%02x:%02x:%02x:%02x:%02x"
                         (aget tha 0) (aget tha 1) (aget tha 2)
                         (aget tha 3) (aget tha 4) (aget tha 5))
           :tpa  (when (= ptype ETH-IPv4)
                   (format "%d.%d.%d.%d"
                           (bit-and 0xFF (aget tpa 0))
                           (bit-and 0xFF (aget tpa 1))
                           (bit-and 0xFF (aget tpa 2))
                           (bit-and 0xFF (aget tpa 3))))})))))

(defn- ipv4 [^ByteBuffer b]
  (let [vihl (u8 b)
        version (bit-shift-right vihl 4)
        ihl (* 4 (bit-and vihl 0x0F))
        tos (u8 b)
        total-len (u16 b)
        id (u16 b)
        flags-frag (u16 b)
        ttl (u8 b)
        proto (u8 b)
        hdr-csum (u16 b)
        src (ipv4-addr b)
        dst (ipv4-addr b)]
    (when (> ihl 20)
      (.position b (+ (.position b) (- ihl 20))))
    ;; ★ 追加: フラグメント解釈（DF=0x4000, MF=0x2000, offset=下位13bit）
    (let [df? (pos? (bit-and flags-frag 0x4000))
          mf? (pos? (bit-and flags-frag 0x2000))
          frag-off (bit-and flags-frag 0x1FFF)         ;; 8オクテット単位
          frag? (or mf? (pos? frag-off))
          payload-len (max 0 (- total-len ihl))
          l4buf (or (limited-slice b payload-len) (.duplicate b))
          ;; 非先頭フラグメントは L4 は解かない（安全）
          l4 (if (pos? frag-off)
               {:type :ipv4-fragment :offset frag-off :payload (remaining-bytes l4buf)}
               (l4-parse proto l4buf))]
      {:type :ipv4 :version version :ihl ihl
       :tos tos :total-length total-len
       :id id :flags-frag flags-frag
       :ttl ttl :protocol proto :header-checksum hdr-csum
       :src src :dst dst
       :frag? frag? :frag-offset (when frag? frag-off)       ;; ★ 追加
       :flow-key (make-flow-key {:src src :dst dst :protocol proto} l4)
       :l4 l4})))

(def ^:private ipv6-ext?
  #{0   ;; Hop-by-Hop Options
    43  ;; Routing
    44  ;; Fragment
    60  ;; Destination Options
    50  ;; ESP（長さ扱いが特殊だがここでは終端扱い）
    51}) ;; AH

(defn- parse-ipv6-ext-chain!
  "buf の position は IPv6 基本ヘッダ直後（= 最初の拡張 or L4 先頭）。
   initial-nh は IPv6 基本ヘッダの Next Header。
   返り値: {:final-nh nh, :buf dup, :frag? bool, :frag-offset int}
   非フラグメント: extをすべてスキップして L4 先頭に position を合わせる
   フラグメント:
     - offset=0（先頭フラグメント）は Fragment ヘッダを読み飛ばし、次のNHへ進む
     - offset>0（後続フラグメント）は L4 が欠けている可能性が高いので、:ipv6-fragment で返す"
  [^java.nio.ByteBuffer buf initial-nh]
  (let [dup (.duplicate buf)]
    (loop [nh initial-nh
           frag? false
           frag-off 0]
      (cond
        (nil? nh)
        {:final-nh nil :buf dup :frag? frag? :frag-offset frag-off}

        (= nh 44) ;; Fragment
        (if (< (.remaining dup) 8)
          ;; 拡張ヘッダが読み切れない → 打ち切り
          {:final-nh nil :buf dup :frag? frag? :frag-offset frag-off}
          (let [next (bit-and 0xFF (.get dup)) ; Next Header
                _    (.get dup)                ; Reserved
                offfl (bit-and 0xFFFF (.getShort dup))
                _ident (.getInt dup)
                offset (bit-shift-right (bit-and offfl 0xFFF8) 3)]
            (if (zero? offset)
              ;; 先頭フラグメント：続行
              (recur next true 0)
              ;; 後続フラグメント：ここで終了（L4は解かず）
              {:final-nh next :buf dup :frag? true :frag-offset offset})))

        (= nh 51) ;; AH = NextHdr(1) + PayloadLen(1) + data((plen+2)*4 - 2)
        (if (< (.remaining dup) 2)
          {:final-nh nil :buf dup :frag? frag? :frag-offset frag-off}
          (let [next (bit-and 0xFF (.get dup))
                plen (bit-and 0xFF (.get dup))
                total (* (+ plen 2) 4)
                skip (max 0 (- total 2))              ; 既に2B読了
                adv  (min skip (.remaining dup))]
            (.position dup (+ (.position dup) adv))
            (if (< adv skip)
              ;; 足りない → 打ち切り
              {:final-nh nil :buf dup :frag? frag? :frag-offset frag-off}
              (recur next frag? frag-off))))

        (= nh 50) ;; ESP はここで終端扱い（中は解さない）
        {:final-nh nh :buf dup :frag? frag? :frag-offset frag-off}

        (ipv6-ext? nh)
        (if (< (.remaining dup) 2)
          {:final-nh nil :buf dup :frag? frag? :frag-offset frag-off}
          (let [next (bit-and 0xFF (.get dup))    ;; NextHdr
                hlen (bit-and 0xFF (.get dup))    ;; HdrExtLen
                total (* (+ hlen 1) 8)            ;; 総ヘッダ長
                ;; 既に 2B 読了済み（NextHdr/HdrExtLen）なので、残オプション領域:
                opt-len (max 0 (- total 2))]
            (cond
              ;; 明確に足りない場合は打ち切り
              (> opt-len (.remaining dup))
              {:final-nh nil :buf dup :frag? frag? :frag-offset frag-off}

              ;; HBH / Dest は TLV を検証してから進める
              (or (= nh 0) (= nh 60))
              (if (valid-ipv6-options-tlv? dup opt-len)
                (do
                  ;; TLV 検証は limited-slice の中で消費しているだけなので、
                  ;; 実体 dup の position を opt-len だけ前に送る
                  (.position dup (+ (.position dup) opt-len))
                  (recur next frag? frag-off))
                ;; TLV が壊れている（途切れ/過走）
                {:final-nh nil :buf dup :frag? frag? :frag-offset frag-off})

              ;; Routing(43) は TLV ではないので長さスキップのみ
              (= nh 43)
              (do
                (.position dup (+ (.position dup) opt-len))
                (recur next frag? frag-off))

              ;; 万一ここに来たら（ESP/AH は上で拾っているはず）安全に打ち切り
              :else
              {:final-nh nil :buf dup :frag? frag? :frag-offset frag-off})))

        :else
        ;; L4 に到達 
        {:final-nh nh :buf dup :frag? frag? :frag-offset frag-off}))))

(defn- ipv6 [^ByteBuffer b]
  (let [vtcfl (u32 b)
        version (bit-shift-right vtcfl 28)
        tclass  (bit-and (bit-shift-right vtcfl 20) 0xFF)
        flabel  (bit-and vtcfl 0xFFFFF)
        payload-len (u16 b)
        next-hdr (u8 b)
        hop-limit (u8 b)
        ;; ここで8ワードを読み取り → 非圧縮/圧縮の両方を作る
        src-w (ipv6-addr-words b)
        dst-w (ipv6-addr-words b)
        src   (ipv6-full-str src-w)          ;; 既存互換（非圧縮）
        dst   (ipv6-full-str dst-w)
        srcC  (ipv6-compress-str src-w)      ;; 新規（圧縮）
        dstC  (ipv6-compress-str dst-w)
        l4buf (or (limited-slice b payload-len) (.duplicate b))
        {:keys [final-nh buf frag? frag-offset]}
        (parse-ipv6-ext-chain! l4buf next-hdr)
        l4 (if (and frag? (pos? frag-offset))
             {:type :ipv6-fragment :offset frag-offset :payload (remaining-bytes buf)}
             (l4-parse final-nh buf))
        flow-key (when final-nh
                   (make-flow-key {:src src :dst dst :next-header final-nh} l4))]
    {:type :ipv6
     :version version :traffic-class tclass :flow-label flabel
     :payload-length payload-len :next-header final-nh :hop-limit hop-limit
     :src src :dst dst
     :src-compact srcC :dst-compact dstC         ;; ★ 追加
     :frag? frag? :frag-offset (when frag? frag-offset)
     :l4 l4
     :flow-key flow-key}))

(defn- tcp-header [^ByteBuffer b]
  (let [src (u16 b)
        dst (u16 b)
        seq (u32 b)
        ack (u32 b)
        off-flags (u16 b)
        data-off (* 4 (bit-shift-right off-flags 12))
        flags-bits (bit-and off-flags 0x3F)
        urg  (pos? (bit-and flags-bits 32))
        ackf (pos? (bit-and flags-bits 16))
        psh  (pos? (bit-and flags-bits 8))
        rst  (pos? (bit-and flags-bits 4))
        syn  (pos? (bit-and flags-bits 2))
        fin  (pos? (bit-and flags-bits 1))
        win  (u16 b)
        csum (u16 b)
        urgp (u16 b)
        hdr-len data-off
        ;; 短縮フラグ（順序: U A P R S F）
        flags-str (apply str (keep (fn [[present ch]] (when present ch))
                                   [[urg \U] [ackf \A] [psh \P] [rst \R] [syn \S] [fin \F]]))]
    (when (> hdr-len 20)
      (.position b (+ (.position b) (- hdr-len 20))))
    {:type :tcp
     :src-port src :dst-port dst
     :seq seq :ack ack
     :flags {:urg urg :ack ackf :psh psh :rst rst :syn syn :fin fin}
     :flags-str flags-str
     :window win :checksum csum :urgent-pointer urgp
     :header-len hdr-len
     :data-len (remaining-len b)
     :payload (remaining-bytes b)}))

(defn- udp-header [^ByteBuffer b]
  ;; ★ 追加: 残量ガード（8B未満なら安全に諦める）
  (if (< (.remaining b) 8)
    {:type :unknown-l4 :reason :truncated-udp :data-len 0 :payload []}
    (let [src (u16 b)
          dst (u16 b)
          len (u16 b)
          csum (u16 b)
          paylen (max 0 (- len 8))
          paybuf (or (limited-slice b paylen) (.duplicate b))]
      {:type :udp :src-port src :dst-port dst
       :length len :checksum csum
       :data-len (remaining-len paybuf)
       :payload (remaining-bytes paybuf)})))

;; --- ICMP name helpers -------------------------------------------------------

(defn- icmpv4-type-name [t]
  (case t
    0  "echo-reply"
    3  "dest-unreachable"
    4  "source-quench"
    5  "redirect"
    8  "echo-request"
    9  "router-advertisement"
    10 "router-solicitation"
    11 "time-exceeded"
    12 "parameter-problem"
    13 "timestamp"
    14 "timestamp-reply"
    17 "address-mask-request"
    18 "address-mask-reply"
    (str "type-" t)))

(defn- icmpv4-code-name [t c]
  (case t
    3  (case c
         0 "net-unreachable"
         1 "host-unreachable"
         2 "proto-unreachable"
         3 "port-unreachable"
         4 "frag-needed"
         5 "src-route-failed"
         9 "net-admin-prohibited"
         10 "host-admin-prohibited"
         13 "comm-admin-prohibited"
         (str "code-" c))
    5  (case c
         0 "redirect-net" 1 "redirect-host"
         2 "redirect-tos-net" 3 "redirect-tos-host"
         (str "code-" c))
    11 (case c
         0 "ttl-exceeded"
         1 "frag-reassembly-time-exceeded"
         (str "code-" c))
    12 (case c
         0 "pointer-indicates-error"
         1 "missing-required-option"
         2 "bad-length"
         (str "code-" c))
    (when (not= c 0) (str "code-" c))))

(defn- icmpv6-type-name [t]
  (case t
    1   "dest-unreachable"
    2   "packet-too-big"
    3   "time-exceeded"
    4   "parameter-problem"
    128 "echo-request"
    129 "echo-reply"
    133 "router-solicitation"
    134 "router-advertisement"
    135 "neighbor-solicitation"
    136 "neighbor-advertisement"
    137 "redirect"
    (str "type-" t)))

(defn- icmpv6-code-name [t c]
  (case t
    1 (case c
        0 "no-route"
        1 "admin-prohibited"
        3 "addr-unreachable"
        4 "port-unreachable"
        (str "code-" c))
    3 (case c
        0 "hop-limit-exceeded"
        1 "frag-reassembly-time-exceeded"
        (str "code-" c))
    4 (case c
        0 "erroneous-header-field"
        1 "unknown-next-header"
        2 "unrecognized-ipv6-option"
        (str "code-" c))
    (when (not= c 0) (str "code-" c))))

(defn- icmpv4-header [^ByteBuffer b]
  (let [t (u8 b) code (u8 b) csum (u16 b)
        tname (icmpv4-type-name t)
        cname (icmpv4-code-name t code)
        summary (if cname (str tname "/" cname) tname)]
    {:type :icmpv4 :icmp-type t :code code :checksum csum
     :type-name tname :code-name cname :summary summary
     :data-len (remaining-len b)
     :payload (remaining-bytes b)}))

(defn- icmpv6-header [^ByteBuffer b]
  (let [t (u8 b) code (u8 b) csum (u16 b)
        tname (icmpv6-type-name t)
        cname (icmpv6-code-name t code)
        summary (if cname (str tname "/" cname) tname)]
    {:type :icmpv6 :icmp-type t :code code :checksum csum
     :type-name tname :code-name cname :summary summary
     :data-len (remaining-len b)
     :payload (remaining-bytes b)}))

;; --- DNS header helpers ------------------------------------------------------

(defn- dns-opcode-name [op]
  (case op
    0 "query"    ; standard query
    1 "iquery"   ; inverse query (obsolete)
    2 "status"
    4 "notify"
    5 "update"
    (str "opcode-" op)))

(defn- dns-rcode-name [rc]
  (case rc
    0  "noerror"
    1  "formerr"
    2  "servfail"
    3  "nxdomain"
    4  "notimp"
    5  "refused"
    6  "yxdomain"
    7  "yxrrset"
    8  "nxrrset"
    9  "notauth"
    10 "notzone"
    16 "badvers"
    22 "badcookie"
    (str "rcode-" rc)))

(defn- dns-min [^bytes payload]
  (when (<= 12 (alength payload))
    (let [bb (-> (ByteBuffer/wrap payload) (.order ByteOrder/BIG_ENDIAN))
          id (.getShort bb)
          flags (.getShort bb)
          qd (.getShort bb)
          an (.getShort bb)
          ns (.getShort bb)
          ar (.getShort bb)
          f (bit-and flags 0xFFFF)]
      (let [qr? (pos? (bit-and f 0x8000))
            opcode (bit-and (bit-shift-right f 11) 0x0F)
            aa? (pos? (bit-and f 0x0400))
            tc? (pos? (bit-and f 0x0200))
            rd? (pos? (bit-and f 0x0100))
            ra? (pos? (bit-and f 0x0080))
            rcode (bit-and f 0x000F)
            oname (dns-opcode-name opcode)
            rname (dns-rcode-name rcode)]
        {:type :dns
         :id (bit-and id 0xFFFF)
         :qdcount (bit-and qd 0xFFFF)
         :ancount (bit-and an 0xFFFF)
         :nscount (bit-and ns 0xFFFF)
         :arcount (bit-and ar 0xFFFF)
         :flags-raw f
         :qr? qr?
         :opcode opcode
         :opcode-name oname
         :aa? aa?
         :tc? tc?
         :rd? rd?
         :ra? ra?
         :rcode rcode
         :rcode-name rname
         :summary (str (if qr? "response" "query")
                       "/" oname
                       (when qr? (str "/" rname)))
         :flags {:raw f
                 :qr qr?
                 :opcode opcode
                 :aa aa?
                 :tc tc?
                 :rd rd?
                 :ra ra?
                 :rcode rcode}}))))

(defn- maybe-attach-dns [m]
  (if (and (= :udp (:type m))
           (or (= 53 (:src-port m)) (= 53 (:dst-port m)))
           (:payload m))
    (assoc m :app (dns-min (:payload m)))
    m))

(defn- l4-parse [proto ^ByteBuffer b]
  (let [m (case proto
            6  (tcp-header b)
            17 (udp-header b)
            1  (icmpv4-header b)
            58 (icmpv6-header b)
            {:type :unknown-l4 :proto proto :payload (remaining-bytes b)})]
    (maybe-attach-dns m)))

(defn packet->clj
  "bytes -> Clojure map
   - Ethernet → VLAN タグ（0〜複数）をはぎ、最終 Ethertype で L3 を解釈
   - L4は TCP/UDP/ICMPv4/ICMPv6 を簡易解析（payload付与）
   - UDP:53 は最小DNS要約を :app に付与
   返り値トップには :vlan-tags（あれば）を付与。"
  [^bytes bytes]
  (let [b (-> (ByteBuffer/wrap bytes) (.order ByteOrder/BIG_ENDIAN))
        dst (mac b) src (mac b)
        first-eth (u16 b)]
    ;; VLAN タグをすべてはぐ（QinQ 対応）
    (loop [eth first-eth
           tags (transient [])]
      (if (VLAN-TPIDs eth)
        (if (< (.remaining b) 4)
          ;; VLAN ヘッダ不足（TCI+次Ethertype で 4B必要）→ 安全に unknown を返却
          {:type :ethernet :src src :dst dst :eth eth
           :vlan-tags (persistent! tags)
           :l3 {:type :unknown-l3 :eth eth}}
          (let [tci (u16 b)
                next-eth (u16 b)
                tag {:tpid eth
                     :pcp  (bit-and (bit-shift-right tci 13) 0x7)    ;; 3bit
                     :dei  (pos? (bit-and tci 0x1000))               ;; 1bit
                     :vid  (bit-and tci 0x0FFF)}]                    ;; 12bit
            (recur next-eth (conj! tags tag))))
        ;; VLAN ではない → 最終 Ethertype が確定
        (let [final-eth eth
              vlan-tags (persistent! tags)]
          (cond
            (= final-eth ETH-IPv4)
            (let [l3 (ipv4 b)]
              (cond-> {:type :ethernet :src src :dst dst :eth final-eth :l3 l3}
                (seq vlan-tags) (assoc :vlan-tags vlan-tags)))

            (= final-eth ETH-IPv6)
            (let [l3 (ipv6 b)]
              (cond-> {:type :ethernet :src src :dst dst :eth final-eth :l3 l3}
                (seq vlan-tags) (assoc :vlan-tags vlan-tags)))

            (= final-eth ETH-ARP)
            (let [l3 (or (arp b) {:type :arp})]
              (cond-> {:type :ethernet :src src :dst dst :eth final-eth :l3 l3}
                (seq vlan-tags) (assoc :vlan-tags vlan-tags)))

            :else
            (cond-> {:type :ethernet :src src :dst dst :eth final-eth
                     :l3 {:type :unknown-l3 :eth final-eth}}
              (seq vlan-tags) (assoc :vlan-tags vlan-tags))))))))
```

### src/paclo/pcap.clj
```clojure
(ns paclo.pcap
  (:require
   [clojure.java.io :as io]
   [clojure.string :as str])
  (:import
   [java.util.concurrent LinkedBlockingQueue]
   [jnr.ffi LibraryLoader Memory Pointer]
   [jnr.ffi.byref IntByReference PointerByReference]
   [paclo.jnr PcapHeader PcapLibrary]))

(def ^:private ^jnr.ffi.Runtime rt (jnr.ffi.Runtime/getSystemRuntime))
(def ^:private ^PcapLibrary lib
  (let [os      (.. System (getProperty "os.name") toLowerCase)
        libname (if (.contains os "win") "wpcap" "pcap")
        loader  (LibraryLoader/create PcapLibrary)]
    (.load loader libname)))

;; --- constants (use before any functions) ---
(def ^:const PCAP_ERRBUF_SIZE 256)
(def ^:private ^:const BPF_PROG_BYTES 16)

(defn ^:private ^Integer lookup-netmask
  "デバイス名から netmask を取得。失敗時は 0 を返す。"
  [^String device]
  (let [err   (Memory/allocate rt PCAP_ERRBUF_SIZE)
        netp  (IntByReference.)
        maskp (IntByReference.)
        rc    (.pcap_lookupnet lib device netp maskp err)]
    (if (neg? rc)
      0
      (.getValue maskp))))

(defn ^:private apply-filter!
  "pcap ハンドルに BPF フィルタを適用。opts 例:
   {:filter \"udp and port 53\" :optimize? true :netmask 0}"
  [^Pointer pcap {:keys [filter optimize? netmask]}]
  (when (and pcap (some? filter) (not (str/blank? filter)))
    (let [opt?  (if (nil? optimize?) true optimize?)
          mask  (int (or netmask 0))]         ;; ★ 既定は 0（不明）
      (let [prog (PcapLibrary/compileFilter pcap filter opt? mask)]
        (try
          (PcapLibrary/setFilterOrThrow pcap prog)
          (finally
            (PcapLibrary/freeFilter prog))))))
  pcap)

(defn- blank-str? [^String s]
  (or (nil? s) (re-find #"^\s*$" s)))

(defn- normalize-desc [^String s]
  (let [t (when s (str/trim s))]
    (when (and t (not (blank-str? t))) t)))

(defn open-offline
  (^Pointer [path]
   (open-offline path {}))
  (^Pointer [path {:keys [filter optimize? netmask] :as opts}]
   ;; 1) まずファイルの存在・サイズを明示チェック（原因を特定しやすく）
   (let [f   (io/file path)
         abs (.getAbsolutePath ^java.io.File f)]
     (when-not (.exists ^java.io.File f)
       (throw (ex-info (str "pcap file not found: " abs)
                       {:path abs :reason :not-found})))
     (when (zero? (.length ^java.io.File f))
       (throw (ex-info (str "pcap file is empty: " abs)
                       {:path abs :reason :empty})))
     ;; 2) 実際に pcap_open_offline（errbufも拾う）
     (let [err  (Memory/allocate rt PCAP_ERRBUF_SIZE)
           pcap (.pcap_open_offline lib abs err)]
       (when (nil? pcap)
         (let [raw (try (.getString err 0) (catch Throwable _ ""))  ; errbuf 取得（失敗しても無視）
               msg (let [t (str/trim (or raw ""))]
                     (if (seq t)
                       (str "pcap_open_offline failed: " t)
                       "pcap_open_offline failed"))]
           (throw (ex-info msg
                           {:path abs :reason :pcap-open-failed :err raw}))))
       ;; 3) BPFフィルタが来ていれば適用（core側でDSL→文字列化されていればそのまま渡る）
       (apply-filter! pcap opts)
       ;; 4) ハンドルを返す
       pcap))))

(defn open-live ^Pointer
  [{:keys [device snaplen promiscuous? timeout-ms filter optimize? netmask]
    :or   {snaplen 65536 promiscuous? true timeout-ms 10}
    :as   opts}]
  (let [err     (Memory/allocate rt PCAP_ERRBUF_SIZE)
        promisc (if promiscuous? 1 0)
        pcap    (.pcap_open_live lib device snaplen promisc timeout-ms err)]
    (when (nil? pcap)
      (throw (ex-info "pcap_open_live failed"
                      {:device device :err (.getString err 0)})))
    ;; ★ netmask 未指定ならデバイスから解決（失敗時は 0 が返る）
    (let [resolved-mask (or netmask (when device (lookup-netmask device)))
          opts*         (if (some? resolved-mask) (assoc opts :netmask resolved-mask) opts)]
      (apply-filter! pcap opts*))))

(defn close! [^Pointer pcap] (.pcap_close lib pcap))

;; ------------------------------------------------------------
;; 安全ラッパ（必ず close/flush する）
;; with-pcap / with-dumper / with-live / with-offline
;; ------------------------------------------------------------

;; Macros below reference these fns; declare them so macro expansion can resolve.
(declare open-dumper dump! flush-dumper! close-dumper!)

(defmacro with-pcap
  "例: (with-pcap [h (open-live {:device \"en0\"})]
         (loop-n! h 10 prn))"
  [[sym open-expr] & body]
  `(let [~sym ~open-expr]
     (try
       ~@body
       (finally
         (close! ~sym)))))

(defmacro with-dumper
  "例: (with-dumper [d (open-dumper h \"out.pcap\")]
         (dump! d hdr data))"
  [[sym open-expr] & body]
  `(let [~sym ~open-expr]
     (try
       ~@body
       (finally
         (flush-dumper! ~sym)
         (close-dumper! ~sym)))))

(defmacro with-live
  "例: (with-live [h {:device \"en0\" :filter \"tcp\"}]
         (loop-n! h 10 prn))"
  [[sym opts] & body]
  `(with-pcap [~sym (open-live ~opts)]
     ~@body))

(defmacro with-offline
  "例:
     (with-offline [h (open-offline \"sample.pcap\")]
       (loop-for-ms! h 2000 prn))
     (with-offline [h (open-offline \"sample.pcap\" {:filter \"udp\"})]
       (loop-n! h 50 prn))"
  [[sym open-expr] & body]
  `(with-pcap [~sym ~open-expr]
     ~@body))

;; ------------------------------------------------------------
;; 生成系ユーティリティ（pcap_open_dead で PCAP を生成）
;; マクロ（with-pcap/with-dumper）より下に置く
;; ------------------------------------------------------------

(def ^:const PCAP_PKTHDR_BYTES 24)
(def ^:const DLT_EN10MB 1) ; Ethernet

(defn ^:private now-sec-usec []
  (let [ms (System/currentTimeMillis)
        sec (long (quot ms 1000))
        usec (long (* 1000 (mod ms 1000)))]
    [sec usec]))

(defn ^Pointer open-dead
  "生成用の pcap ハンドルを作る（linktype は DLT_*、snaplen 既定 65536）"
  (^Pointer []
   (open-dead DLT_EN10MB 65536))
  (^Pointer [linktype snaplen]
   (.pcap_open_dead lib (int linktype) (int snaplen))))

(defn ^:private ^Pointer bytes->ptr [^bytes ba]
  (let [m (Memory/allocate rt (alength ba))]
    (.put m 0 ba 0 (alength ba))
    m))

(defn ^:private ^Pointer mk-hdr
  "pcap_pkthdr を作る。sec/usec は long（エポック秒/マイクロ秒）。len は int。"
  [^long sec ^long usec ^long len]
  (let [hdr (Memory/allocate rt PCAP_PKTHDR_BYTES)]
    (.putLong hdr 0 sec)
    (.putLong hdr 8 usec)
    (.putInt  hdr 16 (int len))
    (.putInt  hdr 20 (int len))
    hdr))

(defn bytes-seq->pcap!
  "バイト列のシーケンスを PCAP に書き出す。
   packets: シーケンス。要素は `byte-array` または
            `{:bytes <ba> :sec <long> :usec <long>}`
   opts: {:out \"out.pcap\" :linktype DLT_* :snaplen 65536}"
  [packets {:keys [out linktype snaplen]
            :or   {linktype DLT_EN10MB snaplen 65536}}]
  (when (str/blank? out)
    (throw (ex-info "bytes-seq->pcap!: :out is required" {})))
  (with-pcap [pcap (open-dead linktype snaplen)]
    (with-dumper [d (open-dumper pcap out)]
      (doseq [p packets]
        (let [[ba sec usec]
              (if (map? p)
                (let [{:keys [bytes sec usec]} p
                      ba' ^bytes (or bytes (byte-array 0))]
                  (when (nil? bytes) (throw (ex-info "missing :bytes" {:item p})))
                  (let [[s u] (if (and sec usec) [sec usec] (now-sec-usec))]
                    [ba' (long s) (long u)]))
                ;; plain byte-array
                (let [[s u] (now-sec-usec)]
                  [^bytes p (long s) (long u)]))
              hdr (mk-hdr sec usec (alength ^bytes ba))
              dat (bytes->ptr ^bytes ba)]
          (dump! d hdr dat))))))

(defn lookupnet
  "デバイス名 dev のネットワークアドレス/マスクを取得。
   成功: {:net int :mask int}
   失敗: ex-info（:phase :lookupnet を含む）"
  [dev]
  (let [net-ref  (IntByReference.)
        mask-ref (IntByReference.)
        err      (Memory/allocate rt PCAP_ERRBUF_SIZE)
        rc       (.pcap_lookupnet lib dev net-ref mask-ref err)]
    (if (zero? rc)
      {:net  (.getValue net-ref)
       :mask (.getValue mask-ref)}
      (throw (ex-info "pcap_lookupnet failed"
                      {:phase  :lookupnet
                       :device dev
                       :rc     rc
                       :err    (.getString err 0)})))))

(defn set-bpf!
  "pcap に BPF を適用。optimize=1、netmask=0（未知時）で apply-filter! に委譲。成功で true。"
  [^Pointer pcap expr]
  (apply-filter! pcap {:filter expr :optimize? true :netmask 0})
  true)

(defn set-bpf-with-netmask!
  "pcap に BPF を適用。optimize=1、netmask 明示で apply-filter! に委譲。成功で true。"
  [^Pointer pcap expr netmask]
  (apply-filter! pcap {:filter expr :optimize? true :netmask (int netmask)})
  true)

(defn set-bpf-on-device!
  "デバイス dev の netmask を lookup して BPF を適用（内部で set-bpf-with-netmask!）。成功で true。"
  [^Pointer pcap dev expr]
  (let [mask (try
               (:mask (lookupnet dev)) ; 既存の詳細版lookupを再利用（失敗時に例外）
               (catch Throwable _ 0))] ; 念のためフォールバック
    (set-bpf-with-netmask! pcap expr mask)))

(defn loop!
  "pcap_next_ex をポーリング。handlerは (fn {:ts-sec :ts-usec :caplen :len :bytes}) を受け取る。
   終端: rc<0（pcap EOF/err）で終了。"
  [^Pointer pcap handler]
  (let [hdr-ref (PointerByReference.)
        dat-ref (PointerByReference.)]
    (loop []
      (let [rc (.pcap_next_ex lib pcap hdr-ref dat-ref)]
        (cond
          (= rc 1)
          (let [hdr (.getValue hdr-ref)
                dat (.getValue dat-ref)
                ts-sec (PcapHeader/tv_sec hdr)
                ts-usec (PcapHeader/tv_usec hdr)
                caplen (PcapHeader/caplen hdr)
                len    (PcapHeader/len hdr)
                arr    (byte-array (int caplen))]
            (.get dat 0 arr 0 (alength arr))
            (handler {:ts-sec ts-sec :ts-usec ts-usec
                      :caplen caplen :len len :bytes arr})
            (recur))

          (= rc 0)  ; timeout (live capture)
          (recur)

          :else     ; -1 error / -2 EOF (offline)
          rc)))))

(defn breakloop! [^Pointer pcap] (.pcap_breakloop lib pcap))

(defn open-dumper ^Pointer [^Pointer pcap path]
  (let [d (.pcap_dump_open lib pcap path)]
    (when (nil? d)
      (throw (ex-info "pcap_dump_open failed" {:path path})))
    d))

(defn dump! [^Pointer dumper ^Pointer hdr ^Pointer data]
  (.pcap_dump lib dumper hdr data))

(defn flush-dumper! [^Pointer dumper]
  (.pcap_dump_flush lib dumper))

(defn close-dumper! [^Pointer dumper]
  (.pcap_dump_close lib dumper))

(defn capture->pcap
  "ライブでキャプチャして out.pcap に保存。
   opts:
   {:device \"en0\"
    :filter \"tcp port 80\"     ; 省略可
    :max 100                    ; 取れたパケット数がこの件数に達したら終了
    :snaplen 65536
    :promiscuous? true
    :timeout-ms 10              ; pcap_next_ex のタイムアウト
    :max-time-ms 10000          ; 壁時計タイム上限（ms）
    :idle-max-ms 3000}          ; 連続アイドル上限（ms）"
  [{:keys [device filter max snaplen promiscuous? timeout-ms max-time-ms idle-max-ms]
    :or {max 100 snaplen 65536 promiscuous? true timeout-ms 10
         max-time-ms 10000 idle-max-ms 3000}}
   out]
  (let [pcap   (open-live {:device device :snaplen snaplen :promiscuous? promiscuous? :timeout-ms timeout-ms})
        dumper (open-dumper pcap out)
        hdr-ref (PointerByReference.)
        dat-ref (PointerByReference.)
        t0 (System/currentTimeMillis)]
    (try
      ;; ★ 変更点：device+filter が両方ある場合は netmask を自動適用
      (when filter
        (if (some? device)
          (set-bpf-on-device! pcap device filter)
          (set-bpf! pcap filter)))
      (loop [n 0 idle 0]
        (let [now (System/currentTimeMillis)]
          (cond
            (>= n max) n
            (>= (- now t0) max-time-ms) n
            (>= idle idle-max-ms) n
            :else
            (let [rc (.pcap_next_ex lib pcap hdr-ref dat-ref)]
              (cond
                (= rc 1)
                (do
                  (dump! dumper (.getValue hdr-ref) (.getValue dat-ref))
                  (recur (inc n) 0))
                (= rc 0) ; timeout
                (recur n (+ idle timeout-ms))
                :else    ; -1 err / -2 EOF
                n)))))
      (finally
        (flush-dumper! dumper)
        (close-dumper! dumper)
        (close! pcap)))))

;; macOS だけ networksetup から “人間が読める名称” を補完
(defn- macos-device->desc []
  (let [os (.. System (getProperty "os.name") toLowerCase)]
    (if (not (.contains os "mac"))
      {}
      (let [pb   (java.lang.ProcessBuilder.
                  (into-array String ["networksetup" "-listallhardwareports"]))
            _    (.redirectErrorStream pb true)   ;; ← Redirect 定数は使わない
            proc (.start pb)
            rdr  (java.io.BufferedReader.
                  (java.io.InputStreamReader. (.getInputStream proc)))]
        (try
          (loop [m {}
                 cur-port nil
                 line (.readLine rdr)]
            (if (nil? line)
              m
              (cond
                (.startsWith line "Hardware Port: ")
                (recur m (str/trim (subs line 14)) (.readLine rdr))

                (.startsWith line "Device: ")
                (let [dev (subs line 8)]
                  (recur (assoc m dev cur-port) cur-port (.readLine rdr)))

                :else
                (recur m cur-port (.readLine rdr)))))
          (finally
            (.close rdr)
            (.waitFor proc)))))))

(defn list-devices
  "利用可能デバイスの簡易一覧。macOSでは networksetup で desc を補完する。
   - name が空/空白のエントリはスキップ
   - desc が空/空白なら fallback を適用"
  []
  (let [err (Memory/allocate rt PCAP_ERRBUF_SIZE)
        pp  (PointerByReference.)]
    (when (neg? (.pcap_findalldevs lib pp err))
      (throw (ex-info "pcap_findalldevs failed" {:err (.getString err 0)})))
    (let [head (.getValue pp)
          fallback (macos-device->desc)]
      (try
        (loop [p head, acc (transient [])]
          (if (or (nil? p) (= 0 (.address p)))
            ;; 完了
            (persistent! acc)
            (let [ifc (paclo.jnr.PcapLibrary$PcapIf. rt)]
              (.useMemory ifc p)
              (let [name-ptr (.get (.-name ifc))
                    desc-ptr (.get (.-desc ifc))
                    next-ptr (.get (.-next ifc))
                    ;; name の空/空白はスキップ
                    name     (when (and name-ptr (not= 0 (.address name-ptr)))
                               (let [s (.getString name-ptr 0)]
                                 (when-not (blank-str? s) s)))
                    ;; desc が空/空白なら fallback に置換
                    desc0    (when (and desc-ptr (not= 0 (.address desc-ptr)))
                               (normalize-desc (.getString desc-ptr 0)))
                    desc     (or desc0 (when name (normalize-desc (get fallback name))))]
                (if name
                  (recur next-ptr (conj! acc {:name name :desc desc}))
                  (recur next-ptr acc))))))
        (finally
          (.pcap_freealldevs lib head))))))

;; --- handler 正規化（0引数でも受け付ける） -------------------------------
(defn- ->pkt-handler
  "渡された handler を『1引数を取る関数』に正規化する。
   - 1引数関数ならそのまま呼ぶ
   - 0引数関数なら ArityException を捕まえて fallback で呼ぶ
   - nil は no-op"
  [handler]
  (cond
    (nil? handler)
    (fn [_] nil)

    :else
    (fn [pkt]
      (try
        (handler pkt)                     ;; 1引数として呼ぶ
        (catch clojure.lang.ArityException _
          (handler))))))                  ;; 0引数で呼ぶ

;; -----------------------------------------
;; REPL用：小回りヘルパ（件数/時間/idleで停止）
;; -----------------------------------------
;; NOTE:
;; - :idle-max-ms を与えた場合のみ idle 監視を有効化。
;; - その場合、:timeout-ms（open-liveに渡した値）も渡すと精度が上がる。
;;   未指定なら 100ms を仮定して idle を積算します。

(defn loop-n!
  "pcap_next_ex を最大 n 件処理して停止。
   オプション: {:idle-max-ms <ms> :timeout-ms <ms>}
   例: (loop-n! h 10 handler) ; 従来どおり
       (loop-n! h 10 handler {:idle-max-ms 3000 :timeout-ms 100})"
  ([^Pointer pcap ^long n handler]
   (assert (pos? n) "n must be positive")
   (let [c (atom 0)
         handle (->pkt-handler handler)]
     (loop! pcap (fn [pkt]
                   (handle pkt)
                   (when (>= (swap! c inc) n)
                     (breakloop! pcap))))))
  ([^Pointer pcap ^long n handler {:keys [idle-max-ms timeout-ms]}]
   (if (nil? idle-max-ms)
     (loop-n! pcap n handler)
     (do
       (assert (pos? n) "n must be positive")
       (let [hdr-ref (PointerByReference.)
             dat-ref (PointerByReference.)
             idle-ms-target (long idle-max-ms)
             tick (long (or timeout-ms 100))
             handle (->pkt-handler handler)]
         (loop [count 0 idle 0]
           (when (< count n)
             (let [rc (.pcap_next_ex lib pcap hdr-ref dat-ref)]
               (cond
                 (= rc 1)
                 (let [hdr (.getValue hdr-ref)
                       dat (.getValue dat-ref)
                       ts-sec (PcapHeader/tv_sec hdr)
                       ts-usec (PcapHeader/tv_usec hdr)
                       caplen (PcapHeader/caplen hdr)
                       len    (PcapHeader/len hdr)
                       arr    (byte-array (int caplen))]
                   (.get dat 0 arr 0 (alength arr))
                   (handle {:ts-sec ts-sec :ts-usec ts-usec
                            :caplen caplen :len len :bytes arr})
                   (recur (inc count) 0))

                 (= rc 0)
                 (let [idle' (+ idle tick)]
                   (if (>= idle' idle-ms-target)
                     (breakloop! pcap)
                     (recur count idle')))

                 :else
                 (breakloop! pcap))))))))))

(defn loop-for-ms!
  "開始から duration-ms 経過したら停止（壁時計基準）。
   オプション: {:idle-max-ms <ms> :timeout-ms <ms>}
   例: (loop-for-ms! h 3000 handler)
       (loop-for-ms! h 3000 handler {:idle-max-ms 1000 :timeout-ms 50})"
  ([^Pointer pcap ^long duration-ms handler]
   (assert (pos? duration-ms) "duration-ms must be positive")
   (let [t0 (System/currentTimeMillis)
         handle (->pkt-handler handler)]
     (loop! pcap (fn [pkt]
                   (handle pkt)
                   (when (>= (- (System/currentTimeMillis) t0) duration-ms)
                     (breakloop! pcap))))))
  ([^Pointer pcap ^long duration-ms handler {:keys [idle-max-ms timeout-ms]}]
   (if (nil? idle-max-ms)
     (loop-for-ms! pcap duration-ms handler)
     (do
       (assert (pos? duration-ms) "duration-ms must be positive")
       (let [hdr-ref (PointerByReference.)
             dat-ref (PointerByReference.)
             t0 (System/currentTimeMillis)
             deadline (+ t0 (long duration-ms))
             idle-ms-target (long idle-max-ms)
             tick (long (or timeout-ms 100))
             handle (->pkt-handler handler)]
         (loop [idle 0]
           (when (< (System/currentTimeMillis) deadline)
             (let [rc (.pcap_next_ex lib pcap hdr-ref dat-ref)]
               (cond
                 (= rc 1)
                 (let [hdr (.getValue hdr-ref)
                       dat (.getValue dat-ref)
                       ts-sec (PcapHeader/tv_sec hdr)
                       ts-usec (PcapHeader/tv_usec hdr)
                       caplen (PcapHeader/caplen hdr)
                       len    (PcapHeader/len hdr)
                       arr    (byte-array (int caplen))]
                   (.get dat 0 arr 0 (alength arr))
                   (handle {:ts-sec ts-sec :ts-usec ts-usec
                            :caplen caplen :len len :bytes arr})
                   (recur 0))

                 (= rc 0)
                 (let [idle' (+ idle tick)]
                   (if (>= idle' idle-ms-target)
                     (breakloop! pcap)
                     (recur idle')))

                 :else
                 (breakloop! pcap))))))))))

(defn loop-n-or-ms!
  "n件到達 or duration-ms 経過の早い方で停止。
   conf: {:n <long> :ms <long> :idle-max-ms <ms-optional> :timeout-ms <ms-optional> :stop? <fn-optional>}"
  [^Pointer pcap {:keys [n ms idle-max-ms timeout-ms stop?] :as conf} handler]
  (when (nil? n) (throw (ex-info "missing :n" {})))
  (when (nil? ms) (throw (ex-info "missing :ms" {})))
  (assert (pos? n) "n must be positive")
  (assert (pos? ms) "ms must be positive")
  (let [handle (->pkt-handler handler)]
    (if (nil? idle-max-ms)
      ;; --- idle監視なし: loop! を使うパス（handler内で停止条件を見る）
      (let [c  (atom 0)
            t0 (System/currentTimeMillis)]
        (loop! pcap (fn [pkt]
                      (handle pkt)
                      (let [stop-n? (>= (swap! c inc) n)
                            stop-t? (>= (- (System/currentTimeMillis) t0) ms)
                            stop-custom? (and stop? (stop? pkt))]
                        (when (or stop-n? stop-t? stop-custom?)
                          (breakloop! pcap))))))
      ;; --- idle監視あり: pcap_next_ex を自前で回すパス（pkt毎に stop? を判定）
      (let [hdr-ref (PointerByReference.)
            dat-ref (PointerByReference.)
            t0 (System/currentTimeMillis)
            deadline (+ t0 (long ms))
            tick (long (or timeout-ms 100))
            idle-target (long idle-max-ms)]
        (loop [count 0 idle 0]
          (when (and (< count n)
                     (< (System/currentTimeMillis) deadline))
            (let [rc (.pcap_next_ex lib pcap hdr-ref dat-ref)]
              (cond
                (= rc 1)
                (let [hdr (.getValue hdr-ref)
                      dat (.getValue dat-ref)
                      ts-sec (PcapHeader/tv_sec hdr)
                      ts-usec (PcapHeader/tv_usec hdr)
                      caplen (PcapHeader/caplen hdr)
                      len    (PcapHeader/len hdr)
                      arr    (byte-array (int caplen))
                      _      (.get dat 0 arr 0 (alength arr))
                      pkt    {:ts-sec ts-sec :ts-usec ts-usec
                              :caplen caplen :len len :bytes arr}]
                  (handle pkt)
                  (if (and stop? (stop? pkt))
                    (breakloop! pcap)            ;; ★ ヒット即停止（オフラインでも即効）
                    (recur (inc count) 0)))

                (= rc 0)
                (let [idle' (+ idle tick)]
                  (if (>= idle' idle-target)
                    (breakloop! pcap)
                    (recur count idle')))

                :else
                (breakloop! pcap)))))))))

;; -----------------------------------------
;; REPL用：ワンショット実験（open→filter→loop→close）
;; -----------------------------------------

(defn run-live-n!
  "デバイスを開いて、必要ならBPFを設定して、n件だけ処理して閉じる。
   追加オプション: :idle-max-ms （:timeout-ms は open-live と共有）
   例: (run-live-n! {:device \"en1\" :filter \"tcp\" :timeout-ms 100}
                    50
                    handler
                    {:idle-max-ms 3000})"
  ([opts ^long n handler]
   (run-live-n! opts n handler {}))
  ([{:keys [device filter snaplen promiscuous? timeout-ms]
     :or {snaplen 65536 promiscuous? true timeout-ms 10}}
    ^long n
    handler
    {:keys [idle-max-ms] :as loop-opts}]
   (let [h (open-live {:device device :snaplen snaplen :promiscuous? promiscuous? :timeout-ms timeout-ms})]
     (try
       (when filter
         (if device (set-bpf-on-device! h device filter)
             (set-bpf! h filter)))
       (if idle-max-ms
         (loop-n! h n handler {:idle-max-ms idle-max-ms :timeout-ms timeout-ms})
         (loop-n! h n handler))
       (finally (close! h))))))

(defn run-live-for-ms!
  "デバイスを開いて、必要ならBPFを設定して、duration-msだけ処理して閉じる。
   追加オプション: {:idle-max-ms <ms>}
   例: (run-live-for-ms! {:device \"en1\" :timeout-ms 50}
                         5000
                         handler
                         {:idle-max-ms 1000})"
  ([opts ^long duration-ms handler]
   (run-live-for-ms! opts duration-ms handler {}))
  ([{:keys [device filter snaplen promiscuous? timeout-ms]
     :or {snaplen 65536 promiscuous? true timeout-ms 10}}
    ^long duration-ms
    handler
    {:keys [idle-max-ms] :as loop-opts}]
   (let [h (open-live {:device device :snaplen snaplen :promiscuous? promiscuous? :timeout-ms timeout-ms})]
     (try
       (when filter
         (if device (set-bpf-on-device! h device filter)
             (set-bpf! h filter)))
       (if idle-max-ms
         (loop-for-ms! h duration-ms handler {:idle-max-ms idle-max-ms :timeout-ms timeout-ms})
         (loop-for-ms! h duration-ms handler))
       (finally (close! h))))))

;; -----------------------------------------
;; 高レベルAPI：capture->seq
;; - ライブ/オフライン両対応
;; - デフォルトで安全に手仕舞い（:max/:max-time-ms/:idle-max-ms）
;; - バックグラウンドでキャプチャし、lazy-seq で取り出し
;; -----------------------------------------

(def ^:private ^:const default-max 100)
(def ^:private ^:const default-max-time-ms 10000)
(def ^:private ^:const default-idle-max-ms 3000)
(def ^:private ^:const default-queue-cap 1024)

(defn capture->seq
  "パケットを lazy-seq で返す高レベルAPI。
   opts:
   - ライブ:  {:device \"en1\" :filter \"tcp\" :snaplen 65536 :promiscuous? true :timeout-ms 10}
   - オフライン: {:path \"sample.pcap\" :filter \"...\"}
   - 共有停止条件（指定なければ安全な既定値で自動手仕舞い）:
       :max <int>               ; 取得最大件数（default 100）
       :max-time-ms <int>       ; 経過時間上限（default 10000）
       :idle-max-ms <int>       ; 無通信連続上限（default 3000）
   - 内部キュー:
       :queue-cap <int>         ; バックグラウンド→呼び出し側のバッファ（default 1024）
   - エラー処理:
       :on-error (fn [throwable])   ; 背景スレッドで例外発生時に呼ばれる（任意）
       :error-mode :throw|:pass     ; 既定 :throw（lazy側に再スロー）/:pass はスキップ
   - ★停止条件フック（新規）:
       :stop? (fn [pkt] boolean)    ; 受信pktを見て true なら即 stop（breakloop!）

   返り値: lazy-seq of packet-maps （loop! ハンドラで渡している {:ts-sec … :bytes …}）"
  [{:keys [device path filter snaplen promiscuous? timeout-ms
           max max-time-ms idle-max-ms queue-cap on-error error-mode stop?]
    :or   {snaplen 65536 promiscuous? true timeout-ms 10
           error-mode :throw}}]
  (let [default-max 100
        default-max-time-ms 10000
        default-idle-max-ms 3000
        default-queue-cap 1024
        max         (or max default-max)
        max-time-ms (or max-time-ms default-max-time-ms)
        idle-max-ms (or idle-max-ms default-idle-max-ms)
        cap         (int (or queue-cap default-queue-cap))
        q           (LinkedBlockingQueue. cap)
        sentinel    ::end-of-capture
        make-error-item (fn [^Throwable ex] {:type :paclo/capture-error :ex ex})
        ;; open
        h (if device
            (open-live {:device device :snaplen snaplen :promiscuous? promiscuous? :timeout-ms timeout-ms})
            (open-offline path))]
    ;; バックグラウンドでキャプチャしてキューに流す
    (future
      (try
        (when filter
          (if device
            (set-bpf-on-device! h device filter)
            (set-bpf! h filter)))
        (loop-n-or-ms! h {:n max :ms max-time-ms :idle-max-ms idle-max-ms :timeout-ms timeout-ms :stop? stop?}
                       (fn [pkt]
                         (.put q pkt)
                         ;; ★ 任意条件で即停止
                         (when (and stop? (stop? pkt))
                           (breakloop! h))))
        (catch Throwable ex
          (when on-error (try (on-error ex) (catch Throwable _)))
          (.put q (make-error-item ex)))
        (finally
          (.put q sentinel)
          (close! h))))
    ;; lazy-seq を返す
    (letfn [(drain []
              (lazy-seq
               (let [x (.take q)]
                 (cond
                   (identical? x sentinel) '()
                   (and (map? x) (= (:type x) :paclo/capture-error))
                   (if (= error-mode :pass)
                     (drain)
                     (throw (ex-info "capture->seq background error"
                                     {:source :capture->seq}
                                     (:ex x))))
                   :else (cons x (drain))))))]
      (drain))))

;; ------------------------------------------------------------
;; ライブ実行のサマリ版（後方互換のため新規追加）
;; - run-live-n-summary!     => {:count n :duration-ms X :stopped :n | :idle-or-eof}
;; - run-live-for-ms-summary!=> {:count n :duration-ms X :stopped :time | :idle-or-eof}
;;   ※ :idle-or-eof は「件数未達で停止（アイドル or EOF/ERR）」の総称
;; ------------------------------------------------------------

(defn run-live-n-summary!
  "run-live-n! と同等の処理を行い、サマリを返す。
   例: (run-live-n-summary! {:device \"en0\" :filter \"udp\" :timeout-ms 50} 100 (fn [_]) {:idle-max-ms 3000})"
  ([opts ^long n handler]
   (run-live-n-summary! opts n handler {}))
  ([opts ^long n handler loop-opts]
   (let [cnt (atom 0)
         t0  (System/currentTimeMillis)
         wrapped (fn [pkt] (swap! cnt inc) (handler pkt))]
     (run-live-n! opts n wrapped loop-opts)
     (let [elapsed (- (System/currentTimeMillis) t0)
           stopped (if (>= @cnt n) :n :idle-or-eof)]
       {:count @cnt :duration-ms elapsed :stopped stopped}))))

(defn run-live-for-ms-summary!
  "run-live-for-ms! と同等の処理を行い、サマリを返す。
   例: (run-live-for-ms-summary! {:device \"en0\" :filter \"tcp\" :timeout-ms 50} 3000 (fn [_]) {:idle-max-ms 1000})"
  ([opts ^long duration-ms handler]
   (run-live-for-ms-summary! opts duration-ms handler {}))
  ([opts ^long duration-ms handler loop-opts]
   (let [cnt (atom 0)
         t0  (System/currentTimeMillis)
         wrapped (fn [pkt] (swap! cnt inc) (handler pkt))]
     (run-live-for-ms! opts duration-ms wrapped loop-opts)
     (let [elapsed (- (System/currentTimeMillis) t0)
           stopped (if (>= elapsed (long duration-ms)) :time :idle-or-eof)]
       {:count @cnt :duration-ms elapsed :stopped stopped}))))
```

### src/paclo/core.clj
```clojure
(ns paclo.core
  "Clojure らしい薄いファサード。
   - packets: ライブ/オフラインどちらも lazy seq を返す（:decode? でparse付与、:xform で後段変換）
   - bpf:      簡易DSL → BPF文字列
   - write-pcap!: bytesシーケンスを書き出す（テスト/再現用）"
  (:require
   [clojure.string :as str]
   [paclo.decode-ext :as decode-ext]
   [paclo.parse :as parse]
   [paclo.pcap  :as pcap]))

;; ---------------------------
;; BPF DSL -> string
;; ---------------------------
(defn ^:private paren [s] (str "(" s ")"))

(defn bpf
  "BPFフィルタを表す簡易DSLを文字列へ。

  サポート（追加含む）:
  - 論理: :and / :or / :not
  - プロトコル: :udp :tcp :icmp :icmp6 :arp に加え、:ip / :ipv4 / :ip6 / :ipv6
    例) (bpf :ipv6)        ;;=> \"ip6\"
        (bpf [:proto :ip]) ;;=> \"ip\"
  - アドレス系: :host / :src-host / :dst-host / :net / :src-net / :dst-net
    例) (bpf [:src-net \"10.0.0.0/8\"]) ;;=> \"src net 10.0.0.0/8\"
  - ポート系: :port / :src-port / :dst-port
    追加: :port-range / :src-port-range / :dst-port-range
    例) (bpf [:port-range 1000 2000])     ;;=> \"portrange 1000-2000\"
        (bpf [:src-port-range 53 60])     ;;=> \"src portrange 53-60\"

  文字列が渡された場合はそのまま返す。"
  [form]
  (letfn [(kw-proto [k]
            (case k
              :udp "udp" :tcp "tcp" :icmp "icmp" :icmp6 "icmp6" :arp "arp"
              :ip "ip" :ipv4 "ip" :ip4 "ip"
              :ip6 "ip6" :ipv6 "ip6"
              (throw (ex-info "unknown proto keyword" {:proto k}))))
          (as-int [x]
            (if (number? x)
              (int x)
              (Integer/parseInt (str x))))]
    (cond
      (nil? form) nil
      (string? form) form

      (keyword? form)
      (kw-proto form)

      (vector? form)
      (let [[op & args] form]
        (case op
          ;; 論理
          :and (->> args (map bpf) (map paren) (clojure.string/join " and "))
          :or  (->> args (map bpf) (map paren) (clojure.string/join " or "))
          :not (str "not " (paren (bpf (first args))))

          ;; プロトコル指定（拡張）
          :proto (kw-proto (first args))

          ;; ホスト/ネット
          :host     (str "host "     (first args))
          :src-host (str "src host " (first args))
          :dst-host (str "dst host " (first args))
          :net      (str "net "      (first args))
          :src-net  (str "src net "  (first args))
          :dst-net  (str "dst net "  (first args))

          ;; ポート（単体）
          :port     (str "port "     (as-int (first args)))
          :src-port (str "src port " (as-int (first args)))
          :dst-port (str "dst port " (as-int (first args)))

          ;; ポート範囲（追加）
          :port-range
          (let [[a b] args] (str "portrange " (as-int a) "-" (as-int b)))
          :src-port-range
          (let [[a b] args] (str "src portrange " (as-int a) "-" (as-int b)))
          :dst-port-range
          (let [[a b] args] (str "dst portrange " (as-int a) "-" (as-int b)))

          ;; 既存トップレベルのキーワードも許容（[:udp] など）
          :udp "udp" :tcp "tcp" :icmp "icmp" :icmp6 "icmp6" :arp "arp"
          :ip "ip" :ipv4 "ip" :ip4 "ip" :ip6 "ip6" :ipv6 "ip6"

          (throw (ex-info "unknown op in bpf" {:form form :op op}))))
      :else
      (throw (ex-info "unsupported bpf form" {:form form})))))

;; ---------------------------
;; Stream API
;; ---------------------------
(def ^:private ETH_MIN_HDR 14)

(defn ^:private decode-result
  "parse/packet->clj を安全に呼び、結果 or エラーメッセージを返す。"
  [^bytes ba]
  (try
    {:ok true :value (parse/packet->clj ba)}
    (catch Throwable e
      {:ok false :error (or (.getMessage e) (str e))})))

(defn ^:private apply-xform
  "xf が nil なら s をそのまま返し、非nil なら (sequence xf s) を返す。
   sequence を使う事で laziness と chunkless の両立を維持。"
  [s xf]
  (if (some? xf) (sequence xf s) s))

(defn packets
  "パケットを lazy seq で返す高レベルAPI。
   opts:
   - ライブ:  {:device \"en0\" :filter <string|DSL> :timeout-ms 10 ...}
   - オフライン: {:path \"trace.pcap\" :filter <string|DSL>}
   - 共通:
       :decode? true|false
         true なら各要素に :decoded を付与。失敗時は :decode-error を付与。
       :xform <transducer>
         出力ストリームに適用する transducer。
         例: (comp (filter pred) (map f))
   返り値は遅延シーケンス。take/into などで消費してください。"
  [{:keys [filter decode? xform] :as opts}]
  (let [filter* (cond
                  (string? filter) filter
                  (or (keyword? filter) (vector? filter)) (bpf filter)
                  (nil? filter) nil
                  :else (throw (ex-info "invalid :filter" {:filter filter})))
        opts*   (cond-> opts (some? filter*) (assoc :filter filter*))
        base    (pcap/capture->seq opts*)
        stream  (if decode?
                  (map (fn [m]
                         (let [ba ^bytes (:bytes m)]
                           (if (and ba (>= (alength ba) ETH_MIN_HDR))
                             (let [{:keys [ok value error]} (decode-result ba)
                                   m' (cond-> m
                                        ok       (assoc :decoded value)
                                        (not ok) (assoc :decode-error error))]
                               ;; ★ ここを追加：decoded があれば拡張フックを適用
                               (if (contains? m' :decoded)
                                 (decode-ext/apply! m')
                                 m'))
                             (assoc m :decode-error (str "frame too short: " (when ba (alength ba)) " bytes")))))
                       base)
                  base)]
    (apply-xform stream xform)))

;; ---------------------------
;; Writer
;; ---------------------------
(defn write-pcap!
  "bytes のシーケンスを PCAP ファイルへ書き出す（テスト/再現用）。
   エントリは (byte-array ..) か {:bytes <ba> :sec <long> :usec <long>}。
   例: (write-pcap! [ba1 {:bytes ba2 :sec 1700000000 :usec 12345}] \"out.pcap\")"
  [packets out]
  (pcap/bytes-seq->pcap! packets {:out out}))

(defn list-devices
  "利用可能デバイスの簡易一覧（pcap/list-devices のファサード）。
   返り値: [{:name \"en0\" :desc \"Wi-Fi\"} ...]"
  []
  (pcap/list-devices))
```

### src/paclo/dev.clj
```clojure
(ns paclo.dev
  "REPLでの即席デバッグ/実験ヘルパ。
   - (parse-hex s)       ; 16進文字列→パケットmap
   - (summarize pktmap)  ; 要約表示
   - (hexd pktmap)       ; :bytes を16進で表示（L2生データ）

   例:
   (-> HBH-OK parse-hex summarize)
   (-> HBH-BAD parse-hex summarize)"
  (:require
   [clojure.string :as str]
   [paclo.parse :as parse])
  (:import
   [java.util Formatter]))

;; テストユーティリティに依存しない最小 hex→bytes
(defn hex->bytes ^bytes [^String s]
  (let [cleaned (-> s
                    str/lower-case
                    ;; ; コメント / Cスタイル /* */ は行儀良く除去
                    (str/replace #"(?m);.*$" "")
                    (str/replace #"(?s)/\*.*?\*/" "")
                    ;; 16進以外を全部落とす
                    (str/replace #"[^0-9a-f]" ""))]
    (when (odd? (count cleaned))
      (throw (ex-info "Odd number of hex digits" {:len (count cleaned)})))
    (byte-array
     (map (fn [[a b]]
            (unchecked-byte (Integer/parseInt (str a b) 16)))
          (partition 2 cleaned)))))

(defn parse-hex
  "16進文字列 s をパースして packet map を返す。"
  [^String s]
  (parse/packet->clj (hex->bytes s)))

(defn- fmt-bytes
  "byte[] を 'xx xx xx ...' の文字列へ"
  [^bytes bs]
  (let [sb (StringBuilder.)
        fmt (Formatter. sb)]
    (dotimes [i (alength bs)]
      (.format fmt "%02x%s"
               (bit-and 0xFF (aget bs i))
               (if (= (inc i) (alength bs)) "" " ")))
    (str sb)))

(defn hexd
  "packet map の :bytes を16進で表示（L2生データ）。戻り値は文字列。"
  [pkt]
  (fmt-bytes (:bytes pkt)))

(defn summarize
  "要点だけサマリ出力（println）。戻り値は pkt そのもの（スレッディングしやすく）。"
  [pkt]
  (let [{:keys [type l3 vlan-tags]} pkt
        l3t (:type l3)
        proto (or (:protocol l3) (:next-header l3))
        l4 (:l4 l3)]
    (println "L2:" type)
    (when (= :ethernet type)
      (print "  src/dst:" (:src pkt) "->" (:dst pkt) "eth" (format "0x%04X" (:eth pkt)))
      (when (seq vlan-tags)
        (print "  VLAN:")
        (doseq [t vlan-tags]
          (print (format " [TPID=0x%04X VID=%d PCP=%d DEI=%s]"
                         (:tpid t) (:vid t) (:pcp t) (boolean (:dei t))))))
      (println))
    (println "L3:" l3t)
    (case l3t
      :ipv4 (println "  proto" proto
                     "src" (:src l3) "dst" (:dst l3)
                     (when (:frag? l3) (str " frag@" (:frag-offset l3))))
      :ipv6 (do
              (println "  nh" proto
                       "src" (or (:src-compact l3) (:src l3))
                       "dst" (or (:dst-compact l3) (:dst l3))
                       (when (:frag? l3) (str "frag@" (:frag-offset l3)))))
      :arp  (println "  op" (:op l3) "spa" (:spa l3) "tpa" (:tpa l3))
      nil)
    (println "L4:" (:type l4)
             (cond
               (= :udp (:type l4)) (str (:src-port l4) "->" (:dst-port l4) " len=" (:data-len l4))
               (= :tcp (:type l4)) (str (:src-port l4) "->" (:dst-port l4)
                                        " " (or (:flags-str l4) "")
                                        " len=" (:data-len l4))
               (= :icmpv4 (:type l4)) (str (or (:summary l4) (str "type=" (:icmp-type l4) " code=" (:code l4)))
                                           " len=" (:data-len l4))
               (= :icmpv6 (:type l4)) (str (or (:summary l4) (str "type=" (:icmp-type l4) " code=" (:code l4)))
                                           " len=" (:data-len l4))
               :else ""))

    (when-let [app (:app l4)]
      (println "App:" (:type app) app))
    pkt))

;; ------------------------------------------------------------
;; 実験用の最小ベクタ（HBH: 正常/異常）
;; ------------------------------------------------------------

(def HBH-OK
  "Ether(IPv6) + IPv6(PL=24, NH=HBH) + HBH(16B, NextHdr=UDP) + UDP(8B)"
  "00 11 22 33 44 55 66 77 88 99 AA BB 86 DD
   60 00 00 00 00 18 00 40
   20 01 0D B8 00 00 00 00 00 00 00 00 00 00 00 01
   20 01 0D B8 00 00 00 00 00 00 00 00 00 00 00 02
   11 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00
   12 34 56 78 00 08 00 00")

(def HBH-BAD-OVERRUN
  "HBHのTLV長が過走（len=0x0Dで14B領域を1Bオーバー）→ 安全に上位へ進まず"
  "00 11 22 33 44 55 66 77 88 99 AA BB 86 DD
   60 00 00 00 00 18 00 40
   20 01 0D B8 00 00 00 00 00 00 00 00 00 00 00 01
   20 01 0D B8 00 00 00 00 00 00 00 00 00 00 00 02
   11 01 01 0D
   00 00 00 00 00 00 00 00 00 00 00 00
   12 34 56 78 00 08 00 00")
```

### src-java/paclo/jnr/PcapLibrary.java
```java
package paclo.jnr;

import jnr.ffi.LibraryLoader;
import jnr.ffi.Runtime;
import jnr.ffi.Pointer;
import jnr.ffi.Struct;
import jnr.ffi.byref.PointerByReference;
import jnr.ffi.byref.IntByReference;
import paclo.jnr.BpfProgram;

public interface PcapLibrary {

  /** libpcap ローダ（Clojure側からも直接使えるようにしておく） */
  PcapLibrary INSTANCE = LibraryLoader.create(PcapLibrary.class).load("pcap");

  // open/close
  Pointer pcap_open_offline(String fname, Pointer errbuf);
  Pointer pcap_open_live(String device, int snaplen, int promisc, int to_ms, Pointer errbuf);
  void    pcap_close(Pointer pcap);

  /** dead pcap_t を作る（生成PCAP用） */
  Pointer pcap_open_dead(int linktype, int snaplen);

  // poll (no callback)
  int     pcap_next_ex(Pointer pcap, PointerByReference headerRef, PointerByReference dataRef);

  // control
  void    pcap_breakloop(Pointer pcap);

  // BPF
  int     pcap_compile(Pointer pcap, Pointer bpfProgram, String expr, int optimize, int netmask);
  int     pcap_setfilter(Pointer pcap, Pointer bpfProgram);
  void    pcap_freecode(Pointer bpfProgram);

  // misc
  String  pcap_lib_version();

  // 追加: dumper（pcap_dump_*）
  Pointer pcap_dump_open(Pointer pcap, String fname);
  void    pcap_dump(Pointer dumper, Pointer hdr, Pointer data);
  void    pcap_dump_flush(Pointer dumper);
  void    pcap_dump_close(Pointer dumper);

  String pcap_geterr(Pointer pcap);

  // 構造体ヘルパー（最小限）
  public static final class PcapIf extends jnr.ffi.Struct {
    public final jnr.ffi.Struct.Pointer  next = new jnr.ffi.Struct.Pointer();
    public final jnr.ffi.Struct.Pointer  name = new jnr.ffi.Struct.Pointer();
    public final jnr.ffi.Struct.Pointer  desc = new jnr.ffi.Struct.Pointer();
    public PcapIf(jnr.ffi.Runtime r) { super(r); }
  }

  int     pcap_findalldevs(jnr.ffi.byref.PointerByReference alldevs, jnr.ffi.Pointer errbuf);
  void    pcap_freealldevs(jnr.ffi.Pointer alldevs);

  int     pcap_lookupnet(String device, IntByReference netp, IntByReference maskp, Pointer errbuf);

  // ===== BPF ヘルパー（利便性向上・例外で失敗がわかるように） =====
  static BpfProgram compileFilter(Pointer pcap, String expr, boolean optimize, int netmask) {
    Runtime rt = Runtime.getRuntime(INSTANCE);
    BpfProgram prog = new BpfProgram(rt);
    int rc = INSTANCE.pcap_compile(pcap, prog.addr(), expr, optimize ? 1 : 0, netmask);
    if (rc != 0) {
      String msg = "(no detail)";
      try { msg = INSTANCE.pcap_geterr(pcap); } catch (Throwable ignore) {}
      throw new IllegalStateException("pcap_compile failed rc=" + rc + " expr=" + expr + " err=" + msg);
    }
    return prog;
  }

  static void setFilterOrThrow(Pointer pcap, BpfProgram prog) {
    int rc = INSTANCE.pcap_setfilter(pcap, prog.addr());
    if (rc != 0) {
      String msg = "(no detail)";
      try { msg = INSTANCE.pcap_geterr(pcap); } catch (Throwable ignore) {}
      throw new IllegalStateException("pcap_setfilter failed rc=" + rc + " err=" + msg);
    }
  }

  static void freeFilter(BpfProgram prog) {
    INSTANCE.pcap_freecode(prog.addr());
  }
}
```

### test/paclo/parse_test.clj
```clojure
(ns paclo.parse-test
  (:require
   [clojure.test :refer :all]
   [paclo.parse :as parse]
   [paclo.test-util :as tu]))

;; 1) IPv4/TCP（payload="hello"）
(deftest ipv4-tcp-min-test
  (let [pkt (tu/hex->bytes
             "00 11 22 33 44 55 66 77 88 99 AA BB 08 00
               45 00 00 2D 00 01 40 00 40 06 00 00
               0A 00 00 01 0A 00 00 02
               30 39 00 50 00 00 00 00 00 00 00 00 50 18 00 20 00 00 00 00
               68 65 6C 6C 6F")
        m (parse/packet->clj pkt)]
    (is (= :ethernet (:type m)))
    (is (= :ipv4 (get-in m [:l3 :type])))
    (is (= 6 (get-in m [:l3 :protocol])))
    (is (= :tcp (get-in m [:l3 :l4 :type])))
    (is (= 5 (get-in m [:l3 :l4 :data-len])))))

;; 2) IPv4/UDP + 最小DNSヘッダ（16B）
(deftest ipv4-udp-dns-min-test
  (let [pkt (tu/hex->bytes
             "FF FF FF FF FF FF 00 00 00 00 00 01 08 00
               45 00 00 30 00 02 00 00 40 11 00 00
               C0 A8 01 64 08 08 08 08
               13 88 00 35 00 18 00 00
               00 3B 01 00 00 01 00 00 00 00 00 00 00 00 00 00")
        m (parse/packet->clj pkt)]
    (is (= :ipv4 (get-in m [:l3 :type])))
    (is (= :udp  (get-in m [:l3 :l4 :type])))
    (is (= :dns  (get-in m [:l3 :l4 :app :type])))
    (is (= 59    (get-in m [:l3 :l4 :app :id])))
    (is (= 1     (get-in m [:l3 :l4 :app :qdcount])))))

;; 3) ARP request（IPv4）
(deftest arp-request-test
  (let [pkt (tu/hex->bytes
             "FF FF FF FF FF FF 00 11 22 33 44 55 08 06
               00 01 08 00 06 04 00 01
               00 11 22 33 44 55 C0 A8 01 64
               66 77 88 99 AA BB C0 A8 01 01")
        m (parse/packet->clj pkt)]
    (is (= :arp (get-in m [:l3 :type])))
    (is (= :request (get-in m [:l3 :op])))
    (is (= "192.168.1.100" (get-in m [:l3 :spa])))
    (is (= "192.168.1.1"   (get-in m [:l3 :tpa])))))

;; 4) IPv6/UDP（payload=4B）
(deftest ipv6-udp-min-test
  (let [pkt (tu/hex->bytes
             "00 11 22 33 44 55 66 77 88 99 AA BB 86 DD
               60 00 00 00 00 0C 11 40
               20 01 0D B8 00 00 00 00 00 00 00 00 00 00 00 01
               20 01 0D B8 00 00 00 00 00 00 00 00 00 00 00 02
               12 34 56 78 00 0C 00 00
               DE AD BE EF")
        m (parse/packet->clj pkt)]
    (is (= :ipv6 (get-in m [:l3 :type])))
    (is (= :udp  (get-in m [:l3 :l4 :type])))
    (is (= 4     (get-in m [:l3 :l4 :data-len])))))

;; 5) IPv6 Hop-by-Hop → UDP へ到達できるか（PL=24, HBH=16, UDP=8）
(deftest ipv6-hbh-udp-test
  (let [pkt (tu/hex->bytes
             "00 11 22 33 44 55 66 77 88 99 AA BB 86 DD
               60 00 00 00 00 18 00 40
               20 01 0D B8 00 00 00 00 00 00 00 00 00 00 00 01
               20 01 0D B8 00 00 00 00 00 00 00 00 00 00 00 02
               11 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00
               12 34 56 78 00 08 00 00")
        m (parse/packet->clj pkt)]
    (is (= :ipv6 (get-in m [:l3 :type])))
    (is (= :udp  (get-in m [:l3 :l4 :type])))))

;; 6) IPv6 Fragment (offset>0) は L4を解さず :ipv6-fragment で返す
(deftest ipv6-frag-nonfirst-test
  (let [pkt (tu/hex->bytes
             "00 11 22 33 44 55 66 77 88 99 AA BB 86 DD
               60 00 00 00 00 08 2C 40
               20 01 0D B8 00 00 00 00 00 00 00 00 00 00 00 01
               20 01 0D B8 00 00 00 00 00 00 00 00 00 00 00 02
               06 00 00 08 12 34 56 78")
        m (parse/packet->clj pkt)]
    (is (= :ipv6 (get-in m [:l3 :type])))
    (is (= true  (get-in m [:l3 :frag?])))
    (is (= :ipv6-fragment (get-in m [:l3 :l4 :type])))))

;; HBH: PadN(12B)でオプション領域14Bを“ちょうど”埋めてUDPに到達
(deftest ipv6-hbh-udp-padn-exact-test
  (let [pkt (tu/hex->bytes
             "00 11 22 33 44 55 66 77 88 99 AA BB 86 DD
               60 00 00 00 00 18 00 40
               20 01 0D B8 00 00 00 00 00 00 00 00 00 00 00 01
               20 01 0D B8 00 00 00 00 00 00 00 00 00 00 00 02
               11 01 01 0C
               00 00 00 00 00 00 00 00 00 00 00 00
               12 34 56 78 00 08 00 00")
        m (parse/packet->clj pkt)]
    (is (= :udp (get-in m [:l3 :l4 :type])))))

;; HBH: TLV過走（lenが残りを超える）→ 安全に上位へ進まず unknown-l4
(deftest ipv6-hbh-bad-tlv-overrun-test
  (let [pkt (tu/hex->bytes
             "00 11 22 33 44 55 66 77 88 99 AA BB 86 DD
               60 00 00 00 00 18 00 40
               20 01 0D B8 00 00 00 00 00 00 00 00 00 00 00 01
               20 01 0D B8 00 00 00 00 00 00 00 00 00 00 00 02
               11 01 01 0D
               00 00 00 00 00 00 00 00 00 00 00 00
               12 34 56 78 00 08 00 00")
        m (parse/packet->clj pkt)]
    (is (= :unknown-l4 (get-in m [:l3 :l4 :type])))))

;; DestOpt: PadN(12B)でオプション領域14Bを“ちょうど”埋め、UDPに到達
(deftest ipv6-destopt-udp-padn-exact-test
  (let [pkt (tu/hex->bytes
             "00 11 22 33 44 55 66 77 88 99 AA BB 86 DD
               60 00 00 00 00 18 3C 40
               20 01 0D B8 00 00 00 00 00 00 00 00 00 00 00 01
               20 01 0D B8 00 00 00 00 00 00 00 00 00 00 00 02
               11 01 01 0C
               00 00 00 00 00 00 00 00 00 00 00 00
               12 34 56 78 00 08 00 00")
        m (parse/packet->clj pkt)]
    (is (= :udp (get-in m [:l3 :l4 :type])))))

;; DestOpt: TLV過走（lenが残りを超える）→ 安全に上位へ進まず unknown-l4
(deftest ipv6-destopt-bad-tlv-overrun-test
  (let [pkt (tu/hex->bytes
             "00 11 22 33 44 55 66 77 88 99 AA BB 86 DD
               60 00 00 00 00 18 3C 40
               20 01 0D B8 00 00 00 00 00 00 00 00 00 00 00 01
               20 01 0D B8 00 00 00 00 00 00 00 00 00 00 00 02
               11 01 01 0D
               00 00 00 00 00 00 00 00 00 00 00 00
               12 34 56 78 00 08 00 00")
        m (parse/packet->clj pkt)]
    (is (= :unknown-l4 (get-in m [:l3 :l4 :type])))))

;; 先頭フラグメント(offset=0, M=1) + UDP(8B) → L4は正しくUDPに到達しつつ fragフラグは立つ
(deftest ipv6-frag-first-udp-test
  (let [pkt (tu/hex->bytes
             "00 11 22 33 44 55 66 77 88 99 AA BB 86 DD
               60 00 00 00 00 10 2C 40
               20 01 0D B8 00 00 00 00 00 00 00 00 00 00 00 01
               20 01 0D B8 00 00 00 00 00 00 00 00 00 00 00 02
               11 00 00 01 12 34 56 78       ; Fragment: NH=UDP(17), res=0, offfl=(offset=0,M=1)->0x0001
               12 34 56 78 00 08 00 00")     ; UDP: src=0x1234, dst=0x5678, len=8, csum=0
        m (parse/packet->clj pkt)]
    (is (= :ipv6 (get-in m [:l3 :type])))
    (is (= true  (get-in m [:l3 :frag?])))
    (is (= 0     (get-in m [:l3 :frag-offset])))
    (is (= :udp  (get-in m [:l3 :l4 :type])))))

;; フラグメントヘッダが8B未満で途切れ → 上位に進まず :unknown-l4
(deftest ipv6-frag-header-truncated-test
  (let [pkt (tu/hex->bytes
             "00 11 22 33 44 55 66 77 88 99 AA BB 86 DD
               60 00 00 00 00 07 2C 40
               20 01 0D B8 00 00 00 00 00 00 00 00 00 00 00 01
               20 01 0D B8 00 00 00 00 00 00 00 00 00 00 00 02
               11 00 00 00 00 00 00")          ; ← Fragmentヘッダを7Bで途切らせる
        m (parse/packet->clj pkt)]
    (is (= :ipv6 (get-in m [:l3 :type])))
    (is (= :unknown-l4 (get-in m [:l3 :l4 :type])))))

;; DNS flags: Query (QR=0, RD=1)
(deftest ipv4-udp-dns-flags-query-test
  (let [pkt (tu/hex->bytes
             "FF FF FF FF FF FF 00 00 00 00 00 01 08 00
               45 00 00 30 00 02 00 00 40 11 00 00
               C0 A8 01 64 08 08 08 08
               13 88 00 35 00 18 00 00
               00 3B 01 00 00 01 00 00 00 00 00 00 00 00 00 00")
        m (parse/packet->clj pkt)
        flags (get-in m [:l3 :l4 :app :flags])]
    (is (= :dns  (get-in m [:l3 :l4 :app :type])))
    (is (= false (:qr flags)))
    (is (= 0     (:opcode flags)))
    (is (= true  (:rd flags)))
    (is (= false (:ra flags)))
    (is (= 0     (:rcode flags)))))

;; DNS flags: Response NXDOMAIN (QR=1, RD=1, RA=1, RCODE=3)
(deftest ipv4-udp-dns-flags-response-nxdomain-test
  (let [pkt (tu/hex->bytes
             "FF FF FF FF FF FF 00 00 00 00 00 01 08 00
               45 00 00 30 00 02 00 00 40 11 00 00
               C0 A8 01 64 08 08 08 08
               13 88 00 35 00 18 00 00
               00 2A 81 83 00 01 00 00 00 00 00 00 00 00 00 00")
        m (parse/packet->clj pkt)
        flags (get-in m [:l3 :l4 :app :flags])]
    (is (= :dns  (get-in m [:l3 :l4 :app :type])))
    (is (= true  (:qr flags)))
    (is (= 0     (:opcode flags)))
    (is (= true  (:rd flags)))
    (is (= true  (:ra flags)))
    (is (= 3     (:rcode flags)))))

;; IPv6/UDP で flow-key が :udp とポートを含む
(deftest ipv6-udp-flow-key-test
  (let [pkt (tu/hex->bytes
             "00 11 22 33 44 55 66 77 88 99 AA BB 86 DD
               60 00 00 00 00 0C 11 40
               20 01 0D B8 00 00 00 00 00 00 00 00 00 00 00 01
               20 01 0D B8 00 00 00 00 00 00 00 00 00 00 00 02
               12 34 56 78 00 0C 00 00
               DE AD BE EF")
        m (parse/packet->clj pkt)
        fk (get-in m [:l3 :flow-key])]
    (is (= :udp (:proto fk)))
    (is (= "2001:db8:0:0:0:0:0:1" (:src-ip fk)))
    (is (= "2001:db8:0:0:0:0:0:2" (:dst-ip fk)))
    (is (= 4660 (:src-port fk)))
    (is (= 22136 (:dst-port fk)))))

;; 非先頭フラグメント（L4ヘッダ無し）でも proto は載る（ここでは TCP）
(deftest ipv6-frag-nonfirst-flow-key-test
  (let [pkt (tu/hex->bytes
             "00 11 22 33 44 55 66 77 88 99 AA BB 86 DD
               60 00 00 00 00 08 2C 40
               20 01 0D B8 00 00 00 00 00 00 00 00 00 00 00 01
               20 01 0D B8 00 00 00 00 00 00 00 00 00 00 00 02
               06 00 00 08 12 34 56 78")
        m (parse/packet->clj pkt)
        fk (get-in m [:l3 :flow-key])]
    (is (= :tcp (:proto fk)))
    (is (= "2001:db8:0:0:0:0:0:1" (:src-ip fk)))
    (is (= "2001:db8:0:0:0:0:0:2" (:dst-ip fk)))
    ;; ポートは無い（nil）ことを確認
    (is (nil? (:src-port fk)))
    (is (nil? (:dst-port fk)))))

;; IPv6 圧縮表記（ゼロ連続を :: に）
(deftest ipv6-addr-compact-basic-test
  (let [pkt (tu/hex->bytes
             "00 11 22 33 44 55 66 77 88 99 AA BB 86 DD
               60 00 00 00 00 0C 11 40
               20 01 0D B8 00 00 00 00 00 00 00 00 00 00 00 01
               20 01 0D B8 00 00 00 00 00 00 00 00 00 00 00 02
               12 34 56 78 00 0C 00 00
               DE AD BE EF")
        m (parse/packet->clj pkt)]
    ;; 既存の非圧縮は維持
    (is (= "2001:db8:0:0:0:0:0:1" (get-in m [:l3 :src])))
    (is (= "2001:db8:0:0:0:0:0:2" (get-in m [:l3 :dst])))
    ;; 新フィールドは圧縮
    (is (= "2001:db8::1" (get-in m [:l3 :src-compact])))
    (is (= "2001:db8::2" (get-in m [:l3 :dst-compact])))))

;; 全ゼロは :: になる
(deftest ipv6-addr-compact-all-zero-test
  (let [pkt (tu/hex->bytes
             "00 11 22 33 44 55 66 77 88 99 AA BB 86 DD
               60 00 00 00 00 08 11 40
               00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
               00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
               12 34 56 78 00 08 00 00")
        m (parse/packet->clj pkt)]
    (is (= "::" (get-in m [:l3 :src-compact])))
    (is (= "::" (get-in m [:l3 :dst-compact])))))

;; 802.1Q (0x8100) 単一タグ → IPv4 に到達し、:vlan-tags を付与
(deftest ipv4-udp-vlan-single-test
  (let [pkt (tu/hex->bytes
             "FF FF FF FF FF FF 00 00 00 00 00 01 81 00 00 64 08 00
               45 00 00 30 00 02 00 00 40 11 00 00
               C0 A8 01 64 08 08 08 08
               13 88 00 35 00 18 00 00
               00 3B 01 00 00 01 00 00 00 00 00 00 00 00 00 00")
        m (parse/packet->clj pkt)
        tag (first (:vlan-tags m))]
    (is (= :ipv4 (get-in m [:l3 :type])))
    (is (= 0x8100 (:tpid tag)))
    (is (= 100   (:vid tag)))
    (is (= 0     (:pcp tag)))
    (is (= false (:dei tag)))
    (is (= :dns  (get-in m [:l3 :l4 :app :type])))))

;; QinQ: 802.1ad(0x88A8, VID=200) の下に 802.1Q(0x8100, VID=100) → IPv6/UDP 到達
(deftest ipv6-udp-vlan-qinq-test
  (let [pkt (tu/hex->bytes
             "00 11 22 33 44 55 66 77 88 99 AA BB 88 A8 00 C8 81 00 00 64 86 DD
               60 00 00 00 00 0C 11 40
               20 01 0D B8 00 00 00 00 00 00 00 00 00 00 00 01
               20 01 0D B8 00 00 00 00 00 00 00 00 00 00 00 02
               12 34 56 78 00 0C 00 00
               DE AD BE EF")
        m (parse/packet->clj pkt)
        tags (:vlan-tags m)]
    (is (= :ipv6 (get-in m [:l3 :type])))
    (is (= 2 (count tags)))
    (is (= 0x88A8 (:tpid (first tags))))
    (is (= 200   (:vid  (first tags))))
    (is (= 0x8100 (:tpid (second tags))))
    (is (= 100    (:vid  (second tags))))
    (is (= :udp (get-in m [:l3 :l4 :type])))
    (is (= 4     (get-in m [:l3 :l4 :data-len])))))

;; TCP flags の短縮表記: 既存のIPv4/TCP最小テストは ACK+PSH（0x18） → "AP"
(deftest ipv4-tcp-flags-ap-test
  (let [pkt (tu/hex->bytes
             "00 11 22 33 44 55 66 77 88 99 AA BB 08 00
               45 00 00 28 00 01 40 00 40 06 00 00
               0A 00 00 01 0A 00 00 02
               30 39 00 50 00 00 00 00 00 00 00 00 50 18 00 20 00 00 00 00")
        m (parse/packet->clj pkt)]
    (is (= :tcp (get-in m [:l3 :l4 :type])))
    (is (= "AP" (get-in m [:l3 :l4 :flags-str])))))

;; TCP flags: SYNのみ（0x02）→ "S"
(deftest ipv4-tcp-flags-syn-test
  (let [pkt (tu/hex->bytes
             "00 11 22 33 44 55 66 77 88 99 AA BB 08 00
               45 00 00 28 00 01 40 00 40 06 00 00
               0A 00 00 01 0A 00 00 02
               30 39 00 50 00 00 00 00 00 00 00 00 50 02 00 20 00 00 00 00")
        m (parse/packet->clj pkt)]
    (is (= :tcp (get-in m [:l3 :l4 :type])))
    (is (= "S" (get-in m [:l3 :l4 :flags-str])))))

;; ICMPv4 Echo Request → type-name/summary を確認
(deftest ipv4-icmp-echo-request-flags-test
  (let [pkt (tu/hex->bytes
             "FF FF FF FF FF FF 00 11 22 33 44 55 08 00
               45 00 00 1C 00 01 00 00 40 01 00 00
               0A 00 00 01 0A 00 00 02
               08 00 00 00 00 00 00 00")
        m (parse/packet->clj pkt)
        l4 (get-in m [:l3 :l4])]
    (is (= :icmpv4 (:type l4)))
    (is (= "echo-request" (:type-name l4)))
    (is (= "echo-request" (:summary l4)))))

;; ICMPv6 Time Exceeded (code=0=hop-limit-exceeded) → type/code-name/summary を確認
(deftest ipv6-icmp6-time-exceeded-test
  (let [pkt (tu/hex->bytes
             "00 11 22 33 44 55 66 77 88 99 AA BB 86 DD
               60 00 00 00 00 08 3A 40
               20 01 0D B8 00 00 00 00 00 00 00 00 00 00 00 01
               20 01 0D B8 00 00 00 00 00 00 00 00 00 00 00 02
               03 00 00 00 00 00 00 00")
        m (parse/packet->clj pkt)
        l4 (get-in m [:l3 :l4])]
    (is (= :icmpv6 (:type l4)))
    (is (= "time-exceeded" (:type-name l4)))
    (is (= "hop-limit-exceeded" (:code-name l4)))
    (is (= "time-exceeded/hop-limit-exceeded" (:summary l4)))))

;; IPv4 先頭フラグメント（offset=0, MF=1）でも L4(UDP) に到達できる
(deftest ipv4-frag-first-udp-test
  (let [pkt (tu/hex->bytes
             "00 11 22 33 44 55 66 77 88 99 AA BB 08 00
               45 00 00 1C 00 01 20 00 40 11 00 00        ; ver/ihl, tos, total=28, id=1, flags+frag=0x2000(MF=1), ttl=64, proto=17(UDP)
               0A 00 00 01 0A 00 00 02                    ; src=10.0.0.1 dst=10.0.0.2
               12 34 00 35 00 08 00 00")                  ; UDP: 0x1234 -> 53, len=8, csum=0
        m (parse/packet->clj pkt)]
    (is (= :ipv4 (get-in m [:l3 :type])))
    (is (= true  (get-in m [:l3 :frag?])))
    (is (= 0     (get-in m [:l3 :frag-offset])))
    (is (= :udp  (get-in m [:l3 :l4 :type])))))

;; IPv4 非先頭フラグメント（offset>0）は L4を解かず :ipv4-fragment で返す
(deftest ipv4-frag-nonfirst-test
  (let [pkt (tu/hex->bytes
             "00 11 22 33 44 55 66 77 88 99 AA BB 08 00
               45 00 00 18 00 02 00 01 40 11 00 00        ; total=24, id=2, flags+frag=0x0001(offset=1*8B), proto=UDP
               0A 00 00 01 0A 00 00 02
               DE AD BE EF")                               ; 4Bだけ適当に
        m (parse/packet->clj pkt)]
    (is (= :ipv4 (get-in m [:l3 :type])))
    (is (= true  (get-in m [:l3 :frag?])))
    (is (= 1     (get-in m [:l3 :frag-offset])))
    (is (= :ipv4-fragment (get-in m [:l3 :l4 :type])))))

;; DNS フラグ（クエリ）: QR=0, RD=1（0x0100）
(deftest ipv4-udp-dns-flags-query-test
  (let [pkt (tu/hex->bytes
             "FF FF FF FF FF FF 00 00 00 00 00 01 08 00
               45 00 00 28 00 02 00 00 40 11 00 00
               C0 A8 01 64 08 08 08 08
               13 88 00 35 00 14 00 00
               00 3B 01 00 00 01 00 00 00 00 00 00")
        m (parse/packet->clj pkt)
        app (get-in m [:l3 :l4 :app])]
    (is (= :dns (:type app)))
    (is (= false (:qr? app)))
    (is (= "query" (:opcode-name app)))
    (is (= true (:rd? app)))
    (is (= false (:ra? app)))))

;; DNS フラグ（レスポンス）: QR=1, RA=1, RD=1（0x8180）
(deftest ipv4-udp-dns-flags-response-test
  (let [pkt (tu/hex->bytes
             "FF FF FF FF FF FF 00 00 00 00 00 01 08 00
               45 00 00 28 00 03 00 00 40 11 00 00
               08 08 08 08 C0 A8 01 64
               00 35 13 88 00 14 00 00
               00 3B 81 80 00 01 00 00 00 00 00 00")
        m (parse/packet->clj pkt)
        app (get-in m [:l3 :l4 :app])]
    (is (= :dns (:type app)))
    (is (= true (:qr? app)))
    (is (= "query" (:opcode-name app)))
    (is (= "noerror" (:rcode-name app)))
    (is (= true (:ra? app)))))
```

### test/paclo/core_test.clj
```clojure
(ns paclo.core-test
  (:require
   [clojure.test :refer :all]
   [paclo.core :as sut])
  (:import
   [java.io File]))

(deftest pcap-roundtrip
  (let [f    (File/createTempFile "paclo" ".pcap")
        path (.getAbsolutePath f)
        ;; 60Bのダミーフレーム（Ethernet最小相当）
        ba1  (byte-array (repeat 60 (byte 0)))
        ba2  (byte-array (repeat 60 (byte -1)))]
    (sut/write-pcap! [ba1 {:bytes ba2 :sec 1700000000 :usec 123456}] path)
    ;; デコードなし: 2件読めること
    (let [xs (vec (sut/packets {:path path}))]
      (is (= 2 (count xs)))
      (is (every? #(contains? % :bytes) xs)))
    ;; デコードあり: 例外を出さず、:decoded か :decode-error のどちらかが付くこと
    (let [xs (vec (sut/packets {:path path :decode? true}))]
      (is (= 2 (count xs)))
      (is (every? #(or (contains? % :decoded)
                       (contains? % :decode-error)) xs)))))

(deftest bpf-dsl
  (is (= "(udp) and (port 53)"
         (sut/bpf [:and [:udp] [:port 53]])))
  (is (= "not (host 8.8.8.8)"
         (sut/bpf [:not [:host "8.8.8.8"]])))
  (is (= "tcp" (sut/bpf :tcp))))

(deftest packets-xform-filters-and-maps
  (let [pcap "target/xform-test.pcap"]
    ;; 3パケット: 60B / 42B / 60B
    (sut/write-pcap! [(byte-array (repeat 60 (byte 0)))
                      (byte-array (repeat 42 (byte 0)))
                      (byte-array (repeat 60 (byte 0)))]
                     pcap)
    (let [xs (sut/packets {:path pcap
                           :decode? false
                           :xform (comp
                                   (filter #(>= (:caplen %) 60))
                                   (map :caplen))})]
      (is (= [60 60] (into [] xs))))))

(deftest bpf-dsl-extended
  ;; :proto + :ipv6 / :ip
  (is (= "ip6" (sut/bpf [:proto :ipv6])))
  (is (= "ip"  (sut/bpf [:proto :ip])))
  (is (= "ip6" (sut/bpf :ip6)))
  (is (= "ip"  (sut/bpf :ipv4)))

  ;; src/dst net
  (is (= "src net 10.0.0.0/8" (sut/bpf [:src-net "10.0.0.0/8"])))
  (is (= "dst net 192.168.0.0/16" (sut/bpf [:dst-net "192.168.0.0/16"])))

  ;; portrange
  (is (= "portrange 1000-2000" (sut/bpf [:port-range 1000 2000])))
  (is (= "src portrange 53-60" (sut/bpf [:src-port-range 53 60])))
  (is (= "dst portrange 8080-8088" (sut/bpf [:dst-port-range 8080 8088])))

  ;; 論理と併用
  (is (= "(ip6) and (udp) and (dst portrange 8000-9000)"
         (sut/bpf [:and [:ipv6] [:udp] [:dst-port-range 8000 9000]])))

  ;; not と組み合わせ（ユーザ要望例）
  (is (= "(net 10.0.0.0/8) and (not (port 22))"
         (sut/bpf [:and [:net "10.0.0.0/8"] [:not [:port 22]]]))))

(deftest packets-xform-filters-and-maps
  (let [pcap (-> (java.io.File/createTempFile "paclo-xf" ".pcap")
                 .getAbsolutePath)]
    ;; 3パケット: 60B / 42B / 60B
    (sut/write-pcap! [(byte-array (repeat 60 (byte 0)))
                      (byte-array (repeat 42 (byte 0)))
                      (byte-array (repeat 60 (byte 0)))]
                     pcap)
    (let [xs (sut/packets {:path pcap
                           :decode? false
                           :xform (comp
                                   (filter #(>= (:caplen %) 60))
                                   (map :caplen))})]
      (is (= [60 60] (into [] xs))))))

(deftest bpf-dsl-error-cases
  ;; フォーム型が不正
  (is (thrown-with-msg? clojure.lang.ExceptionInfo #"unsupported bpf form"
                        (sut/bpf 123)))
  ;; 未知のトップレベルキーワード（実装により "unknown keyword" or "unknown proto keyword"） 
  (is (thrown-with-msg? clojure.lang.ExceptionInfo #"unknown (proto )?keyword"
                        (sut/bpf :foo)))
  ;; 未知の演算子
  (is (thrown-with-msg? clojure.lang.ExceptionInfo #"unknown op"
                        (sut/bpf [:huh 1 2 3]))))
```

### test/paclo/list_devices_test.clj
```clojure
(ns paclo.list-devices-test
  (:require
   [clojure.test :refer :all]
   [paclo.core :as sut]))

(deftest list-devices-basic-shape
  ;; 実環境に依存しない緩めの検証：
  ;; - 例外を投げないこと
  ;; - ベクタであること
  ;; - 各要素は {:name string, :desc (string|nil)} の形
  (let [xs (sut/list-devices)]
    (is (vector? xs))
    (doseq [m xs]
      (is (map? m))
      (is (contains? m :name))
      (is (string? (:name m)))
      (is (not (re-find #"^\s*$" (:name m))))
      (is (contains? m :desc))
      (when-let [d (:desc m)]
        (is (string? d))))))
```

### test/paclo/golden_test.clj
```clojure
(ns paclo.golden-test
  (:require
   [clojure.test :refer :all]
   [paclo.core :as core]
   [paclo.test-util :as tu]))

(deftest golden-roundtrip-and-decode
  (let [tmp  (-> (java.io.File/createTempFile "paclo-gold" ".pcap")
                 .getAbsolutePath)
        ;; 1) 生のイーサ最小相当（60B）
        ether60 (byte-array (repeat 60 (byte 0)))
        ;; 2) IPv4/UDP/DNS(最小) サンプル（parse_test に合わせた最小ベクトル）
        ipv4-udp-dns
        (tu/hex->bytes
         "FF FF FF FF FF FF 00 00 00 00 00 01 08 00
          45 00 00 30 00 02 00 00 40 11 00 00
          C0 A8 01 64 08 08 08 08
          13 88 00 35 00 18 00 00
          00 3B 01 00 00 01 00 00 00 00 00 00 00 00 00 00")
        ;; 3) IPv6/UDP(4B) 最小
        ipv6-udp-min
        (tu/hex->bytes
         "00 11 22 33 44 55 66 77 88 99 AA BB 86 DD
          60 00 00 00 00 0C 11 40
          20 01 0D B8 00 00 00 00 00 00 00 00 00 00 00 01
          20 01 0D B8 00 00 00 00 00 00 00 00 00 00 00 02
          12 34 56 78 00 0C 00 00
          DE AD BE EF")]
    ;; 書く → 読む
    (core/write-pcap! [ether60 ipv4-udp-dns ipv6-udp-min] tmp)

    (testing "decode? false (素通し)"
      (let [xs (vec (core/packets {:path tmp}))]
        (is (= 3 (count xs)))
        (is (every? #(contains? % :bytes) xs))))

    (testing "decode? true（例外を投げず :decoded or :decode-error を付ける）"
      (let [xs (vec (core/packets {:path tmp :decode? true}))]
        (is (= 3 (count xs)))
        (is (every? #(or (contains? % :decoded)
                         (contains? % :decode-error)) xs))
        ;; 2つ目: IPv4/UDP/DNS が取れていること
        (let [m (nth xs 1)]
          (is (= :ipv4 (get-in m [:decoded :l3 :type])))
          (is (= :udp  (get-in m [:decoded :l3 :l4 :type])))
          (is (= :dns  (get-in m [:decoded :l3 :l4 :app :type]))))
        ;; 3つ目: IPv6/UDP 最小
        (let [m (nth xs 2)]
          (is (= :ipv6 (get-in m [:decoded :l3 :type])))
          (is (= :udp  (get-in m [:decoded :l3 :l4 :type])))
          (is (= 4     (get-in m [:decoded :l3 :l4 :data-len]))))))))
```

### test/paclo/test_util.clj
```clojure
(ns paclo.test-util
  (:require
   [clojure.string :as str]))

(defn hex->bytes ^bytes [^String s]
  (let [no-line-comments (str/replace s #"(?m);.*$" "")     ;; 行内 ;コメントを削除
        no-block-comments (str/replace no-line-comments #"(?s)/\*.*?\*/" "") ;; /* ... */ も一応対応
        cleaned (-> no-block-comments
                    str/lower-case
                    (str/replace #"[^0-9a-f]" ""))]         ;; 16進以外は全部削除
    (when (odd? (count cleaned))
      (throw (ex-info "Odd number of hex digits" {:len (count cleaned)})))
    (byte-array
     (map (fn [[a b]]
            (unchecked-byte (Integer/parseInt (str a b) 16)))
          (partition 2 cleaned)))))
```

### .clj-kondo/config.edn
```edn
{:lint-as
 {paclo.pcap/with-pcap     clojure.core/let
  paclo.pcap/with-dumper   clojure.core/let
  paclo.pcap/with-live     clojure.core/let
  paclo.pcap/with-offline  clojure.core/let}}
```

### .github/workflows/ci.yml
```yaml
name: CI

on:
  push:
    branches: [ main, master ]
  pull_request:
    branches: [ main, master ]

concurrency:
  group: ${{ github.workflow }}-${{ github.ref }}
  cancel-in-progress: true

permissions:
  contents: read

jobs:
  build:
    runs-on: ubuntu-latest

    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Set up Temurin JDK
        uses: actions/setup-java@v4
        with:
          distribution: temurin
          java-version: '21'

      # --- Install Clojure CLI via official script (robust) ---
      - name: Install Clojure CLI
        shell: bash
        run: |
          set -e
          curl -sSL -o clj.sh https://download.clojure.org/install/linux-install-1.11.1.1435.sh
          chmod +x clj.sh
          sudo ./clj.sh
          clojure -Sdescribe

      - name: Cache Clojure deps
        uses: actions/cache@v4
        with:
          path: |
            ~/.m2
            ~/.gitlibs
            ~/.clojure
          key: cljdeps-${{ runner.os }}-${{ hashFiles('**/deps.edn') }}
          restore-keys: |
            cljdeps-${{ runner.os }}-

      # --- Install clj-kondo & cljfmt binaries with auth to avoid 403 ---
      - name: Set up Clojure tooling (clj-kondo, cljfmt)
        uses: DeLaGuardo/setup-clojure@13.0
        with:
          clj-kondo: '2024.05.24'
          cljfmt: '0.13.0'
          github-token: ${{ secrets.GITHUB_TOKEN }}

      - name: Compile Java (jnr-ffi bindings)
        shell: bash
        run: |
          set -e
          # Prefer tools.build; fallback to direct javac with deps classpath
          clojure -T:build jar || \
          (mkdir -p target/classes && javac -cp "$(clojure -Spath)" -d target/classes $(find src-java -name "*.java"))

      - name: Run unit tests
        run: clojure -M:test

      # --- Format check with cljfmt binary; fallback to no-op if missing ---
      - name: Lint / Format (cljfmt)
        shell: bash
        run: |
          set -e
          if command -v cljfmt >/dev/null 2>&1; then
            cljfmt check
          else
            echo "cljfmt not found; skipping format check (will be enforced locally & in pre-commit)"
          fi
```

## 整形運用ポリシー（2025-08 更新）

**現在の方針: 保存時整形 OFF + CLI 一本化**

- VS Code 保存時整形: 無効化  
- 整形は必ずコミット前に CLI (`script/fmt.sh`) で実施  
- CI (`clojure-lsp format --dry`) と完全一致  

理由: Calva 保存時整形で `dns-min` などが崩れるため。  
CLI 実行時は問題なし → 保存時整形を切り、CLI に統一。  

将来保存時整形を復活させたい場合は、Calva整形ではなく  
**VS Code → clojure-lsp (LSP フォーマット)** への切替を推奨。

### .vscode/settings.json
```json
{
  "[clojure]": {
    "editor.defaultFormatter": "betterthantomorrow.calva"
  },
  "calva.fmt.configPath": "CLOJURE-LSP",
  "calva.formatOnSave": false,
  "editor.formatOnSave": false,
  "editor.formatOnSaveMode": "modificationsIfAvailable",
  "editor.formatOnType": false
}
```

### .lsp/config.edn
```edn
{:project-specs
 [{:project-path "deps.edn"
   :classpath-cmd ["clojure" "-Spath"]}]

 :source-paths ["src" "src-java" "test" "dev"]
 
 :cljfmt
 {:remove-trailing-whitespace? true
  :remove-consecutive-blank-lines? true
  :insert-missing-whitespace? true
  :remove-multiple-non-indenting-spaces? false
  :extra-indents {deftest [[:block 1]]
                  testing [[:block 1]]
                  is      [[:block 1]]}}}
```

### .editorconfig
```
root = true
[*]
charset = utf-8
end_of_line = lf
insert_final_newline = true
trim_trailing_whitespace = true
indent_style = space
indent_size = 2
```

## Environment snapshot

```
git commit: bbd8a84ac9d8
branch: main
java: openjdk version "21.0.8" 2025-07-15 LTS
clojure: 1.12.1
clojure-lsp: clojure-lsp 2025.08.15-17.11.38
clj-kondo 2025.07.28
clj-kondo: clj-kondo v2025.07.28
os: Darwin Nantos-Mac-mini.local 24.4.0 Darwin Kernel Version 24.4.0: Fri Apr 11 18:28:23 PDT 2025; root:xnu-11417.101.15~117/RELEASE_X86_64 x86_64
```

## Developer bootstrap (git hooks)

このリポジトリでは共有フックを使用します。クローンしたら一度だけ以下を実行してください。

```bash
git config core.hooksPath .githooks
```

