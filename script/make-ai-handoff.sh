#!/usr/bin/env bash
set -euo pipefail

out="AI_HANDOFF.md"
rev="$(git rev-parse --short HEAD || echo 'unknown')"
date="$(date -u '+%Y-%m-%d %H:%M:%S UTC')"

emit () {
  echo "\`\`\`$1"
  cat "$2"
  echo "\`\`\`"
  echo
}

{
  echo "# AI_HANDOFF (auto-generated)"
  echo
  echo "- commit: ${rev}"
  echo "- generated: ${date}"
  echo
  echo "## How to run"
  echo "\\\`clj -M:test\\\` / \\\`clj -T:build jar\\\`"
  echo
  echo "## Notes"
  echo "- IPv6 HBH / Destination Options の HdrExtLen は **(n+1)\\*8 バイト（総ヘッダ長）**。"
  echo "  テストベクタ作成時は NextHdr/HdrExtLen の 2 バイトを除いた *オプション領域長* が (総長-2) に厳密一致するように Pad1/PadN で調整すること。"
  echo "- Ethernet VLAN (802.1Q/802.1ad) を自動ではぎ、最終 Ethertype で L3 を解釈します。"
  echo "  VLAN 情報はトップレベルの \`:vlan-tags\` ベクタ（\`{:tpid :pcp :dei :vid}\`）に入ります。"
  echo "- capture->seq は **:stop?**（任意条件で即停止）と **:error-mode**（:throw|:pass）のオプションがあります。"
  echo
  echo "## Samples"
  echo "\`\`\`clojure"
  echo ";; 任意条件で停止（UDP/53 のパケットを見つけたら止める）"
  echo "(require '[paclo.pcap :as p] '[paclo.parse :as parse])"
  echo "(def s (p/capture->seq {:device \"en0\" :filter \"udp port 53\""
  echo "                        :timeout-ms 50 :idle-max-ms 10000 :max-time-ms 15000"
  echo "                        :stop? (fn [pkt]"
  echo "                                 (let [m (parse/packet->clj (:bytes pkt))"
  echo "                                       l4 (:l4 (:l3 m))]"
  echo "                                   (and (= :udp (:type l4))"
  echo "                                        (or (= 53 (:src-port l4)) (= 53 (:dst-port l4))))))})))"
  echo "(take 1 s)"
  echo
  echo ";; 背景例外をスキップして継続（ログは :on-error で通知）"
  echo "(def s2 (p/capture->seq {:device \"en0\" :filter \"udp and and\"  ; わざと不正"
  echo "                         :timeout-ms 50 :error-mode :pass"
  echo "                         :on-error (fn [ex] (println \"BG error:\" (.getMessage ex)))}))"
  echo "(take 5 s2)"
  echo "\`\`\`"
  echo
  echo "\`\`\`clojure"
  echo ";; ICMPv6 Time Exceeded（hex→parse→要約）。:type-name/:code-name/:summary が付与されます。"
  echo "(require '[paclo.dev :as d])"
  echo "(-> \"00 11 22 33 44 55 66 77 88 99 AA BB 86 DD"
  echo "     60 00 00 00 00 08 3A 40"
  echo "     20 01 0D B8 00 00 00 00 00 00 00 00 00 00 00 01"
  echo "     20 01 0D B8 00 00 00 00 00 00 00 00 00 00 00 02"
  echo "     03 00 00 00 00 00 00 00\""
  echo "    d/parse-hex d/summarize)"
  echo
  echo ";; VLAN (802.1Q, VID=100) の例。:vlan-tags に [ {:tpid 0x8100 :pcp 0 :dei false :vid 100} ] が入ります。"
  echo "(-> \"FF FF FF FF FF FF 00 00 00 00 00 01 81 00 00 64 08 00"
  echo "     45 00 00 30 00 02 00 00 40 11 00 00"
  echo "     C0 A8 01 64 08 08 08 08"
  echo "     13 88 00 35 00 18 00 00"
  echo "     00 3B 01 00 00 01 00 00 00 00 00 00 00 00 00 00\""
  echo "    d/parse-hex d/summarize)"
  echo "\`\`\`"
  echo
  echo "## Files"
  echo "### script/make-ai-handoff.sh"
  emit bash script/make-ai-handoff.sh
  echo "### src/paclo/parse.clj"
  emit clojure src/paclo/parse.clj
  echo "### src/paclo/pcap.clj"
  emit clojure src/paclo/pcap.clj
  echo "### src/paclo/dev.clj"
  emit clojure src/paclo/dev.clj
  echo "### src-java/paclo/jnr/PcapLibrary.java"
  emit java src-java/paclo/jnr/PcapLibrary.java
  echo "### test/paclo/parse_test.clj"
  emit clojure test/paclo/parse_test.clj
  echo "### test/paclo/test_util.clj"
  emit clojure test/paclo/test_util.clj
} > "$out"

echo "Wrote $out"
