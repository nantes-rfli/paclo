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
  echo '````bash'
  cat script/make-ai-handoff.sh
  echo '````'
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

cat <<'EOF' >> AI_HANDOFF.md

## 整形運用ポリシー（2025-08 更新）

**現在の方針: 保存時整形 OFF + CLI 一本化**

- VS Code 保存時整形: 無効化  
- 整形は必ずコミット前に CLI (`script/fmt.sh`) で実施  
- CI (`clojure-lsp format --dry`) と完全一致  

理由: Calva 保存時整形で `dns-min` などが崩れるため。  
CLI 実行時は問題なし → 保存時整形を切り、CLI に統一。  

将来保存時整形を復活させたい場合は、Calva整形ではなく  
**VS Code → clojure-lsp (LSP フォーマット)** への切替を推奨。

### 現行設定ファイル

#### .vscode/settings.json
```json
EOF
if [ -f ".vscode/settings.json" ]; then
  if command -v jq >/dev/null 2>&1; then
    jq -S . .vscode/settings.json >> AI_HANDOFF.md
  else
    cat .vscode/settings.json >> AI_HANDOFF.md
  fi
else
  echo "// (not found: .vscode/settings.json)" >> AI_HANDOFF.md
fi
echo '```' >> AI_HANDOFF.md

cat <<'EOF' >> AI_HANDOFF.md

#### .lsp/config.edn
```edn
EOF
if [ -f ".lsp/config.edn" ]; then
  cat .lsp/config.edn >> AI_HANDOFF.md
else
  echo ";; (not found: .lsp/config.edn)" >> AI_HANDOFF.md
fi
echo '```' >> AI_HANDOFF.md

cat <<'EOF' >> AI_HANDOFF.md

#### .editorconfig
```
EOF
if [ -f ".editorconfig" ]; then
  cat .editorconfig >> AI_HANDOFF.md
else
  echo "# (not found: .editorconfig)" >> AI_HANDOFF.md
fi
echo '```' >> AI_HANDOFF.md

{
  echo
  echo "## Environment snapshot ($(date -u '+%Y-%m-%d %H:%M:%S UTC'))"
  echo
  echo '```'
  echo "git commit: $(git rev-parse --short=12 HEAD 2>/dev/null || echo N/A)"
  echo "branch: $(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo N/A)"
  echo "java: $(java -version 2>&1 | head -n1)"
  echo "clojure: $(clojure -M -e '(println (clojure-version))' 2>/dev/null || echo N/A)"
  echo "clojure-lsp: $(clojure-lsp --version 2>/dev/null || echo N/A)"
  echo "clj-kondo: $(clj-kondo --version 2>/dev/null || echo N/A)"
  echo "os: $(uname -a)"
  echo '```'
} >> AI_HANDOFF.md

cat <<'EOF' >> AI_HANDOFF.md

## Developer bootstrap (git hooks)
このリポジトリでは共有フックを使用します。クローンしたら一度だけ以下を実行してください。

```bash
git config core.hooksPath .githooks
```
EOF

echo "Wrote $out"
