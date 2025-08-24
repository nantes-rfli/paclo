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
