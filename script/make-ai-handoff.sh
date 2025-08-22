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
  echo "- IPv6 HBH / Destination Options の HdrExtLen は **(n+1)\*8 バイト（総ヘッダ長）**。"
  echo "  テストベクタ作成時は NextHdr/HdrExtLen の 2 バイトを除いた *オプション領域長* が (総長-2) に厳密一致するように Pad1/PadN で調整すること。"
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
