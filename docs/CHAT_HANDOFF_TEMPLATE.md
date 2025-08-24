# Paclo 引き継ぎブリーフ（テンプレート）

このテンプレを**次チャット冒頭**に貼るだけで引き継ぎ開始できます。  
AI 側（ChatGPT）は、**ここに書かれた運用ルールに必ず従って**回答します。

---

## 必読ドキュメント（RAW URL）
- AI_HANDOFF.md: https://raw.githubusercontent.com/nantes-rfli/paclo/refs/heads/main/AI_HANDOFF.md
- docs/ROADMAP.md: https://raw.githubusercontent.com/nantes-rfli/paclo/refs/heads/main/docs/ROADMAP.md
- 本テンプレ（RAW）: https://raw.githubusercontent.com/nantes-rfli/paclo/refs/heads/main/docs/CHAT_HANDOFF_TEMPLATE.md

> 回答前に必ず上記3点を参照し、要点を把握してから開始すること。

---

## 現状スナップショット
- branch: `<main or feature/...>`
- HEAD: `<shortSHA> <subject>`
- CI: `<green/red>`（直近の失敗ポイントがあれば一言）
- ローカル検証: `<OK/未実施/要確認>`

---

## 進め方の希望（恒常ルール）
- **コード提示は diff ではなく「コピペ置換」**
  - 🔁 REPLACE-FUNCTION（関数丸ごと）
  - ✏️ UPDATE-NS（ns の require のみ）
  - ➕ ADD-FILE（新規は**全文**）
- **実行コマンド（VERIFY）を必ず併記**（REPL または `clojure -M:dev -m …`）
- **コミット手順（git add/commit/push）を必ず併記**
- 表示崩れ防止のため、**関数全体**または**ファイル全体**で提示（部分差分は出さない）

---

## ファイル提示・参照ポリシー（重要／セッション基準）
- **新しいチャット（セッション）では、変更提案の前に、そのセッションでまだ見ていない対象ファイルに限り**  
  AI は必ず **「このファイルを見せて」** と明示要請すること（RAW URL 最優先。未 push の場合のみ単一ファイル添付）。
- **同一セッションで一度でも内容確認済みのファイル**については、**再依頼は不要**。  
  ただし **更新の疑い（ユーザー申告／テスト失敗／文脈差分）**があれば、**再提示（RAW or diff）**を依頼する。
- **プロジェクト丸ごと ZIP は使用しない。**

---

## 今回やること（上から順に必達）
1. `<TODO-1>`
2. `<TODO-2>`
3. `<TODO-3>`

---

## 検証に使うもの（必要なら）
- pcap: `<dns-sample.pcap / sample.pcap / 共有URL>`
- 備考: `<OS/JDK/Clojure CLI の差分など>`

---

## AI 側の回答スタイル（必ずこの順）
1) **Plan**（狙い・作業単位・影響範囲）  
2) **Code**（🔁/✏️/➕：**コピペ置換**できる形）  
3) **Verify**（実行コマンド：REPL or `clojure -M:dev -m …`）  
4) **Commit**（`git add` / `git commit -m` / `git push`）  
5) **Notes**（注意点・次の一手）

---

## 呼び出し合図（次チャット用）
- ユーザーが **「次の引き継ぎのまとめをお願いします」** と送る。  
- AI は本テンプレ（RAW）と **AI_HANDOFF.md / ROADMAP.md** を参照し、  
  **この雛形に沿った最新ブリーフ**を作成して提示する。  
- 以後、その**セッション内**で一度確認済みのファイルには再提示を求めない（更新疑い時を除く）。
