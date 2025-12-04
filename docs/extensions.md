# Decode extensions (post-decode hooks)

`paclo.decode-ext` lets you annotate or transform decoded packets **right after decode** without
breaking the base parser (`parse/packet->clj`). It is designed as an after-the-fact, pluggable hook
layer.

## How it works

- A hook is a function `m -> m'` where `m` is one packet map from `packets {:decode? true}`.
- Exceptions are swallowed inside the hook runner, so a failing hook does not affect others.
- Only map return values are applied; anything else is ignored.
- Hooks run only when `:decoded` exists (they are skipped on `:decode-error` entries).
- Hooks run in registration order; same key overwrites prior registration and moves to the tail.

### Stability notes (v0.3)

- API 互換性: hook 署名（`m -> m'`）と `register!` / `unregister!` / `installed` の挙動を v0.3 で固定。
- 適用条件: `:decoded` が存在し、かつ `:decode-error` が無いパケットのみ hook を適用（防御的ガードを追加）。
- 失敗耐性: hook 内例外は握りつぶし（ログ無し）。必要なら hook 側で明示的に処理するか、今後の opt-in ロギング（検討中）を利用。
- 非 map 戻り値: map 以外は無視される（副作用は許容）。
- 追加検討中: 一時的に hook セットを差し替えるユーティリティ `dx/with-hooks` を Phase C で検討。

```clojure
(require '[paclo.decode-ext :as dx])

(dx/register! ::my-hook
  (fn [m]
    (if (= :udp (get-in m [:decoded :l3 :l4 :type]))
      (assoc-in m [:decoded :note] "hello-udp")
      m)))

(dx/unregister! ::my-hook)
(dx/installed)  ;; => (list of keys)
```

`paclo.core/packets` calls `decode-ext/apply!` when `{:decode? true}` is set, so every decoded
packet passes through installed hooks.

## Example: DNS summary

```clojure
(require '[paclo.proto.dns-ext :as dns-ext]) ; ← リポをcloneして動かすときは :dns-ext alias を付けてください
(dns-ext/register!)
;; adds [:l3 :l4 :app :summary] to DNS packets in :decoded
```

CLI で DNS 拡張を使うときは `clojure -M:dev:dns-ext ...` のように `:dns-ext` alias を付けてください（リポ clone 時）。
ライブラリとして利用する場合は paclo の JAR に DNS 拡張も含まれるので、そのまま `paclo.proto.dns-ext` を require すれば使えます。

## Best practices

- Use namespaced keywords for hook keys (e.g. `:my.ns/hook`).
- In REPL work, avoid accidental duplicate registration; same key overwrites.
- Wrap fragile logic in `try` inside the hook if needed—framework already isolates failures, but
  explicit handling makes intent clear.

## Example: TLS ClientHello SNI annotation

Extract SNI from TLS ClientHello on a best-effort basis and annotate `:decoded`.  
Assumes a single TLS record within a single TCP segment (no stream reassembly).

```clojure
(require '[paclo.proto.tls-ext :as tls-ext])

(tls-ext/register!)
;; When a ClientHello fits in one record:
;; [:decoded :l3 :l4 :app] gets
;;   :type    => :tls
;;   :sni     => "example.com"
;;   :summary => "TLS ClientHello SNI=example.com"

;; Minimal usage: pull only SNI + summary
(into []
  (comp
    (filter #(= :tls (get-in % [:decoded :l3 :l4 :app :type])))
    (map #(select-keys (get-in % [:decoded :l3 :l4 :app]) [:sni :summary])))
  (paclo.core/packets {:path "tls-sample.pcap"
                       :filter "tcp and port 443"
                       :decode? true}))
```

CLI 例（トップNの SNI を集計）:

```bash
# Top 50 SNI over port 443 (EDN)
clojure -Srepro -M:dev -m examples.tls-sni-scan tls-sample.pcap

# With BPF, topN=10, JSONL
clojure -Srepro -M:dev -m examples.tls-sni-scan tls-sample.pcap 'tcp and port 443' 10 jsonl
```

### Notes / limitations

- ClientHello split across fragments/records is out of scope (best-effort only).
- No SNI → nothing is added.
- Hook runner is defensive: exceptions are swallowed and only map returns are applied.
