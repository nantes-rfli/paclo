# Decode Extensions (post-decode hooks)

`paclo.decode-ext` は **デコード直後**に任意の注釈・変換を差し込むためのフック機構です。  
既存の `parse/packet->clj` を壊さず、**後付け**で機能を拡張できます。

## 仕組み

- フックは `m -> m'` の関数（`m` は `packets {:decode? true}` が返す1要素のマップ）
- 例外は内部で握りつぶされ、**他のフックに影響しません**
- 返り値が `map?` のときだけ反映されます（それ以外は無視）
- `:decode-error` の要素には適用されません（`decoded` があるときのみ）

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

`paclo.core/packets` 側では、`{:decode? true}` のときに `decode-ext/apply!` を通してから値を返します。

## サンプル: DNS summary

```clojure
(require '[paclo.proto.dns-ext :as dns-ext])
(dns-ext/register!)
;; 以降、DNSパケットの :decoded に [:l3 :l4 :app :summary] が付与されます
```

## ベストプラクティス

* フック名（キー）は **名前空間付きキーワード**にする（例: `:my.ns/hook`）
* REPL 作業では **重複登録に注意**（同一キーなら上書きされます）
* 失敗しやすい処理は `try` を内部で持つ（ただし本ライブラリ側でも全体を保護）