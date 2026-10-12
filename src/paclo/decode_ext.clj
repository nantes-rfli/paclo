(ns paclo.decode-ext
  "Public post-decode hook registry.

  Hooks are applied to packet maps after decode and are intentionally isolated:
  failures in one hook do not stop packet processing.")

(def ^:private hooks
  "Registered post-decode hooks as an ordered vector of [k f].
  Order = registration order. Same key overwrites and moves to the tail."
  (atom []))

(defn register!
  "Register hook `f` under key `k`.

  `f` has shape `(fn [m] m')` where `m` is a packet map.
  Re-registering `k` overwrites the previous hook and moves it to the tail."
  [k f]
  (swap! hooks (fn [hs]
                 (conj (vec (remove #(= (first %) k) hs)) [k f])))
  k)

(defn unregister!
  "Remove a previously registered hook by key."
  [k]
  (swap! hooks (fn [hs] (vec (remove #(= (first %) k) hs))))
  nil)

(defn installed
  "Return installed hook keys in execution order."
  []
  (map first @hooks))

(defn- apply-hook [m f]
  (try
    (let [result (f m)]
      (if (map? result) result m))
    (catch Throwable _ m)))

(defn apply!
  "Apply post-decode functions to packet map `m`.

  With one argument, consult the current global hooks in registration order.
  With `extensions`, apply only those functions in their supplied order,
  including duplicates. An empty collection leaves the packet unchanged.
  Core's `:extensions` option validates its vector at pipeline construction.

  Exceptions are swallowed and non-map return values are ignored; subsequent
  functions receive the last successful map. Functions are skipped unless `m`
  contains `:decoded` and does not contain `:decode-error`."
  ([m]
   (apply! m (map second @hooks)))
  ([m extensions]
   (if (and (map? m)
            (contains? m :decoded)
            (not (contains? m :decode-error)))
     (reduce apply-hook m extensions)
     m)))
