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

(defn apply!
  "Apply all hooks to packet map `m`.

  Hooks run in registration order.
  Exceptions are swallowed and non-map return values are ignored.
  Hooks are skipped unless `m` contains `:decoded` and does not contain `:decode-error`."
  [m]
  (if (and (map? m)
           (contains? m :decoded)
           (not (contains? m :decode-error)))
    (reduce
     (fn [mm [_ f]]
       (try
         (let [r (f mm)]
           (if (map? r) r mm))
         (catch Throwable _
           mm)))
     m
     @hooks)
    m))
