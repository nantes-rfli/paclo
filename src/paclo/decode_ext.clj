(ns paclo.decode-ext)

(def ^:private hooks
  "Registered post-decode hooks as an ordered vector of [k f].
  Order = registration order. Same key overwrites and moves to the tail."
  (atom []))

(defn register!
  "Register a post-decode hook.
   k: keyword/ident for later management
   f: (fn [m] m') — take whole message map (with :decoded) and return updated map.
   Overwrites existing key and keeps the latest position."
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
  "Return a sequence of installed hook keys in execution order."
  []
  (map first @hooks))

(defn apply!
  "Apply all hooks to message map m (execution order = registration order).
   Hooks are isolated; exceptions are caught and ignored.
   Only map return values are applied; others are ignored."
  [m]
  (reduce
   (fn [mm [_ f]]
     (try
       (let [r (f mm)]
         (if (map? r) r mm))
       (catch Throwable _
         mm)))
   m
   @hooks))
