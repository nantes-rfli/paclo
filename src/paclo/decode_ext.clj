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

(defn- failure [m index reason error]
  (update m :diagnostics (fnil conj [])
          (cond-> {:stage :extension :reason reason :index index}
            error (assoc :exception-class (.getName (class error))
                         :message (or (.getMessage ^Throwable error) (str error))))))

(defn- apply-hook
  ([m f] (apply-hook m f nil false))
  ([m f index report?]
   (try
     (let [result (f m)]
       (if (map? result)
         result
         (if report? (failure m index :extension-non-map nil) m)))
     (catch Throwable error
       (if report? (failure m index :extension-exception error) m)))))

(defn apply!
  "Apply post-decode functions to packet map `m`.

  One argument consults current global hooks. Two arguments select only the
  supplied functions, including duplicates; an empty collection disables hooks.
  Both arities ignore exceptions and non-map results, preserving the last map.
  The third arity accepts :ignore or :report; nil extensions there selects global
  hooks. :report appends EDN diagnostics with zero-based execution indices.
  Later hooks continue. Core validates options at pipeline construction.

  Functions are skipped unless `m` contains :decoded and lacks :decode-error."
  ([m]
   (apply! m nil :ignore))
  ([m extensions]
   (apply! m (or extensions []) :ignore))
  ([m extensions error-mode]
   (if (and (map? m)
            (contains? m :decoded)
            (not (contains? m :decode-error)))
     (let [functions (if (nil? extensions) (map second @hooks) extensions)
           report? (= :report error-mode)]
       (if report?
         (loop [remaining (seq functions) index 0 result m]
           (if remaining
             (recur (next remaining) (inc index)
                    (apply-hook result (first remaining) index true))
             result))
         ;; Retain vector reduction's allocation-free iteration in default mode.
         (reduce apply-hook m functions)))
     m)))
