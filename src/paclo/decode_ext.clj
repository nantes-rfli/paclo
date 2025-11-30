(ns paclo.decode-ext)

(def ^:private hooks
  "Registered post-decode hooks: {k f}, where f: (fn [m] m')"
  (atom {}))

(defn register!
  "Register a post-decode hook.
   k: keyword/ident for later management
   f: (fn [m] m') — take whole message map (with :decoded) and return updated map."
  [k f]
  (swap! hooks assoc k f)
  k)

(defn unregister!
  "Remove a previously registered hook by key."
  [k]
  (swap! hooks dissoc k)
  nil)

(defn installed
  "Return a sequence of installed hook keys."
  []
  (keys @hooks))

(defn apply!
  "Apply all hooks to message map m (order: map iteration of @hooks).
   Hooks are isolated; exceptions are caught and ignored."
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
