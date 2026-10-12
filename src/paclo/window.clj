(ns paclo.window
  "Pure bounded tumbling windows over integer microsecond events.")

(defn- fail! [reason]
  (throw (ex-info (name reason) {:reason reason})))

(defn- integer! [value]
  (when-not (integer? value) (fail! :invalid-time)))

(defn- open! [state]
  (when (:finished? state) (fail! :finished)))

(defn- group? [value]
  (or (nil? value) (boolean? value) (string? value) (keyword? value)
      (symbol? value) (integer? value) (char? value)
      (and (vector? value) (every? group? value))))

(defn- plain-group [value]
  (cond
    (vector? value) (mapv plain-group value)
    (symbol? value) (with-meta value nil)
    :else value))

(defn init
  "Create immutable state. Requires positive integer :width-us, :max-windows,
   :max-groups (total window/group pairs); :allowed-lateness-us defaults to 0.
   No clock or implicit watermark. Limits count entries, not key bytes."
  [{:keys [width-us max-windows max-groups allowed-lateness-us]
    :or {allowed-lateness-us 0}}]
  (doseq [value [width-us max-windows max-groups]]
    (when-not (and (integer? value) (pos? value)) (fail! :invalid-options)))
  (when-not (and (integer? allowed-lateness-us) (<= 0 allowed-lateness-us))
    (fail! :invalid-options))
  {:options {:width-us width-us :max-windows max-windows :max-groups max-groups
             :allowed-lateness-us allowed-lateness-us}
   :watermark-us nil :windows (sorted-map) :group-count 0 :finished? false})

(defn step
  "Add {:time-us integer :group EDN-scalar-or-vector :captured-bytes nonnegative-integer}.
   Epoch-aligned [start,end) windows use floor division, including negative time.
   A window with end+lateness <= watermark emits :late-event without retention.
   New entries exceeding either bound throw ex-info. Counts promote on overflow.
   Returns {:state immutable-map :events vector} containing only new events."
  [state {:keys [time-us group captured-bytes] :as event}]
  (open! state)
  (integer! time-us)
  (when-not (and (map? event) (contains? event :group) (group? group)
                 (integer? captured-bytes) (<= 0 captured-bytes))
    (fail! :invalid-event))
  (let [group (plain-group group)
        {:keys [width-us allowed-lateness-us max-windows max-groups]} (:options state)
        remainder (mod time-us width-us)
        start (-' time-us remainder)
        end (+' start width-us)
        groups (get (:windows state) start)
        new-group? (not (contains? groups group))]
    (if (and (:watermark-us state)
             (<= (+' end allowed-lateness-us) (:watermark-us state)))
      {:state state :events [{:kind :late-event :time-us time-us :start-us start :end-us end}]}
      (do
        (when (and (nil? groups) (>= (count (:windows state)) max-windows))
          (fail! :max-windows))
        (when (and new-group? (>= (:group-count state) max-groups))
          (fail! :max-groups))
        (let [previous (get groups group)]
          {:state (-> state
                      (assoc-in [:windows start group]
                                {:packets (inc' (or (:packets previous) 0))
                                 :captured-bytes (+' (or (:captured-bytes previous) 0) captured-bytes)})
                      (update :group-count #(if new-group? (inc' %) %)))
           :events []})))))

(defn- emit [state start groups complete?]
  {:kind :window :start-us start :end-us (+' start (get-in state [:options :width-us]))
   :complete? complete? :groups groups})

(defn advance
  "Advance an integer microsecond watermark monotonically (equal is allowed).
   Emit/remove nonempty windows with end+lateness <= watermark, in start order.
   Never zero-fill gaps. A backward watermark throws :watermark-regression."
  [state watermark-us]
  (open! state)
  (integer! watermark-us)
  (when (and (:watermark-us state) (< watermark-us (:watermark-us state)))
    (fail! :watermark-regression))
  (let [{:keys [width-us allowed-lateness-us]} (:options state)
        ready (take-while (fn [[start _]] (<= (+' start width-us allowed-lateness-us) watermark-us))
                          (sort-by key (:windows state)))]
    {:state (reduce (fn [s [start groups]]
                      (-> s (update :windows dissoc start) (update :group-count - (count groups))))
                    (assoc state :watermark-us watermark-us) ready)
     :events (mapv (fn [[start groups]] (emit state start groups true)) ready)}))

(defn finish
  "Emit retained windows in start order with :complete? false and clear state.
   Idempotent. Subsequent step/advance throws :finished; no infinite watermark."
  [state]
  {:state (assoc state :windows (sorted-map) :group-count 0 :finished? true)
   :events (mapv (fn [[start groups]] (emit state start groups false)) (sort-by key (:windows state)))})
