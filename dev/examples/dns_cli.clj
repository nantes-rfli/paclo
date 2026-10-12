(ns examples.dns-cli
  "Private example adapters: bounded delivery, flags and explicit event time."
  (:require
   [clojure.core.async :as async]
   [clojure.string :as str]
   [examples.common :as ex]
   [paclo.core :as core]
   [paclo.dns :as dns]
   [paclo.proto.dns-ext :as dns-ext]))

(def execution-defaults
  {:async? false :async-buffer 1024 :async-mode :buffer :async-timeout-ms nil
   :reorder-us 0})

(defn number! [label text minimum]
  (let [n (ex/parse-long* text)]
    (when-not (and n (<= minimum n))
      (ex/error-exit! (str label " requires an integer >= " minimum) 4))
    n))

(defn positional-number [label text default minimum]
  (if (ex/blank? text) default (number! label text minimum)))

(defn parse-flags
  "Specs map flag strings to [option minimum], [option :text], or [option :flag]."
  [flags defaults specs]
  (let [specs (merge {"--async" [:async? :flag]
                      "--async-buffer" [:async-buffer 1]
                      "--async-mode" [:async-mode :mode]
                      "--async-timeout-ms" [:async-timeout-ms 0]
                      "--reorder-us" [:reorder-us 0]} specs)]
    (loop [xs (seq flags) opts (merge execution-defaults defaults)]
      (if-not xs
        opts
        (let [flag (first xs) [option kind] (get specs flag)]
          (when-not option (ex/error-exit! (str "unknown flag: " flag) 4))
          (if (= :flag kind)
            (recur (next xs) (assoc opts option true))
            (let [text (second xs)
                  value (case kind
                          :text (do (when (or (nil? text) (str/starts-with? text "-"))
                                      (ex/error-exit! (str flag " requires a value") 4)) text)
                          :mode (let [m (keyword text)]
                                  (when-not (#{:buffer :dropping} m)
                                    (ex/error-exit! "--async-mode must be buffer|dropping" 4)) m)
                          (number! flag text kind))]
              (recur (nnext xs) (assoc opts option value)))))))))

(defn capture-options [path bpf]
  {:path path :filter bpf :decode? true :extensions [dns-ext/annotate-dns]
   :extension-error-mode :report :error-mode :throw :max Long/MAX_VALUE
   ;; Offline reports run to EOF, not the capture API's 100 packet/10s defaults.
   ;; Half MAX avoids overflow in libpcap wrapper's current-time + duration.
   :max-time-ms (quot Long/MAX_VALUE 2) :idle-max-ms (quot Long/MAX_VALUE 2)})

(defn limit! [reason size maximum]
  (when (> size maximum)
    (throw (ex-info (str (name reason) " exceeded")
                    {:reason reason :limit maximum :required size}))))

(defn advance-packet
  "Advance before admission; CLI reorder allowance is applied only here."
  [state packet advance consume]
  (let [t (dns/packet-time-us packet)
        maximum (max t (or (:max-time-us state) t))
        result (advance (:analysis state) (-' maximum (:reorder-us state)))]
    (reduce consume
            (assoc state :analysis (:state result) :max-time-us maximum)
            (:events result))))

(defn transition [state result consume]
  (reduce consume (assoc state :analysis (:state result)) (:events result)))

(defn diagnostic [state event]
  (update-in state [:diagnostics (:kind event)] (fnil inc' 0)))

(defn- async-reduce [source step initial {:keys [async-buffer async-mode async-timeout-ms]}]
  (let [read-count (atom 0) dropped (atom 0) cancelled? (atom false)
        stop (async/chan)
        timeout (when (some? async-timeout-ms)
                  (if (zero? async-timeout-ms)
                    (doto (async/chan) async/close!)
                    (async/timeout async-timeout-ms)))
        ports (cond-> [stop] timeout (conj timeout))
        packets (async/chan (async/buffer async-buffer))
        stopped? (fn []
                   (let [[_ port] (async/alts!! ports :default :active :priority true)]
                     (when (not= :default port) (reset! cancelled? true))
                     (not= :default port)))
        producer (async/thread
                   (try
                     (when-not (stopped?)
                       (core/reduce-packets
                        (assoc source :stop? (fn [_] (stopped?)))
                        (fn [acc packet]
                          (swap! read-count inc)
                          (cond
                            (stopped?) (reduced acc)
                            (= :dropping async-mode)
                            (do (when-not (async/offer! packets packet) (swap! dropped inc)) acc)
                            :else
                            (let [[sent port] (async/alts!! (conj ports [packets packet]) :priority true)]
                              (if (and (= port packets) sent) acc
                                  (do (reset! cancelled? true) (reduced acc))))))
                        nil))
                     {:ok true}
                     (catch Throwable error {:error error})
                     (finally (async/close! packets))))]
    (try
      (let [[state delivered]
            (loop [state initial delivered 0]
              (if (stopped?)
                [state delivered]
                (let [take-ports (cond-> [packets] timeout (conj timeout))
                      [packet port] (async/alts!! take-ports :priority true)]
                  (cond
                    (= port timeout) (do (reset! cancelled? true) [state delivered])
                    (nil? packet) [state delivered]
                    :else (recur (step state packet) (inc' delivered))))))
            _ (async/close! stop)
            _ (async/close! packets)
            status (async/<!! producer)]
        (when-let [error (:error status)] (throw error))
        {:state state :execution {:read @read-count :delivered delivered :dropped @dropped
                                  :cancelled? @cancelled? :complete? (and (not @cancelled?) (zero? @dropped))}})
      (finally
        (async/close! stop)
        (async/close! packets)
        (async/<!! producer)))))

(defn run
  "Same step for sync/async. The producer owns and closes the native source."
  [source step initial execution]
  (if (:async? execution)
    (async-reduce source step initial execution)
    (let [[state n] (core/reduce-packets source
                                         (fn [[s n] p] [(step s p) (inc' n)])
                                         [initial 0])]
      {:state state :execution {:read n :delivered n :dropped 0 :cancelled? false :complete? true}})))

(defn metadata [state execution opts]
  (merge execution
         (select-keys opts [:async? :async-mode :async-buffer :async-timeout-ms :reorder-us])
         {:diagnostics (:diagnostics state) :watermark-us (get-in state [:analysis :watermark-us])
          :async-dropped (:dropped execution) :async-cancelled? (:cancelled? execution)}))
