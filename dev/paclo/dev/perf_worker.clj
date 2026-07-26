(ns paclo.dev.perf-worker
  "One-process benchmark worker. Use paclo.dev.perf as the public runner."
  (:require
   [clojure.java.io :as io]
   [paclo.core :as core]
   [paclo.dev.perf-metrics :as metrics]
   [paclo.pcap :as pcap])
  (:import
   [java.net DatagramPacket DatagramSocket InetAddress]
   [java.util HashMap]
   [java.util.concurrent.locks LockSupport]))

(defn- parse-args [args]
  (loop [result {}
         remaining args]
    (if (empty? remaining)
      result
      (let [[flag value & more] remaining]
        (when-not (and flag value (.startsWith ^String flag "--"))
          (throw (ex-info "expected --name value arguments"
                          {:remaining remaining})))
        (recur (assoc result (keyword (subs flag 2)) value) more)))))

(defn- parse-long! [value label]
  (try
    (Long/parseLong value)
    (catch Throwable cause
      (throw (ex-info (str label " must be an integer")
                      {:label label :value value}
                      cause)))))

(defn- parse-boolean! [value label]
  (case value
    "true" true
    "false" false
    (throw (ex-info (str label " must be true or false")
                    {:label label :value value}))))

(defn- reduce-packets [packets]
  (reduce
   (fn [{:keys [packets bytes decode-errors] :as result} packet]
     (assoc result
            :packets (unchecked-inc (long packets))
            :bytes (+ (long bytes) (long (:caplen packet)))
            :decode-errors (+ (long decode-errors)
                              (if (contains? packet :decode-error) 1 0))))
   {:packets 0 :bytes 0 :decode-errors 0}
   packets))

(defn- offline-opts [path count]
  ;; capture->seq has a safe interactive default of ten seconds. Reference and
  ;; stress benchmarks must instead consume the complete deterministic file.
  {:path path
   :max count
   :max-time-ms 3600000})

(defn- raw-seq-run [path count]
  (reduce-packets (core/packets (offline-opts path count))))

(defn- raw-reduce-run [path count]
  (core/reduce-packets
   (offline-opts path count)
   (fn [{:keys [packets bytes] :as result} packet]
     (assoc result
            :packets (unchecked-inc (long packets))
            :bytes (+ (long bytes) (long (:caplen packet)))))
   {:packets 0 :bytes 0 :decode-errors 0}))

(defn- sync-loop-run [path]
  (let [packets (volatile! 0)
        bytes (volatile! 0)
        handle (pcap/open-offline path)]
    (try
      (pcap/loop! handle
                  (fn [packet]
                    (vswap! packets unchecked-inc)
                    (vswap! bytes + (long (:caplen packet)))))
      {:packets @packets :bytes @bytes :decode-errors 0}
      (finally
        (pcap/close! handle)))))

(defn- full-decode-run [path count]
  (reduce-packets
   (core/packets (assoc (offline-opts path count) :decode? true))))

(defn- full-reduce-run [path count]
  (core/reduce-packets
   (assoc (offline-opts path count) :decode? true)
   (fn [{:keys [packets bytes decode-errors] :as result} packet]
     (assoc result
            :packets (unchecked-inc (long packets))
            :bytes (+ (long bytes) (long (:caplen packet)))
            :decode-errors (+ (long decode-errors)
                              (if (contains? packet :decode-error) 1 0))))
   {:packets 0 :bytes 0 :decode-errors 0}))

(defn- flow-step [^HashMap flows]
  (fn [{:keys [packets bytes decode-errors] :as result} packet]
    (when-let [flow-key (get-in packet [:decoded :l3 :flow-key])]
      (let [current (.get flows flow-key)]
        (.put flows flow-key
              (if current (unchecked-inc (long current)) 1))))
    (assoc result
           :packets (unchecked-inc (long packets))
           :bytes (+ (long bytes) (long (:caplen packet)))
           :decode-errors (+ (long decode-errors)
                             (if (contains? packet :decode-error) 1 0)))))

(defn- flow-seq-run [path count]
  (let [flows (HashMap.)]
    (assoc
     (reduce
      (flow-step flows)
      {:packets 0 :bytes 0 :decode-errors 0}
      (core/packets (assoc (offline-opts path count) :decode? true)))
     :unique-flows (.size flows))))

(defn- flow-reduce-run [path count]
  (let [flows (HashMap.)]
    (assoc
     (core/reduce-packets
      (assoc (offline-opts path count) :decode? true)
      (flow-step flows)
      {:packets 0 :bytes 0 :decode-errors 0})
     :unique-flows (.size flows))))

(defn- flow-project-run [path count]
  (core/reduce-packets
   (assoc (offline-opts path count) :decode-mode :flow)
   (fn [{:keys [packets bytes decode-errors] :as result} packet]
     (assoc result
            :packets (unchecked-inc (long packets))
            :bytes (+ (long bytes) (long (:caplen packet)))
            :decode-errors (+ (long decode-errors)
                              (if (contains? packet :decode-error) 1 0))))
   {:packets 0 :bytes 0 :decode-errors 0}))

(defn- write-run [path count]
  (let [output (java.io.File/createTempFile "paclo-perf-write" ".pcap")
        packets (volatile! 0)
        bytes (volatile! 0)
        xf (map
            (fn [packet]
              (vswap! packets unchecked-inc)
              (vswap! bytes + (long (:caplen packet)))
              (:bytes packet)))]
    (try
      (core/write-pcap! (core/packets
                         (assoc (offline-opts path count) :xform xf))
                        (.getAbsolutePath output))
      {:packets @packets :bytes @bytes :decode-errors 0}
      (finally
        (when (.exists output)
          (.delete output))))))

(defn- offline-runner [scenario path count]
  (case scenario
    :raw-seq #(raw-seq-run path count)
    :sync-loop #(sync-loop-run path)
    :raw-reduce #(raw-reduce-run path count)
    :full-decode #(full-decode-run path count)
    :full-reduce #(full-reduce-run path count)
    :flow-aggregate #(flow-seq-run path count)
    :flow-reduce #(flow-reduce-run path count)
    :flow-project #(flow-project-run path count)
    :write-pipeline #(write-run path count)
    (throw (ex-info "unknown offline scenario" {:scenario scenario}))))

(defn- send-udp!
  [{:keys [port target-pps duration-ms payload-bytes]}]
  (let [address (InetAddress/getLoopbackAddress)
        payload (byte-array payload-bytes)
        packet (DatagramPacket. payload (alength payload) address (int port))
        interval (/ 1.0e9 (double target-pps))
        started (System/nanoTime)
        deadline (+ started (* (long duration-ms) 1000000))]
    (with-open [socket (DatagramSocket.)]
      (loop [sent 0]
        (let [now (System/nanoTime)]
          (if (>= now deadline)
            sent
            (do
              (.send socket packet)
              (let [sent' (unchecked-inc (long sent))
                    target (+ started (long (* sent' interval)))
                    remaining (- target (System/nanoTime))]
                (if (> remaining 50000)
                  (LockSupport/parkNanos remaining)
                  (while (< (System/nanoTime) target)
                    (Thread/onSpinWait)))
                (recur sent')))))))))

(defn- live-run
  [{:keys [device port target-pps duration-ms frame-size decode? senders
           buffer-size immediate?]}]
  (let [stats (atom nil)
        errors (atom [])
        opts (cond-> {:device device
                      :filter (str "udp dst port " port)
                      :decode? decode?
                      :max Long/MAX_VALUE
                      :max-time-ms (+ duration-ms 1000)
                      :idle-max-ms 250
                      :timeout-ms 10
                      :on-stats #(reset! stats %)
                      :on-error #(swap! errors conj
                                        (or (.getMessage ^Throwable %) (str %)))}
               buffer-size (assoc :buffer-size buffer-size)
               (some? immediate?) (assoc :immediate? immediate?))
        packets (core/packets opts)
        base-rate (quot target-pps senders)
        remainder (mod target-pps senders)
        sender-tasks
        (vec
         (for [index (range senders)]
           (future
             (Thread/sleep 50)
             (send-udp! {:port port
                         :target-pps (+ base-rate
                                        (if (< index remainder) 1 0))
                         :duration-ms duration-ms
                         :payload-bytes (max 1 (- frame-size 28))}))))
        result (reduce-packets packets)
        sent (reduce + (map deref sender-tasks))
        capture @stats
        received (long (or (:received capture) 0))
        dropped (long (or (:dropped capture) 0))
        interface-dropped (long (or (:interface-dropped capture) 0))
        capture-total (+ received dropped)
        duration-seconds (/ (double duration-ms) 1000.0)]
    (merge result
           {:sent sent
            :realized-send-pps (/ (double sent) duration-seconds)
            :processed-vs-sent-rate (if (pos? sent)
                                      (/ (double (:packets result))
                                         (double sent))
                                      0.0)
            :kernel-drop-rate (if (pos? capture-total)
                                (/ (double dropped)
                                   (double capture-total))
                                0.0)
            :interface-drop-rate (if (pos? capture-total)
                                   (/ (double interface-dropped)
                                      (double capture-total))
                                   0.0)
            :target-pps target-pps
            :capture-stats capture
            :capture-errors @errors})))

(defn- run-measured
  [runner warmups runs]
  (dotimes [_ warmups]
    (runner))
  (let [measurements (vec (repeatedly runs #(metrics/measure runner)))]
    {:runs measurements
     :summary (metrics/summarize-runs measurements)}))

(defn- run-offline [opts]
  (let [scenario (keyword (:scenario opts))
        path (:path opts)
        count (parse-long! (:count opts) "count")
        warmups (parse-long! (:warmups opts) "warmups")
        runs (parse-long! (:runs opts) "runs")]
    (when-not (.isFile (io/file path))
      (throw (ex-info "benchmark PCAP does not exist" {:path path})))
    (merge
     {:mode :offline
      :scenario scenario
      :path path
      :environment (metrics/environment)}
     (run-measured (offline-runner scenario path count) warmups runs))))

(defn- run-live [opts]
  (let [scenario (keyword (:scenario opts))
        warmups (parse-long! (:warmups opts) "warmups")
        runs (parse-long! (:runs opts) "runs")
        scenario-config
        (case scenario
          :live-raw {}
          :live-raw-buffered {:buffer-size (* 16 1024 1024)
                              :immediate? false}
          :live-raw-immediate {:buffer-size (* 16 1024 1024)
                               :immediate? true}
          :live-full {:decode? true}
          (throw (ex-info "unknown live scenario" {:scenario scenario})))
        config (merge
                {:device (:device opts)
                 :port (parse-long! (:port opts) "port")
                 :target-pps (parse-long! (:target-pps opts) "target-pps")
                 :duration-ms (parse-long! (:duration-ms opts) "duration-ms")
                 :frame-size (parse-long! (:frame-size opts) "frame-size")
                 :senders (parse-long! (or (:senders opts) "1") "senders")
                 :decode? false}
                scenario-config
                (cond-> {}
                  (:buffer-size opts)
                  (assoc :buffer-size
                         (parse-long! (:buffer-size opts) "buffer-size"))
                  (:immediate opts)
                  (assoc :immediate?
                         (parse-boolean! (:immediate opts) "immediate"))))]
    (when-not (pos? (long (:senders config)))
      (throw (ex-info "senders must be positive"
                      {:senders (:senders config)})))
    (when (> (long (:senders config)) (long (:target-pps config)))
      (throw (ex-info "senders cannot exceed target-pps"
                      {:senders (:senders config)
                       :target-pps (:target-pps config)})))
    (merge
     {:mode :live
      :scenario scenario
      :config config
      :environment (metrics/environment)}
     (run-measured #(live-run config) warmups runs))))

(defn -main [& args]
  (try
    (let [opts (parse-args args)
          mode (keyword (:mode opts))
          result (case mode
                   :offline (run-offline opts)
                   :live (run-live opts)
                   (throw (ex-info "mode must be offline or live"
                                   {:mode mode})))]
      (prn result))
    (finally
      ;; core/packets uses futures; do not make each isolated worker wait for
      ;; the cached executor keep-alive before the process can exit.
      (shutdown-agents))))
