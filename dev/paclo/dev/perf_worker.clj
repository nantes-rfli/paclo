(ns paclo.dev.perf-worker
  "One-process benchmark worker. Use paclo.dev.perf as the public runner."
  (:require
   [clojure.java.io :as io]
   [paclo.core :as core]
   [paclo.dev.perf-metrics :as metrics]
   [paclo.pcap :as pcap]
   [paclo.stream.impl :as stream])
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

(defn- reduce-packets
  ([packets]
   (reduce-packets packets 0))
  ([packets consumer-delay-ns]
   (reduce
    (fn [{:keys [packets bytes decode-errors] :as result} packet]
      (when (pos? (long consumer-delay-ns))
        (LockSupport/parkNanos (long consumer-delay-ns)))
      (assoc result
             :packets (unchecked-inc (long packets))
             :bytes (+ (long bytes) (long (:caplen packet)))
             :decode-errors (+ (long decode-errors)
                               (if (contains? packet :decode-error) 1 0))))
    {:packets 0 :bytes 0 :decode-errors 0}
    packets)))

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

(defn- sender-tasks
  [{:keys [source port target-pps duration-ms frame-size senders]}]
  (if (= source :external)
    []
    (let [target-pps (long target-pps)
          senders (long senders)
          duration-ms (long duration-ms)
          frame-size (long frame-size)
          base-rate (quot target-pps senders)
          remainder (mod target-pps senders)]
      (vec
       (for [index (range senders)]
         (future
           ;; Give both queue and direct capture paths time to activate.
           (Thread/sleep 100)
           (send-udp! {:port port
                       :target-pps (+ base-rate
                                      (if (< (long index) remainder) 1 0))
                       :duration-ms duration-ms
                       :payload-bytes (max 1 (- frame-size 28))})))))))

(defn- live-capture-max
  [source expected-packets]
  (if (and (= source :external) expected-packets)
    (long expected-packets)
    Long/MAX_VALUE))

(defn- live-reducer [consumer-delay-ns]
  (fn [{:keys [packets bytes decode-errors] :as result} packet]
    (when (pos? (long consumer-delay-ns))
      (LockSupport/parkNanos (long consumer-delay-ns)))
    (assoc result
           :packets (unchecked-inc (long packets))
           :bytes (+ (long bytes) (long (:caplen packet)))
           :decode-errors (+ (long decode-errors)
                             (if (contains? packet :decode-error) 1 0)))))

(defn- fanout-branch-config
  [{:keys [fanout-mode branch-cap slow-cap]}]
  (case fanout-mode
    :dual
    {:left {:buffer-mode :blocking :buffer-cap branch-cap}
     :right {:buffer-mode :blocking :buffer-cap branch-cap}}

    :slow-dropping
    {:fast {:buffer-mode :blocking :buffer-cap branch-cap}
     :slow {:buffer-mode :dropping :buffer-cap slow-cap}}))

(defn- fanout-live-run
  [capture config]
  (let [{:keys [fanout-mode consumer-delay-ns]} config
        fanout
        (stream/start
         (core/capture-packets capture)
         (fanout-branch-config config)
         {:cancel! #(core/stop-capture! capture)})]
    (try
      (case fanout-mode
        :dual
        (let [left (stream/branch fanout :left)
              right (stream/branch fanout :right)
              left-task (future (reduce-packets left consumer-delay-ns))
              right-task (future (reduce-packets right consumer-delay-ns))
              left-result @left-task
              right-result @right-task]
          (when-not (= (:packets left-result) (:packets right-result))
            (throw (ex-info "fan-out blocking branches diverged"
                            {:left (:packets left-result)
                             :right (:packets right-result)})))
          (assoc left-result
                 :left-count (:packets left-result)
                 :right-count (:packets right-result)
                 :stream-stats (stream/stats fanout)))

        :slow-dropping
        (let [fast (stream/branch fanout :fast)
              slow (stream/branch fanout :slow)
              fast-result (reduce-packets fast consumer-delay-ns)]
          (when-not (stream/await! fanout)
            (throw (ex-info "fan-out dispatcher timed out" {})))
          (let [slow-result (reduce-packets slow)
                stream-stats (stream/stats fanout)]
            (assoc fast-result
                   :fast-count (:packets fast-result)
                   :slow-count (:packets slow-result)
                   :slow-dropped
                   (get-in stream-stats [:branches :slow :dropped])
                   :stream-stats stream-stats))))
      (finally
        (.close ^java.io.Closeable fanout)))))

(defn- live-run
  [{:keys [device port target-pps duration-ms decode? source engine filter
           snaplen queue-cap queue-mode consumer-delay-ns
           buffer-size immediate? expected-packets ready-file]
    :as config}]
  (let [duration-ms (long duration-ms)
        target-pps (long target-pps)
        stats (atom nil)
        queue-stats (atom nil)
        errors (atom [])
        filter* (or filter
                    (when (= source :loopback)
                      (str "udp dst port " port)))
        opts (cond-> {:device device
                      :filter filter*
                      :decode? decode?
                      :snaplen snaplen
                      :max (live-capture-max source expected-packets)
                      :max-time-ms (if (= source :external)
                                     duration-ms
                                     (+ duration-ms 1000))
                      :idle-max-ms (if (= source :external)
                                     (+ duration-ms 100)
                                     250)
                      :timeout-ms 10
                      :on-ready (when ready-file
                                  #(spit ready-file "ready\n"))
                      :on-stats #(reset! stats %)
                      :on-error #(swap! errors conj
                                        (or (.getMessage ^Throwable %) (str %)))}
               buffer-size (assoc :buffer-size buffer-size)
               (some? immediate?) (assoc :immediate? immediate?)
               (contains? #{:queue :managed :fanout} engine)
               (assoc :queue-cap queue-cap
                      :queue-mode queue-mode
                      :on-queue-stats #(reset! queue-stats %)))
        [result senders]
        (case engine
          :queue
          (let [packets (core/packets opts)
                tasks (sender-tasks config)]
            [(reduce-packets packets consumer-delay-ns) tasks])

          :direct
          (let [tasks (sender-tasks config)]
            [(core/reduce-packets
              opts
              (live-reducer consumer-delay-ns)
              {:packets 0 :bytes 0 :decode-errors 0})
             tasks])

          :managed
          (let [capture (core/start-capture opts)
                tasks (sender-tasks config)
                result
                (try
                  (reduce-packets
                   (core/capture-packets capture)
                   consumer-delay-ns)
                  (finally
                    (.close ^java.io.Closeable capture)))
                snapshot (core/capture-stats capture)]
            (reset! stats (:pcap snapshot))
            (reset! queue-stats (:queue snapshot))
            [result tasks])

          :fanout
          (let [capture (core/start-capture opts)
                tasks (sender-tasks config)
                result
                (try
                  (fanout-live-run capture config)
                  (finally
                    (.close ^java.io.Closeable capture)))
                snapshot (core/capture-stats capture)]
            (reset! stats (:pcap snapshot))
            (reset! queue-stats (:queue snapshot))
            [result tasks]))
        sent-source (cond
                      (not= source :external) :internal-observed
                      expected-packets :external-expected
                      :else :unavailable)
        sent (if (= sent-source :external-expected)
               (long expected-packets)
               (long (reduce + 0 (map deref senders))))
        capture @stats
        queue (or @queue-stats
                  {:mode :direct
                   :capacity 0
                   :enqueued (:packets result)
                   :dropped 0
                   :blocked-events 0
                   :blocked-ns 0
                   :max-depth 0})
        received (long (or (:received capture) 0))
        kernel-dropped (long (or (:dropped capture) 0))
        interface-dropped (long (or (:interface-dropped capture) 0))
        capture-total (+ received kernel-dropped)
        queue-enqueued (long (or (:enqueued queue) 0))
        queue-dropped (long (or (:dropped queue) 0))
        queue-total (+ queue-enqueued queue-dropped)
        consumer-processed (long (:packets result))
        consumer-gap (max 0 (- queue-enqueued consumer-processed))
        send-loss (max 0 (- sent consumer-processed))
        duration-seconds (/ (double duration-ms) 1000.0)]
    (merge result
           {:sent sent
            :sent-source sent-source
            :realized-send-pps (when (and (= sent-source :internal-observed)
                                          (pos? sent))
                                 (/ (double sent) duration-seconds))
            :sustained-processed-pps
            (/ (double consumer-processed) duration-seconds)
            :processed-vs-sent-rate
            (when (pos? sent)
              (/ (double consumer-processed) (double sent)))
            :send-loss-rate
            (when (pos? sent)
              (/ (double send-loss) (double sent)))
            :kernel-drop-rate (if (pos? capture-total)
                                (/ (double kernel-dropped)
                                   (double capture-total))
                                0.0)
            :interface-drop-rate (if (pos? capture-total)
                                   (/ (double interface-dropped)
                                      (double capture-total))
                                   0.0)
            :queue-drop-rate (if (pos? queue-total)
                               (/ (double queue-dropped)
                                  (double queue-total))
                               0.0)
            :consumer-gap-rate (if (pos? queue-enqueued)
                                 (/ (double consumer-gap)
                                    (double queue-enqueued))
                                 0.0)
            :target-pps target-pps
            :source source
            :engine engine
            :capture-stats capture
            :queue-stats queue
            :stage-counts
            {:sent sent
             :capture-received received
             :capture-delivered queue-total
             :kernel-dropped kernel-dropped
             :interface-dropped interface-dropped
             :queue-enqueued queue-enqueued
             :queue-dropped queue-dropped
             :consumer-processed consumer-processed
             :consumer-gap consumer-gap
             :send-loss send-loss}
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
          :live-raw {:engine :queue}
          :live-raw-buffered {:engine :queue
                              :buffer-size (* 16 1024 1024)
                              :immediate? false}
          :live-raw-immediate {:engine :queue
                               :buffer-size (* 16 1024 1024)
                               :immediate? true}
          :live-managed-raw {:engine :managed
                             :buffer-size (* 16 1024 1024)
                             :immediate? true}
          :live-full {:engine :queue :decode? true}
          :live-sync-raw {:engine :direct
                          :buffer-size (* 16 1024 1024)
                          :immediate? true}
          :live-dropping-raw {:engine :queue
                              :queue-mode :dropping
                              :buffer-size (* 16 1024 1024)
                              :immediate? true}
          :live-sync-full {:engine :direct
                           :decode? true
                           :buffer-size (* 16 1024 1024)
                           :immediate? true}
          :live-managed-full {:engine :managed
                              :decode? true
                              :buffer-size (* 16 1024 1024)
                              :immediate? true}
          :live-managed-fanout-dual
          {:engine :fanout
           :fanout-mode :dual
           :buffer-size (* 16 1024 1024)
           :immediate? true}
          :live-managed-fanout-slow-dropping
          {:engine :fanout
           :fanout-mode :slow-dropping
           :buffer-size (* 16 1024 1024)
           :immediate? true}
          :live-dropping-full {:engine :queue
                               :decode? true
                               :queue-mode :dropping
                               :buffer-size (* 16 1024 1024)
                               :immediate? true}
          (throw (ex-info "unknown live scenario" {:scenario scenario})))
        config (merge
                {:device (:device opts)
                 :port (parse-long! (:port opts) "port")
                 :target-pps (parse-long! (:target-pps opts) "target-pps")
                 :duration-ms (parse-long! (:duration-ms opts) "duration-ms")
                 :frame-size (parse-long! (:frame-size opts) "frame-size")
                 :senders (parse-long! (or (:senders opts) "1") "senders")
                 :source (keyword (or (:source opts) "loopback"))
                 :engine :queue
                 :decode? false
                 :snaplen 65536
                 :queue-cap 1024
                 :queue-mode :blocking
                 :branch-cap 4096
                 :slow-cap 64
                 :consumer-delay-ns 0}
                scenario-config
                (cond-> {}
                  (:ready-file opts)
                  (assoc :ready-file (:ready-file opts))
                  (:filter opts) (assoc :filter (:filter opts))
                  (:snaplen opts)
                  (assoc :snaplen (parse-long! (:snaplen opts) "snaplen"))
                  (:queue-cap opts)
                  (assoc :queue-cap
                         (parse-long! (:queue-cap opts) "queue-cap"))
                  (:queue-mode opts)
                  (assoc :queue-mode (keyword (:queue-mode opts)))
                  (:branch-cap opts)
                  (assoc :branch-cap
                         (parse-long! (:branch-cap opts) "branch-cap"))
                  (:slow-cap opts)
                  (assoc :slow-cap
                         (parse-long! (:slow-cap opts) "slow-cap"))
                  (:consumer-delay-ns opts)
                  (assoc :consumer-delay-ns
                         (parse-long! (:consumer-delay-ns opts)
                                      "consumer-delay-ns"))
                  (:expected-packets opts)
                  (assoc :expected-packets
                         (parse-long! (:expected-packets opts)
                                      "expected-packets"))
                  (:buffer-size opts)
                  (assoc :buffer-size
                         (parse-long! (:buffer-size opts) "buffer-size"))
                  (:immediate opts)
                  (assoc :immediate?
                         (parse-boolean! (:immediate opts) "immediate"))))]
    (when-not (contains? #{:loopback :external} (:source config))
      (throw (ex-info "source must be loopback or external"
                      {:source (:source config)})))
    (when-not (contains? #{:queue :direct :managed :fanout} (:engine config))
      (throw (ex-info "engine must be queue, direct, managed, or fanout"
                      {:engine (:engine config)})))
    (when-not (contains? #{:blocking :dropping} (:queue-mode config))
      (throw (ex-info "queue-mode must be blocking or dropping"
                      {:queue-mode (:queue-mode config)})))
    (when-not (pos? (long (:senders config)))
      (throw (ex-info "senders must be positive"
                      {:senders (:senders config)})))
    (when (and (= :loopback (:source config))
               (> (long (:senders config)) (long (:target-pps config))))
      (throw (ex-info "senders cannot exceed target-pps"
                      {:senders (:senders config)
                       :target-pps (:target-pps config)})))
    (when (and (:expected-packets config)
               (not= :external (:source config)))
      (throw (ex-info "expected-packets requires source=external"
                      {:source (:source config)
                       :expected-packets (:expected-packets config)})))
    (when (and (:expected-packets config)
               (not (pos? (long (:expected-packets config)))))
      (throw (ex-info "expected-packets must be positive"
                      {:expected-packets (:expected-packets config)})))
    (when-not (<= 1 (long (:snaplen config)) 65536)
      (throw (ex-info "snaplen must be between 1 and 65536"
                      {:snaplen (:snaplen config)})))
    (when-not (pos? (long (:queue-cap config)))
      (throw (ex-info "queue-cap must be positive"
                      {:queue-cap (:queue-cap config)})))
    (when-not (pos? (long (:branch-cap config)))
      (throw (ex-info "branch-cap must be positive"
                      {:branch-cap (:branch-cap config)})))
    (when-not (pos? (long (:slow-cap config)))
      (throw (ex-info "slow-cap must be positive"
                      {:slow-cap (:slow-cap config)})))
    (when (neg? (long (:consumer-delay-ns config)))
      (throw (ex-info "consumer-delay-ns cannot be negative"
                      {:consumer-delay-ns (:consumer-delay-ns config)})))
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
