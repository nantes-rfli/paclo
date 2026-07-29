(ns paclo.dev.perf
  "Offline and staged live-capture performance runner."
  (:require
   [clojure.data.json :as json]
   [clojure.edn :as edn]
   [clojure.java.io :as io]
   [clojure.java.shell :as shell]
   [clojure.string :as str]
   [paclo.dev.perf-data :as data])
  (:import
   [java.time Instant]))

(def ^:private offline-scenarios
  [:raw-seq :sync-loop :raw-reduce
   :full-decode :full-reduce
   :flow-aggregate :flow-reduce :flow-project
   :write-pipeline])

(def ^:private live-scenarios
  [:live-raw
   :live-raw-buffered
   :live-raw-immediate
   :live-full
   :live-sync-raw
   :live-dropping-raw
   :live-sync-full
   :live-dropping-full])

(def ^:private stress-live-scenarios
  [:live-sync-raw :live-dropping-raw
   :live-sync-full :live-dropping-full])

(def ^:private ^:const live-drop-threshold 0.001)

(def ^:private live-profiles
  {:quick {:rates [10000]
           :duration-ms 2000
           :warmups 1
           :runs 1}
   :reference {:rates [10000 50000 100000 250000 500000 1000000]
               :duration-ms 15000
               :warmups 1
               :runs 5}
   :stress {:rates [1000000]
            :duration-ms 60000
            :warmups 1
            :runs 5}})

(defn- usage []
  (println "Usage:")
  (println "  clojure -M:perf [--mode offline|live|all]")
  (println "                   [--profile quick|reference|stress]")
  (println "                   [--output target/perf]")
  (println "                   [--device lo0] [--port 39053]")
  (println "                   [--source loopback|external] [--filter BPF]")
  (println "                   [--scenarios name,...] [--rates pps,...]")
  (println "                   [--duration-ms MS] [--warmups N] [--runs N]")
  (println "                   [--frame-size BYTES] [--snaplen BYTES]")
  (println "                   [--queue-cap N] [--queue-mode blocking|dropping]")
  (println "                   [--consumer-delay-ns NS]")
  (println "                   [--expected-packets N]")
  (println)
  (println "The default is the offline quick profile.")
  (println "Use source=external with one selected scenario for a real-NIC/manual probe."))

(defn- parse-args [args]
  (loop [opts {:mode :offline
               :profile :quick
               :output "target/perf"
               :device "lo0"
               :port 39053}
         remaining args]
    (if (empty? remaining)
      opts
      (let [[flag value & more] remaining]
        (case flag
          "--help" (assoc opts :help? true)
          "-h" (assoc opts :help? true)
          "--mode" (recur (assoc opts :mode (keyword value)) more)
          "--profile" (recur (assoc opts :profile (keyword value)) more)
          "--output" (recur (assoc opts :output value) more)
          "--device" (recur (assoc opts :device value) more)
          "--port" (recur (assoc opts :port (Long/parseLong value)) more)
          "--source" (recur (assoc opts :source (keyword value)) more)
          "--filter" (recur (assoc opts :filter value) more)
          "--scenarios" (recur (assoc opts :scenarios value) more)
          "--rates" (recur (assoc opts :rates value) more)
          "--duration-ms" (recur (assoc opts :duration-ms
                                        (Long/parseLong value)) more)
          "--warmups" (recur (assoc opts :warmups
                                    (Long/parseLong value)) more)
          "--runs" (recur (assoc opts :runs (Long/parseLong value)) more)
          "--frame-size" (recur (assoc opts :frame-size
                                       (Long/parseLong value)) more)
          "--snaplen" (recur (assoc opts :snaplen
                                    (Long/parseLong value)) more)
          "--queue-cap" (recur (assoc opts :queue-cap
                                      (Long/parseLong value)) more)
          "--queue-mode" (recur (assoc opts :queue-mode
                                       (keyword value)) more)
          "--consumer-delay-ns"
          (recur (assoc opts :consumer-delay-ns
                        (Long/parseLong value)) more)
          "--expected-packets"
          (recur (assoc opts :expected-packets
                        (Long/parseLong value)) more)
          (throw (ex-info "unknown or incomplete argument"
                          {:remaining remaining})))))))

(defn- comma-keywords [value]
  (when value
    (mapv keyword (remove str/blank? (str/split value #",")))))

(defn- comma-longs [value]
  (when value
    (mapv #(Long/parseLong %) (remove str/blank? (str/split value #",")))))

(defn- validate-opts!
  [{:keys [mode profile port source scenarios rates duration-ms warmups runs
           frame-size snaplen queue-cap queue-mode consumer-delay-ns
           expected-packets]}]
  (when-not (contains? #{:offline :live :all} mode)
    (throw (ex-info "mode must be offline, live, or all" {:mode mode})))
  (when-not (contains? data/profiles profile)
    (throw (ex-info "unknown profile" {:profile profile})))
  (when-not (<= 1 (long port) 65535)
    (throw (ex-info "port must be between 1 and 65535" {:port port})))
  (when-not (contains? #{:loopback :external} (or source :loopback))
    (throw (ex-info "source must be loopback or external" {:source source})))
  (when-let [selected (comma-keywords scenarios)]
    (when-let [unknown (seq (remove (set live-scenarios) selected))]
      (throw (ex-info "unknown live scenario" {:scenarios unknown}))))
  (when-let [selected-rates (comma-longs rates)]
    (when (or (empty? selected-rates)
              (some #(not (pos? (long %))) selected-rates))
      (throw (ex-info "rates must contain positive integers"
                      {:rates selected-rates}))))
  (doseq [[label value] [[:duration-ms duration-ms]
                         [:runs runs]
                         [:frame-size frame-size]
                         [:snaplen snaplen]
                         [:queue-cap queue-cap]]]
    (when (and value (not (pos? (long value))))
      (throw (ex-info (str (name label) " must be positive")
                      {label value}))))
  (when (and warmups (neg? (long warmups)))
    (throw (ex-info "warmups cannot be negative" {:warmups warmups})))
  (when (and consumer-delay-ns (neg? (long consumer-delay-ns)))
    (throw (ex-info "consumer-delay-ns cannot be negative"
                    {:consumer-delay-ns consumer-delay-ns})))
  (when (and expected-packets (not (pos? (long expected-packets))))
    (throw (ex-info "expected-packets must be positive"
                    {:expected-packets expected-packets})))
  (when (and expected-packets (not= :external (or source :loopback)))
    (throw (ex-info "expected-packets requires source=external"
                    {:source source :expected-packets expected-packets})))
  (when (and expected-packets (nil? rates))
    (throw (ex-info "expected-packets requires an external offered rate"
                    {:expected-packets expected-packets})))
  (when-not (contains? #{:blocking :dropping} (or queue-mode :blocking))
    (throw (ex-info "queue-mode must be blocking or dropping"
                    {:queue-mode queue-mode}))))

(defn- worker!
  ([arguments]
   (worker! arguments false))
  ([arguments signal-ready?]
   (let [ready-file (when signal-ready?
                      (java.io.File/createTempFile
                       "paclo-perf-ready-" ".signal"))
         _ (when (and ready-file (not (.delete ready-file)))
             (throw (ex-info "cannot initialize capture readiness signal"
                             {:path (.getAbsolutePath ready-file)})))
         arguments (cond-> arguments
                     ready-file
                     (conj "--ready-file" (.getAbsolutePath ready-file)))
         task (future
                (apply shell/sh "clojure" "-M:perf-worker" arguments))]
     (try
       (when ready-file
         (loop []
           (cond
             (.isFile ready-file)
             (println "[perf] capture ready")

             (realized? task)
             nil

             :else
             (do
               (Thread/sleep 10)
               (recur)))))
       (let [{:keys [exit out err]} @task]
         (when-not (zero? (long exit))
           (throw (ex-info "performance worker failed"
                           {:arguments arguments
                            :exit exit
                            :stderr err
                            :stdout out})))
         (try
           (edn/read-string (str/trim out))
           (catch Throwable cause
             (throw (ex-info "performance worker returned invalid EDN"
                             {:arguments arguments
                              :stdout out
                              :stderr err}
                             cause)))))
       (finally
         (when ready-file
           (.delete ready-file)))))))

(defn- validate-offline-result!
  [result config]
  (let [expected-packets (long (:count config))
        expected-bytes (long (data/expected-captured-bytes config))]
    (doseq [run (:runs result)]
      (when-not (and (= expected-packets (long (:packets run)))
                     (= expected-bytes (long (:bytes run)))
                     (zero? (long (:decode-errors run))))
        (throw (ex-info "offline benchmark result failed consistency checks"
                        {:scenario (:scenario result)
                         :expected {:packets expected-packets
                                    :bytes expected-bytes
                                    :decode-errors 0}
                         :actual (select-keys
                                  run
                                  [:packets :bytes :decode-errors])})))))
  result)

(defn- validate-live-result!
  [result]
  (doseq [run (:runs result)]
    (when (or (seq (:capture-errors run))
              (nil? (:capture-stats run))
              (nil? (:queue-stats run))
              (nil? (:stage-counts run))
              (not= (long (get-in run [:stage-counts :queue-enqueued]))
                    (long (get-in run [:stage-counts :consumer-processed]))))
      (throw (ex-info "live benchmark did not collect clean capture statistics"
                      {:scenario (:scenario result)
                       :capture-errors (:capture-errors run)
                       :capture-stats (:capture-stats run)
                       :queue-stats (:queue-stats run)
                       :stage-counts (:stage-counts run)}))))
  result)

(defn- send-count-available?
  [run]
  (contains? #{:internal-observed :external-expected}
             (:sent-source run)))

(defn- sustainable-run?
  [run]
  (let [threshold (double live-drop-threshold)]
    (and (empty? (:capture-errors run))
         (send-count-available? run)
         (or (nil? (:send-loss-rate run))
             (<= (double (:send-loss-rate run)) threshold))
         (every? #(<= (double (or (% run) 0.0)) threshold)
                 [:kernel-drop-rate
                  :interface-drop-rate
                  :queue-drop-rate
                  :consumer-gap-rate]))))

(defn- annotate-sustainability
  [result]
  (let [runs (:runs result)
        passing (filter sustainable-run? runs)
        processed-rates (keep :sustained-processed-pps passing)
        end-to-end? (every? send-count-available? runs)]
    (assoc result
           :sustainability
           {:drop-threshold live-drop-threshold
            :end-to-end? end-to-end?
            :passing-runs (count passing)
            :total-runs (count runs)
            :all-runs-pass? (= (count passing) (count runs))
            :max-passing-processed-pps
            (when (seq processed-rates) (apply max processed-rates))})))

(defn- max-sustainable-by-scenario
  [results]
  (into {}
        (keep
         (fn [[scenario candidates]]
           (when-let [best
                      (->> candidates
                           (filter #(get-in % [:sustainability :all-runs-pass?]))
                           (sort-by #(or (get-in % [:summary
                                                    :sustained-processed-pps
                                                    :median])
                                         0.0)
                                    >)
                           first)]
             [scenario
              {:target-pps (get-in best [:config :target-pps])
               :processed-pps
               (get-in best [:summary :sustained-processed-pps :median])
               :realized-send-pps
               (get-in best [:summary :realized-send-pps :median])
               :source (get-in best [:config :source])}]))
         (group-by :scenario results))))

(defn- offline-results!
  [{:keys [profile output]}]
  (let [{:keys [count cases]} (get data/profiles profile)
        warmups 1
        runs (if (= profile :quick) 1 5)
        root (str (io/file output "datasets"))]
    (vec
     (for [{:keys [id] :as case-config} cases
           :let [config (assoc case-config :count count)
                 path (data/dataset-path root profile id)
                 _ (do
                     (println "[perf] preparing" path)
                     (data/ensure-dataset! path config))]
           scenario offline-scenarios]
       (do
         (println "[perf] offline" (name id) (name scenario))
         (validate-offline-result!
          (worker! ["--mode" "offline"
                    "--scenario" (name scenario)
                    "--path" path
                    "--count" (str count)
                    "--warmups" (str warmups)
                    "--runs" (str runs)])
          config))))))

(defn- worker-live-args
  [{:keys [device port source filter frame-size snaplen queue-cap queue-mode
           consumer-delay-ns expected-packets]}
   {:keys [scenario rate duration-ms warmups runs senders]}]
  (cond-> ["--mode" "live"
           "--scenario" (name scenario)
           "--device" device
           "--port" (str port)
           "--source" (name source)
           "--target-pps" (str rate)
           "--duration-ms" (str duration-ms)
           "--frame-size" (str frame-size)
           "--snaplen" (str snaplen)
           "--queue-cap" (str queue-cap)
           "--consumer-delay-ns" (str consumer-delay-ns)
           "--senders" (str senders)
           "--warmups" (str warmups)
           "--runs" (str runs)]
    filter (conj "--filter" filter)
    queue-mode (conj "--queue-mode" (name queue-mode))
    expected-packets (conj "--expected-packets" (str expected-packets))))

(defn- validate-external-run-shape!
  [expected-packets scenarios warmups runs]
  (when (and expected-packets
             (or (not= 0 (long warmups))
                 (not= 1 (long runs))
                 (not= 1 (count scenarios))))
    (throw (ex-info
            "external expected-packets requires one scenario, no warm-up, and one run"
            {:scenarios scenarios :warmups warmups :runs runs}))))

(defn- live-results!
  [{:keys [profile device port source filter scenarios rates
           duration-ms warmups runs frame-size snaplen queue-cap queue-mode
           consumer-delay-ns expected-packets]}]
  (let [profile-config (get live-profiles profile)
        source (or source :loopback)
        rates (if (= source :external)
                (or (comma-longs rates) [0])
                (or (comma-longs rates) (:rates profile-config)))
        scenarios (or (comma-keywords scenarios)
                      (if (= profile :stress)
                        stress-live-scenarios
                        live-scenarios))
        duration-ms (or duration-ms (:duration-ms profile-config))
        warmups (if (some? warmups) warmups (:warmups profile-config))
        runs (or runs (:runs profile-config))
        worker-config {:device device
                       :port port
                       :source source
                       :filter filter
                       :frame-size (or frame-size 64)
                       :snaplen (or snaplen 65536)
                       :queue-cap (or queue-cap 1024)
                       :queue-mode queue-mode
                       :expected-packets expected-packets
                       :consumer-delay-ns (or consumer-delay-ns 0)}]
    (validate-external-run-shape! expected-packets scenarios warmups runs)
    (vec
     (for [rate rates
           scenario scenarios
           :let [senders (min 8
                              (if (= source :external)
                                1
                                (max 1
                                     (long
                                      (Math/ceil
                                       (/ (double rate) 100000.0))))))]]
       (do
         (println "[perf] live" device (name scenario)
                  "source=" (name source)
                  "target-pps=" rate "senders=" senders)
         (-> (worker! (worker-live-args
                       worker-config
                       {:scenario scenario
                        :rate rate
                        :duration-ms duration-ms
                        :warmups warmups
                        :runs runs
                        :senders senders})
                      (= source :external))
             validate-live-result!
             annotate-sustainability))))))

(defn- json-key [value]
  (if (keyword? value) (name value) (str value)))

(defn- write-results!
  [output result]
  (let [edn-path (io/file output "results.edn")
        json-path (io/file output "results.json")]
    (io/make-parents edn-path)
    (spit edn-path (str (pr-str result) "\n"))
    (spit json-path (str (json/write-str result :key-fn json-key) "\n"))
    {:edn (.getAbsolutePath edn-path)
     :json (.getAbsolutePath json-path)}))

(defn run-benchmarks!
  [{:keys [mode profile output] :as opts}]
  (validate-opts! opts)
  (let [live-results (when (#{:live :all} mode)
                       (live-results! opts))
        result {:schema-version 2
                :created-at (str (Instant/now))
                :profile profile
                :offline (when (#{:offline :all} mode)
                           (offline-results! opts))
                :live live-results
                :max-sustainable-by-scenario
                (when live-results
                  (max-sustainable-by-scenario live-results))}
        paths (write-results! output result)]
    (println "[perf] wrote" (:edn paths))
    (println "[perf] wrote" (:json paths))
    (assoc result :result-paths paths)))

(defn -main [& args]
  (try
    (let [opts (parse-args args)]
      (if (:help? opts)
        (usage)
        (run-benchmarks! opts)))
    (finally
      (shutdown-agents))))
