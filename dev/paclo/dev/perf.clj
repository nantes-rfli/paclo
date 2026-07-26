(ns paclo.dev.perf
  "Phase-1 performance runner for offline and loopback-live benchmarks."
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
  [:live-raw :live-raw-buffered :live-raw-immediate :live-full])

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
  (println)
  (println "The default is the offline quick profile."))

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
          (throw (ex-info "unknown or incomplete argument"
                          {:remaining remaining})))))))

(defn- validate-opts! [{:keys [mode profile port]}]
  (when-not (contains? #{:offline :live :all} mode)
    (throw (ex-info "mode must be offline, live, or all" {:mode mode})))
  (when-not (contains? data/profiles profile)
    (throw (ex-info "unknown profile" {:profile profile})))
  (when-not (<= 1 (long port) 65535)
    (throw (ex-info "port must be between 1 and 65535" {:port port}))))

(defn- worker!
  [arguments]
  (let [{:keys [exit out err]}
        (apply shell/sh "clojure" "-M:perf-worker" arguments)]
    (when-not (zero? exit)
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
                        cause))))))

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
              (nil? (:capture-stats run)))
      (throw (ex-info "live benchmark did not collect clean capture statistics"
                      {:scenario (:scenario result)
                       :capture-errors (:capture-errors run)
                       :capture-stats (:capture-stats run)}))))
  result)

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

(defn- live-results!
  [{:keys [profile device port]}]
  (let [{:keys [rates duration-ms warmups runs]} (get live-profiles profile)]
    (vec
     (for [rate rates
           scenario live-scenarios
           :let [senders (min 8
                              (max 1
                                   (long
                                    (Math/ceil
                                     (/ (double rate) 100000.0)))))]]
       (do
         (println "[perf] live" device (name scenario)
                  "target-pps=" rate "senders=" senders)
         (validate-live-result!
          (worker! ["--mode" "live"
                    "--scenario" (name scenario)
                    "--device" device
                    "--port" (str port)
                    "--target-pps" (str rate)
                    "--duration-ms" (str duration-ms)
                    "--frame-size" "64"
                    "--senders" (str senders)
                    "--warmups" (str warmups)
                    "--runs" (str runs)])))))))

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
  (let [result {:schema-version 1
                :created-at (str (Instant/now))
                :profile profile
                :offline (when (#{:offline :all} mode)
                           (offline-results! opts))
                :live (when (#{:live :all} mode)
                        (live-results! opts))}
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
