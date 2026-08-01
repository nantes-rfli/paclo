(ns paclo.dev.stream-combined-bench
  "Offline managed-capture plus production fan-out benchmark for v1.3 gates."
  (:require
   [clojure.java.io :as io]
   [paclo.core :as core]
   [paclo.dev.perf-data :as data]
   [paclo.dev.perf-metrics :as metrics]
   [paclo.stream.impl :as stream])
  (:import
   [java.io Closeable]))

(def ^:private default-count 200000)
(def ^:private default-runs 5)
(def ^:private default-warmups 3)
(def ^:private default-queue-cap 4096)
(def ^:private default-branch-cap 4096)
(def ^:private default-slow-cap 64)

(defn- parse-positive-long [flag value]
  (let [parsed (Long/parseLong value)]
    (when-not (pos? parsed)
      (throw (ex-info (str flag " must be positive")
                      {:flag flag :value value})))
    parsed))

(defn- parse-non-negative-long [flag value]
  (let [parsed (Long/parseLong value)]
    (when (neg? parsed)
      (throw (ex-info (str flag " must be non-negative")
                      {:flag flag :value value})))
    parsed))

(defn- parse-args [args]
  (loop [opts {:count default-count
               :runs default-runs
               :warmups default-warmups
               :queue-cap default-queue-cap
               :branch-cap default-branch-cap
               :slow-cap default-slow-cap
               :scenario nil
               :output nil}
         remaining args]
    (if-let [flag (first remaining)]
      (let [value (second remaining)]
        (when-not value
          (throw (ex-info "missing combined benchmark option value"
                          {:flag flag})))
        (recur
         (case flag
           "--count"
           (assoc opts :count (parse-positive-long flag value))

           "--runs"
           (assoc opts :runs (parse-positive-long flag value))

           "--warmups"
           (assoc opts :warmups (parse-non-negative-long flag value))

           "--queue-cap"
           (assoc opts :queue-cap (parse-positive-long flag value))

           "--branch-cap"
           (assoc opts :branch-cap (parse-positive-long flag value))

           "--slow-cap"
           (assoc opts :slow-cap (parse-positive-long flag value))

           "--scenario"
           (assoc opts :scenario (keyword value))

           "--output"
           (assoc opts :output value)

           (throw (ex-info "unknown combined benchmark option"
                           {:flag flag})))
         (nnext remaining)))
      opts)))

(defn- count-values [values]
  (reduce
   (fn [^long count* _]
     (unchecked-inc count*))
   0
   values))

(defn- capture-opts [path {:keys [count queue-cap]}]
  {:path path
   :max count
   :max-time-ms 60000
   :queue-cap queue-cap
   :queue-mode :blocking})

(defn- blocking-branches [{:keys [branch-cap]}]
  {:left {:buffer-mode :blocking :buffer-cap branch-cap}
   :right {:buffer-mode :blocking :buffer-cap branch-cap}})

(defn- dropping-branches [{:keys [branch-cap slow-cap]}]
  {:fast {:buffer-mode :blocking :buffer-cap branch-cap}
   :slow {:buffer-mode :dropping :buffer-cap slow-cap}})

(defn- check-count! [scenario branch expected actual]
  (when-not (= expected actual)
    (throw (ex-info "combined benchmark packet count mismatch"
                    {:scenario scenario
                     :branch branch
                     :expected expected
                     :actual actual}))))

(defn- managed-control-run [path {:keys [count] :as opts}]
  (with-open [^Closeable capture
              (core/start-capture (capture-opts path opts))]
    (let [actual (count-values (core/capture-packets capture))]
      (check-count! :managed-control :consumer count actual)
      {:packets count
       :bytes (unchecked-multiply (long count) 64)
       :consumer-count actual
       :capture-stats (core/capture-stats capture)})))

(defn- dual-run [path {:keys [count] :as opts}]
  (with-open [^Closeable capture (core/start-capture (capture-opts path opts))
              ^Closeable fanout
              (stream/start
               (core/capture-packets capture)
               (blocking-branches opts)
               {:cancel! #(core/stop-capture! capture)})
              ^Closeable left (stream/branch fanout :left)
              ^Closeable right (stream/branch fanout :right)]
    (let [left-task (future (count-values left))
          right-task (future (count-values right))
          left-count @left-task
          right-count @right-task]
      (check-count! :dual :left count left-count)
      (check-count! :dual :right count right-count)
      {:packets count
       :bytes (unchecked-multiply (long count) 64)
       :left-count left-count
       :right-count right-count
       :capture-stats (core/capture-stats capture)
       :stream-stats (stream/stats fanout)})))

(defn- dropping-run [path {:keys [count] :as opts}]
  (with-open [^Closeable capture (core/start-capture (capture-opts path opts))
              ^Closeable fanout
              (stream/start
               (core/capture-packets capture)
               (dropping-branches opts)
               {:cancel! #(core/stop-capture! capture)})
              ^Closeable fast (stream/branch fanout :fast)
              ^Closeable slow (stream/branch fanout :slow)]
    (let [fast-count (count-values fast)
          _ (when-not (stream/await! fanout)
              (throw (ex-info "combined dropping dispatcher timed out" {})))
          slow-count (count-values slow)
          stream-stats (stream/stats fanout)]
      (check-count! :slow-dropping :fast count fast-count)
      {:packets count
       :bytes (unchecked-multiply (long count) 64)
       :fast-count fast-count
       :slow-count slow-count
       :slow-dropped (get-in stream-stats [:branches :slow :dropped])
       :capture-stats (core/capture-stats capture)
       :stream-stats stream-stats})))

(def ^:private scenarios
  [{:id :managed-offline-control
    :run managed-control-run}
   {:id :managed-offline-dual
    :run dual-run}
   {:id :managed-offline-slow-dropping
    :run dropping-run}])

(defn- selected-scenarios [{:keys [scenario]}]
  (if scenario
    (let [matches (filterv #(= scenario (:id %)) scenarios)]
      (when-not (seq matches)
        (throw (ex-info "unknown combined benchmark scenario"
                        {:scenario scenario
                         :supported (set (map :id scenarios))})))
      matches)
    scenarios))

(defn- scenario-result [path {:keys [id run]} {:keys [warmups runs] :as opts}]
  (println "[stream-combined]" (name id))
  (dotimes [_ warmups]
    (run path opts))
  (let [measurements
        (mapv
         (fn [_]
           (metrics/measure #(run path opts)))
         (range runs))]
    {:scenario id
     :runs measurements
     :summary (metrics/summarize-runs measurements)}))

(defn- write-fixture! [path count]
  (core/write-pcap!
   (repeat count (data/ethernet-ipv4-frame 64 :udp))
   path))

(defn run-benchmark! [opts]
  (let [file (java.io.File/createTempFile "paclo-stream-combined" ".pcap")
        path (.getAbsolutePath file)]
    (try
      (println "[stream-combined] fixture" path "packets" (:count opts))
      (write-fixture! path (:count opts))
      {:schema-version 1
       :experiment :v1.3-stream-combined-offline
       :config (dissoc opts :output)
       :environment (metrics/environment)
       :results (mapv #(scenario-result path % opts)
                      (selected-scenarios opts))}
      (finally
        (when (.exists file)
          (.delete file))))))

(defn- write-result! [path result]
  (let [file (io/file path)]
    (when-let [parent (.getParentFile file)]
      (.mkdirs parent))
    (spit file (str (pr-str result) "\n"))
    (.getAbsolutePath file)))

(defn -main [& args]
  (try
    (let [{:keys [output] :as opts} (parse-args args)
          result (run-benchmark! opts)]
      (if output
        (println "[stream-combined] wrote" (write-result! output result))
        (prn result)))
    (finally
      (shutdown-agents))))
