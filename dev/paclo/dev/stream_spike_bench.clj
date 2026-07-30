(ns paclo.dev.stream-spike-bench
  "Repeatable benchmark for the internal v1.3 stream experiment."
  (:require
   [clojure.java.io :as io]
   [paclo.dev.perf-metrics :as metrics]
   [paclo.dev.stream-spike :as spike])
  (:import
   [java.io Closeable]))

(def ^:private default-count 200000)
(def ^:private default-runs 3)
(def ^:private default-warmups 1)
(def ^:private buffer-cap 4096)

(defn- parse-positive-long [flag value]
  (let [parsed (Long/parseLong value)]
    (when-not (pos? parsed)
      (throw (ex-info (str flag " must be positive")
                      {:flag flag
                       :value value})))
    parsed))

(defn- parse-non-negative-long [flag value]
  (let [parsed (Long/parseLong value)]
    (when (neg? parsed)
      (throw (ex-info (str flag " must be non-negative")
                      {:flag flag
                       :value value})))
    parsed))

(defn- parse-args [args]
  (loop [opts {:count default-count
               :runs default-runs
               :warmups default-warmups
               :output nil}
         remaining args]
    (if-let [flag (first remaining)]
      (let [value (second remaining)]
        (when-not value
          (throw (ex-info "missing stream spike benchmark option value"
                          {:flag flag})))
        (recur
         (case flag
           "--count"
           (assoc opts :count (parse-positive-long flag value))

           "--runs"
           (assoc opts :runs (parse-positive-long flag value))

           "--warmups"
           (assoc opts :warmups (parse-non-negative-long flag value))

           "--output"
           (assoc opts :output value)

           (throw (ex-info "unknown stream spike benchmark option"
                           {:flag flag})))
         (nnext remaining)))
      opts)))

(defn- expected-sum [^long count]
  (quot (unchecked-multiply count (unchecked-dec count)) 2))

(defn- sum-values [values]
  (reduce
   (fn [^long total value]
     (unchecked-add total (long value)))
   0
   values))

(defn- direct-run [count]
  (let [checksum (sum-values (range count))]
    (when-not (= (expected-sum count) checksum)
      (throw (ex-info "direct stream spike checksum mismatch"
                      {:expected (expected-sum count)
                       :actual checksum})))
    {:packets count
     :bytes 0
     :checksum checksum}))

(defn- single-branch-run [backend count]
  (with-open [^Closeable fanout
              (spike/fan-out
               (range count)
               {:primary {:buffer-cap buffer-cap
                          :buffer-mode :blocking}}
               {:backend backend})
              ^Closeable primary
              (spike/branch fanout :primary)]
    (let [checksum (sum-values primary)]
      (when-not (= (expected-sum count) checksum)
        (throw (ex-info "single branch checksum mismatch"
                        {:backend backend
                         :expected (expected-sum count)
                         :actual checksum})))
      {:packets count
       :bytes 0
       :checksum checksum
       :stream-stats (spike/stats fanout)})))

(defn- dual-branch-run [backend count]
  (with-open [^Closeable fanout
              (spike/fan-out
               (range count)
               {:left {:buffer-cap buffer-cap
                       :buffer-mode :blocking}
                :right {:buffer-cap buffer-cap
                        :buffer-mode :blocking}}
               {:backend backend})
              ^Closeable left
              (spike/branch fanout :left)
              ^Closeable right
              (spike/branch fanout :right)]
    (let [left-result (future (sum-values left))
          right-result (future (sum-values right))
          expected (expected-sum count)
          left-sum @left-result
          right-sum @right-result]
      (when-not (= [expected expected] [left-sum right-sum])
        (throw (ex-info "dual branch checksum mismatch"
                        {:backend backend
                         :expected expected
                         :left left-sum
                         :right right-sum})))
      {:packets count
       :bytes 0
       :checksum left-sum
       :secondary-checksum right-sum
       :stream-stats (spike/stats fanout)})))

(defn- slow-dropping-run [backend count]
  (with-open [^Closeable fanout
              (spike/fan-out
               (range count)
               {:fast {:buffer-cap buffer-cap
                       :buffer-mode :blocking}
                :slow {:buffer-cap 64
                       :buffer-mode :dropping}}
               {:backend backend})
              ^Closeable fast
              (spike/branch fanout :fast)
              ^Closeable slow
              (spike/branch fanout :slow)]
    (let [fast-checksum (sum-values fast)]
      (when-not (= (expected-sum count) fast-checksum)
        (throw (ex-info "fast branch checksum mismatch"
                        {:backend backend
                         :expected (expected-sum count)
                         :actual fast-checksum})))
      (when-not (spike/await! fanout)
        (throw (ex-info "slow dropping stream spike did not finish"
                        {:backend backend})))
      (let [slow-delivered (reduce (fn [^long count* _]
                                     (unchecked-inc count*))
                                   0
                                   slow)
            stream-stats (spike/stats fanout)]
        {:packets count
         :bytes 0
         :checksum fast-checksum
         :slow-delivered slow-delivered
         :slow-dropped
         (get-in stream-stats [:branches :slow :dropped])
         :stream-stats stream-stats}))))

(def ^:private scenarios
  [{:id :direct
   :run (fn [_ count] (direct-run count))}
   {:id :jdk-array-single
    :run (fn [_ count] (single-branch-run :jdk-array count))}
   {:id :jdk-linked-single
    :run (fn [_ count] (single-branch-run :jdk-linked count))}
   {:id :core-async-single
    :run (fn [_ count] (single-branch-run :core-async count))}
   {:id :jdk-array-dual
    :run (fn [_ count] (dual-branch-run :jdk-array count))}
   {:id :jdk-linked-dual
    :run (fn [_ count] (dual-branch-run :jdk-linked count))}
   {:id :core-async-dual
    :run (fn [_ count] (dual-branch-run :core-async count))}
   {:id :jdk-array-slow-dropping
    :run (fn [_ count] (slow-dropping-run :jdk-array count))}
   {:id :jdk-linked-slow-dropping
    :run (fn [_ count] (slow-dropping-run :jdk-linked count))}
   {:id :core-async-slow-dropping
    :run (fn [_ count] (slow-dropping-run :core-async count))}])

(defn- scenario-results [{:keys [id run]} {:keys [count warmups runs]}]
  (println "[stream-spike]" (name id))
  (dotimes [_ warmups]
    (run id count))
  (let [measurements
        (vec
         (for [_ (range runs)]
           (metrics/measure #(run id count))))]
    {:scenario id
     :runs measurements
     :summary (metrics/summarize-runs measurements)}))

(defn run-benchmark! [opts]
  {:schema-version 1
   :experiment :v1.3-stream-spike
   :config (select-keys opts [:count :runs :warmups])
   :environment (metrics/environment)
   :results (mapv #(scenario-results % opts) scenarios)})

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
        (println "[stream-spike] wrote" (write-result! output result))
        (prn result)))
    (finally
      (shutdown-agents))))
