(ns paclo.dev.flow-perf
  "Reproducible opt-in comparison with the pre-P06 CLI aggregate.
   clojure -M:dev -m paclo.dev.flow-perf 7711170
   Uses numeric synthetic inputs; this is not native capture throughput."
  (:require
   [clojure.java.shell :as shell]
   [clojure.string :as str]
   [paclo.flow :as flow])
  (:import
   [com.sun.management ThreadMXBean]
   [java.lang.management ManagementFactory]
   [java.util HashMap]))

(defn- used-heap []
  (System/gc)
  (Thread/sleep 50)
  (let [runtime (Runtime/getRuntime)]
    (- (.totalMemory runtime) (.freeMemory runtime))))

(defn- inputs [cardinality]
  (let [flows (mapv (fn [i]
                      {:ip-version 4 :protocol 17
                       :src-ip (+ 167772161 i) :src-port 12000
                       :dst-ip 167772160 :dst-port 53
                       :caplen 64 :len 84})
                    (range cardinality))]
    (mapv #(nth flows (mod % cardinality)) (range 100000))))

(defn- median [xs]
  (nth (vec (sort xs)) (quot (count xs) 2)))

(defn- measure [run packets cardinality]
  (dotimes [_ 3] (run packets))
  (let [^ThreadMXBean bean (ManagementFactory/getThreadMXBean)
        supported? (.isThreadAllocatedMemorySupported bean)
        _ (when supported? (.setThreadAllocatedMemoryEnabled bean true))
        measurements
        (doall
         (for [_ (range 5)]
           (let [before (when supported? (.getCurrentThreadAllocatedBytes bean))
                 start (System/nanoTime)
                 result (run packets)
                 elapsed (- (System/nanoTime) start)
                 allocated (when supported? (- (.getCurrentThreadAllocatedBytes bean) before))]
             {:ns elapsed :allocated allocated :flows (count result)})))
        ;; Hold inputs across both GC measurements; retain 100000 flow entries.
        ;; Memory experiment uses one packet/key, separate from throughput runs.
        input-owner (atom packets)
        unique-inputs (vec (take cardinality packets))
        copies (max 10 (quot 100000 cardinality))
        before (used-heap)
        retained (mapv (fn [_] (run unique-inputs)) (range copies))
        after (used-heap)
        kept-flows (reduce + (map count retained))]
    {:flows cardinality :verified-retained-flows kept-flows
     :input-retained? (identical? @input-owner packets)
     :packets-per-second (/ 1e14 (double (median (map :ns measurements))))
     :allocation-bytes-per-packet (when supported?
                                    (/ (double (median (map :allocated measurements))) 100000))
     :estimated-retained-bytes-per-flow (/ (double (- after before)) kept-flows)}))

(defn -main [& [baseline-ref]]
  (try
    (let [baseline-ref (or baseline-ref "7711170")
          {:keys [exit out err]} (shell/sh "git" "show" (str baseline-ref ":dev/examples/flow_topn.clj"))]
      (when-not (zero? exit) (throw (ex-info "cannot load baseline" {:error err})))
      ;; Load the historical implementation only for this opt-in benchmark.
      (load-string (str/replace-first out "(ns examples.flow-topn" "(ns paclo.dev.flow-baseline"))
      (let [legacy-add (requiring-resolve 'paclo.dev.flow-baseline/add-packet!)]
        (println (pr-str {:baseline baseline-ref :jdk (System/getProperty "java.version")
                          :clojure (clojure-version) :os (System/getProperty "os.name")
                          :arch (System/getProperty "os.arch") :packets 100000 :warmups 3 :runs 5
                          :scope :aggregation-only :drops 0}))
        (doseq [cardinality [10 10000]
                direction [:unidir :bidir]
                implementation [:legacy :persistent]]
          (let [packets (inputs cardinality)
                rf (flow/aggregate-rf {:max-flows cardinality :direction direction})
                run (if (= :legacy implementation)
                      (fn [ps]
                        (let [counts (HashMap.)]
                          (doseq [p ps] (legacy-add counts p (= :bidir direction)))
                          counts))
                      (fn [ps] (:flows (reduce rf (rf) ps))))]
            (println (pr-str (assoc (measure run packets cardinality)
                                    :direction direction :implementation implementation)))))))
    (finally (shutdown-agents))))
