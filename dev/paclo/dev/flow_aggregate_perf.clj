(ns paclo.dev.flow-aggregate-perf
  "Paired exact aggregation comparison (no capture throughput claim).
   clojure -J-Xms512m -J-Xmx512m -M:dev -m paclo.dev.flow-aggregate-perf e069657
   Second argument filters names or selects profile-baseline/profile-current.
   Select key-reuse for boundary, mixed-revisit and all-new coverage.
   Optional third writes a JFR; profile runs are separate from timing comparisons."
  (:require
   [clojure.java.io :as io]
   [clojure.java.shell :as shell]
   [clojure.string :as str]
   [paclo.core :as core]
   [paclo.dev.perf-metrics :as metrics]
   [paclo.flow :as flow])
  (:import
   [com.sun.management ThreadMXBean]
   [java.io File]
   [java.lang.management ManagementFactory]
   [java.nio.file Paths]
   [java.time Duration]
   [jdk.jfr Recording]))

(def ^:private packet-count 100000)
(def ^:private warmups 10)
(def ^:private runs 9)

(defn- baseline [ref]
  (let [{:keys [exit out err]} (if (.isFile (io/file ref))
                                 {:exit 0 :out (slurp ref)}
                                 (shell/sh "git" "show" (str ref ":src/paclo/flow.clj")))]
    (when-not (zero? exit) (throw (ex-info "cannot read baseline" {:ref ref :error err})))
    (load-string (str/replace-first out "(ns paclo.flow" "(ns paclo.dev.aggregate-baseline"))
    (ns-resolve 'paclo.dev.aggregate-baseline 'aggregate-rf)))

(defn- reverse-packet [p]
  (assoc p :src-ip (:dst-ip p) :src-port (:dst-port p)
         :dst-ip (:src-ip p) :dst-port (:src-port p)))

(defn- synthetic [version cardinality]
  (mapv (fn [i]
          {:ip-version version :protocol 17
           :src-ip (if (= 4 version) (+ 167772161 i) [-1 i]) :src-port 12000
           :dst-ip (if (= 4 version) 167772160 [0 -1]) :dst-port 53
           :caplen 64 :len 84})
        (range cardinality)))

(defn- read-pcap [path mode]
  (core/reduce-packets {:path path :decode-mode mode :max Long/MAX_VALUE}
                       conj []))

(defn- scenarios [key-reuse?]
  (concat
   (for [version [4 6] cardinality (if key-reuse? [7 8 9 10 10000 25000 50000 75000 100000] [10 10000])]
     {:name (str "ipv" version "-" cardinality) :scope :aggregation-only :max-flows cardinality
      :inputs (synthetic version cardinality) :alternate-reversal? true})
   (when key-reuse?
     [{:name "ipv4-hotset" :scope :aggregation-only :max-flows 10000
       :inputs (synthetic 4 10000) :hotset? true :alternate-reversal? true}])
   (for [path ["test/resources/dns-sample.pcap" "test/resources/cooked/sll2.pcap"]
         mode [:flow nil]]
     {:name (str path (if mode "-projected" "-decode"))
      :scope (if mode :pcap-projection-replay :pcap-bytes-decode-replay)
      :path path :inputs (read-pcap path mode) :decode? (nil? mode)})))

(defn- expand-inputs [inputs alternate-reversal? hotset?]
  (let [n (count inputs)]
    (when (zero? n) (throw (ex-info "empty benchmark input" {})))
    (mapv (fn [i]
            (let [index (if hotset?
                          (if (zero? (mod i 10)) (+ 100 (mod (quot i 10) (- n 100))) (mod (quot i 10) 100))
                          (mod i n))
                  p (nth inputs index)]
              (if (and alternate-reversal? (odd? (quot i n))) (reverse-packet p) p)))
          (range packet-count))))

(defn- gc-state []
  (reduce (fn [acc bean]
            (-> acc (update :count + (.getCollectionCount bean))
                (update :ms + (.getCollectionTime bean))))
          {:count 0 :ms 0} (ManagementFactory/getGarbageCollectorMXBeans)))

(defn- sample [run inputs expected]
  (let [^ThreadMXBean bean (ManagementFactory/getThreadMXBean)
        gc-before (gc-state)
        allocated (.getCurrentThreadAllocatedBytes bean)
        cpu (.getCurrentThreadCpuTime bean)
        start (System/nanoTime)
        result (run inputs)
        elapsed (- (System/nanoTime) start)
        cpu (- (.getCurrentThreadCpuTime bean) cpu)
        allocated (- (.getCurrentThreadAllocatedBytes bean) allocated)
        gc-after (gc-state)]
    ;; Compare the complete result after stopping all measured counters.
    (when-not (= expected result) (throw (ex-info "measured result mismatch" {})))
    {:equal? true :ns elapsed :cpu-ns cpu :allocated allocated
     :gc-count (- (:count gc-after) (:count gc-before))
     :gc-ms (- (:ms gc-after) (:ms gc-before))
     :summary (:summary result) :flows (count (:flows result))}))

(defn- used-heap []
  (dotimes [_ 2] (System/gc) (Thread/sleep 75))
  (let [runtime (Runtime/getRuntime)] (- (.totalMemory runtime) (.freeMemory runtime))))

(defn- retained [run inputs]
  ;; Amplify to about 100k entries; keep the exact inputs alive across both GCs.
  ;; Each result is independent. Shared immutable input endpoints are excluded.
  (let [expected (run inputs)
        flows (count (:flows expected))
        copies (max 2 (quot 100000 (max 1 flows)))
        owner (atom inputs)
        before (used-heap)
        results (mapv (fn [_] (run @owner)) (range copies))
        after (used-heap)
        entries (reduce + (map #(count (:flows %)) results))]
    {:estimated-retained-bytes-per-flow (/ (double (- after before)) (max 1 entries))
     :retained-flows entries :inputs-reachable? (identical? inputs @owner)
     :results-equal? (every? #(= expected %) results)}))

(defn- report [samples]
  (let [median metrics/median]
    {:packets-per-second (/ (* 1e9 packet-count) (double (median (map :ns samples))))
     :allocation-bytes-per-packet (/ (double (median (map :allocated samples))) packet-count)
     :thread-cpu-ns-per-packet (/ (double (median (map :cpu-ns samples))) packet-count)
     :gc-count (reduce + (map :gc-count samples))
     :gc-ms (reduce + (map :gc-ms samples))
     :samples samples}))

(defn- compare-scenario [constructors {:keys [name inputs decode? alternate-reversal?] :as scenario} direction]
  (let [expanded (expand-inputs inputs (and alternate-reversal? (= direction :bidir)) (:hotset? scenario))
        opts {:max-flows (or (:max-flows scenario) packet-count) :direction direction}
        variants (mapv (fn [[implementation constructor]]
                         (let [rf (constructor opts)
                               xf (if decode? (core/packet-xf {:decode-mode :flow}) identity)]
                           {:implementation implementation
                            :run (if-let [path (:native-path scenario)]
                                   (fn [_] (core/reduce-packets
                                            {:path path :decode-mode :flow :max Long/MAX_VALUE}
                                            rf (rf)))
                                   #(transduce xf rf %))
                            :retained-run #(transduce xf rf %)})) constructors)
        expected ((:run (first variants)) expanded)
        samples (atom {})]
    (doseq [{:keys [run]} variants]
      (when-not (= expected (run expanded))
        (throw (ex-info "baseline/current mismatch" {:scenario name :direction direction}))))
    (dotimes [_ warmups] (doseq [{:keys [run]} variants] (run expanded)))
    (dotimes [round runs]
      (doseq [{:keys [implementation run]} (if (even? round) variants (reverse variants))]
        (swap! samples update implementation (fnil conj []) (sample run expanded expected))))
    (doseq [{:keys [implementation retained-run]} variants]
      (println (pr-str (merge (select-keys scenario [:name :scope :path])
                              {:direction direction :implementation implementation :equal? true}
                              (report (get @samples implementation))
                              (retained retained-run inputs))))
      (flush))))

(defn- compare-native [constructors key-reuse?]
  (doseq [[name path linktype] (if key-reuse?
                                 [["dns" "test/resources/dns-sample.pcap" 1]
                                  ["sll2" "test/resources/cooked/sll2.pcap" 276]]
                                 [["dns" "test/resources/dns-sample.pcap" 1]])]
    (let [file (File/createTempFile "paclo-flow-perf-" ".pcap")]
      (try
      ;; Repeat actual fixture bytes; the same generated file serves both reducers.
        (core/write-pcap! (take packet-count (cycle (read-pcap path nil)))
                          (.getAbsolutePath file) {:linktype linktype})
        (doseq [direction [:unidir :bidir]]
          (compare-scenario constructors
                            {:name (str name "-native-replay") :scope :native-read-decode-aggregate
                             :path path :native-path (.getAbsolutePath file)
                             :inputs (read-pcap path :flow)} direction))
        (finally
          (when-not (.delete file)
            (throw (ex-info "cannot delete benchmark capture" {:path (.getAbsolutePath file)}))))))))

(defn- profile-run [constructor]
  ;; Separate from timed comparisons: stack collection perturbs execution.
  ;; Portable fallback when JFR execution sampling is unavailable on the host.
  (let [inputs (synthetic 6 10000)
        rf (constructor {:max-flows 10000 :direction :bidir})
        thread (Thread/currentThread)
        running (atom true)
        samples (atom [])]
    (dotimes [_ 20] (reduce rf (rf) inputs))
    (let [sampler (future
                    (while @running
                      (swap! samples conj (mapv str (.getStackTrace thread)))
                      (Thread/sleep 2)))]
      (try
        (dotimes [_ 1000] (reduce rf (rf) inputs))
        (finally (reset! running false) @sampler)))
    (println (pr-str {:sample-count (count @samples) :packets 10000000
                      :scenario :ipv6-10000-bidir :scope :perturbed-stack-sampling
                      :top-frames (take 35 (sort-by val > (frequencies (map first @samples))))
                      :flow-inclusive
                      (take 20 (sort-by val >
                                        (frequencies
                                         (keep #(first (filter (fn [frame]
                                                                 (or (str/includes? frame "paclo.flow$")
                                                                     (str/includes? frame "aggregate_baseline$"))) %))
                                               @samples))))}))))

(defn -main [& [ref selected jfr-path]]
  (try
    (let [ref (or ref "e069657")
          baseline-rf (baseline ref)
          ^ThreadMXBean bean (ManagementFactory/getThreadMXBean)]
      (when-not (and (.isThreadAllocatedMemorySupported bean) (.isCurrentThreadCpuTimeSupported bean))
        (throw (ex-info "allocation/CPU measurement unavailable" {})))
      (.setThreadAllocatedMemoryEnabled bean true)
      (.setThreadCpuTimeEnabled bean true)
      (println (pr-str {:baseline ref :environment (metrics/environment)
                        :packets packet-count :warmups warmups :runs runs
                        :order :alternating :drops 0
                        :pcap-note "Finite fixture replay; only native row includes I/O; decode rows include packet-xf."
                        :retained-scope :independent-seed-states-excluding-shared-inputs}))
      (with-open [recording (Recording.)]
        (when jfr-path
          (doto (.enable recording "jdk.ExecutionSample") (.withPeriod (Duration/ofMillis 10)))
          (.withStackTrace (.enable recording "jdk.ObjectAllocationSample"))
          (.enable recording "jdk.GarbageCollection")
          (.start recording))
        (if (contains? #{"profile-baseline" "profile-current"} selected)
          (profile-run (if (= selected "profile-baseline") baseline-rf flow/aggregate-rf))
          (let [constructors [[:baseline baseline-rf] [:current flow/aggregate-rf]]
                key-reuse? (= selected "key-reuse")]
            (doseq [scenario (scenarios key-reuse?) :when (or key-reuse? (nil? selected) (str/includes? (:name scenario) selected))
                    direction [:unidir :bidir]]
              (compare-scenario constructors scenario direction))
            (when (or key-reuse? (nil? selected) (= "native" selected))
              (compare-native constructors key-reuse?))))
        (when jfr-path
          (.stop recording)
          (.dump recording (Paths/get jfr-path (make-array String 0))))))
    (finally (shutdown-agents))))
