(ns paclo.dev.dns-cli-perf
  "Same generated PCAP and complete CLI/output cost. Optional baseline directory
   contains dns_rtt.clj/dns_qps.clj extracted from the comparison commit.
   clojure -M:dev:dns-ext -m paclo.dev.dns-cli-perf [baseline-directory]"
  (:require
   [clojure.edn :as edn]
   [examples.common :as ex]
   [examples.dns-cli :as cli]
   [examples.dns-qps :as qps]
   [examples.dns-rtt :as rtt]
   [paclo.core :as core]
   [paclo.dev.perf-data :as data])
  (:import
   [com.sun.management ThreadMXBean]
   [java.io File Writer]
   [java.lang.management ManagementFactory MemoryPoolMXBean MemoryType]))

(defn- put-u16! [^bytes frame offset value]
  (aset-byte frame offset (unchecked-byte (bit-shift-right value 8)))
  (aset-byte frame (inc offset) (unchecked-byte value)))

(defn- frame [id response?]
  (let [labels [(str "q" id) "example"]
        question (byte-array (concat (mapcat #(cons (count %) (map int %)) labels) [0 0 1 0 1]))
        ba (data/ethernet-ipv4-frame (+ 54 (alength question)) :udp)]
    (put-u16! ba 34 (if response? 53 50000))
    (put-u16! ba 36 (if response? 50000 53))
    (when response?
      (doseq [offset (range 4)]
        (let [src (aget ba (+ 26 offset))]
          (aset-byte ba (+ 26 offset) (aget ba (+ 30 offset)))
          (aset-byte ba (+ 30 offset) src))))
    (put-u16! ba 42 id)
    (put-u16! ba 44 (if response? 32768 0))
    (put-u16! ba 46 1)
    (System/arraycopy question 0 ba 54 (alength question))
    ba))

(defn- generate! [path n]
  (core/write-pcap!
   (mapcat (fn [i] [{:bytes (frame i false) :ts-sec 1000 :ts-usec (* i 1000)}
                    {:bytes (frame i true) :ts-sec 1000 :ts-usec (+ (* i 1000) 100)}])
           (range n)) path))

(defn- allocations [^ThreadMXBean bean]
  (let [ids (.getAllThreadIds bean)]
    (into {} (map vector ids (.getThreadAllocatedBytes bean ids)))))

(defn- call-cli [f args]
  (let [sink (Writer/nullWriter) packets core/packets]
    ;; Normalize the legacy QPS capture default (100 packets) for equal input.
    ;; Do not change its analysis, result retention or output implementation.
    (with-redefs [core/packets (fn [opts] (packets (assoc opts :max Long/MAX_VALUE
                                                          :max-time-ms (quot Long/MAX_VALUE 2))))]
      (binding [*out* sink *err* sink] (apply f args)))))

(defn- measure [label f args]
  (let [^ThreadMXBean bean (ManagementFactory/getThreadMXBean)
        supported? (.isThreadAllocatedMemorySupported bean)
        pools (filter #(= MemoryType/HEAP (.getType ^MemoryPoolMXBean %))
                      (ManagementFactory/getMemoryPoolMXBeans))]
    (when supported? (.setThreadAllocatedMemoryEnabled bean true))
    (dotimes [_ 3] (call-cli f args))
    (dotimes [i 5]
      (doseq [^MemoryPoolMXBean pool pools] (.resetPeakUsage pool))
      (let [before (when supported? (allocations bean)) start (System/nanoTime)]
        (call-cli f args)
        (prn {:scenario label :run i :packets 1000 :qnames 500
              :ms (/ (- (System/nanoTime) start) 1000000.0)
              :live-thread-allocated-bytes
              (when supported? (reduce + (for [[id after] (allocations bean) :when (not (neg? after))]
                                           (max 0 (- after (max 0 (get before id 0)))))))
              :heap-pool-peak-used-bytes
              (reduce + (map #(.getUsed (.getPeakUsage ^MemoryPoolMXBean %)) pools))})))))

(defn- retention [path]
  (doseq [[label init step] [[:rtt-pairs rtt/init rtt/step] [:rtt-qstats rtt/init rtt/step] [:qps qps/init qps/step]]]
    (let [state (core/reduce-packets (cli/capture-options path "udp and port 53") step
                                     (init (if (= label :qps) {:group :qname} {:mode (if (= label :rtt-pairs) :pairs :qstats)})))
          small (dissoc state :analysis)
          a (:analysis state)]
      (prn {:retention label :pairs (:pairs state) :candidates (count (:candidates state))
            :samples (count (:samples state))
            :group-samples (reduce + (map #(count (:samples %)) (vals (:qstats state))))
            :qnames (count (:qstats state)) :output-rows (count (:rows state))
            :pending (count (:pending a)) :retired (count (:retired a))
            :windows (count (:windows a)) :window-groups (:group-count a)
            :retained-report-edn-characters (count (pr-str small))
            :retained-analysis-edn-characters (count (pr-str a))}))))

(defn -main [& [baseline]]
  (let [file (File/createTempFile "paclo-dns-cli-perf" ".pcap") path (.getAbsolutePath file)]
    (try
      (generate! path 500)
      (prn {:baseline baseline :scope :offline-cli-with-output :jdk (System/getProperty "java.version")
            :os (System/getProperty "os.name") :arch (System/getProperty "os.arch")
            :clojure (clojure-version) :warmups 3 :runs 5 :dropping false})
      (when baseline
        (load-file (str baseline "/dns_rtt.clj"))
        (load-file (str baseline "/dns_qps.clj")))
      (doseq [async? [false true]
              [label f args] [[:rtt-pairs rtt/-main [path "_" "50" "pairs" "_" "edn"]]
                              [:rtt-qstats rtt/-main [path "_" "50" "qstats" "p95" "edn"]]
                              [:qps qps/-main [path "_" "1000" "qname" "edn"]]]]
        (measure [label async?] f (concat args (when async? ["--async" "--async-buffer" "1"]))))
      (when-not baseline
        (retention path)
        (let [output (edn/read-string (with-out-str (qps/-main path "_" "1000" "qname" "edn")))
              sink (Writer/nullWriter)]
          (dotimes [_ 3] (binding [*out* sink] (ex/emit :edn output)))
          (let [start (System/nanoTime)]
            (dotimes [_ 100] (binding [*out* sink] (ex/emit :edn output)))
            (prn {:output-only-iterations 100 :rows (count output)
                  :ms (/ (- (System/nanoTime) start) 1000000.0)}))))
      (finally (.delete file) (shutdown-agents)))))
