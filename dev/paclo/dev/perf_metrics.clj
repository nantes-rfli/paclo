(ns paclo.dev.perf-metrics
  "Low-overhead JVM and throughput measurements for performance scenarios."
  (:require
   [clojure.java.shell :as shell]
   [clojure.string :as str])
  (:import
   [com.sun.management OperatingSystemMXBean ThreadMXBean]
   [java.lang.management ManagementFactory MemoryPoolMXBean MemoryType]
   [paclo.jnr PcapLibrary]))

(defn- gc-snapshot []
  (reduce
   (fn [acc bean]
     (let [count (.getCollectionCount bean)
           time-ms (.getCollectionTime bean)]
       (-> acc
           (update :count + (max 0 count))
           (update :time-ms + (max 0 time-ms)))))
   {:count 0 :time-ms 0}
   (ManagementFactory/getGarbageCollectorMXBeans)))

(defn- reset-heap-peaks! []
  (doseq [^MemoryPoolMXBean pool (ManagementFactory/getMemoryPoolMXBeans)]
    (when (= MemoryType/HEAP (.getType pool))
      (try
        (.resetPeakUsage pool)
        (catch UnsupportedOperationException _))))
  nil)

(defn- heap-peak-bytes []
  (reduce
   (fn [total ^MemoryPoolMXBean pool]
     (if (= MemoryType/HEAP (.getType pool))
       (let [usage (.getPeakUsage pool)]
         (+ total (max 0 (.getUsed usage))))
       total))
   0
   (ManagementFactory/getMemoryPoolMXBeans)))

(defn- allocation-snapshot []
  (try
    (let [bean (ManagementFactory/getThreadMXBean)]
      (when (instance? ThreadMXBean bean)
        (let [^ThreadMXBean thread-bean bean]
          (when (.isThreadAllocatedMemorySupported thread-bean)
            (when-not (.isThreadAllocatedMemoryEnabled thread-bean)
              (.setThreadAllocatedMemoryEnabled thread-bean true))
            (into {}
                  (keep
                   (fn [thread-id]
                     (let [allocated (.getThreadAllocatedBytes thread-bean thread-id)]
                       (when-not (neg? allocated)
                         [thread-id allocated]))))
                  (.getAllThreadIds thread-bean))))))
    (catch Throwable _
      nil)))

(defn- allocation-delta [before after]
  (when (and before after)
    (reduce-kv
     (fn [total thread-id allocated]
       (+ total (max 0 (- allocated (long (get before thread-id 0))))))
     0
     after)))

(defn- process-cpu-ns []
  (try
    (let [bean (ManagementFactory/getOperatingSystemMXBean)]
      (when (instance? OperatingSystemMXBean bean)
        (let [value (.getProcessCpuTime ^OperatingSystemMXBean bean)]
          (when-not (neg? value) value))))
    (catch Throwable _
      nil)))

(defn measure
  "Measure one invocation of `f`.

   `f` must return at least `{:packets n :bytes n}`. Additional result fields
   are preserved."
  [f]
  (System/gc)
  (Thread/sleep 25)
  (reset-heap-peaks!)
  (let [gc-before (gc-snapshot)
        allocation-before (allocation-snapshot)
        cpu-before (process-cpu-ns)
        started (System/nanoTime)
        result (f)
        elapsed (- (System/nanoTime) started)
        cpu-after (process-cpu-ns)
        allocation-after (allocation-snapshot)
        gc-after (gc-snapshot)
        packets (long (:packets result))
        bytes (long (:bytes result))
        seconds (/ (double elapsed) 1.0e9)]
    (merge
     result
     {:elapsed-ns elapsed
      :packets-per-sec (if (pos? seconds) (/ packets seconds) 0.0)
      :mb-per-sec (if (pos? seconds) (/ bytes seconds 1000000.0) 0.0)
      :ns-per-packet (if (pos? packets) (/ (double elapsed) packets) 0.0)
      :allocated-bytes (allocation-delta allocation-before allocation-after)
      :allocated-bytes-per-packet
      (when-let [allocated (allocation-delta allocation-before allocation-after)]
        (if (pos? packets) (/ (double allocated) packets) 0.0))
      :gc-count (- (:count gc-after) (:count gc-before))
      :gc-time-ms (- (:time-ms gc-after) (:time-ms gc-before))
      :heap-peak-bytes (heap-peak-bytes)
      :process-cpu-ns (when (and cpu-before cpu-after)
                        (- cpu-after cpu-before))})))

(defn median
  "Return the median of numeric values, or nil for an empty collection."
  [values]
  (let [xs (vec (sort values))
        n (count xs)]
    (when (pos? n)
      (if (odd? n)
        (nth xs (quot n 2))
        (/ (+ (double (nth xs (dec (quot n 2))))
              (double (nth xs (quot n 2))))
           2.0)))))

(defn summarize-runs
  [runs]
  (let [metric-keys [:elapsed-ns :packets-per-sec :mb-per-sec :ns-per-packet
                     :allocated-bytes :allocated-bytes-per-packet
                     :gc-count :gc-time-ms :heap-peak-bytes :process-cpu-ns]]
    (into {}
          (keep
           (fn [metric]
             (let [values (keep metric runs)]
               (when (seq values)
                 [metric {:median (median values)
                          :min (apply min values)
                          :max (apply max values)}]))))
          metric-keys)))

(defn- git-sha []
  (let [{:keys [exit out]} (shell/sh "git" "rev-parse" "HEAD")]
    (when (zero? exit) (str/trim out))))

(defn environment
  []
  {:git-sha (git-sha)
   :os-name (System/getProperty "os.name")
   :os-version (System/getProperty "os.version")
   :architecture (System/getProperty "os.arch")
   :available-processors (.availableProcessors (Runtime/getRuntime))
   :java-version (System/getProperty "java.version")
   :java-vendor (System/getProperty "java.vendor")
   :clojure-version (clojure-version)
   :libpcap-version (try
                      (.pcap_lib_version PcapLibrary/INSTANCE)
                      (catch Throwable _ nil))
   :jvm-arguments (vec (.getInputArguments
                        (ManagementFactory/getRuntimeMXBean)))})
