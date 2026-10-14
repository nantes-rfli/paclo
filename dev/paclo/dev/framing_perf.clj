(ns paclo.dev.framing-perf
  "Same-JVM P08-C/D1 full/flow framing comparison; transformation only, no native I/O.
   clojure -M:dev -m paclo.dev.framing-perf 9d83bb2 [native-DLT]
   Alternates baseline/current samples after warming both; no threshold changes."
  (:require
   [clojure.java.shell :as shell]
   [clojure.string :as str]
   [paclo.core :as core]
   [paclo.dev.perf-data :as data])
  (:import
   [com.sun.management ThreadMXBean]
   [java.lang.management ManagementFactory]
   [java.util Arrays]))

(def ^:private packet-count 50000)
(def ^:private names
  {"paclo.linktype" "paclo.dev.framing-baseline-linktype"
   "paclo.parse" "paclo.dev.framing-baseline-parse"
   "paclo.flow.project" "paclo.dev.framing-baseline-project"
   "paclo.core" "paclo.dev.framing-baseline-core"})

(defn- baseline-xf [ref]
  (doseq [path ["src/paclo/linktype.clj" "src/paclo/parse.clj"
                "src/paclo/flow/project.clj" "src/paclo/core.clj"]]
    (let [{:keys [exit out err]} (shell/sh "git" "show" (str ref ":" path))
          source (reduce-kv str/replace out names)]
      (when-not (zero? exit) (throw (ex-info "cannot read baseline" {:path path :error err})))
      (load-string source)
      ;; load-string defines the renamed namespace without registering a loaded
      ;; library. Register it so the next source's require reuses that definition.
      (dosync (alter @#'clojure.core/*loaded-libs* conj
                     (symbol (get names (-> path (str/replace "src/" "")
                                            (str/replace ".clj" "") (str/replace "/" "."))))))))
  (ns-resolve 'paclo.dev.framing-baseline-core 'packet-xf))

(defn- packet [^bytes ethernet dlt]
  (let [header-size (case dlt 1 14 12 0 113 16 276 20)
        bytes (if (= dlt 1)
                ethernet
                (let [frame (byte-array (+ header-size (- (alength ethernet) 14)))]
                  (cond
                    (= dlt 12) nil
                    (= dlt 113) (do (aset-byte frame 3 (byte 1)) (aset-byte frame 5 (byte 6))
                                    (System/arraycopy ethernet 12 frame 14 2))
                    :else (do (aset-byte frame 9 (byte 1)) (aset-byte frame 11 (byte 6))
                              (System/arraycopy ethernet 12 frame 0 2)))
                  (System/arraycopy ethernet 14 frame header-size (- (alength ethernet) 14))
                  frame))]
    {:bytes bytes :linktype dlt :caplen (alength ^bytes bytes) :len (alength ^bytes bytes)
     :ts-sec 1700000000 :ts-usec 123456}))

(defn- run [xf packets]
  (transduce xf (completing (fn [total packet]
                              (when (:decode-error packet)
                                (throw (ex-info "unexpected benchmark decode failure" packet)))
                              (unchecked-add (long total) (long (:caplen packet)))))
             0 packets))

(defn- median [xs] (nth (vec (sort xs)) (quot (count xs) 2)))

(defn- sample [xf packets]
  (let [^ThreadMXBean bean (ManagementFactory/getThreadMXBean)
        before (.getCurrentThreadAllocatedBytes bean)
        start (System/nanoTime)
        checksum (run xf packets)
        elapsed (- (System/nanoTime) start)
        allocated (- (.getCurrentThreadAllocatedBytes bean) before)]
    {:ns elapsed :allocation allocated :checksum checksum}))

(defn -main [& [ref dlt-filter]]
  (try
    (let [ref (or ref "4998ddc") legacy-xf (baseline-xf ref)
          selected (when dlt-filter (parse-long dlt-filter))
          ^ThreadMXBean bean (ManagementFactory/getThreadMXBean)]
      (when (and dlt-filter (not (contains? #{1 12 113 276} selected)))
        (throw (ex-info "unsupported benchmark DLT" {:dlt dlt-filter})))
      (when-not (.isThreadAllocatedMemorySupported bean)
        (throw (ex-info "allocation measurement unavailable" {})))
      (.setThreadAllocatedMemoryEnabled bean true)
      (println (pr-str {:baseline ref :jdk (System/getProperty "java.version")
                        :clojure (clojure-version) :os (System/getProperty "os.name")
                        :arch (System/getProperty "os.arch") :packets packet-count
                        :warmups 5 :runs 7 :scope :packet-xf-only :drops 0 :dlt-filter selected}))
      (doseq [[traffic size] [[:udp 64] [:tcp 512]]
              mode [:full :flow]]
        (let [ethernet (data/ethernet-ipv4-frame size traffic)
              options (if (= :full mode) {:decode? true :extensions []} {:decode-mode :flow})
              baseline-dlts (remove #((ns-resolve 'paclo.dev.framing-baseline-linktype 'unsupported?)
                                      {:linktype %}) (if selected [selected] [1 113 276]))
              variants (into (mapv (fn [dlt] {:implementation :baseline :dlt dlt :xf (legacy-xf options)
                                              :packet (packet ethernet dlt)}) baseline-dlts)
                             (map (fn [dlt] {:implementation :current :dlt dlt :xf (core/packet-xf options)
                                             :packet (packet ethernet dlt)}) (if selected [selected] [1 113 276 12])))
              variants (mapv #(assoc % :inputs (vec (repeat packet-count (:packet %)))
                                     :snapshot (aclone ^bytes (:bytes (:packet %)))) variants)
              samples (atom {})]
          (dotimes [_ 5] (doseq [{:keys [xf inputs]} variants] (run xf inputs)))
          (dotimes [round 7]
            (doseq [{:keys [xf inputs implementation dlt]} (if (even? round) variants (reverse variants))]
              (swap! samples update [implementation dlt] (fnil conj []) (sample xf inputs))))
          (doseq [{:keys [implementation dlt packet xf snapshot]} variants]
            (let [measurements (get @samples [implementation dlt])
                  full (when (= mode :full) (first (into [] xf [packet])))]
              (println (pr-str {:implementation implementation :dlt dlt :mode mode :traffic traffic
                                :ethernet-size size :frame-size (:caplen packet)
                                :packets-per-second (/ (* 1e9 packet-count) (double (median (map :ns measurements))))
                                :allocation-bytes-per-packet (/ (double (median (map :allocation measurements))) packet-count)
                                :full-input-identity (when full (identical? (:bytes packet) (:bytes full)))
                                :bytes-unchanged (Arrays/equals ^bytes snapshot ^bytes (:bytes packet))
                                :checksums (set (map :checksum measurements))})))))))
    (finally (shutdown-agents))))
