(ns paclo.dev.perf-gate
  "Simple performance gate for the mid-50k decode path used in ROADMAP/CI."
  (:require
   [examples.common :as ex]
   [paclo.core :as core]
   [paclo.pcap :as pcap]))

(def ^:private default-count 50000)
(def ^:private default-caplen 74)
(def ^:private default-warn-ms 1000)
(def ^:private default-fail-ms 1200)

(defn- usage []
  (binding [*out* *err*]
    (println "Usage:")
    (println "  clojure -M:perf-gate [<count>] [<caplen>] [<warn-ms>] [<fail-ms>]")
    (println "Defaults: count=50000 caplen=74 warn-ms=1000 fail-ms=1200")))

(defn- ensure-positive! [label n]
  (when-not (and (number? n) (pos? (long n)))
    (ex/error-exit! (str label " must be positive integer") 4)))

(defn- synth-path []
  (str (System/getProperty "java.io.tmpdir") "/paclo-mid-50k.pcap"))

(defn- tmp-out-path []
  (-> (java.io.File/createTempFile "paclo-perf-out" ".pcap")
      .getAbsolutePath))

(defn- make-synth-pcap! [path count caplen]
  (let [pkt (byte-array (repeat caplen (byte 0)))]
    (pcap/bytes-seq->pcap! (repeat count pkt) {:out path})))

(defn- run-pipeline-ms [path count out]
  (let [counter (volatile! 0)
        xf      (comp
                 (filter #(>= (long (or (:caplen %) 0)) 60))
                 (map (fn [m]
                        (vswap! counter unchecked-inc)
                        (select-keys m [:bytes :sec :usec]))))
        t0      (System/nanoTime)]
    (core/write-pcap! (core/packets {:path path :decode? true :xform xf :max count}) out)
    (/ (- (System/nanoTime) t0) 1e6)))

(defn -main [& args]
  (let [[count-str caplen-str warn-str fail-str] args
        count   (or (ex/parse-long* count-str) default-count)
        caplen  (or (ex/parse-long* caplen-str) default-caplen)
        warn-ms (or (ex/parse-long* warn-str) default-warn-ms)
        fail-ms (or (ex/parse-long* fail-str) default-fail-ms)]
    (when (some #{"-h" "--help"} args)
      (usage)
      (System/exit 0))
    (ensure-positive! "count" count)
    (ensure-positive! "caplen" caplen)
    (ensure-positive! "warn-ms" warn-ms)
    (ensure-positive! "fail-ms" fail-ms)
    (when (> warn-ms fail-ms)
      (ex/error-exit! "warn-ms must be <= fail-ms" 4))
    (let [in-path (synth-path)
          out-path (tmp-out-path)]
      (try
        (println "[perf-gate] generating synth pcap:" in-path "count=" count "caplen=" caplen)
        (make-synth-pcap! in-path count caplen)
        (let [elapsed-ms (run-pipeline-ms in-path count out-path)]
          (println (format "[perf-gate] decode?=true mid-%dk elapsed-ms=%.1f (warn=%d fail=%d)"
                           (long (/ count 1000))
                           (double elapsed-ms)
                           (long warn-ms)
                           (long fail-ms)))
          (when (> elapsed-ms warn-ms)
            (binding [*out* *err*]
              (println (format "WARNING: perf budget warning (%.1fms > %dms)" (double elapsed-ms) (long warn-ms)))))
          (if (> elapsed-ms fail-ms)
            (do
              (binding [*out* *err*]
                (println (format "FAIL: perf budget exceeded (%.1fms > %dms)" (double elapsed-ms) (long fail-ms))))
              (System/exit 1))
            (System/exit 0)))
        (finally
          (try (.delete (java.io.File. out-path)) (catch Throwable _)))))))
