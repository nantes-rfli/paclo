(ns examples.pcap-filter
  (:require
   [examples.common :as ex]
   [paclo.core :as core]))

(defn- usage []
  (binding [*out* *err*]
    (println "Usage:")
    (println "  clojure -M:dev -m examples.pcap-filter <in.pcap> <out.pcap> [<bpf>] [<min-caplen>] [<format>]")
    (println "Defaults: <bpf>=nil, <min-caplen>=nil, <format>=edn")
    (println "Formats : edn | jsonl")))

;; clojure.core/parse-long と衝突しないように別名で
(defn- parse-long-opt [s]
  (try (some-> s Long/parseLong) (catch Exception _ nil)))

(defn -main [& args]
  (let [[in out bpf min-caplen-str fmt-str] args]
    (when (or (nil? in) (nil? out))
      (usage) (System/exit 1))
    (let [in*        (ex/require-file! in)
          fmt        (keyword (or fmt-str "edn"))
          _          (ex/ensure-one-of! "format" fmt #{:edn :jsonl})
          min-caplen (ex/parse-long* min-caplen-str)
          xf         (if min-caplen (filter #(>= (:caplen %) min-caplen)) identity)]
      (println "reading:" in)
      (println "writing:" out)
      (let [in-seq   (into [] (core/packets {:path in* :filter bpf :max Long/MAX_VALUE}))
            written  (core/write-pcap! (sequence xf in-seq) out)
            out-seq  (into [] (core/packets {:path out :max Long/MAX_VALUE}))
            in-pkts  (count in-seq)
            out-pkts (count out-seq)
            in-bytes (reduce + 0 (map :caplen in-seq))
            out-bytes (reduce + 0 (map :caplen out-seq))
            drop-pct (if (pos? in-pkts)
                       (double (* 100.0 (- 1.0 (/ (double out-pkts) (double in-pkts)))))
                       0.0)
            meta {:in in :out out :filter bpf
                  :min-caplen min-caplen
                  :in-packets  in-pkts
                  :out-packets out-pkts
                  :in-bytes  in-bytes
                  :out-bytes out-bytes
                  :drop-pct drop-pct}]
        (println "done. wrote packets =" written)
        (ex/emit fmt meta)))))
