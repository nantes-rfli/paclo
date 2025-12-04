(ns examples.pcap-filter
  (:require
   [examples.common :as ex]
   [paclo.core :as core]))

(defn- usage []
  (binding [*out* *err*]
    (println "Usage:")
    (println "  clojure -M:dev -m examples.pcap-filter <in.pcap> <out.pcap> [<bpf>] [<min-caplen>] [<format>]")
    (println "Defaults: <bpf>=nil, <min-caplen>=nil, <format>=edn")
    (println "Formats : edn | jsonl")
    (println "Tips    : use \"_\" to skip an optional arg (e.g., '_' for <bpf>)")))

(defn -main [& args]
  (let [[in out bpf min-caplen-str fmt-str] args]
    (when (or (nil? in) (nil? out))
      (usage) (System/exit 1))
    (let [in*        (ex/require-file! in)
          fmt        (ex/parse-format fmt-str)
          bpf*       (when-not (ex/blank? bpf) bpf)
          min-caplen (ex/parse-long* min-caplen-str)
          xf         (if min-caplen (filter #(>= (long (:caplen %)) (long min-caplen))) identity)]
      (println "reading:" in)
      (println "writing:" out)
      (let [in-seq   (into [] (core/packets {:path in* :filter bpf* :max Long/MAX_VALUE}))
            written  (core/write-pcap! (sequence xf in-seq) out)
            out-seq  (into [] (core/packets {:path out :max Long/MAX_VALUE}))
            in-pkts  (count in-seq)
            out-pkts (count out-seq)
            in-bytes (reduce + 0 (map :caplen in-seq))
            out-bytes (reduce + 0 (map :caplen out-seq))
            drop-pct (if (pos? in-pkts)
                       (double (* 100.0 (- 1.0 (/ (double out-pkts) (double in-pkts)))))
                       0.0)
            meta {:in in :out out :filter bpf*
                  :min-caplen min-caplen
                  :in-packets  in-pkts
                  :out-packets out-pkts
                  :in-bytes  in-bytes
                  :out-bytes out-bytes
                  :drop-pct drop-pct}]
        (println "done. wrote packets =" written)
        (ex/emit fmt meta)))))
