(ns examples.flow-topn
  (:require
   [paclo.core :as core]))

(defn- usage []
  (binding [*out* *err*]
    (println "Usage:")
    (println "  clojure -M:dev -m examples.flow-topn <in.pcap> [<bpf-string>] [<topN>]")
    (println)
    (println "Examples:")
    (println "  clojure -M:dev -m examples.flow-topn dns-sample.pcap")
    (println "  clojure -M:dev -m examples.flow-topn dns-sample.pcap 'udp and port 53' 5")))

(defn- flow->repr [{:keys [proto src-ip src-port dst-ip dst-port]}]
  {:proto proto
   :src (str src-ip (when src-port (str ":" src-port)))
   :dst (str dst-ip (when dst-port (str ":" dst-port)))})

(defn -main
  "Compute Top-N flows by packet count (and bytes) from a PCAP.
   Optional BPF narrows the set upstream.

   Args:
     in.pcap          - required
     [bpf-string]     - optional (e.g., 'udp and port 53')
     [topN]           - optional (default 10)

   Output: EDN vector of maps, e.g.
   [{:flow {:proto :udp, :src \"192.168.0.2:5353\", :dst \"224.0.0.251:5353\"}
     :packets 123, :bytes 45678} ...]"
  [& args]
  (let [[in bpf-str topn-str] args]
    (when (nil? in)
      (usage) (System/exit 1))
    (let [topN   (long (or (some-> topn-str Long/parseLong) 10))
          ;; 集計本体：reduceでマップに詰める
          stats  (reduce
                  (fn [acc m]
                    (if-let [fk (get-in m [:decoded :l3 :flow-key])]
                      (let [k   fk
                            cap (:caplen m)
                            e   (get acc k)]
                        (assoc acc k
                               (if e
                                 (-> e
                                     (update :packets inc)
                                     (update :bytes (fnil + 0) (long (or cap 0))))
                                 {:flow (flow->repr fk)
                                  :packets 1
                                  :bytes (long (or cap 0))})))
                      acc))
                  {}
                  (core/packets (cond-> {:path in
                                         :decode? true
                                         :max Long/MAX_VALUE}
                                  bpf-str (assoc :filter bpf-str))))]
      ;; 出力整形：packets desc → take topN
      (let [ranked (->> stats vals (sort-by :packets >) (take topN) vec)
            total  (reduce (fn [s {:keys [packets]}] (+ s packets)) 0 (vals stats))]
        (println (pr-str ranked))
        (binding [*out* *err*]
          (println "flows=" (count stats) " total-packets=" total " topN=" topN))))))
