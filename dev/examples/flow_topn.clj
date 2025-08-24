(ns examples.flow-topn
  (:require
   [paclo.core :as core]))

(defn- usage []
  (binding [*out* *err*]
    (println "Usage:")
    (println "  clojure -M:dev -m examples.flow-topn <in.pcap> [<bpf-string>] [<topN>] [<mode>] [<metric>]")
    (println)
    (println "  <mode>   : unidir | bidir   (default: unidir)")
    (println "  <metric> : packets | bytes  (default: packets)")
    (println)
    (println "Examples:")
    (println "  clojure -M:dev -m examples.flow-topn dns-sample.pcap")
    (println "  clojure -M:dev -m examples.flow-topn dns-sample.pcap 'udp and port 53' 5 bidir bytes")))

(defn- flow->repr [{:keys [proto src-ip src-port dst-ip dst-port]}]
  {:proto proto
   :src (str src-ip (when src-port (str ":" src-port)))
   :dst (str dst-ip (when dst-port (str ":" dst-port)))})

(defn- canon-fk
  "双方向正規化（bidir=true）なら、(src, dst)を辞書順で並べ替えて
   片側に寄せる。unidir の場合は fk をそのまま返す。"
  [{:keys [proto src-ip src-port dst-ip dst-port] :as fk} bidir?]
  (if-not bidir?
    fk
    (let [a [(or src-ip "") (long (or src-port -1))]
          b [(or dst-ip "") (long (or dst-port -1))]]
      (if (neg? (compare a b))
        fk
        {:proto proto
         :src-ip dst-ip :src-port dst-port
         :dst-ip src-ip :dst-port src-port}))))

(defn -main
  "Compute Top-N flows by packet count or bytes from a PCAP.
   Optional BPF narrows the set upstream.

   Args:
     in.pcap                - required
     [bpf-string]           - optional (e.g., 'udp and port 53')
     [topN]                 - optional (default 10)
     [mode]                 - optional: 'unidir' | 'bidir'  (default unidir)
     [metric]               - optional: 'packets' | 'bytes' (default packets)

   Output: EDN vector of maps, e.g.
   [{:flow {:proto :udp, :src \"192.168.0.2:5353\", :dst \"224.0.0.251:5353\"}
     :packets 123, :bytes 45678} ...]"
  [& args]
  (let [[in bpf-str topn-str mode-str metric-str] args]
    (when (nil? in)
      (usage) (System/exit 1))
    (let [topN    (long (or (some-> topn-str Long/parseLong) 10))
          bidir?  (= "bidir" (some-> mode-str clojure.string/lower-case))
          metric  (keyword (or (some-> metric-str clojure.string/lower-case) "packets"))
          key-of  (if (#{:bytes :packets} metric) metric :packets)
          stats   (reduce
                   (fn [acc m]
                     (if-let [fk (get-in m [:decoded :l3 :flow-key])]
                       (let [k   (canon-fk fk bidir?)
                             cap (long (or (:caplen m) 0))
                             e   (get acc k)]
                         (assoc acc k
                                (if e
                                  (-> e
                                      (update :packets inc)
                                      (update :bytes (fnil + 0) cap))
                                  {:flow (flow->repr k)
                                   :packets 1
                                   :bytes cap})))
                       acc))
                   {}
                   (core/packets (cond-> {:path in
                                          :decode? true
                                          :max Long/MAX_VALUE}
                                   bpf-str (assoc :filter bpf-str))))]
      (let [ranked (->> stats vals (sort-by key-of >) (take topN) vec)
            total  (reduce (fn [s {:keys [packets]}] (+ s packets)) 0 (vals stats))]
        (println (pr-str ranked))
        (binding [*out* *err*]
          (println "flows=" (count stats)
                   " total-packets=" total
                   " topN=" topN
                   " mode=" (if bidir? "bidir" "unidir")
                   " metric=" (name key-of)))))))
