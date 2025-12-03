(ns examples.flow-topn
  (:require
   [examples.common :as ex]
   [paclo.core :as core]))

(defn- usage []
  (binding [*out* *err*]
    (println "Usage:")
    (println "  clojure -M:dev -m examples.flow-topn <in.pcap> [<bpf>] [<topN>] [<mode>] [<metric>] [<format>]")
    (println "Defaults: <bpf>='udp or tcp', <topN>=10, <mode>=unidir, <metric>=packets, <format>=edn")
    (println "Modes  : unidir | bidir")
    (println "Metric : packets | bytes")
    (println "Formats: edn | jsonl")))

(defn- flow->repr [{:keys [proto src-ip src-port dst-ip dst-port]}]
  {:proto proto
   :src (str src-ip (when src-port (str ":" src-port)))
   :dst (str dst-ip (when dst-port (str ":" dst-port)))})

(defn- canon-fk
  "双方向正規化（bidir=true）なら、(src, dst)を辞書順で並べ替えて片側に寄せる。"
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

(defn- pkt->fk
  "パケット m からフローキーを作る。mode=bidir の場合は canon-fk で正規化。"
  [m bidir?]
  (let [proto   (get-in m [:decoded :l3 :l4 :type])
        src-ip  (get-in m [:decoded :l3 :src])
        dst-ip  (get-in m [:decoded :l3 :dst])
        src-port (get-in m [:decoded :l3 :l4 :src-port])
        dst-port (get-in m [:decoded :l3 :l4 :dst-port])]
    (when (and proto src-ip dst-ip)
      (canon-fk {:proto proto
                 :src-ip src-ip :src-port src-port
                 :dst-ip dst-ip :dst-port dst-port}
                bidir?))))

(defn -main [& args]
  (let [[in bpf topn-str mode-str metric-str fmt-str] args]
    (when (nil? in) (usage) (System/exit 1))
    (let [in*    (ex/require-file! in)
          bpf    (or bpf "udp or tcp")
          topN   (or (ex/parse-long* topn-str) 10)
          mode   (keyword (or mode-str "unidir"))
          metric (keyword (or metric-str "packets"))
          fmt    (ex/parse-format fmt-str)]
      (ex/ensure-one-of! "mode"   mode   #{:unidir :bidir})
      (ex/ensure-one-of! "metric" metric #{:packets :bytes})
      (let [bidir? (= :bidir mode)
            pkts   (into [] (core/packets {:path in* :filter bpf :decode? true :max Long/MAX_VALUE}))
            total  (count pkts)
            counts (reduce
                    (fn [m p]
                      (if-let [fk (pkt->fk p bidir?)]
                        (let [k fk
                              prev (get m k {:packets 0 :bytes 0})
                              b (:caplen p)]
                          (assoc m k {:packets (unchecked-inc (long (:packets prev)))
                                      :bytes   (unchecked-add (long (:bytes prev)) (long (or b 0)))}))
                        m))
                    {} pkts)
            rows   (->> counts
                        (map (fn [[fk agg]]
                               {:flow (flow->repr fk)
                                :packets (:packets agg)
                                :bytes   (:bytes agg)}))
                        (sort-by (case metric
                                   :bytes   :bytes
                                   :packets :packets)
                                 >)
                        (take topN)
                        vec)]
        (ex/emit fmt rows)
        (binding [*out* *err*]
          (println "flows=" (count rows)
                   " total-packets=" total
                   " topN=" topN " mode=" (name mode) " metric=" (name metric)))))))
