(ns examples.flow-topn
  (:require
   [clojure.core.async :as async]
   [examples.common :as ex]
   [paclo.core :as core]))

(def ^:private default-async-buffer 1024)
(def ^:private default-async-mode :buffer)

(defn- usage []
  (binding [*out* *err*]
    (println "Usage:")
    (println "  clojure -M:dev -m examples.flow-topn <in.pcap> [<bpf>] [<topN>] [<mode>] [<metric>] [<format>] [--async] [--async-buffer N] [--async-mode buffer|dropping] [--async-timeout-ms MS]")
    (println "Defaults: <bpf>='udp or tcp', <topN>=10, <mode>=unidir, <metric>=packets, <format>=edn, async=off, async-buffer=1024, async-mode=buffer")
    (println "Modes  : unidir | bidir")
    (println "Metric : packets | bytes")
    (println "Formats: edn | jsonl")
    (println "Tips   : use \"_\" to skip an optional arg (e.g., '_' for <bpf>); async is opt-in for long runs")))

(defn- flow->repr [{:keys [proto src-ip src-port dst-ip dst-port]}]
  {:proto proto
   :src (str src-ip (when src-port (str ":" src-port)))
   :dst (str dst-ip (when dst-port (str ":" dst-port)))})

(defn- canon-fk
  "Canonicalize flow key for bidirectional mode."
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
  "Build a flow key from a decoded packet."
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
  (let [[in bpf topn-str mode-str metric-str fmt-str & flags] args]
    (when (nil? in) (usage) (System/exit 1))
    (let [in*    (ex/require-file! in)
          bpf    (if (ex/blank? bpf) "udp or tcp" bpf)
          topN   (or (ex/parse-long* topn-str) 10)
          mode   (keyword (or mode-str "unidir"))
          metric (keyword (or metric-str "packets"))
          fmt    (ex/parse-format fmt-str)
          {:keys [async? async-buffer async-mode async-timeout-ms]} (ex/parse-async-opts flags {:default-buffer default-async-buffer :default-mode default-async-mode})]
      (ex/ensure-one-of! "mode"   mode   #{:unidir :bidir})
      (ex/ensure-one-of! "metric" metric #{:packets :bytes})
      (let [bidir? (= :bidir mode)
            counts (atom {})
            total  (atom 0)
            dropped (atom 0)
            cancelled? (atom false)]
        (if-not async?
          ;; synchronous path
          (let [pkts   (into [] (core/packets {:path in* :filter bpf :decode? true :max Long/MAX_VALUE}))
                total* (count pkts)
                counts* (reduce
                         (fn [m p]
                           (if-let [fk (pkt->fk p bidir?)]
                             (let [prev (get m fk {:packets 0 :bytes 0})
                                   b (:caplen p)]
                               (assoc m fk {:packets (unchecked-inc (long (:packets prev)))
                                            :bytes   (unchecked-add (long (:bytes prev)) (long (or b 0)))}))
                             m))
                         {} pkts)
                rows   (->> counts*
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
                       " total-packets=" total*
                       " topN=" topN " mode=" (name mode) " metric=" (name metric))))
          ;; asynchronous path
          (let [cancel-ch (when async-timeout-ms (async/timeout async-timeout-ms))
                buf (case async-mode
                      :dropping (async/dropping-buffer async-buffer)
                      (async/buffer async-buffer))
                pkt-ch (async/chan buf)
                reader (async/thread
                         (try
                           (doseq [p (core/packets {:path in* :filter bpf :decode? true :max Long/MAX_VALUE})]
                             (swap! total inc)
                             (when cancel-ch
                               (let [[_ port] (async/alts!! [cancel-ch] :default [:ok nil])]
                                 (when port (reset! cancelled? true))))
                             (when-not @cancelled?
                               (if (= async-mode :dropping)
                                 (when-not (async/offer! pkt-ch p)
                                   (swap! dropped inc))
                                 (async/>!! pkt-ch p))))
                           (finally (async/close! pkt-ch))))
                _ (async/thread (async/<!! reader))
                ;; consume
                _ (loop []
                    (when-let [p (async/<!! pkt-ch)]
                      (when-let [fk (pkt->fk p bidir?)]
                        (let [prev (get @counts fk {:packets 0 :bytes 0})
                              b (:caplen p)]
                          (swap! counts assoc fk {:packets (unchecked-inc (long (:packets prev)))
                                                  :bytes   (unchecked-add (long (:bytes prev)) (long (or b 0)))})))
                      (recur)))
                rows (->> @counts
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
                       " total-packets=" @total
                       " topN=" topN " mode=" (name mode) " metric=" (name metric)
                       " async=true" " buffer=" async-buffer " async-mode=" (name async-mode)
                       " dropped=" @dropped " cancelled=" @cancelled?))))))))
