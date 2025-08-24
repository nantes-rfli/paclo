(ns examples.pcap-stats
  (:require
   [clojure.data.json :as json]
   [paclo.core :as core]))

(defn- usage []
  (binding [*out* *err*]
    (println "Usage:")
    (println "  clojure -M:dev -m examples.pcap-stats <in.pcap> [<bpf-string>] [<topN>] [<format>]")
    (println)
    (println "Defaults:")
    (println "  <bpf-string> = (none)")
    (println "  <topN>       = 5   (top talkers/ports)")
    (println "  <format>     = edn | jsonl   (default: edn)")
    (println)
    (println "Examples:")
    (println "  clojure -M:dev -m examples.pcap-stats dns-sample.pcap")
    (println "  clojure -M:dev -m examples.pcap-stats dns-sample.pcap 'udp and port 53' 10 jsonl")))

(defn- micros [{:keys [sec usec]}]
  (when (and (number? sec) (number? usec))
    (+ (* (long sec) 1000000) (long usec))))

(defn- fmt-ts
  "マイクロ秒のエポックを ISO8601（UTC）文字列に。無ければ nil。"
  [us]
  (when (number? us)
    (-> us
        (quot 1000)               ; μs → ms
        (long)
        (java.time.Instant/ofEpochMilli)
        (.toString))))

(defn- topN
  "頻度マップ → 上位Nの {:key k :count v} ベクタ"
  [m n]
  (->> m (sort-by val >) (take n) (map (fn [[k v]] {:key k :count v})) vec))

(defn -main
  "基本統計（件数、バイト、caplen統計、時間範囲、L3/L4分布、上位送信元/宛先/ポート、pps/bps）を出力。"
  [& args]
  (let [[in bpf-str topn-str fmt-str] args]
    (when (nil? in)
      (usage) (System/exit 1))
    (let [n   (long (or (some-> topn-str Long/parseLong) 5))
          fmt (keyword (or fmt-str "edn"))
          {:keys [count bytes min-cap max-cap start end l3 l4 src dst srcp dstp]}
          (reduce
           (fn [{:keys [count bytes min-cap max-cap start end l3 l4 src dst srcp dstp] :as st} m]
             (let [cap (long (or (:caplen m) 0))
                   t   (micros m)
                   l3t (get-in m [:decoded :l3 :type])
                   l4t (get-in m [:decoded :l3 :l4 :type])
                   sip (get-in m [:decoded :l3 :src])
                   dip (get-in m [:decoded :l3 :dst])
                   sp  (get-in m [:decoded :l3 :l4 :src-port])
                   dp  (get-in m [:decoded :l3 :l4 :dst-port])]
               {:count   (inc (long count))
                :bytes   (+ (long bytes) cap)
                :min-cap (if (some? min-cap) (min min-cap cap) cap)
                :max-cap (if (some? max-cap) (max max-cap cap) cap)
                :start   (if (and (number? start) (number? t)) (min start t) (or start t))
                :end     (if (and (number? end) (number? t))   (max end t)   (or end t))
                :l3      (if l3t (update l3 l3t (fnil inc 0)) l3)
                :l4      (if l4t (update l4 l4t (fnil inc 0)) l4)
                :src     (if sip (update src sip (fnil inc 0)) src)
                :dst     (if dip (update dst dip (fnil inc 0)) dst)
                :srcp    (if (number? sp) (update srcp sp (fnil inc 0)) srcp)
                :dstp    (if (number? dp) (update dstp dp (fnil inc 0)) dstp)}))
           {:count 0 :bytes 0 :min-cap nil :max-cap nil :start nil :end nil
            :l3 {} :l4 {} :src {} :dst {} :srcp {} :dstp {}}
           (core/packets (cond-> {:path in :decode? true :max Long/MAX_VALUE}
                           bpf-str (assoc :filter bpf-str))))
          avg (when (pos? count) (double (/ (long bytes) (double count))))
          dur-ms (when (and (number? start) (number? end))
                   (double (/ (- end start) 1000.0)))
          dur-s  (when (number? dur-ms) (/ dur-ms 1000.0))
          pps    (when (and (number? dur-s) (pos? dur-s)) (/ count dur-s))
          bps    (when (and (number? dur-s) (pos? dur-s)) (/ (* bytes 8.0) dur-s))
          out {:packets count
               :bytes bytes
               :caplen {:avg avg :min min-cap :max max-cap}
               :times {:start-iso (fmt-ts start)
                       :end-iso   (fmt-ts end)
                       :duration-ms dur-ms}
               :throughput {:pps pps :bps bps}
               :proto {:l3 l3 :l4 l4}
               :top {:src (topN src n)
                     :dst (topN dst n)
                     :src-ports (topN srcp n)
                     :dst-ports (topN dstp n)}}]
      (case fmt
        :jsonl (do (json/write out *out*) (println))
        (println (pr-str out)))
      (binding [*out* *err*]
        (println "bpf=" (pr-str bpf-str) " topN=" n " format=" (name fmt))))))
