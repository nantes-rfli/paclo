(ns examples.pcap-stats
  (:require
   [examples.common :as ex]
   [paclo.core :as core]))

(defn- usage []
  (binding [*out* *err*]
    (println "Usage:")
    (println "  clojure -M:dev -m examples.pcap-stats <in.pcap> [<bpf>] [<topN>] [<format>]")
    (println "Defaults: <bpf>=nil, <topN>=5, <format>=edn")
    (println "Formats : edn | jsonl")))

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

(defn- top-freqs
  [n m]
  (->> m
       (sort-by val >)
       (take n)
       (map (fn [[k v]] {:key k :count v}))
       vec))

(defn -main [& args]
  (let [[in bpf topn-str fmt-str] args]
    (when (nil? in) (usage) (System/exit 1))
    (let [in*  (ex/require-file! in)
          n    (or (ex/parse-long* topn-str) 5)      ;; ← 変数名を n に
          fmt  (keyword (or fmt-str "edn"))
          _    (ex/ensure-one-of! "format" fmt #{:edn :jsonl})
          ;; すべて decode? して L3/L4 を取る
          pkts  (into [] (core/packets {:path in* :filter bpf :decode? true :max Long/MAX_VALUE}))
          cnt   (count pkts)
          bytes (reduce + 0 (map :caplen pkts))
          caplens (map :caplen pkts)
          cmin (when (seq caplens) (apply min caplens))
          cmax (when (seq caplens) (apply max caplens))
          cavg (when (seq caplens) (double (/ (reduce + 0 caplens) cnt)))
          ;; タイムスタンプ（無ければ nil のまま）
          tlist (->> pkts
                     (map (fn [{:keys [sec usec]}]
                            (when (and sec usec)
                              (+ (* (long sec) 1000000) (long usec)))))
                     (remove nil?) vec)
          start-us (first tlist)
          end-us   (last tlist)
          stats {:packets cnt
                 :bytes   bytes
                 :caplen  {:avg cavg :min cmin :max cmax}
                 :times   {:start-iso (fmt-ts start-us)
                           :end-iso   (fmt-ts end-us)
                           :duration-ms (when (and start-us end-us)
                                          (long (/ (- end-us start-us) 1000)))}
                 :proto   {:l3 (->> pkts (map #(get-in % [:decoded :l3 :type])) (remove nil?) frequencies)
                           :l4 (->> pkts (map #(get-in % [:decoded :l3 :l4 :type])) (remove nil?) frequencies)}
                 :top     {:src (->> pkts (map #(get-in % [:decoded :l3 :src])) (remove nil?) frequencies (top-freqs n))
                           :dst (->> pkts (map #(get-in % [:decoded :l3 :dst])) (remove nil?) frequencies (top-freqs n))}}]
      (ex/emit fmt stats)
      (binding [*out* *err*]
        (println "bpf=" (pr-str bpf) " topN=" n " format=" (name fmt))))))
