(ns examples.pcap-stats
  (:require
   [clojure.core.async :as async]
   [examples.common :as ex]
   [paclo.core :as core]))

(defn- usage []
  (binding [*out* *err*]
    (println "Usage:")
    (println "  clojure -M:dev -m examples.pcap-stats <in.pcap> [<bpf>] [<topN>] [<format>]")
    (println "Defaults: <bpf>=nil, <topN>=5, <format>=edn")
    (println "Formats : edn | jsonl")
    (println "Tips    : use \"_\" to skip an optional arg (e.g., '_' for <bpf>)")))

(defn- fmt-ts
  "Convert microseconds-since-epoch to ISO8601 UTC. Returns nil when unavailable."
  [us]
  (when (number? us)
    (-> (long us)
        (quot 1000)               ; us -> ms
        (java.time.Instant/ofEpochMilli)
        (.toString))))

(defn- top-freqs
  [n m]
  (->> m
       (sort-by val >)
       (take n)
       (map (fn [[k v]] {:key k :count v}))
       vec))

(defn -main [& args]
  (let [[in bpf topn-str fmt-str & flags] args]
    (when (nil? in) (usage) (System/exit 1))
    (let [in*  (ex/require-file! in)
          n    (or (ex/parse-long* topn-str) 5)
          fmt  (ex/parse-format fmt-str)
          bpf* (when-not (ex/blank? bpf) bpf)
          {:keys [async? async-buffer async-mode async-timeout-ms]} (ex/parse-async-opts flags {:default-buffer 1024 :default-mode :buffer})
          dropped    (atom 0)
          cancelled? (atom false)
          pkt-ch     (when async? (async/chan (case async-mode
                                                :dropping (async/dropping-buffer async-buffer)
                                                (async/buffer async-buffer))))
          cancel-ch  (when (and async? async-timeout-ms) (async/timeout async-timeout-ms))
          pkts (if-not async?
                 (into [] (core/packets {:path in* :filter bpf* :decode? true :max Long/MAX_VALUE}))
                 ;; async path: stream through channel, allow drop/cancel
                 (do
                   (async/thread
                     (try
                       (doseq [p (core/packets {:path in* :filter bpf* :decode? true :max Long/MAX_VALUE})]
                         (when cancel-ch
                           (let [[_ port] (async/alts!! [cancel-ch] :default [:ok nil])]
                             (when port (reset! cancelled? true))))
                         (when-not @cancelled?
                           (if (= async-mode :dropping)
                             (when-not (async/offer! pkt-ch p)
                               (swap! dropped inc))
                             (async/>!! pkt-ch p))))
                       (finally (async/close! pkt-ch))))
                   (loop [acc []]
                     (if-let [p (async/<!! pkt-ch)]
                       (recur (conj acc p))
                       acc))))
          cnt   (count pkts)
          bytes (reduce + 0 (map :caplen pkts))
          caplens (map :caplen pkts)
          cmin (when (seq caplens) (apply min caplens))
          cmax (when (seq caplens) (apply max caplens))
          cavg (when (seq caplens) (double (/ (long (reduce + 0 caplens)) (long cnt))))
          ;; Keep only valid timestamp pairs.
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
                                          (long (/ (unchecked-subtract (long end-us) (long start-us)) 1000)))}
                 :proto   {:l3 (->> pkts (map #(get-in % [:decoded :l3 :type])) (remove nil?) frequencies)
                           :l4 (->> pkts (map #(get-in % [:decoded :l3 :l4 :type])) (remove nil?) frequencies)}
                 :top     {:src (->> pkts (map #(get-in % [:decoded :l3 :src])) (remove nil?) frequencies (top-freqs n))
                           :dst (->> pkts (map #(get-in % [:decoded :l3 :dst])) (remove nil?) frequencies (top-freqs n))}
                 :async? async?
                 :async-mode async-mode
                 :async-buffer async-buffer
                 :async-timeout-ms async-timeout-ms
                 :async-cancelled? @cancelled?
                 :async-dropped @dropped}]
      (ex/emit fmt stats)
      (binding [*out* *err*]
        (println "bpf=" (pr-str bpf) " topN=" n " format=" (name fmt)
                 (when async? (str " async=true buffer=" async-buffer " async-mode=" (name async-mode)
                                   " dropped=" @dropped " cancelled=" @cancelled?)))))))
