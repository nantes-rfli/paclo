(ns examples.pcap-filter
  (:require
   [clojure.core.async :as async]
   [examples.common :as ex]
   [paclo.core :as core]))

(def ^:private default-async-buffer 1024)
(def ^:private default-async-mode :buffer)

(defn- chan->lazy-seq
  "Drain channel into lazy seq, tracking counts/bytes via atoms."
  [ch out-count out-bytes]
  (lazy-seq
   (when-let [v (async/<!! ch)]
     (swap! out-count inc)
     (when-let [c (:caplen v)] (swap! out-bytes + (long c)))
     (cons v (chan->lazy-seq ch out-count out-bytes)))))

(defn- usage []
  (binding [*out* *err*]
    (println "Usage:")
    (println "  clojure -M:dev -m examples.pcap-filter <in.pcap> <out.pcap> [<bpf>] [<min-caplen>] [<format>] [--async] [--async-buffer N] [--async-mode buffer|dropping] [--async-timeout-ms MS]")
    (println "Defaults: <bpf>=nil, <min-caplen>=nil, <format>=edn, async=off, async-buffer=1024, async-mode=buffer")
    (println "Formats : edn | jsonl")
    (println "Tips    : use \"_\" to skip an optional arg (e.g., '_' for <bpf>); async is opt-in for long runs")
    (println "Examples: --async (backpressure), --async --async-mode dropping --async-buffer 16 (lossy), --async --async-timeout-ms 1000 (cancel after 1s)")))

(defn -main [& args]
  (let [[in out bpf min-caplen-str fmt-str & flags] args]
    (when (or (nil? in) (nil? out))
      (usage) (System/exit 1))
    (let [in*        (ex/require-file! in)
          fmt        (ex/parse-format fmt-str)
          bpf*       (when-not (ex/blank? bpf) bpf)
          min-caplen (ex/parse-long* min-caplen-str)
          xf         (if min-caplen (filter #(>= (long (:caplen %)) (long min-caplen))) identity)
          {:keys [async? async-buffer async-mode async-timeout-ms]} (ex/parse-async-opts flags {:default-buffer default-async-buffer :default-mode default-async-mode})
          in-pkts    (atom 0)
          in-bytes   (atom 0)
          out-pkts   (atom 0)
          out-bytes  (atom 0)
          cancelled? (atom false)
          dropped    (atom 0)]
      (println "reading:" in)
      (println "writing:" out)
      (if-not async?
        ;; synchronous path
        (let [in-seq   (into [] (core/packets {:path in* :filter bpf* :max Long/MAX_VALUE}))
              written  (core/write-pcap! (sequence xf in-seq) out)
              out-seq  (into [] (core/packets {:path out :max Long/MAX_VALUE}))
              in-count (count in-seq)
              out-count (count out-seq)
              in-total (reduce + 0 (map :caplen in-seq))
              out-total (reduce + 0 (map :caplen out-seq))
              drop-pct (if (pos? in-count)
                         (double (* 100.0 (- 1.0 (/ (double out-count) (double in-count)))))
                         0.0)
              meta {:in in :out out :filter bpf*
                    :min-caplen min-caplen
                    :in-packets  in-count
                    :out-packets out-count
                    :in-bytes  in-total
                    :out-bytes out-total
                    :drop-pct drop-pct}]
          (println "done. wrote packets =" written)
          (ex/emit fmt meta))
        ;; asynchronous path (buffer, dropping, timeout-cancel)
        (let [cancel-ch (when async-timeout-ms (async/timeout async-timeout-ms))
              pkt-ch    (async/chan (async/buffer async-buffer) xf)
              reader    (async/thread
                          (try
                            (loop [s (core/packets {:path in* :filter bpf* :max Long/MAX_VALUE})]
                              (when-let [p (first s)]
                                (swap! in-pkts inc)
                                (when-let [c (:caplen p)] (swap! in-bytes + (long c)))
                                (when cancel-ch
                                  (let [[_ port] (async/alts!! [cancel-ch] :default [:ok nil])]
                                    (when port (reset! cancelled? true))))
                                (when-not @cancelled?
                                  (if (= async-mode :dropping)
                                    (when-not (async/offer! pkt-ch p)
                                      (swap! dropped inc))
                                    (async/>!! pkt-ch p)))
                                (when-not @cancelled?
                                  (recur (rest s)))))
                            (finally
                              (async/close! pkt-ch))))
              drain     (chan->lazy-seq pkt-ch out-pkts out-bytes)
              written   (core/write-pcap! drain out)
              _         (async/<!! reader)
              out-seq   (into [] (core/packets {:path out :max Long/MAX_VALUE}))
              out-count (count out-seq)
              out-total (reduce + 0 (map :caplen out-seq))
              drop-pct  (if (pos? (long @in-pkts))
                          (double (* 100.0 (- 1.0 (/ (double out-count) (double @in-pkts)))))
                          0.0)
              meta {:in in :out out :filter bpf*
                    :min-caplen min-caplen
                    :in-packets  @in-pkts
                    :out-packets out-count
                    :in-bytes  @in-bytes
                    :out-bytes out-total
                    :drop-pct drop-pct
                    :async? async?
                    :async-mode async-mode
                    :async-buffer async-buffer
                    :async-timeout-ms async-timeout-ms
                    :async-cancelled? @cancelled?
                    :async-dropped @dropped}]
          (println "done. wrote packets =" written (when @cancelled? "(cancelled)"))
          (ex/emit fmt meta))))))
