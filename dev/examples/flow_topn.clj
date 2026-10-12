(ns examples.flow-topn
  (:require
   [clojure.core.async :as async]
   [examples.common :as ex]
   [paclo.core :as core]
   [paclo.flow :as flow]))

(def ^:private default-async-buffer 1024)
(def ^:private default-async-mode :buffer)
(def ^:private protocol-names
  {1 :icmp
   6 :tcp
   17 :udp
   58 :icmp6})

(defn- usage []
  (binding [*out* *err*]
    (println "Usage:")
    (println "  clojure -M:dev -m examples.flow-topn <in.pcap> [<bpf>] [<topN>] [<mode>] [<metric>] [<format>] [--async] [--async-buffer N] [--async-mode buffer|dropping] [--async-timeout-ms MS] [--max-flows N]")
    (println "Defaults: <bpf>='udp or tcp', <topN>=10, <mode>=unidir, <metric>=packets, <format>=edn, async=off, async-buffer=1024, async-mode=buffer, max-flows=100000")
    (println "Modes  : unidir | bidir")
    (println "Metric : packets | bytes")
    (println "Formats: edn | jsonl")
    (println "Tips   : use \"_\" to skip an optional arg (e.g., '_' for <bpf>); async is opt-in for long runs")))

(defn- ipv4->str [address]
  (str (bit-and (unsigned-bit-shift-right (long address) 24) 0xff) "."
       (bit-and (unsigned-bit-shift-right (long address) 16) 0xff) "."
       (bit-and (unsigned-bit-shift-right (long address) 8) 0xff) "."
       (bit-and (long address) 0xff)))

(defn- ipv6->str [[high low]]
  (let [word (fn [value ^long shift]
               (Long/toHexString
                (bit-and (unsigned-bit-shift-right (long value) shift)
                         0xffff)))]
    (str (word high 48) ":" (word high 32) ":"
         (word high 16) ":" (word high 0) ":"
         (word low 48) ":" (word low 32) ":"
         (word low 16) ":" (word low 0))))

(defn- ip->str [address]
  (if (vector? address)
    (ipv6->str address)
    (ipv4->str address)))

(defn- flow->repr [{:keys [protocol src-ip src-port dst-ip dst-port]}]
  {:proto (get protocol-names protocol protocol)
   :src (str (ip->str src-ip) (when src-port (str ":" src-port)))
   :dst (str (ip->str dst-ip) (when dst-port (str ":" dst-port)))})

(defn- parse-flags [flags]
  (loop [xs flags max-flows 100000 async-flags []]
    (if (empty? xs)
      (assoc (ex/parse-async-opts async-flags
                                  {:default-buffer default-async-buffer
                                   :default-mode default-async-mode})
             :max-flows max-flows)
      (if (= "--max-flows" (first xs))
        (let [value (ex/parse-long* (second xs))]
          (when-not (and value (pos? (long value)))
            (throw (ex-info "--max-flows requires a positive integer" {})))
          (recur (nnext xs) (long value) async-flags))
        (recur (next xs) max-flows (conj async-flags (first xs)))))))

(defn- display-rows [result metric top-n]
  (mapv (fn [{:keys [flow packets captured-bytes]}]
          {:flow (flow->repr flow) :packets packets :bytes captured-bytes})
        (flow/top-n result {:metric (if (= :bytes metric) :captured-bytes :packets)
                            :n top-n})))

(defn- async-aggregate [opts rf {:keys [async-buffer async-mode async-timeout-ms]}]
  (let [total (atom 0)
        dropped (atom 0)
        cancelled? (atom false)
        stop-ch (async/chan)
        cancel-ch (when async-timeout-ms
                    (if (zero? async-timeout-ms)
                      (doto (async/chan) (async/close!))
                      (async/timeout async-timeout-ms)))
        ;; offer! against a fixed buffer reports every discarded input.
        pkt-ch (async/chan (async/buffer async-buffer))
        reader (async/thread
                 (try
                   (core/reduce-packets
                    opts
                    (fn [state packet]
                      (swap! total inc)
                      (let [stop-ports (cond-> [stop-ch] cancel-ch (conj cancel-ch))
                            [_ ready] (async/alts!! stop-ports :default :active)
                            sent? (and (= :default ready)
                                       (if (= :dropping async-mode)
                                         (do (when-not (async/offer! pkt-ch packet)
                                               (swap! dropped inc))
                                             true)
                                         (let [[sent port] (async/alts!! (conj stop-ports [pkt-ch packet])
                                                                         :priority true)]
                                           (and (= port pkt-ch) sent))))]
                        (if sent?
                          state
                          (do (reset! cancelled? true) (reduced state)))))
                    nil)
                   {:ok true}
                   (catch Throwable error {:error error})
                   (finally (async/close! pkt-ch))))]
    (try
      (let [result (loop [state (rf)]
                     (if-let [packet (async/<!! pkt-ch)]
                       (recur (rf state packet))
                       (rf state)))
            reader-result (async/<!! reader)]
        (when-let [error (:error reader-result)] (throw error))
        {:result result :total @total :dropped @dropped :cancelled? @cancelled?})
      (finally
        ;; Release a blocked producer when aggregation throws (e.g. max-flows).
        (async/close! stop-ch)
        (async/close! pkt-ch)
        (async/<!! reader)))))

(defn -main [& args]
  (let [[positional flags] (split-with #(not (.startsWith ^String % "--")) args)
        [in bpf topn-str mode-str metric-str fmt-str] positional]
    (when (nil? in) (usage) (System/exit 1))
    (let [in* (ex/require-file! in)
          bpf (if (ex/blank? bpf) "udp or tcp" bpf)
          topN (or (ex/parse-long* topn-str) 10)
          mode (keyword (if (ex/blank? mode-str) "unidir" mode-str))
          metric (keyword (if (ex/blank? metric-str) "packets" metric-str))
          fmt (ex/parse-format fmt-str)
          {:keys [async? async-buffer async-mode max-flows] :as execution} (parse-flags flags)]
      (ex/ensure-one-of! "mode" mode #{:unidir :bidir})
      (ex/ensure-one-of! "metric" metric #{:packets :bytes})
      (let [rf (flow/aggregate-rf {:direction mode :max-flows max-flows})
            opts {:path in* :filter bpf :decode-mode :flow :max Long/MAX_VALUE}
            {:keys [result total dropped cancelled?]}
            (if async?
              (async-aggregate opts rf execution)
              (let [result (core/reduce-packets opts rf (rf))]
                {:result result :total (get-in result [:summary :seen])}))
            rows (display-rows result metric topN)]
        (ex/emit fmt rows)
        (binding [*out* *err*]
          (print "flows=" (count rows) " total-packets=" total
                 " topN=" topN " mode=" (name mode) " metric=" (name metric))
          (when async?
            (print " async=true" " buffer=" async-buffer " async-mode=" (name async-mode)
                   " dropped=" dropped " cancelled=" cancelled?))
          (println))))))
