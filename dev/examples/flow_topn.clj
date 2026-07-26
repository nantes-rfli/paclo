(ns examples.flow-topn
  (:require
   [clojure.core.async :as async]
   [examples.common :as ex]
   [paclo.core :as core])
  (:import
   [java.util HashMap]))

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
    (println "  clojure -M:dev -m examples.flow-topn <in.pcap> [<bpf>] [<topN>] [<mode>] [<metric>] [<format>] [--async] [--async-buffer N] [--async-mode buffer|dropping] [--async-timeout-ms MS]")
    (println "Defaults: <bpf>='udp or tcp', <topN>=10, <mode>=unidir, <metric>=packets, <format>=edn, async=off, async-buffer=1024, async-mode=buffer")
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

(defn- flow->repr [{:keys [proto src-ip src-port dst-ip dst-port]}]
  {:proto proto
   :src (str (ip->str src-ip) (when src-port (str ":" src-port)))
   :dst (str (ip->str dst-ip) (when dst-port (str ":" dst-port)))})

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

(defn- packet->flow-key
  "Build a compatible flow key from a numeric flow projection."
  [m bidir?]
  (let [{:keys [protocol src-ip dst-ip src-port dst-port]} m]
    (when (and protocol src-ip dst-ip)
      (canon-fk {:proto (get protocol-names protocol protocol)
                 :src-ip src-ip :src-port src-port
                 :dst-ip dst-ip :dst-port dst-port}
                bidir?))))

(defn- add-packet! [^HashMap counts packet bidir?]
  (if-let [flow-key (packet->flow-key packet bidir?)]
    (if-let [^longs aggregate (.get counts flow-key)]
      (do
        (aset-long aggregate 0 (unchecked-inc (aget aggregate 0)))
        (aset-long aggregate 1
                   (unchecked-add (aget aggregate 1)
                                  (long (or (:caplen packet) 0)))))
      (.put counts flow-key
            (long-array [1 (long (or (:caplen packet) 0))])))
    counts))

(defn- top-rows [^HashMap counts metric top-n]
  (->> counts
       (map (fn [[flow-key ^longs aggregate]]
              {:flow (flow->repr flow-key)
               :packets (aget aggregate 0)
               :bytes (aget aggregate 1)}))
       (sort-by (case metric
                  :bytes :bytes
                  :packets :packets)
                >)
       (take top-n)
       vec))

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
            counts (HashMap.)
            total  (atom 0)
            dropped (atom 0)
            cancelled? (atom false)]
        (if-not async?
          ;; synchronous path
          (let [total (volatile! 0)
                _ (core/reduce-packets
                   {:path in*
                    :filter bpf
                    :decode-mode :flow
                    :max Long/MAX_VALUE}
                   (fn [state packet]
                     (vswap! total
                             (fn [value]
                               (unchecked-inc (long value))))
                     (add-packet! counts packet bidir?)
                     state)
                   nil)
                rows (top-rows counts metric topN)]
            (ex/emit fmt rows)
            (binding [*out* *err*]
              (println "flows=" (count rows)
                       " total-packets=" @total
                       " topN=" topN " mode=" (name mode) " metric=" (name metric))))
          ;; asynchronous path
          (let [cancel-ch (when async-timeout-ms (async/timeout async-timeout-ms))
                buf (case async-mode
                      :dropping (async/dropping-buffer async-buffer)
                      (async/buffer async-buffer))
                pkt-ch (async/chan buf)
                reader (async/thread
                         (try
                           (core/reduce-packets
                            {:path in*
                             :filter bpf
                             :decode-mode :flow
                             :max Long/MAX_VALUE}
                            (fn [state packet]
                              (swap! total inc)
                              (when cancel-ch
                                (let [[_ port] (async/alts!! [cancel-ch] :default [:ok nil])]
                                  (when port (reset! cancelled? true))))
                              (when-not @cancelled?
                                (if (= async-mode :dropping)
                                  (when-not (async/offer! pkt-ch packet)
                                    (swap! dropped inc))
                                  (async/>!! pkt-ch packet)))
                              state)
                            nil)
                           (finally (async/close! pkt-ch))))
                _ (async/thread (async/<!! reader))
                ;; consume
                _ (loop []
                    (when-let [p (async/<!! pkt-ch)]
                      (add-packet! counts p bidir?)
                      (recur)))
                rows (top-rows counts metric topN)]
            (ex/emit fmt rows)
            (binding [*out* *err*]
              (println "flows=" (count rows)
                       " total-packets=" @total
                       " topN=" topN " mode=" (name mode) " metric=" (name metric)
                       " async=true" " buffer=" async-buffer " async-mode=" (name async-mode)
                       " dropped=" @dropped " cancelled=" @cancelled?))))))))
