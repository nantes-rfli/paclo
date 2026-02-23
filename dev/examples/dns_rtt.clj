(ns examples.dns-rtt
  (:require
   [clojure.core.async :as async]
   [clojure.data.json :as json]
   [clojure.string :as str]
   [examples.common :as ex]
   [paclo.core :as core]
   [paclo.proto.dns-ext :as dns-ext]))

;; -------- usage/help --------

(defn- usage []
  (binding [*out* *err*]
    (println "Usage:")
    (println "  clojure -M:dev:dns-ext -m examples.dns-rtt <in.pcap>"
             " [<bpf-string>] [<topN>] [<mode>] [<metric>] [<format>] [<alert%>]"
             " [--client <prefix>] [--server <prefix>] [--async] [--async-buffer N] [--async-mode buffer|dropping] [--async-timeout-ms MS]")
    (println)
    (println "Defaults:")
    (println "  <bpf-string> = 'udp and port 53'")
    (println "  <topN>       = 50 (used by pairs/qstats)")
    (println "  <mode>       = pairs | stats | qstats   (default: pairs)")
    (println "  <metric>     = pairs | with-rtt | p50 | p95 | p99 | avg | max (qstats only; default: pairs)")
    (println "  <format>     = edn | jsonl (default: edn)")
    (println "  <alert%>     = NXDOMAIN+SERVFAIL threshold (example: 5 -> 5%)")
    (println "  --client/-c  <prefix>   : 192.168.4.28  or  192.168.4.28:5")
    (println "  --server/-s  <prefix>   : 1.1.1.1       or  1.1.1.1:53")
    (println "  async        = opt-in (backpressure/drop/cancel). Defaults: buffer=1024, mode=buffer")
    (println "  Tips         = optional args can be skipped with '_' (e.g., '_' for <alert%>)")
    (println)
    (println "Examples:")
    (println "  clojure -M:dev:dns-ext -m examples.dns-rtt test/resources/dns-sample.pcap")
    (println "  clojure -M:dev:dns-ext -m examples.dns-rtt test/resources/dns-sample.pcap 'udp and port 53' 10")
    (println "  clojure -M:dev:dns-ext -m examples.dns-rtt test/resources/dns-sample.pcap 'udp and port 53' 50 stats jsonl 2.5")
    (println "  clojure -M:dev:dns-ext -m examples.dns-rtt test/resources/dns-sample.pcap 'udp and port 53' 20 qstats p95 jsonl --server 1.1.1.1:53")))

;; -------- tiny helpers --------

(defn- micros [{:keys [sec usec]}]
  (when (and (number? sec) (number? usec))
    (+ (* (long sec) 1000000) (long usec))))

(defn- endpoint [m side]
  (let [ip (get-in m [:decoded :l3 (case side :src :src :dst :dst)])
        p  (get-in m [:decoded :l3 :l4 (case side :src :src-port :dst :dst-port)])]
    (str ip (when p (str ":" p)))))

(defn- starts-opt? [s] (and (string? s) (str/starts-with? s "-")))

;; -------- DNS header parse --------

(defn- u8  ^long [^bytes ba ^long i]
  (when (and ba (<= 0 i) (< i (alength ba)))
    (bit-and 0xFF (aget ba i))))

(defn- u16 ^long [^bytes ba ^long i]
  (when-let [hi (u8 ba i)]
    (when-let [lo (u8 ba (inc i))]
      (bit-or (bit-shift-left hi 8) lo))))

(defn- parse-dns-header
  "Parse DNS header fields from payload.
  Returns {:id <u16> :qr? <bool>} or nil."
  [^bytes ba]
  (when (and ba (<= 12 (alength ba)))
    (let [id    (u16 ba 0)
          flags (u16 ba 2)]
      (when (and id flags)
        {:id id :qr? (pos? (bit-and flags 0x8000))}))))

;; -------- pairing key & pretty endpoints --------

(defn- canon-key
  "Canonical key for DNS transaction pairing: [id endpoint-a endpoint-b]."
  [m id]
  (let [a (endpoint m :src)
        b (endpoint m :dst)]
    (if (neg? (compare a b))
      [id a b]
      [id b a])))

(defn- classify-client-server
  "Classify client/server by port 53 when possible; otherwise use stable lexical order."
  [m]
  (let [sp (get-in m [:decoded :l3 :l4 :src-port])
        dp (get-in m [:decoded :l3 :l4 :dst-port])]
    (cond
      (= 53 sp) {:client (endpoint m :dst) :server (endpoint m :src)}
      (= 53 dp) {:client (endpoint m :src) :server (endpoint m :dst)}
      :else     (let [a (endpoint m :src) b (endpoint m :dst)]
                  (if (neg? (compare a b))
                    {:client a :server b}
                    {:client b :server a})))))

;; -------- stats helpers --------

(defn- nearest-rank
  "Nearest-rank percentile(p 0.0..100.0)"
  [sorted-xs p]
  (let [n (count sorted-xs)]
    (when (pos? n)
      (let [rank (int (Math/ceil (* (/ (double p) 100.0) (long n))))
            idx  (max 0 (min (dec n) (dec rank)))]
        (nth sorted-xs idx)))))

(defn- summarize-rtt [rows]
  (let [xs   (->> rows (keep :rtt-ms) sort vec)
        n    (count xs)
        sum  (reduce + 0.0 xs)]
    {:count n
     :min   (when (pos? n) (first xs))
     :p50   (nearest-rank xs 50.0)
     :p95   (nearest-rank xs 95.0)
     :p99   (nearest-rank xs 99.0)
     :avg   (when (pos? n) (/ (long sum) (long n)))
     :max   (when (pos? n) (peek xs))}))

(defn- summarize-rcode [rows]
  (let [pairs (count rows)
        cnts  (frequencies (map #(or (:rcode %) :unknown) rows))
        ratio (into {} (for [[k c] cnts]
                         [k (double (/ (long c) (long (max 1 pairs))))]))]
    {:counts cnts
     :ratio  ratio}))

(defn- summarize-qstats
  "Summarize rows by qname. Output shape:
   [{:qname \"example.com\", :pairs 123, :with-rtt 100,
     :rtt {...}, :rcode {...}} ...]"
  [rows]
  (->> (group-by #(or (:qname %) :unknown) rows)
       (map (fn [[q xs]]
              (let [rtt (summarize-rtt xs)
                    rc  (summarize-rcode xs)]
                {:qname (if (= :unknown q) nil q)
                 :pairs (count xs)
                 :with-rtt (:count rtt)
                 :rtt rtt
                 :rcode rc})))
       vec))

(defn- metric->keyfn
  "Metric selector for qstats ranking. Missing values sort as negative infinity."
  [metric]
  (case metric
    :pairs     (fn [{:keys [pairs]}]     (long (or pairs 0)))
    :with-rtt  (fn [{:keys [with-rtt]}]  (long (or with-rtt 0)))
    :p50       (fn [{:keys [rtt]}]       (double (or (:p50 rtt) Double/NEGATIVE_INFINITY)))
    :p95       (fn [{:keys [rtt]}]       (double (or (:p95 rtt) Double/NEGATIVE_INFINITY)))
    :p99       (fn [{:keys [rtt]}]       (double (or (:p99 rtt) Double/NEGATIVE_INFINITY)))
    :avg       (fn [{:keys [rtt]}]       (double (or (:avg rtt) Double/NEGATIVE_INFINITY)))
    :max       (fn [{:keys [rtt]}]       (double (or (:max rtt) Double/NEGATIVE_INFINITY)))
    ;; default
    (fn [{:keys [pairs]}] (long (or pairs 0)))))

(defn- overall-error-rate
  "Compute NXDOMAIN/SERVFAIL ratio and counts from rows."
  [rows]
  (let [pairs (max 1 (count rows))
        cnts  (frequencies (map #(or (:rcode %) :unknown) rows))
        ne    (long (get cnts :nxdomain 0))
        sf    (long (get cnts :servfail 0))
        rate  (/ (+ ne sf) (double pairs))]
    {:rate rate :counts {:nxdomain ne :servfail sf :total pairs}}))

;; -------- option parsing --------

(defn- parse-filters
  "Parse endpoint prefix filters from --client/-c and --server/-s."
  [opts]
  (loop [m {:client nil :server nil}
         xs (seq opts)]
    (if (nil? xs)
      m
      (let [[a & more] xs]
        (cond
          (and (#{"--client" "-c"} a) (seq more))
          (recur (assoc m :client (first more)) (next more))

          (and (#{"--server" "-s"} a) (seq more))
          (recur (assoc m :server (first more)) (next more))

          :else
          (recur m (next xs)))))))

(defn- drop-client-server-opts
  "Remove client/server filter flags before passing args to async option parser."
  [opts]
  (loop [xs opts acc []]
    (if (empty? xs)
      acc
      (let [[a & more] xs]
        (cond
          (#{"--client" "-c"} a) (recur more acc)
          (#{"--server" "-s"} a) (recur more acc)
          :else (recur (rest xs) (conj acc a)))))))

(defn- parse-positionals
  "Parse positional arguments in order [:bpf :topn :mode :metric :fmt :alert].
   '_' skips a positional; first option token starts :tail."
  [xs]
  (loop [order [:bpf :topn :mode :metric :fmt :alert]
         acc   {:bpf nil :topn nil :mode nil :metric nil :fmt nil :alert nil :tail []}
         more  xs]
    (if (empty? more)
      acc
      (let [t (first more)]
        (if (starts-opt? t)
          (assoc acc :tail more)
          (if (empty? order)
            (assoc acc :tail more)
            (recur (rest order)
                   (assoc acc (first order) (when-not (ex/blank? t) t))
                   (rest more))))))))

;; -------- endpoint filter --------

(defn- match-prefix? [^String prefix ^String s]
  (or (nil? prefix)
      (and (string? s) (str/starts-with? s prefix))))

(defn- apply-endpoint-filters
  "Apply optional client/server prefix filters to computed rows."
  [{cf :client sf :server} rows]
  (if (and (nil? cf) (nil? sf))
    rows
    (filterv (fn [row]
               (let [c (:client row)
                     s (:server row)]
                 (and (match-prefix? cf c)
                      (match-prefix? sf s))))
             rows)))

;; -------- main --------

(defn -main
  "Compute DNS transaction RTTs by pairing queries with responses.
   - default BPF: 'udp and port 53'
   - pairing key: DNS id + canonicalized endpoints
   - qname/qtype/rcode come from dns-ext on best effort
   - mode=pairs returns top-N rows by RTT ordering
   - mode=stats returns aggregate RTT and RCODE stats
   - mode=qstats returns per-qname aggregates
   - format=edn | jsonl
   - alert% emits warning when NXDOMAIN+SERVFAIL rate exceeds threshold
   - --client/--server filter endpoint prefixes (IP or IP:PORT)"
  [& args]
  (let [[in & rest-args] args]
    (when (nil? in) (usage) (System/exit 1))
    (let [{:keys [bpf topn mode metric fmt alert tail]} (parse-positionals rest-args)
          bpf    (or bpf "udp and port 53")
          topN   (or (ex/parse-long* topn) 50)
          mode   (keyword (or mode "pairs"))
          metric (keyword (or metric "pairs"))
          fmt    (ex/parse-format fmt)
          alert% (ex/parse-double* alert)
          fopts  (parse-filters tail)
          async-tail (drop-client-server-opts tail)
          {:keys [async? async-buffer async-mode async-timeout-ms]} (ex/parse-async-opts async-tail {:default-buffer 1024 :default-mode :buffer})
          _      (dns-ext/register!)]
      (ex/ensure-one-of! "mode"   mode   #{:pairs :stats :qstats})
      (ex/ensure-one-of! "format" fmt    #{:edn :jsonl})
      ;; Build rows, optionally via async ingestion.
      (let [rows-all
            (if-not async?
              (->> (core/packets {:path in
                                  :filter bpf
                                  :decode? true
                                  :max Long/MAX_VALUE})
                   (reduce
                    (fn [{:keys [pending out]} m]
                      (let [ba (get-in m [:decoded :l3 :l4 :payload])]
                        (if-let [{:keys [id qr?]} (parse-dns-header ^bytes ba)]
                          (let [k (canon-key m id)]
                            (if (not qr?) ; query
                              (if (contains? pending k)
                                {:pending pending :out out}
                                (let [app (get-in m [:decoded :l3 :l4 :app])
                                      t   (micros m)
                                      es  (classify-client-server m)]
                                  {:pending (assoc pending k
                                                   (merge es
                                                          {:t t
                                                           :id id
                                                           :qname (:qname app)
                                                           :qtype (:qtype-name app)}))
                                   :out out}))
                              ;; response
                              (if-let [{qt :t :as q} (get pending k)]
                                (let [rt     (micros m)
                                      app    (get-in m [:decoded :l3 :l4 :app])
                                      rcode  (some-> (:rcode-name app) keyword)
                                      rtt-ms (when (and (number? qt) (number? rt))
                                               (double (/ (unchecked-subtract (long rt) (long qt)) 1000.0)))]
                                  {:pending (dissoc pending k)
                                   :out (conj out
                                              (cond-> (-> (select-keys q [:id :qname :qtype :client :server])
                                                          (assoc :rcode rcode))
                                                (and (number? rtt-ms) (not (neg? (double rtt-ms))))
                                                (assoc :rtt-ms rtt-ms)))})
                                {:pending pending :out out})))
                          {:pending pending :out out})))
                    {:pending {} :out []})
                   :out)
              (let [dropped    (atom 0)
                    cancelled? (atom false)
                    buf (case async-mode
                          :dropping (async/dropping-buffer async-buffer)
                          (async/buffer async-buffer))
                    pkt-ch (async/chan buf)
                    cancel-ch (when async-timeout-ms (async/timeout async-timeout-ms))]
                (async/thread
                  (try
                    (doseq [m (core/packets {:path in :filter bpf :decode? true :max Long/MAX_VALUE})]
                      (when cancel-ch
                        (let [[_ port] (async/alts!! [cancel-ch] :default [:ok nil])]
                          (when port (reset! cancelled? true))))
                      (when-not @cancelled?
                        (if (= async-mode :dropping)
                          (when-not (async/offer! pkt-ch m)
                            (swap! dropped inc))
                          (async/>!! pkt-ch m))))
                    (finally (async/close! pkt-ch))))
                (loop [pending {} out []]
                  (if-let [m (async/<!! pkt-ch)]
                    (let [ba (get-in m [:decoded :l3 :l4 :payload])]
                      (if-let [{:keys [id qr?]} (parse-dns-header ^bytes ba)]
                        (let [k (canon-key m id)]
                          (if (not qr?)
                            (if (contains? pending k)
                              (recur pending out)
                              (let [app (get-in m [:decoded :l3 :l4 :app])
                                    t   (micros m)
                                    es  (classify-client-server m)]
                                (recur (assoc pending k (merge es {:t t :id id :qname (:qname app) :qtype (:qtype-name app)})) out)))
                            (if-let [{qt :t :as q} (get pending k)]
                              (let [rt     (micros m)
                                    app    (get-in m [:decoded :l3 :l4 :app])
                                    rcode  (some-> (:rcode-name app) keyword)
                                    rtt-ms (when (and (number? qt) (number? rt))
                                             (double (/ (unchecked-subtract (long rt) (long qt)) 1000.0)))]
                                (recur (dissoc pending k)
                                       (conj out (cond-> (-> (select-keys q [:id :qname :qtype :client :server])
                                                             (assoc :rcode rcode))
                                                   (and (number? rtt-ms) (not (neg? (double rtt-ms))))
                                                   (assoc :rtt-ms rtt-ms)))))
                              (recur pending out))))
                        (recur pending out)))
                    (conj out {:dangling (count pending)
                               :async? async?
                               :async-mode async-mode
                               :async-buffer async-buffer
                               :async-timeout-ms async-timeout-ms
                               :async-cancelled? @cancelled?
                               :async-dropped @dropped})))))
            rows (apply-endpoint-filters fopts rows-all)]

        ;; Optional error-rate alert.
        (when alert%
          (let [{:keys [rate counts]} (overall-error-rate rows)
                pct (unchecked-multiply 100.0 (double rate))]
            (when (>= pct (double alert%))
              (binding [*out* *err*]
                (println "WARNING: DNS error rate"
                         (format "%.2f%%" pct)
                         ">= threshold" (format "%.2f%%" alert%)
                         "details" (pr-str counts))))))

        (case mode
          :stats
          (let [rtt (summarize-rtt rows)
                rc  (summarize-rcode rows)
                out {:pairs (count rows)
                     :with-rtt (:count rtt)
                     :rtt rtt
                     :rcode rc}]
            (case fmt
              :jsonl (do (json/write out *out*) (println))
              (println (pr-str out)))
            (binding [*out* *err*]
              (println "mode=stats bpf=" (pr-str bpf)
                       " format=" (name fmt)
                       " client=" (pr-str (:client fopts))
                       " server=" (pr-str (:server fopts))
                       (when async? (str " async=true buffer=" async-buffer " async-mode=" (name async-mode)
                                         " dropped=" (:async-dropped (last rows-all))
                                         " cancelled=" (:async-cancelled? (last rows-all)))))))

          :qstats
          (let [qs    (summarize-qstats rows)
                keyf  (metric->keyfn metric)
                ranked (->> qs (sort-by keyf >) (take topN) vec)]
            (case fmt
              :jsonl (doseq [row ranked] (json/write row *out*) (println))
              (println (pr-str ranked)))
            (binding [*out* *err*]
              (println "mode=qstats metric=" (name metric)
                       " topN=" topN
                       " qnames=" (count qs)
                       " bpf=" (pr-str bpf)
                       " format=" (name fmt)
                       " client=" (pr-str (:client fopts))
                       " server=" (pr-str (:server fopts))
                       (when async? (str " async=true buffer=" async-buffer " async-mode=" (name async-mode)
                                         " dropped=" (:async-dropped (last rows-all))
                                         " cancelled=" (:async-cancelled? (last rows-all)))))))

          ;; default: pairs
          (let [sorted (->> rows
                            (sort-by (fn [{x :rtt-ms}]
                                       (if (number? x) x Double/POSITIVE_INFINITY)))
                            (take topN) vec)]
            (case fmt
              :jsonl (doseq [row sorted] (json/write row *out*) (println))
              (println (pr-str sorted)))
            (binding [*out* *err*]
              (println "pairs=" (count rows)
                       " topN=" topN
                       " bpf=" (pr-str bpf)
                       " format=" (name fmt)
                       " client=" (pr-str (:client fopts))
                       " server=" (pr-str (:server fopts))
                       (when async? (str " async=true buffer=" async-buffer " async-mode=" (name async-mode)
                                         " dropped=" (:async-dropped (last rows-all))
                                         " cancelled=" (:async-cancelled? (last rows-all))))))))))))
