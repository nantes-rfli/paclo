(ns examples.dns-rtt
  (:require
   [clojure.string :as str]
   [examples.common :as ex]
   [examples.dns-cli :as cli]
   [paclo.dns :as dns]))

(def defaults
  {:mode :pairs :topn 50 :metric :pairs :max-pending 100000 :max-retired 100000
   :timeout-us 5000000 :reuse-delay-us 5000000 :max-samples 1000000 :max-qnames 100000})

(defn- usage []
  (binding [*out* *err*]
    (println "Usage: clojure -M:dev:dns-ext -m examples.dns-rtt <in.pcap> [bpf] [topN] [pairs|stats|qstats] [metric] [edn|jsonl] [alert%]")
    (println "Options: --client/-c PREFIX --server/-s PREFIX --reorder-us N --timeout-us N --reuse-delay-us N --max-pending N --max-retired N --max-samples N --max-qnames N")
    (println "Delivery: --async --async-buffer N --async-mode buffer|dropping --async-timeout-ms MS; use '_' to skip positionals.")))

(def ^:private rcode-names
  {0 :noerror 1 :formerr 2 :servfail 3 :nxdomain 4 :notimp 5 :refused
   6 :yxdomain 7 :yxrrset 8 :nxrrset 9 :notauth 10 :notzone})
(def ^:private qtype-names {1 :A 2 :NS 5 :CNAME 6 :SOA 12 :PTR 15 :MX 16 :TXT 28 :AAAA 33 :SRV 64 :SVCB 65 :HTTPS})

(defn- rcode-name [n] (get rcode-names n (if (nil? n) :unknown (keyword (str "rcode-" n)))))
(defn- endpoint [{:keys [ip port]}] (str ip ":" port))
(defn- pair-order [row]
  [(:rtt-us row) (:client row) (:server row) (:id row) (:qname row) (:qtype row) (:rcode row)])
(defn- match-filter? [prefix value] (or (nil? prefix) (str/starts-with? value prefix)))

(defn init [options]
  (let [opts (merge defaults cli/execution-defaults options)]
    (doseq [k [:topn :max-samples :max-qnames]]
      (when-not (and (integer? (k opts)) (pos? (k opts)))
        (throw (ex-info "invalid report bound" {:reason :invalid-options :option k}))))
    (cli/limit! :max-samples (:topn opts) (:max-samples opts))
    {:options opts :reorder-us (:reorder-us opts)
     :analysis (dns/init opts) :diagnostics {} :pairs 0 :rcode {} :samples [] :qstats {} :candidates []}))

(defn- consume [state event]
  (let [state (if (pos? (or (:retransmissions event) 0))
                (update-in state [:diagnostics :retransmissions] (fnil +' 0) (:retransmissions event))
                state)]
    (if (not= :match (:kind event))
      (cli/diagnostic state event)
      (let [q (:query event) r (:response event) opts (:options state)
            row {:id (:id q) :qname (:qname q) :qtype (:qtype q)
                 :client (endpoint (:src q)) :server (endpoint (:dst q))
                 :rtt-us (:rtt-us event) :rcode (rcode-name (:rcode r))}]
        (if-not (and (match-filter? (:client opts) (:client row))
                     (match-filter? (:server opts) (:server row)))
          state
          (let [n (inc' (:pairs state))
                base (-> state (assoc :pairs n) (update-in [:rcode (:rcode row)] (fnil inc' 0)))]
            (case (:mode opts)
              :pairs (update base :candidates
                             #(vec (take (:topn opts) (sort-by pair-order (conj % row)))))
              :stats (do (cli/limit! :max-samples n (:max-samples opts))
                         (update base :samples conj (:rtt-us row)))
              :qstats
              (let [name (:qname row) group (get-in base [:qstats name])]
                (cli/limit! :max-samples n (:max-samples opts))
                (cli/limit! :max-qnames (+ (count (:qstats base)) (if group 0 1)) (:max-qnames opts))
                (-> base
                    (update-in [:qstats name :samples] (fnil conj []) (:rtt-us row))
                    (update-in [:qstats name :rcode (:rcode row)] (fnil inc' 0)))))))))))

(defn step [state packet]
  (let [s (cli/advance-packet state packet dns/advance consume)]
    (if-let [event (dns/packet->event packet)]
      (cli/transition s (dns/step (:analysis s) event) consume)
      (update-in s [:diagnostics :ineligible-packet] (fnil inc' 0)))))

(defn finish [state]
  (cli/transition state (dns/finish (:analysis state)) consume))

(defn- milliseconds [us] (when (some? us) (/ (double us) 1000.0)))
(defn- nearest-rank [xs p]
  (when (seq xs) (nth xs (dec (max 1 (long (Math/ceil (* p (count xs)))))))))

(defn- summarize-rtt [samples]
  (let [xs (vec (sort samples)) n (count xs)]
    {:count n :min (milliseconds (first xs)) :p50 (milliseconds (nearest-rank xs 0.5))
     :p95 (milliseconds (nearest-rank xs 0.95)) :p99 (milliseconds (nearest-rank xs 0.99))
     :avg (when (pos? n) (milliseconds (/ (reduce +' 0 xs) n))) :max (milliseconds (peek xs))}))

(defn- summarize-rcode [counts n]
  {:counts counts :ratio (into {} (map (fn [[k v]] [k (double (/ v (max 1 n)))]) counts))})

(defn report [state]
  (let [{:keys [mode metric topn]} (:options state)]
    (case mode
      :pairs (mapv (fn [row] (-> row (dissoc :rtt-us)
                                 (assoc :rtt-ms (milliseconds (:rtt-us row))
                                        :qtype (get qtype-names (:qtype row) (keyword (str "TYPE" (:qtype row)))))))
                   (:candidates state))
      :stats {:pairs (:pairs state) :with-rtt (:pairs state)
              :rtt (summarize-rtt (:samples state)) :rcode (summarize-rcode (:rcode state) (:pairs state))}
      :qstats (let [rows (map (fn [[q {:keys [samples rcode]}]]
                                {:qname q :pairs (count samples) :with-rtt (count samples)
                                 :rtt (summarize-rtt samples) :rcode (summarize-rcode rcode (count samples))})
                              (:qstats state))
                    value (fn [row] (if (#{:pairs :with-rtt} metric) (metric row) (get-in row [:rtt metric])))]
                (vec (take topn (sort-by (fn [r] [(- (value r)) (:qname r)]) rows)))))))

(defn- alert! [state threshold]
  (when threshold
    (let [counts (:rcode state) ne (get counts :nxdomain 0) sf (get counts :servfail 0)
          pct (* 100.0 (/ (+ ne sf) (double (max 1 (:pairs state)))))]
      (when (>= pct threshold)
        (binding [*out* *err*]
          (println "WARNING: DNS error rate" (format "%.2f%%" pct)
                   ">= threshold" (format "%.2f%%" (double threshold))
                   "details" (pr-str {:nxdomain ne :servfail sf :total (:pairs state)})))))))

(defn -main [& args]
  (let [[positional flags] (split-with #(not (str/starts-with? % "-")) args)
        [path bpf top mode metric fmt alert] positional]
    (when-not path (usage) (System/exit 1))
    (let [path (ex/require-file! path)
          opts (cli/parse-flags flags defaults
                                {"--client" [:client :text] "-c" [:client :text]
                                 "--server" [:server :text] "-s" [:server :text]
                                 "--timeout-us" [:timeout-us 1] "--reuse-delay-us" [:reuse-delay-us 1]
                                 "--max-pending" [:max-pending 1] "--max-retired" [:max-retired 1]
                                 "--max-samples" [:max-samples 1] "--max-qnames" [:max-qnames 1]})
          opts (assoc opts :topn (cli/positional-number "topN" top 50 1)
                      :mode (keyword (if (ex/blank? mode) "pairs" mode))
                      :metric (keyword (if (ex/blank? metric) "pairs" metric)))
          fmt (ex/parse-format fmt)
          threshold (when-not (ex/blank? alert) (ex/parse-double* alert))]
      (when (and (not (ex/blank? alert)) (or (nil? threshold) (not (<= 0.0 threshold 100.0))))
        (ex/error-exit! "alert% requires a number from 0 to 100" 4))
      (ex/ensure-one-of! "mode" (:mode opts) #{:pairs :stats :qstats})
      (ex/ensure-one-of! "metric" (:metric opts) #{:pairs :with-rtt :p50 :p95 :p99 :avg :max})
      (try
        (let [{:keys [state execution]} (cli/run (cli/capture-options path (if (ex/blank? bpf) "udp and port 53" bpf)) step (init opts) opts)
              state (finish state) rows (report state)]
          (alert! state threshold)
          (ex/emit fmt rows)
          (binding [*out* *err*]
            (println (pr-str (merge (cli/metadata state execution opts)
                                    {:pairs (:pairs state) :mode (:mode opts) :qnames (count (:qstats state))})))
            (when (:async? opts)
              (println (str "async=true dropped=" (:dropped execution) " cancelled=" (:cancelled? execution))))))
        (catch Exception error (ex/error-exit! (str (.getMessage error) " " (pr-str (ex-data error))) 5))))))
