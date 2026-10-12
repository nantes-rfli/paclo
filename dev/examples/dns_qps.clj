(ns examples.dns-qps
  (:require
   [clojure.data.json :as json]
   [clojure.string :as str]
   [examples.common :as ex]
   [examples.dns-cli :as cli]
   [paclo.dns :as dns]
   [paclo.window :as window])
  (:import [java.net IDN]))

(def defaults
  {:bucket-ms 1000 :group :rcode :max-buckets 200000 :max-windows 10000
   :max-groups 200000 :warn-buckets-threshold 100000
   :punycode? false :log-punycode-fail? false :emit-empty? false :emit-empty-per-key? false})

(defn- usage []
  (binding [*out* *err*]
    (println "Usage: clojure -M:dev:dns-ext -m examples.dns-qps <pcap> [bpf] [bucket-ms] [group] [edn|jsonl|csv]")
    (println "Groups: rcode rrtype qname qname-suffix client server; use '_' to skip positionals.")
    (println "Options: --punycode-to-unicode --log-punycode-fail --emit-empty-buckets --emit-empty-per-key --max-buckets N --warn-buckets-threshold N --max-windows N --max-groups N --reorder-us N")
    (println "Delivery: --async --async-buffer N --async-mode buffer|dropping --async-timeout-ms MS")))

(defn- csv-quote [^String s]
  (let [s (or s "")]
    (if (re-find #"[\";,\n]" s)
      (str "\"" (str/replace s "\"" "\"\"") "\"")
      s)))

(defn- emit [fmt rows]
  (case fmt
    :csv   (do
             (println "t_ms,key,count,bytes")
             (doseq [{:keys [t key count bytes]} rows]
               (println (str t "," (csv-quote (str key)) "," count "," (or bytes 0)))))
    :jsonl (doseq [row rows] (json/write row *out*) (println))
    (println (pr-str rows))))

(defn- normalize-qname [^String q puny? log-fail?]
  (when (seq q)
    (let [trimmed (-> q str/trim (str/replace #"\.$" "") str/lower-case)
          decoded (if (and puny? (some #(str/starts-with? % "xn--") (str/split trimmed #"\.")))
                    (try
                      (let [_ (IDN/toASCII trimmed)]
                        (IDN/toUnicode trimmed))
                      (catch Exception e
                        (when log-fail?
                          (binding [*out* *err*]
                            (println "WARN punycode-decode failed:" (.getMessage e) "label=" trimmed)))
                        trimmed))
                    trimmed)]
      decoded)))

(defn- qname-suffix [^String q puny? log-fail?]
  (when (seq q)
    (let [trimmed (normalize-qname q puny? log-fail?)
          parts   (str/split trimmed #"\.")
          n (count parts)]
      (cond
        (<= n 0) nil
        (= n 1) trimmed
        :else (str/join "." (take-last 2 parts))))))

(defn- group-key [pkt group puny? log-fail?]
  (let [app (get-in pkt [:decoded :l3 :l4 :app])]
    (case group
      :rcode        (some-> (:rcode-name app) keyword)
      :rrtype       (some-> (:qtype-name app) keyword)
      :qname        (some-> (:qname app) (normalize-qname puny? log-fail?))
      :qname-suffix (some-> (:qname app) (qname-suffix puny? log-fail?))
      :client       (get-in pkt [:decoded :l3 :src])
      :server       (get-in pkt [:decoded :l3 :dst])
      nil)))

(defn init [options]
  (let [opts (merge defaults cli/execution-defaults options)]
    (doseq [k [:max-buckets :bucket-ms]]
      (when-not (and (integer? (k opts)) (pos? (k opts)))
        (throw (ex-info "invalid report bound" {:reason :invalid-options :option k}))))
    {:options opts :reorder-us (:reorder-us opts) :diagnostics {} :rows [] :total 0 :open-tail-windows 0
     :analysis (window/init {:width-us (*' 1000 (:bucket-ms opts))
                             :max-windows (:max-windows opts) :max-groups (:max-groups opts)
                             :allowed-lateness-us 0})}))

(defn- row-order [{:keys [t count key]}] [t (-' count) (pr-str key)])

(defn- consume [state event]
  (if (not= :window (:kind event))
    (cli/diagnostic state event)
    (let [rows (mapv (fn [[key {:keys [packets captured-bytes]}]]
                       {:t (quot (:start-us event) 1000) :key key :count packets :bytes captured-bytes})
                     (:groups event))]
      (cli/limit! :max-buckets (+ (count (:rows state)) (count rows)) (get-in state [:options :max-buckets]))
      (cond-> (update state :rows into rows)
        (not (:complete? event)) (update :open-tail-windows inc')))))

(defn step [state packet]
  (let [state (cli/advance-packet state packet window/advance consume)
        {:keys [group punycode? log-punycode-fail?]} (:options state)]
    (if (= :dns (get-in packet [:decoded :l3 :l4 :app :type]))
      (if-let [key (group-key packet group punycode? log-punycode-fail?)]
        (let [result (window/step (:analysis state)
                                  {:time-us (dns/packet-time-us packet) :group key :captured-bytes (:caplen packet)})]
          (cond-> (cli/transition state result consume)
            (empty? (:events result)) (update :total inc')))
        (update-in state [:diagnostics :missing-group] (fnil inc' 0)))
      state)))

(defn finish [state]
  (cli/transition state (window/finish (:analysis state)) consume))

(defn report [state]
  (let [rows (vec (sort-by row-order (:rows state)))
        {:keys [bucket-ms max-buckets emit-empty? emit-empty-per-key?]} (:options state)]
    (if (or (empty? rows) (not (or emit-empty? emit-empty-per-key?)))
      rows
      (let [first-t (:t (first rows)) last-t (:t (peek rows))
            buckets (inc' (quot (-' last-t first-t) bucket-ms))
            by-time (group-by :t rows)
            keys (sort-by pr-str (set (map :key rows)))
            required (if emit-empty-per-key?
                       (*' buckets (count keys))
                       (+' (count rows) (-' buckets (count by-time))))]
        ;; Preflight before generating a range, lookup or filled rows.
        (cli/limit! :max-buckets required max-buckets)
        (let [lookup (when emit-empty-per-key? (into {} (map (fn [r] [[(:t r) (:key r)] r]) rows)))
              filled (mapcat (fn [t]
                               (if emit-empty-per-key?
                                 (map (fn [k] (get lookup [t k] {:t t :key k :count 0 :bytes 0})) keys)
                                 (or (get by-time t) [{:t t :key :_all :count 0 :bytes 0}])))
                             (take buckets (iterate #(+' % bucket-ms) first-t)))]
          (vec (sort-by row-order filled)))))))

(defn -main [& args]
  (let [[positional flags] (split-with #(not (str/starts-with? % "--")) args)
        [path bpf bucket group fmt] positional]
    (when-not path (usage) (System/exit 1))
    (let [path (ex/require-file! path)
          opts (cli/parse-flags flags defaults
                                {"--punycode-to-unicode" [:punycode? :flag]
                                 "--log-punycode-fail" [:log-punycode-fail? :flag]
                                 "--emit-empty-buckets" [:emit-empty? :flag]
                                 "--emit-empty-per-key" [:emit-empty-per-key? :flag]
                                 "--max-buckets" [:max-buckets 1]
                                 "--warn-buckets-threshold" [:warn-buckets-threshold 1]
                                 "--max-windows" [:max-windows 1] "--max-groups" [:max-groups 1]})
          opts (assoc opts :bucket-ms (cli/positional-number "bucket-ms" bucket 1000 1)
                      :group (keyword (if (ex/blank? group) "rcode" group)))
          fmt (keyword (if (ex/blank? fmt) "edn" fmt))]
      (ex/ensure-one-of! "group" (:group opts) #{:rcode :rrtype :qname :qname-suffix :client :server})
      (ex/ensure-one-of! "format" fmt #{:edn :jsonl :csv})
      (try
        (let [{:keys [state execution]} (cli/run (cli/capture-options path (if (ex/blank? bpf) "udp and port 53" bpf)) step (init opts) opts)
              state (finish state) rows (report state)
              warned? (>= (count rows) (:warn-buckets-threshold opts))]
          (emit fmt rows)
          (binding [*out* *err*]
            (println (pr-str (merge (cli/metadata state execution opts)
                                    (select-keys opts [:bucket-ms :group :max-buckets :max-windows :max-groups :warn-buckets-threshold])
                                    {:rows (count rows) :total (:total state) :format fmt
                                     :open-tail-windows (:open-tail-windows state)
                                     :punycode (:punycode? opts) :log-punycode-fail (:log-punycode-fail? opts)
                                     :emit-empty-buckets (:emit-empty? opts) :emit-empty-per-key (:emit-empty-per-key? opts)
                                     :empty-per-key-truncated? false :warned-buckets? warned?})))
            (when warned? (println "WARNING: dns-qps produced" (count rows) "rows"))))
        (catch Exception error (ex/error-exit! (str (.getMessage error) " " (pr-str (ex-data error))) 5))))))
