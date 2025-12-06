(ns examples.dns-qps
  (:require
   [clojure.core.async :as async]
   [clojure.data.json :as json]
   [clojure.string :as str]
   [examples.common :as ex]
   [paclo.core :as core]
   [paclo.proto.dns-ext :as dns-ext])
  (:import
   (java.net IDN)))

(def ^:private default-bpf "udp and port 53")
(def ^:private default-bucket-ms 1000)
(def ^:private default-group :rcode)
(def ^:private default-format :edn)
(def ^:private default-async-buffer 1024)
(def ^:private default-async-mode :buffer)
(def ^:private allowed-groups #{:rcode :rrtype :qname :qname-suffix :client :server})
(def ^:private allowed-formats #{:edn :jsonl :csv})
(def ^:private default-max-buckets 200000)
(def ^:private warn-buckets-threshold-default 100000)

(defn- usage []
  (binding [*out* *err*]
    (println "Usage:")
    (println "  clojure -M:dev:dns-ext -m examples.dns-qps <pcap> [<bpf>] [<bucket-ms>] [<group>] [<format>]"
             "[--punycode-to-unicode] [--emit-empty-buckets] [--emit-empty-per-key] [--max-buckets N] [--warn-buckets-threshold N]"
             "[--async] [--async-buffer N] [--async-mode buffer|dropping] [--async-timeout-ms MS]")
    (println "Defaults: bpf='" default-bpf "', bucket-ms=" default-bucket-ms ", group=rcode, format=edn, async=off")
    (println "Groups : rcode | rrtype | qname | qname-suffix | client | server")
    (println "Format : edn | jsonl | csv")
    (println "Tips   : '_' で位置引数をスキップ可。max-buckets でメモリ上限を守る。empty-per-key は行数が増えるので注意。warn-buckets-threshold で警告閾値を調整。")))

(defn- parse-format [s]
  (let [f (keyword (or (when-not (ex/blank? s) s) (name default-format)))]
    (ex/ensure-one-of! "format" f allowed-formats)
    f))

(defn- parse-flags [flags]
  (loop [xs flags
         acc {:punycode? false
              :emit-empty? false
              :emit-empty-per-key? false
              :max-buckets default-max-buckets
              :warn-buckets-threshold warn-buckets-threshold-default
              :async {:async? false :async-buffer default-async-buffer :async-mode default-async-mode :async-timeout-ms nil}}]
    (if (empty? xs)
      acc
      (let [[k & more] xs]
        (case k
          "--punycode-to-unicode" (recur more (assoc acc :punycode? true))
          "--emit-empty-buckets"  (recur more (assoc acc :emit-empty? true))
          "--emit-empty-per-key" (recur more (assoc acc :emit-empty-per-key? true))
          "--max-buckets" (let [n (ex/parse-long* (first more))]
                            (when-not n (ex/error-exit! "--max-buckets requires a number" 4))
                            (recur (rest more) (assoc acc :max-buckets n)))
          "--warn-buckets-threshold" (let [n (ex/parse-long* (first more))]
                                       (when-not n (ex/error-exit! "--warn-buckets-threshold requires a number" 4))
                                       (recur (rest more) (assoc acc :warn-buckets-threshold n)))
          "--async" (recur more (assoc-in acc [:async :async?] true))
          "--async-buffer" (let [n (ex/parse-long* (first more))]
                             (when-not n (ex/error-exit! "--async-buffer requires a number" 4))
                             (recur (rest more) (assoc-in acc [:async :async-buffer] n)))
          "--async-mode" (let [m (keyword (or (first more) ""))]
                           (when-not (contains? #{:buffer :dropping} m)
                             (ex/error-exit! "--async-mode must be buffer|dropping" 4))
                           (recur (rest more) (assoc-in acc [:async :async-mode] m)))
          "--async-timeout-ms" (let [n (ex/parse-long* (first more))]
                                 (when-not n (ex/error-exit! "--async-timeout-ms requires a number" 4))
                                 (recur (rest more) (assoc-in acc [:async :async-timeout-ms] n)))
          (ex/error-exit! (str "unknown flag: " k) 4))))))

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

(defn- normalize-qname [^String q puny?]
  (when (seq q)
    (let [trimmed (-> q str/trim (str/replace #"\.$" "") str/lower-case)
          decoded (if (and puny? (str/starts-with? trimmed "xn--"))
                    (try (IDN/toUnicode trimmed) (catch Exception _ trimmed))
                    trimmed)]
      decoded)))

(defn- qname-suffix [^String q puny?]
  (when (seq q)
    (let [trimmed (normalize-qname q puny?)
          parts   (str/split trimmed #"\.")
          n (count parts)]
      (cond
        (<= n 0) nil
        (= n 1) trimmed
        :else (str/join "." (take-last 2 parts))))))

(defn- group-key [pkt group puny?]
  (let [app (get-in pkt [:decoded :l3 :l4 :app])]
    (case group
      :rcode        (some-> (:rcode-name app) keyword)
      :rrtype       (some-> (:qtype-name app) keyword)
      :qname        (some-> (:qname app) (normalize-qname puny?))
      :qname-suffix (some-> (:qname app) (qname-suffix puny?))
      :client       (get-in pkt [:decoded :l3 :src])
      :server       (get-in pkt [:decoded :l3 :dst])
      nil)))

(defn- pkt-ts-ms
  "パケットのタイムスタンプをミリ秒で取得。ts-sec があれば優先。
  ts-usec が絶対値（>1e12）っぽい場合は usec/1e3 で代用。"
  [pkt]
  (let [sec (get pkt :ts-sec)
        usec (get pkt :ts-usec)
        base (cond
               (number? sec) (+ (double sec) (/ (double (mod (long (or usec 0)) 1000000)) 1e6))
               (and (number? usec) (> usec 1e12)) (/ (double usec) 1e6)
               (number? usec) (/ (double usec) 1e6)
               :else nil)]
    (when base
      (long (Math/floor (* base 1000.0))))))

(defn- bucket-start [bucket-ms t-ms]
  (* (quot t-ms bucket-ms) bucket-ms))

(defn -main [& args]
  ;; <pcap> [bpf] [bucket-ms] [group] [format] flags...
  (let [[pcap bpf-str bucket-str group-str fmt-str & flags] args]
    (when (nil? pcap) (usage) (System/exit 1))
    (let [pcap* (ex/require-file! pcap)
          _     (dns-ext/register!)
          bpf   (if (ex/blank? bpf-str) default-bpf bpf-str)
          bucket-ms (or (ex/parse-long* bucket-str) default-bucket-ms)
          group (keyword (or (when-not (ex/blank? group-str) group-str)
                             (name default-group)))
          fmt   (parse-format fmt-str)
          {:keys [punycode? emit-empty? emit-empty-per-key? max-buckets warn-buckets-threshold async]} (parse-flags flags)
          {:keys [async? async-buffer async-mode async-timeout-ms]} async]
      (ex/ensure-one-of! "group" group allowed-groups)
      (let [agg (atom {})
            total (atom 0)
            dropped (atom 0)
            cancelled? (atom false)
            start-ts (System/nanoTime)
            process! (fn [p]
                       (when (= :dns (get-in p [:decoded :l3 :l4 :app :type]))
                         (when-let [t (pkt-ts-ms p)]
                           (when-let [k (group-key p group punycode?)]
                             (let [bucket (bucket-start bucket-ms t)]
                               (swap! agg update [bucket k]
                                      (fn [{:keys [count bytes]}]
                                        {:t bucket :key k
                                         :count (inc (long (or count 0)))
                                         :bytes (+ (long (or bytes 0)) (long (or (:caplen p) 0)))}))
                               (swap! total inc))))))]
        (if-not async?
          (doseq [p (core/packets {:path pcap* :filter bpf :decode? true})]
            (process! p))
          ;; async path
          (let [cancel-ch (when async-timeout-ms (async/timeout async-timeout-ms))
                buf (case async-mode
                      :dropping (async/dropping-buffer async-buffer)
                      (async/buffer async-buffer))
                pkt-ch (async/chan buf)
                reader (async/thread
                         (try
                           (doseq [p (core/packets {:path pcap* :filter bpf :decode? true})]
                             (when cancel-ch
                               (let [[_ port] (async/alts!! [cancel-ch] :default [:ok nil])]
                                 (when port (reset! cancelled? true))))
                             (when-not @cancelled?
                               (if (= async-mode :dropping)
                                 (when-not (async/offer! pkt-ch p)
                                   (swap! dropped inc))
                                 (async/>!! pkt-ch p))))
                           (finally (async/close! pkt-ch))))]
            (async/thread (async/<!! reader))
            (loop []
              (when-let [p (async/<!! pkt-ch)]
                (process! p)
                (recur)))))
        ;; rows
        (let [rows-core (->> @agg vals
                             (sort-by (juxt :t (fn [m] (- (long (or (:count m) 0))))))
                             vec)
              rows-empty-range (fn [rows]
                                 (when (seq rows)
                                   (let [min-t (:t (first rows))
                                         max-t (:t (peek rows))
                                         step bucket-ms
                                         filled (transient [])]
                                     (loop [t min-t
                                            xs rows]
                                       (cond
                                         (> t max-t) (persistent! filled)
                                         (and (seq xs) (= t (:t (first xs))))
                                         (let [_ (conj! filled (first xs))]
                                           (recur (+ t step) (rest xs)))
                                         :else (let [_ (conj! filled {:t t :key :_all :count 0 :bytes 0})]
                                                 (recur (+ t step) xs)))))))
              rows-per-key (fn [rows]
                             (when (seq rows)
                               (let [min-t (:t (first rows))
                                     max-t (:t (peek rows))
                                     step bucket-ms
                                     keys (set (map :key rows))
                                     lookup (into {} (map (fn [m] [[(:t m) (:key m)] m]) rows))
                                     bucket-count (inc (quot (- max-t min-t) step))
                                     total (* bucket-count (count keys))]
                                 (if (> total max-buckets)
                                   {:rows rows :truncated? true}
                                   (let [filled (transient [])]
                                     (loop [t min-t]
                                       (when (<= t max-t)
                                         (doseq [k keys]
                                           (let [_ (conj! filled (get lookup [t k] {:t t :key k :count 0 :bytes 0}))]
                                             nil))
                                         (recur (+ t step))))
                                     {:rows (persistent! filled) :truncated? false})))))
              rows1 (cond
                      (and emit-empty-per-key? rows-core)
                      (let [{rows :rows truncated? :truncated?} (rows-per-key rows-core)]
                        {:rows rows :per-key? true :truncated? truncated?})
                      (and emit-empty? rows-core)
                      {:rows (rows-empty-range rows-core) :per-key? false :truncated? false}
                      :else {:rows rows-core :per-key? false :truncated? false})
              rows2 (or (:rows rows1) [])
              rows (if (> (count rows2) max-buckets)
                     (subvec (vec rows2) 0 max-buckets)
                     rows2)
              meta {:rows (count rows)
                    :total @total
                    :bucket-ms bucket-ms
                    :group group
                    :format fmt
                    :emit-empty-buckets emit-empty?
                    :emit-empty-per-key emit-empty-per-key?
                    :empty-per-key-truncated? (:truncated? rows1)
                    :max-buckets max-buckets
                    :warn-buckets-threshold warn-buckets-threshold
                    :warned-buckets? (<= warn-buckets-threshold (count rows))
                    :async? async?
                    :async-mode async-mode
                    :async-buffer async-buffer
                    :async-timeout-ms async-timeout-ms
                    :async-dropped @dropped
                    :async-cancelled? @cancelled?
                    :elapsed-ms (/ (- (System/nanoTime) start-ts) 1e6)}]
          (emit fmt rows)
          (binding [*out* *err*]
            (println (pr-str meta))
            (when (and emit-empty-per-key? (> (count rows) warn-buckets-threshold))
              (println "WARNING: emit-empty-per-key produced" (count rows) "rows (threshold" warn-buckets-threshold ")"))))))))
