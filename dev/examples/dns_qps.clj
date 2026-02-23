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
             "[--punycode-to-unicode] [--log-punycode-fail] [--emit-empty-buckets] [--emit-empty-per-key] [--max-buckets N] [--warn-buckets-threshold N]"
             "[--async] [--async-buffer N] [--async-mode buffer|dropping] [--async-timeout-ms MS]")
    (println "Defaults: bpf='" default-bpf "', bucket-ms=" default-bucket-ms ", group=rcode, format=edn, async=off")
    (println "Groups : rcode | rrtype | qname | qname-suffix | client | server")
    (println "Format : edn | jsonl | csv")
    (println "Tips   : use '_' to skip optional args; tune max-buckets and empty-bucket flags for large files.")))

(defn- parse-format [s]
  (let [f (keyword (or (when-not (ex/blank? s) s) (name default-format)))]
    (ex/ensure-one-of! "format" f allowed-formats)
    f))

(defn- parse-flags [flags]
  (loop [xs flags
         acc {:punycode? false
              :log-punycode-fail? false
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
          "--log-punycode-fail" (recur more (assoc acc :log-punycode-fail? true))
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

(defn- normalize-qname [^String q puny? log-fail?]
  (when (seq q)
    (let [trimmed (-> q str/trim (str/replace #"\.$" "") str/lower-case)
          decoded (if (and puny? (str/starts-with? trimmed "xn--"))
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

(defn- pkt-ts-ms
  "Resolve packet timestamp in milliseconds.
  Prefer (:ts-sec, :ts-usec); fall back to :ts-usec-only values when needed."
  [pkt]
  (let [sec (get pkt :ts-sec)
        usec (get pkt :ts-usec)
        ^double base (cond
                       (number? sec) (+ (double sec) (/ (double (mod (long (or usec 0)) 1000000)) 1e6))
                       (and (number? usec) (> (double usec) 1e12)) (/ (double usec) 1e6)
                       (number? usec) (/ (double usec) 1e6)
                       :else nil)]
    (when base
      (long (Math/floor (* base 1000.0))))))

(defn- bucket-start [bucket-ms t-ms]
  (let [q (quot (long t-ms) (long bucket-ms))]
    (unchecked-multiply q (long bucket-ms))))

(defn -main [& args]
  ;; <pcap> [bpf] [bucket-ms] [group] [format] flags...
  (let [[pcap bpf-str bucket-str group-str fmt-str & flags] args]
    (when (nil? pcap) (usage) (System/exit 1))
    (let [pcap* (ex/require-file! pcap)
          _     (dns-ext/register!)
          bpf   (if (ex/blank? bpf-str) default-bpf bpf-str)
          bucket-ms (long (or (ex/parse-long* bucket-str) default-bucket-ms))
          group (keyword (or (when-not (ex/blank? group-str) group-str)
                             (name default-group)))
          fmt   (parse-format fmt-str)
          {:keys [punycode? log-punycode-fail? emit-empty? emit-empty-per-key? max-buckets warn-buckets-threshold async]} (parse-flags flags)
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
                           (when-let [k (group-key p group punycode? log-punycode-fail?)]
                             (let [bucket (bucket-start bucket-ms t)
                                   cap (long (or (:caplen p) 0))]
                               (swap! agg update [bucket k]
                                      (fn [{:keys [count bytes]}]
                                        (let [c (long (or count 0))
                                              b (long (or bytes 0))]
                                          {:t bucket :key k
                                           :count (unchecked-inc c)
                                           :bytes (unchecked-add b cap)})))
                               (swap! total (fn [n] (unchecked-inc (long n)))))))))]
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
                                         step (long bucket-ms)
                                         filled (transient [])]
                                     (loop [t min-t xs rows]
                                       (let [t-long (long t)
                                             max-long (long max-t)]
                                         (cond
                                           (> t-long max-long) (persistent! filled)
                                           (and (seq xs) (= t-long (:t (first xs))))
                                           (let [_ (conj! filled (first xs))]
                                             (recur (unchecked-add t-long step) (rest xs)))
                                           :else (let [_ (conj! filled {:t t-long :key :_all :count 0 :bytes 0})]
                                                   (recur (unchecked-add t-long step) xs))))))))
              rows-per-key
              (fn [rows]
                (when (seq rows)
                  (let [min-t (:t (first rows))
                        max-t (:t (peek rows))
                        step (long bucket-ms)
                        keys (set (map :key rows))
                        lookup (into {} (map (fn [m] [[(:t m) (:key m)] m]) rows))
                        bucket-count (unchecked-inc (quot (- (long max-t) (long min-t)) step))
                        total (unchecked-multiply bucket-count (long (count keys)))]
                    (if (> total (long max-buckets))
                      {:rows rows :truncated? true}
                      (let [filled (transient [])]
                        (loop [t min-t]
                          (let [t-long (long t)
                                max-long (long max-t)]
                            (when (<= t-long max-long)
                              (doseq [k keys]
                                (let [_ (conj! filled (get lookup [t-long k] {:t t-long :key k :count 0 :bytes 0}))]
                                  nil))
                              (recur (unchecked-add t-long step)))))
                        {:rows (persistent! filled) :truncated? false})))))
              rows1 (cond
                      (and emit-empty-per-key? rows-core)
                      (let [{rows :rows truncated? :truncated?} (rows-per-key rows-core)]
                        {:rows rows :per-key? true :truncated? truncated?})
                      (and emit-empty? rows-core)
                      {:rows (rows-empty-range rows-core) :per-key? false :truncated? false}
                      :else {:rows rows-core :per-key? false :truncated? false})
              rows2 (or (:rows rows1) [])
              rows (if (> (count rows2) (long max-buckets))
                     (subvec (vec rows2) 0 max-buckets)
                     rows2)
              meta {:rows (count rows)
                    :total @total
                    :bucket-ms bucket-ms
                    :group group
                    :format fmt
                    :punycode punycode?
                    :log-punycode-fail log-punycode-fail?
                    :emit-empty-buckets emit-empty?
                    :emit-empty-per-key emit-empty-per-key?
                    :empty-per-key-truncated? (:truncated? rows1)
                    :max-buckets max-buckets
                    :warn-buckets-threshold warn-buckets-threshold
                    :warned-buckets? (<= (long warn-buckets-threshold) (count rows))
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
            (when (and emit-empty-per-key? (> (count rows) (long warn-buckets-threshold)))
              (println "WARNING: emit-empty-per-key produced" (count rows) "rows (threshold" warn-buckets-threshold ")"))))))))
