(ns examples.dns-topn
  (:require
   [clojure.core.async :as async]
   [clojure.data.json :as json]
   [clojure.string :as str]
   [examples.common :as ex]
   [paclo.core :as core]
   [paclo.proto.dns-ext :as dns-ext]
   [paclo.proto.tls-ext :as tls-ext])
  (:import
   (java.net IDN)))

(def ^:private default-dns-bpf "udp and port 53")
(def ^:private default-sni-bpf "tcp and port 443")
(def ^:private default-topn 20)
(def ^:private default-group :rcode)
(def ^:private default-metric :count)
(def ^:private default-format :edn)
(def ^:private default-async-buffer 1024)
(def ^:private default-async-mode :buffer)

(def ^:private allowed-groups #{:rcode :rrtype :qname :qname-suffix :client :server :sni :alpn})
(def ^:private allowed-metrics #{:count :bytes})
(def ^:private allowed-formats #{:edn :jsonl :csv})

(defn- usage []
  (binding [*out* *err*]
    (println "Usage:")
    (println "  clojure -M:dev:dns-ext -m examples.dns-topn <pcap> [<bpf>] [<topN>] [<group>] [<format>] [<metric>]"
             "[--punycode-to-unicode] [--log-punycode-fail] [--sni-bpf <bpf>] [--alpn-join]"
             "[--async] [--async-buffer N] [--async-mode buffer|dropping] [--async-timeout-ms MS]")
    (println "Defaults: bpf='" default-dns-bpf "' (group=sni/alpn uses '" default-sni-bpf "'), topN=" default-topn ", group=rcode, format=edn, metric=count, async=off")
    (println "Groups  : rcode | rrtype | qname | qname-suffix | client | server | sni | alpn")
    (println "ALPN    : default emits first ALPN; --alpn-join emits comma-joined values")
    (println "Metric  : count | bytes")
    (println "Format  : edn | jsonl | csv")
    (println "Tips    : use '_' to skip optional args; async is opt-in; for SNI/ALPN use TLS-oriented BPF.")))

(defn- parse-format [s]
  (let [f (keyword (or (when-not (ex/blank? s) s) (name default-format)))]
    (ex/ensure-one-of! "format" f allowed-formats)
    f))

(defn- parse-flags
  "flags -> {:punycode? bool :sni-bpf str|nil :async-opts {...}}
         Parse optional CLI flags."
  [flags]
  (loop [xs flags
         acc {:punycode? false
              :sni-bpf nil
              :log-punycode-fail? false
              :alpn-join? false
              :async-opts {:async? false
                           :async-buffer default-async-buffer
                           :async-mode default-async-mode
                           :async-timeout-ms nil}}]
    (if (empty? xs)
      acc
      (let [[k & more] xs]
        (case k
          "--punycode-to-unicode" (recur more (assoc acc :punycode? true))
          "--log-punycode-fail" (recur more (assoc acc :log-punycode-fail? true))
          "--sni-bpf" (let [b (first more)]
                        (when-not b (ex/error-exit! "--sni-bpf requires value" 4))
                        (recur (rest more) (assoc acc :sni-bpf b)))
          "--alpn-join" (recur more (assoc acc :alpn-join? true))
          "--async" (recur more (assoc-in acc [:async-opts :async?] true))
          "--async-buffer" (let [n (ex/parse-long* (first more))]
                             (when-not n (ex/error-exit! "--async-buffer requires a number" 4))
                             (recur (rest more) (assoc-in acc [:async-opts :async-buffer] n)))
          "--async-mode" (let [m (keyword (or (first more) ""))]
                           (when-not (contains? #{:buffer :dropping} m)
                             (ex/error-exit! "--async-mode must be buffer|dropping" 4))
                           (recur (rest more) (assoc-in acc [:async-opts :async-mode] m)))
          "--async-timeout-ms" (let [n (ex/parse-long* (first more))]
                                 (when-not n (ex/error-exit! "--async-timeout-ms requires a number" 4))
                                 (recur (rest more) (assoc-in acc [:async-opts :async-timeout-ms] n)))
          (ex/error-exit! (str "unknown flag: " k) 4))))))

(defn- csv-quote [^String s]
  (let [s (or s "")]
    (if (re-find #"[\";,\n]" s)
      (str "\"" (str/replace s "\"" "\"\"") "\"")
      s)))

(defn- emit [fmt rows]
  (case fmt
    :csv   (do
             (println "key,count,bytes,pct")
             (doseq [{:keys [key count bytes pct]} rows]
               (println (str (csv-quote (str key)) "," count "," (or bytes 0) "," (format "%.6f" (double pct))))))
    :jsonl (doseq [row rows] (json/write row *out*) (println))
    (println (pr-str rows))))

(defn- dns-packet? [pkt]
  (= :dns (get-in pkt [:decoded :l3 :l4 :app :type])))

(defn- tls-sni [pkt]
  (get-in pkt [:decoded :l3 :l4 :app :sni]))

(defn- normalize-qname [^String q puny? log-fail?]
  (when (seq q)
    (let [trimmed (-> q str/trim (str/replace #"\.$" "") str/lower-case)
          decoded (if (and puny? (str/starts-with? trimmed "xn--"))
                    (try
                      ;; Validate first via toASCII, then decode.
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

(defn- group-key [pkt group puny? log-fail? alpn-join?]
  (let [app (get-in pkt [:decoded :l3 :l4 :app])]
    (case group
      :rcode        (some-> (:rcode-name app) keyword)
      :rrtype       (some-> (:qtype-name app) keyword)
      :qname        (some-> (:qname app) (normalize-qname puny? log-fail?))
      :qname-suffix (some-> (:qname app) (qname-suffix puny? log-fail?))
      :client       (get-in pkt [:decoded :l3 :src])
      :server       (get-in pkt [:decoded :l3 :dst])
      :sni          (some-> (tls-sni pkt) str/lower-case)
      :alpn         (let [alpns (get-in pkt [:decoded :l3 :l4 :app :alpn])]
                      (when (seq alpns)
                        (let [xs (map str/lower-case alpns)]
                          (if alpn-join?
                            (str/join "," xs)
                            (first xs)))))
      ;; fallback
      nil)))

(defn- summarize [rows metric topN]
  (let [total-count (long (reduce + 0 (map :count rows)))
        total-bytes (long (reduce + 0 (map #(long (or (:bytes %) 0)) rows)))
        total (case metric :bytes (max 1 total-bytes) :count (max 1 total-count))]
    (->> rows
         (sort-by (case metric :bytes :bytes :count :count) >)
         (take topN)
         (map (fn [m]
                (assoc m :pct (double (/ (long (or (metric m) 0)) total)))))
         vec)))

(defn -main [& args]
  ;; positionals: <pcap> [bpf] [topN] [group] [format] [metric] flags...
  (let [[pcap bpf-str topn-str group-str fmt-str metric-str & flags] args]
    (when (nil? pcap) (usage) (System/exit 1))
    (let [pcap* (ex/require-file! pcap)
          _     (do (dns-ext/register!) (tls-ext/register!))
          topN  (or (ex/parse-long* topn-str) default-topn)
          group (keyword (or (when-not (ex/blank? group-str) group-str)
                             (name default-group)))
          fmt   (parse-format fmt-str)
          metric (keyword (or (when-not (ex/blank? metric-str) metric-str)
                              (name default-metric)))
          {:keys [punycode? log-punycode-fail? sni-bpf alpn-join? async-opts]} (parse-flags flags)
          {:keys [async? async-buffer async-mode async-timeout-ms]} async-opts
          bpf   (if (ex/blank? bpf-str)
                  (if (#{:sni :alpn} group) (or sni-bpf default-sni-bpf) default-dns-bpf)
                  bpf-str)]
      (ex/ensure-one-of! "group" group allowed-groups)
      (ex/ensure-one-of! "metric" metric allowed-metrics)
      (let [agg (atom {})
            total (atom 0)
            dropped (atom 0)
            cancelled? (atom false)
            start-ts (System/nanoTime)
            process! (fn [p]
                       (when (or (dns-packet? p) (#{:sni :alpn} group))
                         (when-let [k (group-key p group punycode? log-punycode-fail? alpn-join?)]
                           (swap! agg update k (fn [{:keys [count bytes]}]
                                                 {:key k
                                                  :count (inc (long (or count 0)))
                                                  :bytes (+ (long (or bytes 0)) (long (or (:caplen p) 0)))}))
                           (swap! total inc))))]
        (if-not async?
          ;; synchronous path
          (doseq [p (core/packets {:path pcap* :filter bpf :decode? true})]
            (process! p))
          ;; asynchronous path
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
        (let [rows (summarize (vals @agg) metric topN)
              meta {:rows (count rows)
                    :total @total
                    :group group
                    :metric metric
                    :format fmt
                    :async? async?
                    :async-mode async-mode
                    :async-buffer async-buffer
                    :async-timeout-ms async-timeout-ms
                    :async-dropped @dropped
                    :async-cancelled? @cancelled?
                    :elapsed-ms (/ (- (System/nanoTime) start-ts) 1e6)}]
          (emit fmt rows)
          (binding [*out* *err*]
            (println (pr-str meta))))))))
