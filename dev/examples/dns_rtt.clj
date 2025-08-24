(ns examples.dns-rtt
  (:require
   [clojure.data.json :as json]
   [paclo.core :as core]
   [paclo.proto.dns-ext :as dns-ext]))

;; -------- usage/help --------

(defn- usage []
  (binding [*out* *err*]
    (println "Usage:")
    (println "  clojure -M:dev -m examples.dns-rtt <in.pcap> [<bpf-string>] [<topN>] [<mode>] [<metric>] [<format>] [<alert%>]")
    (println)
    (println "Defaults:")
    (println "  <bpf-string> = 'udp and port 53'")
    (println "  <topN>       = 50   (pairs/qstats の表示上限)")
    (println "  <mode>       = pairs | stats | qstats   (default: pairs)")
    (println "  <metric>     = pairs | with-rtt | p50 | p95 | p99 | avg | max  (qstats の並び替え; default: pairs)")
    (println "  <format>     = edn | jsonl (default: edn)")
    (println "  <alert%>     = しきい値（例: 5 → 5%）。未指定なら警告なし。")
    (println)
    (println "Examples:")
    (println "  clojure -M:dev -m examples.dns-rtt dns-sample.pcap")
    (println "  clojure -M:dev -m examples.dns-rtt dns-sample.pcap 'udp and port 53' 50 stats jsonl 2.5")
    (println "  clojure -M:dev -m examples.dns-rtt dns-sample.pcap 'udp and port 53' 20 qstats p95 jsonl 10")))

;; -------- time & endpoint helpers --------

(defn- micros [{:keys [sec usec]}]
  (when (and (number? sec) (number? usec))
    (+ (* (long sec) 1000000) (long usec))))

(defn- endpoint [m side]
  (let [ip (get-in m [:decoded :l3 (case side :src :src :dst :dst)])
        p  (get-in m [:decoded :l3 :l4 (case side :src :src-port :dst :dst-port)])]
    (str ip (when p (str ":" p)))))

;; -------- DNS header parse --------

(defn- u8  ^long [^bytes ba ^long i]
  (when (and ba (<= 0 i) (< i (alength ba)))
    (bit-and 0xFF (aget ba i))))

(defn- u16 ^long [^bytes ba ^long i]
  (when-let [hi (u8 ba i)]
    (when-let [lo (u8 ba (inc i))]
      (bit-or (bit-shift-left hi 8) lo))))

(defn- parse-dns-header
  "payload から {:id <u16> :qr? <bool>} を取り出す（失敗なら nil）"
  [^bytes ba]
  (when (and ba (<= 12 (alength ba)))
    (let [id    (u16 ba 0)
          flags (u16 ba 2)]
      (when (and id flags)
        {:id id :qr? (pos? (bit-and flags 0x8000))}))))

;; -------- pairing key & pretty endpoints --------

(defn- canon-key
  "方向非依存キー：[id lo-end hi-end]。end は \"ip:port\" の文字列。"
  [m id]
  (let [a (endpoint m :src)
        b (endpoint m :dst)]
    (if (neg? (compare a b))
      [id a b]
      [id b a])))

(defn- classify-client-server
  "見栄え用：53番が server。両方/どちらも53でないときは辞書順で安定化。"
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
  "Nearest-rank percentile（pは0.0..100.0）"
  [sorted-xs p]
  (let [n (count sorted-xs)]
    (when (pos? n)
      (let [rank (int (Math/ceil (* (/ p 100.0) n)))
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
     :avg   (when (pos? n) (/ sum n))
     :max   (when (pos? n) (peek xs))}))

(defn- summarize-rcode [rows]
  (let [pairs (count rows)
        cnts  (frequencies (map #(or (:rcode %) :unknown) rows))
        ratio (into {} (for [[k c] cnts]
                         [k (double (/ c (max 1 pairs)))]))]
    {:counts cnts
     :ratio  ratio}))

(defn- summarize-qstats
  "qnameごとの統計。返り値はベクタ：
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
  "qstats の並び替えキー生成。未知/欠損は -∞ 的に扱って下位へ。"
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
  "rows から NXDOMAIN/SERVFAIL の合計率（0.0..1.0）と counts を返す。"
  [rows]
  (let [pairs (max 1 (count rows))
        cnts  (frequencies (map #(or (:rcode %) :unknown) rows))
        ne    (long (get cnts :nxdomain 0))
        sf    (long (get cnts :servfail 0))
        rate  (/ (+ ne sf) (double pairs))]
    {:rate rate :counts {:nxdomain ne :servfail sf :total pairs}}))

;; -------- main --------

(defn -main
  "Compute DNS transaction RTTs by pairing queries with responses.
   - 既定BPF: 'udp and port 53'
   - ペアリング: ID + (src,dst) を辞書順で正規化したキー
   - qname/qtype/rcode は best-effort（dns-ext を登録）
   - mode=pairs : :rtt-ms 昇順のペア（Top-N）
   - mode=stats : 全体のRTT統計とRCODE分布
   - mode=qstats: qname別統計（Top-N、metric で並び替え）
   - format=edn | jsonl
   - alert%: NXDOMAIN+SERVFAIL が超えたら WARNING"
  [& args]
  (let [[in bpf-str topn-str mode-str metric-str fmt-str alert-str] args]
    (when (nil? in)
      (usage) (System/exit 1))
    (let [bpf    (or bpf-str "udp and port 53")
          topN   (long (or (some-> topn-str Long/parseLong) 50))
          mode   (keyword (or mode-str "pairs"))
          metric (keyword (or metric-str "pairs"))
          fmt    (keyword (or fmt-str "edn"))
          alert% (some-> alert-str Double/parseDouble)]
      (dns-ext/register!)
      ;; まずはペア一覧（rows）を構築
      (let [rows (->> (core/packets {:path in
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
                                                  (double (/ (- rt qt) 1000.0)))]
                                     {:pending (dissoc pending k)
                                      :out (conj out
                                                 (cond-> (-> (select-keys q [:id :qname :qtype :client :server])
                                                             (assoc :rcode rcode))
                                                   (and (number? rtt-ms) (not (neg? rtt-ms)))
                                                   (assoc :rtt-ms rtt-ms)))})
                                   {:pending pending :out out})))
                             {:pending pending :out out})))
                       {:pending {} :out []})
                      :out)]
        ;; しきい値アラート（mode に関係なく全体 rows を対象）
        (when alert%
          (let [{:keys [rate counts]} (overall-error-rate rows)
                pct (* 100.0 rate)]
            (when (>= pct alert%)
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
              (println "mode=stats bpf=" (pr-str bpf) " format=" (name fmt))))

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
                       " format=" (name fmt))))

          ;; default: pairs
          (let [sorted (->> rows (sort-by (fn [{x :rtt-ms}] (if (number? x) x Double/POSITIVE_INFINITY)))
                            (take topN) vec)]
            (case fmt
              :jsonl (doseq [row sorted] (json/write row *out*) (println))
              (println (pr-str sorted)))
            (binding [*out* *err*]
              (println "pairs=" (count rows)
                       " topN=" topN
                       " bpf=" (pr-str bpf)
                       " format=" (name fmt)))))))))
