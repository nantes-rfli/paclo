(ns examples.pcap-filter
  (:require
   [clojure.data.json :as json]
   [paclo.core :as core]))

(defn- usage []
  (binding [*out* *err*]
    (println "Usage:")
    (println "  clojure -M:dev -m examples.pcap-filter <in.pcap> <out.pcap> [<bpf-string>] [<min-caplen>] [<format>]")
    (println)
    (println "Defaults:")
    (println "  <bpf-string> = (none)")
    (println "  <min-caplen> = (none)")
    (println "  <format>     = edn | jsonl   (default: edn)")
    (println)
    (println "Examples:")
    (println "  clojure -M:dev -m examples.pcap-filter dns-sample.pcap out.pcap")
    (println "  clojure -M:dev -m examples.pcap-filter dns-sample.pcap out-dns.pcap 'udp and port 53'")
    (println "  clojure -M:dev -m examples.pcap-filter dns-sample.pcap out-dns60.pcap 'udp and port 53' 60 jsonl")))

;; clojure.core/parse-long と衝突しないようリネーム
(defn- parse-long-opt [s]
  (try (some-> s Long/parseLong) (catch Exception _ nil)))

(defn -main
  "PCAP を読み、任意の BPF と最小 caplen を適用して書き出す。
   末尾の <format> が jsonl のとき、メタ情報を 1 行 JSON で出力する。"
  [& args]
  (let [[in out bpf min-caplen-str fmt-str] args]
    (when (or (nil? in) (nil? out))
      (usage) (System/exit 1))
    (let [min-caplen (parse-long-opt min-caplen-str)
          fmt        (keyword (or fmt-str "edn"))]
      (println "reading:" in)
      (println "writing:" out)
      (let [{:keys [sel out-pkts out-bytes in-pkts in-bytes]}
            (reduce
             (fn [{:keys [sel out-pkts out-bytes in-pkts in-bytes] :as st} m]
               (let [cap (long (or (:caplen m) 0))
                     st' (-> st
                             (assoc :in-pkts  (inc (long in-pkts)))
                             (assoc :in-bytes (+ (long in-bytes) cap)))]
                 (if (and (or (nil? min-caplen) (>= cap (long min-caplen))))
                   (if-let [raw (:raw m)]                        ;; ← :raw が nil のものはスキップ
                     (-> st'
                         (update :sel conj raw)
                         (assoc :out-pkts  (inc (long out-pkts)))
                         (assoc :out-bytes (+ (long out-bytes) cap)))
                     st')
                   st')))
             {:sel [] :out-pkts 0 :out-bytes 0 :in-pkts 0 :in-bytes 0}
             (core/packets
              (merge {:path in
                      :max Long/MAX_VALUE
                      :decode? false}         ;; ← 必ず raw が付くように明示
                     (when bpf {:filter bpf}))))]

        ;; 書き出し（nil は弾いているので NPE 不発）
        (core/write-pcap! sel out)
        (println "done. wrote packets =" out-pkts)

        ;; メタ出力
        (let [drop-pct (if (pos? in-pkts)
                         (* 100.0 (- 1.0 (/ (double out-pkts) (double in-pkts))))
                         0.0)
              meta {:in in
                    :out out
                    :filter bpf
                    :min-caplen min-caplen
                    :in-packets in-pkts
                    :out-packets out-pkts
                    :drop-pct drop-pct
                    :in-bytes in-bytes
                    :out-bytes out-bytes}]
          (case fmt
            :jsonl (do (json/write meta *out*) (println))
            (println (pr-str meta))))))))
