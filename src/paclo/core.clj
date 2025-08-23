(ns paclo.core
  "Clojure らしい薄いファサード。
   - packets: ライブ/オフラインどちらも lazy seq を返す（:decode? でparse付与、:xform で後段変換）
   - bpf:      簡易DSL → BPF文字列
   - write-pcap!: bytesシーケンスを書き出す（テスト/再現用）"
  (:require
   [clojure.string :as str]
   [paclo.parse :as parse]
   [paclo.pcap  :as pcap]))

;; ---------------------------
;; BPF DSL -> string
;; ---------------------------
(defn ^:private paren [s] (str "(" s ")"))

(defn bpf
  "BPFフィルタを表す簡易DSLを文字列へ。

  サポート（追加含む）:
  - 論理: :and / :or / :not
  - プロトコル: :udp :tcp :icmp :icmp6 :arp に加え、:ip / :ipv4 / :ip6 / :ipv6
    例) (bpf :ipv6)        ;;=> \"ip6\"
        (bpf [:proto :ip]) ;;=> \"ip\"
  - アドレス系: :host / :src-host / :dst-host / :net / :src-net / :dst-net
    例) (bpf [:src-net \"10.0.0.0/8\"]) ;;=> \"src net 10.0.0.0/8\"
  - ポート系: :port / :src-port / :dst-port
    追加: :port-range / :src-port-range / :dst-port-range
    例) (bpf [:port-range 1000 2000])     ;;=> \"portrange 1000-2000\"
        (bpf [:src-port-range 53 60])     ;;=> \"src portrange 53-60\"

  文字列が渡された場合はそのまま返す。"
  [form]
  (letfn [(kw-proto [k]
            (case k
              :udp "udp" :tcp "tcp" :icmp "icmp" :icmp6 "icmp6" :arp "arp"
              :ip "ip" :ipv4 "ip" :ip4 "ip"
              :ip6 "ip6" :ipv6 "ip6"
              (throw (ex-info "unknown proto keyword" {:proto k}))))
          (as-int [x]
            (if (number? x)
              (int x)
              (Integer/parseInt (str x))))]
    (cond
      (nil? form) nil
      (string? form) form

      (keyword? form)
      (kw-proto form)

      (vector? form)
      (let [[op & args] form]
        (case op
          ;; 論理
          :and (->> args (map bpf) (map paren) (clojure.string/join " and "))
          :or  (->> args (map bpf) (map paren) (clojure.string/join " or "))
          :not (str "not " (paren (bpf (first args))))

          ;; プロトコル指定（拡張）
          :proto (kw-proto (first args))

          ;; ホスト/ネット
          :host     (str "host "     (first args))
          :src-host (str "src host " (first args))
          :dst-host (str "dst host " (first args))
          :net      (str "net "      (first args))
          :src-net  (str "src net "  (first args))
          :dst-net  (str "dst net "  (first args))

          ;; ポート（単体）
          :port     (str "port "     (as-int (first args)))
          :src-port (str "src port " (as-int (first args)))
          :dst-port (str "dst port " (as-int (first args)))

          ;; ポート範囲（追加）
          :port-range
          (let [[a b] args] (str "portrange " (as-int a) "-" (as-int b)))
          :src-port-range
          (let [[a b] args] (str "src portrange " (as-int a) "-" (as-int b)))
          :dst-port-range
          (let [[a b] args] (str "dst portrange " (as-int a) "-" (as-int b)))

          ;; 既存トップレベルのキーワードも許容（[:udp] など）
          :udp "udp" :tcp "tcp" :icmp "icmp" :icmp6 "icmp6" :arp "arp"
          :ip "ip" :ipv4 "ip" :ip4 "ip" :ip6 "ip6" :ipv6 "ip6"

          (throw (ex-info "unknown op in bpf" {:form form :op op}))))
      :else
      (throw (ex-info "unsupported bpf form" {:form form})))))

;; ---------------------------
;; Stream API
;; ---------------------------
(def ^:private ETH_MIN_HDR 14)

(defn ^:private decode-result
  "parse/packet->clj を安全に呼び、結果 or エラーメッセージを返す。"
  [^bytes ba]
  (try
    {:ok true :value (parse/packet->clj ba)}
    (catch Throwable e
      {:ok false :error (or (.getMessage e) (str e))})))

(defn ^:private apply-xform
  "xf が nil なら s をそのまま返し、非nil なら (sequence xf s) を返す。
   sequence を使う事で laziness と chunkless の両立を維持。"
  [s xf]
  (if (some? xf) (sequence xf s) s))

(defn packets
  "パケットを lazy seq で返す高レベルAPI。
   opts:
   - ライブ:  {:device \"en0\" :filter <string|DSL> :timeout-ms 10 ...}
   - オフライン: {:path \"trace.pcap\" :filter <string|DSL>}
   - 共通:
       :decode? true|false
         true なら各要素に :decoded を付与。失敗時は :decode-error を付与。
       :xform <transducer>
         出力ストリームに適用する transducer。
         例: (comp (filter pred) (map f))
   返り値は遅延シーケンス。take/into などで消費してください。"
  [{:keys [filter decode? xform] :as opts}]
  (let [filter* (cond
                  (string? filter) filter
                  (or (keyword? filter) (vector? filter)) (bpf filter)
                  (nil? filter) nil
                  :else (throw (ex-info "invalid :filter" {:filter filter})))
        opts*   (cond-> opts (some? filter*) (assoc :filter filter*))
        base    (pcap/capture->seq opts*)
        stream  (if decode?
                  ;; デコード安全版（例外は投げず :decode-error を付与）
                  (map (fn [m]
                         (let [ba ^bytes (:bytes m)]
                           (if (and ba (>= (alength ba) ETH_MIN_HDR))
                             (let [{:keys [ok value error]} (decode-result ba)]
                               (cond-> m
                                 ok       (assoc :decoded value)
                                 (not ok) (assoc :decode-error error)))
                             (assoc m :decode-error (str "frame too short: " (when ba (alength ba)) " bytes")))))
                       base)
                  base)]
    (apply-xform stream xform)))

;; ---------------------------
;; Writer
;; ---------------------------
(defn write-pcap!
  "bytes のシーケンスを PCAP ファイルへ書き出す（テスト/再現用）。
   エントリは (byte-array ..) か {:bytes <ba> :sec <long> :usec <long>}。
   例: (write-pcap! [ba1 {:bytes ba2 :sec 1700000000 :usec 12345}] \"out.pcap\")"
  [packets out]
  (pcap/bytes-seq->pcap! packets {:out out}))
