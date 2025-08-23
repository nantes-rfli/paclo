(ns paclo.core
  "Clojure らしい薄いファサード。
   - packets: ライブ/オフラインどちらも lazy seq を返す（:decode? でparse付与）
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
   例:
     (bpf [:and [:udp] [:port 53]])       ;;=> \"(udp) and (port 53)\"
     (bpf [:or [:tcp] [:udp]])            ;;=> \"(tcp) or (udp)\"
     (bpf [:not [:host \"8.8.8.8\"]])     ;;=> \"not (host 8.8.8.8)\"
     (bpf [:and [:tcp] [:dst-port 80]])   ;;=> \"(tcp) and (dst port 80)\"
     (bpf \"udp and port 53\")            ;;=> そのまま"
  [form]
  (cond
    (nil? form) nil
    (string? form) form
    (keyword? form)
    (case form
      :udp "udp" :tcp "tcp" :icmp "icmp" :icmp6 "icmp6" :arp "arp"
      (throw (ex-info "unknown keyword in bpf" {:form form})))

    (vector? form)
    (let [[op & args] form]
      (case op
        :and (->> args (map bpf) (map paren) (str/join " and "))
        :or  (->> args (map bpf) (map paren) (str/join " or "))
        :not (str "not " (paren (bpf (first args))))
        :port      (str "port "      (int (first args)))
        :src-port  (str "src port "  (int (first args)))
        :dst-port  (str "dst port "  (int (first args)))
        :host      (str "host "      (first args))
        :src-host  (str "src host "  (first args))
        :dst-host  (str "dst host "  (first args))
        :net       (str "net "       (first args))
        :udp "udp" :tcp "tcp" :icmp "icmp" :icmp6 "icmp6" :arp "arp"
        (throw (ex-info "unknown op in bpf" {:form form}))))
    :else
    (throw (ex-info "unsupported bpf form" {:form form}))))

;; ---------------------------
;; Stream API
;; ---------------------------
;; 追加: Ethernet最小ヘッダ長
(def ^:private ETH_MIN_HDR 14)

;; 追加: デコードの結果を {:ok true :value v} or {:ok false :error msg} で返す
(defn ^:private decode-result [^bytes ba]
  (try
    {:ok true :value (parse/packet->clj ba)}
    (catch Throwable e
      {:ok false :error (or (.getMessage e) (str e))})))

;; 置き換え: packets（安全デコード版）
(defn packets
  "パケットを lazy seq で返す高レベルAPI。
   opts:
   - ライブ:  {:device \"en0\" :filter <string|DSL> :timeout-ms 10 ...}
   - オフライン: {:path \"trace.pcap\" :filter <string|DSL>}
   - 共通:
       :decode? true|false  ; true なら各要素に :decoded を付与。失敗時は :decode-error を付与。"
  [{:keys [filter decode?] :as opts}]
  (let [filter* (cond
                  (string? filter) filter
                  (or (keyword? filter) (vector? filter)) (bpf filter)
                  (nil? filter) nil
                  :else (throw (ex-info "invalid :filter" {:filter filter})))
        opts*   (cond-> opts (some? filter*) (assoc :filter filter*))
        base    (pcap/capture->seq opts*)]
    (if decode?
      (map (fn [m]
             (let [ba ^bytes (:bytes m)]
               (if (and ba (>= (alength ba) ETH_MIN_HDR))
                 (let [{:keys [ok value error]} (decode-result ba)]
                   (cond-> m
                     ok      (assoc :decoded value)
                     (not ok) (assoc :decode-error error)))
                 ;; 短すぎるフレームはデコードせずにエラーだけ付与
                 (assoc m :decode-error (str "frame too short: " (when ba (alength ba)) " bytes")))))
           base)
      base)))

;; ---------------------------
;; Writer
;; ---------------------------
(defn write-pcap!
  "bytes のシーケンスを PCAP ファイルへ書き出す（テスト/再現用）。
   エントリは (byte-array ..) か {:bytes <ba> :sec <long> :usec <long>}。
   例: (write-pcap! [ba1 {:bytes ba2 :sec 1700000000 :usec 12345}] \"out.pcap\")"
  [packets out]
  (pcap/bytes-seq->pcap! packets {:out out}))
