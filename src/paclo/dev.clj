(ns paclo.dev
  "REPLでの即席デバッグ/実験ヘルパ。
   - (parse-hex s)       ; 16進文字列→パケットmap
   - (summarize pktmap)  ; 要約表示
   - (hexd pktmap)       ; :bytes を16進で表示（L2生データ）

   例:
   (-> HBH-OK parse-hex summarize)
   (-> HBH-BAD parse-hex summarize)"
  (:require
   [clojure.string :as str]
   [paclo.parse :as parse])
  (:import
   [java.util Formatter]))

;; テストユーティリティに依存しない最小 hex→bytes
(defn hex->bytes ^bytes [^String s]
  (let [cleaned (-> s
                    str/lower-case
                    ;; ; コメント / Cスタイル /* */ は行儀良く除去
                    (str/replace #"(?m);.*$" "")
                    (str/replace #"(?s)/\*.*?\*/" "")
                    ;; 16進以外を全部落とす
                    (str/replace #"[^0-9a-f]" ""))]
    (when (odd? (count cleaned))
      (throw (ex-info "Odd number of hex digits" {:len (count cleaned)})))
    (byte-array
     (map (fn [[a b]]
            (unchecked-byte (Integer/parseInt (str a b) 16)))
          (partition 2 cleaned)))))

(defn parse-hex
  "16進文字列 s をパースして packet map を返す。"
  [^String s]
  (parse/packet->clj (hex->bytes s)))

(defn- fmt-bytes
  "byte[] を 'xx xx xx ...' の文字列へ"
  [^bytes bs]
  (let [sb (StringBuilder.)
        fmt (Formatter. sb)]
    (dotimes [i (alength bs)]
      (.format fmt "%02x%s"
               (bit-and 0xFF (aget bs i))
               (if (= (inc i) (alength bs)) "" " ")))
    (str sb)))

(defn hexd
  "packet map の :bytes を16進で表示（L2生データ）。戻り値は文字列。"
  [pkt]
  (fmt-bytes (:bytes pkt)))

(defn summarize
  "要点だけサマリ出力（println）。戻り値は pkt そのもの（スレッディングしやすく）。"
  [pkt]
  (let [{:keys [type l3 vlan-tags]} pkt
        l3t (:type l3)
        proto (or (:protocol l3) (:next-header l3))
        l4 (:l4 l3)]
    (println "L2:" type)
    (when (= :ethernet type)
      (print "  src/dst:" (:src pkt) "->" (:dst pkt) "eth" (format "0x%04X" (:eth pkt)))
      (when (seq vlan-tags)
        (print "  VLAN:")
        (doseq [t vlan-tags]
          (print (format " [TPID=0x%04X VID=%d PCP=%d DEI=%s]"
                         (:tpid t) (:vid t) (:pcp t) (boolean (:dei t))))))
      (println))
    (println "L3:" l3t)
    (case l3t
      :ipv4 (println "  proto" proto
                     "src" (:src l3) "dst" (:dst l3)
                     (when (:frag? l3) (str " frag@" (:frag-offset l3))))
      :ipv6 (do
              (println "  nh" proto
                       "src" (or (:src-compact l3) (:src l3))
                       "dst" (or (:dst-compact l3) (:dst l3))
                       (when (:frag? l3) (str "frag@" (:frag-offset l3)))))
      :arp  (println "  op" (:op l3) "spa" (:spa l3) "tpa" (:tpa l3))
      nil)
    (println "L4:" (:type l4)
             (cond
               (= :udp (:type l4)) (str (:src-port l4) "->" (:dst-port l4) " len=" (:data-len l4))
               (= :tcp (:type l4)) (str (:src-port l4) "->" (:dst-port l4)
                                        " " (or (:flags-str l4) "")
                                        " len=" (:data-len l4))
               (= :icmpv4 (:type l4)) (str (or (:summary l4) (str "type=" (:icmp-type l4) " code=" (:code l4)))
                                           " len=" (:data-len l4))
               (= :icmpv6 (:type l4)) (str (or (:summary l4) (str "type=" (:icmp-type l4) " code=" (:code l4)))
                                           " len=" (:data-len l4))
               :else ""))

    (when-let [app (:app l4)]
      (println "App:" (:type app) app))
    pkt))

;; ------------------------------------------------------------
;; 実験用の最小ベクタ（HBH: 正常/異常）
;; ------------------------------------------------------------

(def HBH-OK
  "Ether(IPv6) + IPv6(PL=24, NH=HBH) + HBH(16B, NextHdr=UDP) + UDP(8B)"
  "00 11 22 33 44 55 66 77 88 99 AA BB 86 DD
   60 00 00 00 00 18 00 40
   20 01 0D B8 00 00 00 00 00 00 00 00 00 00 00 01
   20 01 0D B8 00 00 00 00 00 00 00 00 00 00 00 02
   11 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00
   12 34 56 78 00 08 00 00")

(def HBH-BAD-OVERRUN
  "HBHのTLV長が過走（len=0x0Dで14B領域を1Bオーバー）→ 安全に上位へ進まず"
  "00 11 22 33 44 55 66 77 88 99 AA BB 86 DD
   60 00 00 00 00 18 00 40
   20 01 0D B8 00 00 00 00 00 00 00 00 00 00 00 01
   20 01 0D B8 00 00 00 00 00 00 00 00 00 00 00 02
   11 01 01 0D
   00 00 00 00 00 00 00 00 00 00 00 00
   12 34 56 78 00 08 00 00")
