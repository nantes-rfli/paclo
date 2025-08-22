(ns paclo.parse
  (:import [java.nio ByteBuffer ByteOrder])
  (:require [clojure.string :as str]))

(declare l4-parse)
(declare maybe-attach-dns)

(defn- u8  [^ByteBuffer b] (bit-and (.get b) 0xFF))
(defn- u16 [^ByteBuffer b] (bit-and (.getShort b) 0xFFFF))
(defn- u32 [^ByteBuffer b] (bit-and (.getInt b) 0xFFFFFFFF))

(defn- mac [^ByteBuffer b]
  (format "%02x:%02x:%02x:%02x:%02x:%02x"
          (u8 b) (u8 b) (u8 b) (u8 b) (u8 b) (u8 b)))

(def ETH-IPv4 0x0800)
(def ETH-IPv6 0x86DD)
(def ETH-ARP  0x0806)

(def ETH-VLAN-8100 0x8100)  ;; 802.1Q
(def ETH-VLAN-88A8 0x88A8)  ;; 802.1ad (QinQ outer)
(def ETH-VLAN-9100 0x9100)  ;; 追加TPID（環境による）
(def ETH-VLAN-9200 0x9200)
(def ^:private VLAN-TPIDs #{ETH-VLAN-8100 ETH-VLAN-88A8 ETH-VLAN-9100 ETH-VLAN-9200})

(defn- ipv4-addr [^ByteBuffer b]
  (format "%d.%d.%d.%d" (u8 b) (u8 b) (u8 b) (u8 b)))

(defn- ipv6-addr [^ByteBuffer b]
  ;; 簡易表記。ゼロ圧縮はしていない（後で最適化可）
  (format "%x:%x:%x:%x:%x:%x:%x:%x"
          (u16 b) (u16 b) (u16 b) (u16 b)
          (u16 b) (u16 b) (u16 b) (u16 b)))

;; IPv6: 8ワード読み取り（u16×8）
(defn- ipv6-addr-words ^clojure.lang.IPersistentVector [^ByteBuffer b]
  (vector (u16 b) (u16 b) (u16 b) (u16 b)
          (u16 b) (u16 b) (u16 b) (u16 b)))

(defn- ipv6-full-str [ws]                   ;; 非圧縮（既存の ipv6-addr と同等の見た目）
  (clojure.string/join ":" (map #(format "%x" %) ws)))

(defn- ipv6-compress-str
  "RFC5952に準拠した簡易圧縮: 0の最長連続（長さ>=2）を :: に。
   先頭/末尾/全ゼロ も自然に処理。"
  [ws]
  (let [n (count ws)
        ;; 最長0連続を探索（>=2のみ）
        [best-i best-len]
        (loop [i 0 cur-i nil cur-len 0 best-i nil best-len 0]
          (if (= i n)
            ;; ループ終了時、直前の連続が最長なら更新
            (let [[best-i best-len]
                  (if (and cur-i (>= cur-len 2) (> cur-len best-len))
                    [cur-i cur-len] [best-i best-len])]
              [best-i best-len])
            (let [z? (zero? (nth ws i))]
              (cond
                z?
                (recur (inc i)
                       (or cur-i i)
                       (inc cur-len)
                       best-i best-len)

                ;; 連続0が途切れた
                :else
                (let [[best-i best-len]
                      (if (and cur-i (>= cur-len 2) (> cur-len best-len))
                        [cur-i cur-len] [best-i best-len])]
                  (recur (inc i) nil 0 best-i best-len))))))]
    (if (>= best-len 2)
      (let [before (subvec ws 0 best-i)
            after  (subvec ws (+ best-i best-len) n)
            hexs   (fn [v] (map #(Integer/toHexString (int %)) v))
            s-before (clojure.string/join ":" (hexs before))
            s-after  (clojure.string/join ":" (hexs after))]
        (cond
          (and (empty? before) (empty? after)) "::"
          (empty? before)      (str "::" s-after)
          (empty? after)       (str s-before "::")
          :else                (str s-before "::" s-after)))
      ;; 圧縮対象ナシ
      (clojure.string/join ":" (map #(Integer/toHexString (int %)) ws)))))

;; 安全ヘルパ: 現在位置から len バイト分だけ読める ByteBuffer を作る
(defn- limited-slice ^ByteBuffer [^ByteBuffer b ^long len]
  (when (and (<= 0 len) (<= len (.remaining b)))
    (doto (.duplicate b)
      (.limit (+ (.position b) len)))))

;; 残りを byte[] でコピー（payloadを地味に見たい時用）
(defn- remaining-bytes ^bytes [^ByteBuffer b]
  (let [dup (.duplicate b)
        arr (byte-array (.remaining dup))]
    (.get dup arr)
    arr))

;; 残りバイト数（ByteBufferを消費せずに測る）
(defn- remaining-len ^long [^ByteBuffer b]
  (.remaining (.duplicate b)))

(defn- make-flow-key
  "L3の src/dst と L4の src/dst port から5タプルマップを作る。
   TCP/UDP以外はポートが無いので proto/ipだけの簡易キーにする。"
  [{:keys [src dst protocol next-header] :as l3} l4]
  (let [proto (or protocol next-header)]   ;; IPv4は :protocol, IPv6は :next-header
    (case proto
      6  {:proto :tcp  :src-ip src :src-port (:src-port l4) :dst-ip dst :dst-port (:dst-port l4)}
      17 {:proto :udp  :src-ip src :src-port (:src-port l4) :dst-ip dst :dst-port (:dst-port l4)}
      1  {:proto :icmp :src-ip src :dst-ip dst}
      58 {:proto :icmp6 :src-ip src :dst-ip dst}
      {:proto proto :src-ip src :dst-ip dst})))

;; ------------------------------------------------------------
;; IPv6 Options (HBH / Destination Options) の TLV 検証
;; - 呼び出し時点で NextHdr/HdrExtLen の 2B は既に読み終えている前提
;; - len バイト分のオプション領域を、Pad1/PadN/任意TLV として走査
;; - 過走/途切れが無ければ true を返す
;; ------------------------------------------------------------
(defn- valid-ipv6-options-tlv?
  [^ByteBuffer b ^long len]
  (if-let [opt (limited-slice b len)]
    (loop []
      (if (zero? (.remaining opt))
        true
        (let [t (u8 opt)]
          (if (= t 0) ;; Pad1 (1 byte)
            (recur)
            (if (zero? (.remaining opt)) ;; 長さフィールドが読めない
              false
              (let [l (u8 opt)]
                (if (> l (.remaining opt)) ;; value が足りない（過走）
                  false
                  (do
                    (.position opt (+ (.position opt) l)) ;; value を飛ばす
                    (recur)))))))))
    false))


(defn- arp [^ByteBuffer b]
  (when (<= 8 (.remaining b))                             ;; 最低限の固定部
    (let [htype (u16 b) ptype (u16 b)
          hlen  (u8 b)  plen  (u8 b)
          oper  (u16 b)]
      (when (<= (+ (* 2 hlen) (* 2 plen)) (.remaining b))
        (let [sha (byte-array hlen) _ (.get b sha)
              spa (byte-array plen) _ (.get b spa)
              tha (byte-array hlen) _ (.get b tha)
              tpa (byte-array plen) _ (.get b tpa)]
          {:type :arp
           :op   (case oper 1 :request 2 :reply oper)
           :sha  (format "%02x:%02x:%02x:%02x:%02x:%02x"
                         (aget sha 0) (aget sha 1) (aget sha 2)
                         (aget sha 3) (aget sha 4) (aget sha 5))
           :spa  (when (= ptype ETH-IPv4)
                   (format "%d.%d.%d.%d"
                           (bit-and 0xFF (aget spa 0))
                           (bit-and 0xFF (aget spa 1))
                           (bit-and 0xFF (aget spa 2))
                           (bit-and 0xFF (aget spa 3))))
           :tha  (format "%02x:%02x:%02x:%02x:%02x:%02x"
                         (aget tha 0) (aget tha 1) (aget tha 2)
                         (aget tha 3) (aget tha 4) (aget tha 5))
           :tpa  (when (= ptype ETH-IPv4)
                   (format "%d.%d.%d.%d"
                           (bit-and 0xFF (aget tpa 0))
                           (bit-and 0xFF (aget tpa 1))
                           (bit-and 0xFF (aget tpa 2))
                           (bit-and 0xFF (aget tpa 3))))})))))

(defn- ipv4 [^ByteBuffer b]
  (let [vihl (u8 b)
        version (bit-shift-right vihl 4)
        ihl (* 4 (bit-and vihl 0x0F))
        tos (u8 b)
        total-len (u16 b)
        id (u16 b)
        flags-frag (u16 b)
        ttl (u8 b)
        proto (u8 b)
        hdr-csum (u16 b)
        src (ipv4-addr b)
        dst (ipv4-addr b)]
    (when (> ihl 20)
      (.position b (+ (.position b) (- ihl 20))))
    (let [payload-len (max 0 (- total-len ihl))
          l4buf (or (limited-slice b payload-len) (.duplicate b))
          l4 (l4-parse proto l4buf)]
      {:type :ipv4 :version version :ihl ihl
       :tos tos :total-length total-len
       :id id :flags-frag flags-frag
       :ttl ttl :protocol proto :header-checksum hdr-csum
       :src src :dst dst
       :flow-key (make-flow-key {:src src :dst dst :protocol proto} l4) ;; ★ 追加
       :l4 l4})))

(def ^:private ipv6-ext?
  #{0   ;; Hop-by-Hop Options
    43  ;; Routing
    44  ;; Fragment
    60  ;; Destination Options
    50  ;; ESP（長さ扱いが特殊だがここでは終端扱い）
    51}) ;; AH

(defn- parse-ipv6-ext-chain!
  "buf の position は IPv6 基本ヘッダ直後（= 最初の拡張 or L4 先頭）。
   initial-nh は IPv6 基本ヘッダの Next Header。
   返り値: {:final-nh nh, :buf dup, :frag? bool, :frag-offset int}
   非フラグメント: extをすべてスキップして L4 先頭に position を合わせる
   フラグメント:
     - offset=0（先頭フラグメント）は Fragment ヘッダを読み飛ばし、次のNHへ進む
     - offset>0（後続フラグメント）は L4 が欠けている可能性が高いので、:ipv6-fragment で返す"
  [^java.nio.ByteBuffer buf initial-nh]
  (let [dup (.duplicate buf)]
    (loop [nh initial-nh
           frag? false
           frag-off 0]
      (cond
        (nil? nh)
        {:final-nh nil :buf dup :frag? frag? :frag-offset frag-off}

        (= nh 44) ;; Fragment
        (if (< (.remaining dup) 8)
          ;; 拡張ヘッダが読み切れない → 打ち切り
          {:final-nh nil :buf dup :frag? frag? :frag-offset frag-off}
          (let [next (bit-and 0xFF (.get dup)) ; Next Header
                _    (.get dup)                ; Reserved
                offfl (bit-and 0xFFFF (.getShort dup))
                _ident (.getInt dup)
                offset (bit-shift-right (bit-and offfl 0xFFF8) 3)]
            (if (zero? offset)
              ;; 先頭フラグメント：続行
              (recur next true 0)
              ;; 後続フラグメント：ここで終了（L4は解かず）
              {:final-nh next :buf dup :frag? true :frag-offset offset})))

        (= nh 51) ;; AH = NextHdr(1) + PayloadLen(1) + data((plen+2)*4 - 2)
        (if (< (.remaining dup) 2)
          {:final-nh nil :buf dup :frag? frag? :frag-offset frag-off}
          (let [next (bit-and 0xFF (.get dup))
                plen (bit-and 0xFF (.get dup))
                total (* (+ plen 2) 4)
                skip (max 0 (- total 2))              ; 既に2B読了
                adv  (min skip (.remaining dup))]
            (.position dup (+ (.position dup) adv))
            (if (< adv skip)
              ;; 足りない → 打ち切り
              {:final-nh nil :buf dup :frag? frag? :frag-offset frag-off}
              (recur next frag? frag-off))))

        (= nh 50) ;; ESP はここで終端扱い（中は解さない）
        {:final-nh nh :buf dup :frag? frag? :frag-offset frag-off}

        (ipv6-ext? nh)
        (if (< (.remaining dup) 2)
          {:final-nh nil :buf dup :frag? frag? :frag-offset frag-off}
          (let [next (bit-and 0xFF (.get dup))    ;; NextHdr
                hlen (bit-and 0xFF (.get dup))    ;; HdrExtLen
                total (* (+ hlen 1) 8)            ;; 総ヘッダ長
                ;; 既に 2B 読了済み（NextHdr/HdrExtLen）なので、残オプション領域:
                opt-len (max 0 (- total 2))]
            (cond
              ;; 明確に足りない場合は打ち切り
              (> opt-len (.remaining dup))
              {:final-nh nil :buf dup :frag? frag? :frag-offset frag-off}
              
              ;; HBH / Dest は TLV を検証してから進める
              (or (= nh 0) (= nh 60))
              (if (valid-ipv6-options-tlv? dup opt-len)
                (do
                  ;; TLV 検証は limited-slice の中で消費しているだけなので、
                  ;; 実体 dup の position を opt-len だけ前に送る
                  (.position dup (+ (.position dup) opt-len))
                  (recur next frag? frag-off))
                ;; TLV が壊れている（途切れ/過走）
                {:final-nh nil :buf dup :frag? frag? :frag-offset frag-off})
              
              ;; Routing(43) は TLV ではないので長さスキップのみ
              (= nh 43)
              (do
                (.position dup (+ (.position dup) opt-len))
                (recur next frag? frag-off))
              
              ;; 万一ここに来たら（ESP/AH は上で拾っているはず）安全に打ち切り
              :else
              {:final-nh nil :buf dup :frag? frag? :frag-offset frag-off})))

        :else
        ;; L4 に到達 
        {:final-nh nh :buf dup :frag? frag? :frag-offset frag-off}))))

(defn- ipv6 [^ByteBuffer b]
  (let [vtcfl (u32 b)
        version (bit-shift-right vtcfl 28)
        tclass  (bit-and (bit-shift-right vtcfl 20) 0xFF)
        flabel  (bit-and vtcfl 0xFFFFF)
        payload-len (u16 b)
        next-hdr (u8 b)
        hop-limit (u8 b)
        ;; ここで8ワードを読み取り → 非圧縮/圧縮の両方を作る
        src-w (ipv6-addr-words b)
        dst-w (ipv6-addr-words b)
        src   (ipv6-full-str src-w)          ;; 既存互換（非圧縮）
        dst   (ipv6-full-str dst-w)
        srcC  (ipv6-compress-str src-w)      ;; 新規（圧縮）
        dstC  (ipv6-compress-str dst-w)
        l4buf (or (limited-slice b payload-len) (.duplicate b))
        {:keys [final-nh buf frag? frag-offset]}
        (parse-ipv6-ext-chain! l4buf next-hdr)
        l4 (if (and frag? (pos? frag-offset))
             {:type :ipv6-fragment :offset frag-offset :payload (remaining-bytes buf)}
             (l4-parse final-nh buf))
        flow-key (when final-nh
                   (make-flow-key {:src src :dst dst :next-header final-nh} l4))]
    {:type :ipv6
     :version version :traffic-class tclass :flow-label flabel
     :payload-length payload-len :next-header final-nh :hop-limit hop-limit
     :src src :dst dst
     :src-compact srcC :dst-compact dstC         ;; ★ 追加
     :frag? frag? :frag-offset (when frag? frag-offset)
     :l4 l4
     :flow-key flow-key}))



(defn- tcp-header [^ByteBuffer b]
  (let [src (u16 b)
        dst (u16 b)
        seq (u32 b)
        ack (u32 b)
        off-flags (u16 b)
        data-off (* 4 (bit-shift-right off-flags 12))
        flags-bits (bit-and off-flags 0x3F)
        urg  (pos? (bit-and flags-bits 32))
        ackf (pos? (bit-and flags-bits 16))
        psh  (pos? (bit-and flags-bits 8))
        rst  (pos? (bit-and flags-bits 4))
        syn  (pos? (bit-and flags-bits 2))
        fin  (pos? (bit-and flags-bits 1))
        win  (u16 b)
        csum (u16 b)
        urgp (u16 b)
        hdr-len data-off
        ;; 短縮フラグ（順序: U A P R S F）
        flags-str (apply str (keep (fn [[present ch]] (when present ch))
                                   [[urg \U] [ackf \A] [psh \P] [rst \R] [syn \S] [fin \F]]))]
    (when (> hdr-len 20)
      (.position b (+ (.position b) (- hdr-len 20))))
    {:type :tcp
     :src-port src :dst-port dst
     :seq seq :ack ack
     :flags {:urg urg :ack ackf :psh psh :rst rst :syn syn :fin fin}
     :flags-str flags-str
     :window win :checksum csum :urgent-pointer urgp
     :header-len hdr-len
     :data-len (remaining-len b)
     :payload (remaining-bytes b)}))


(defn- udp-header [^ByteBuffer b]
  ;; ★ 追加: 残量ガード（8B未満なら安全に諦める）
  (if (< (.remaining b) 8)
    {:type :unknown-l4 :reason :truncated-udp :data-len 0 :payload []}
    (let [src (u16 b)
          dst (u16 b)
          len (u16 b)
          csum (u16 b)
          paylen (max 0 (- len 8))
          paybuf (or (limited-slice b paylen) (.duplicate b))]
      {:type :udp :src-port src :dst-port dst
       :length len :checksum csum
       :data-len (remaining-len paybuf)
       :payload (remaining-bytes paybuf)})))



(defn- icmpv4-header [^ByteBuffer b]
  (let [t (u8 b) code (u8 b) csum (u16 b)]
    {:type :icmpv4 :icmp-type t :code code :checksum csum
     :data-len (remaining-len b)           ;; ★ 追加
     :payload (remaining-bytes b)}))

(defn- icmpv6-header [^ByteBuffer b]
  (let [t (u8 b) code (u8 b) csum (u16 b)]
    {:type :icmpv6 :icmp-type t :code code :checksum csum
     :data-len (remaining-len b)           ;; ★ 追加
     :payload (remaining-bytes b)}))


(defn- dns-min [^bytes payload]
  (when (<= 12 (alength payload))
    (let [bb (-> (ByteBuffer/wrap payload) (.order ByteOrder/BIG_ENDIAN))
          id (.getShort bb)      ;; u16
          flags (.getShort bb)   ;; u16
          qd (.getShort bb)
          an (.getShort bb)
          ns (.getShort bb)
          ar (.getShort bb)
          f  (bit-and flags 0xFFFF)
          qr (pos? (bit-and f 0x8000))
          opcode (bit-and (bit-shift-right f 11) 0x0F)
          aa (pos? (bit-and f 0x0400))
          tc (pos? (bit-and f 0x0200))
          rd (pos? (bit-and f 0x0100))
          ra (pos? (bit-and f 0x0080))
          ad (pos? (bit-and f 0x0020))
          cd (pos? (bit-and f 0x0010))
          rcode (bit-and f 0x000F)]
      {:type    :dns
       :id      (bit-and id 0xFFFF)
       :qdcount (bit-and qd 0xFFFF)
       :ancount (bit-and an 0xFFFF)
       :nscount (bit-and ns 0xFFFF)
       :arcount (bit-and ar 0xFFFF)
       :flags   {:qr qr :opcode opcode :aa aa :tc tc :rd rd :ra ra :ad ad :cd cd :rcode rcode}})))


(defn- maybe-attach-dns [m]
  (if (and (= :udp (:type m))
           (or (= 53 (:src-port m)) (= 53 (:dst-port m)))
           (:payload m))
    (assoc m :app (dns-min (:payload m)))
    m))

(defn- l4-parse [proto ^ByteBuffer b]
  (let [m (case proto
            6  (tcp-header b)
            17 (udp-header b)
            1  (icmpv4-header b)
            58 (icmpv6-header b)
            {:type :unknown-l4 :proto proto :payload (remaining-bytes b)})]
    (maybe-attach-dns m)))

(defn packet->clj
  "bytes -> Clojure map
   - Ethernet → VLAN タグ（0〜複数）をはぎ、最終 Ethertype で L3 を解釈
   - L4は TCP/UDP/ICMPv4/ICMPv6 を簡易解析（payload付与）
   - UDP:53 は最小DNS要約を :app に付与
   返り値トップには :vlan-tags（あれば）を付与。"
  [^bytes bytes]
  (let [b (-> (ByteBuffer/wrap bytes) (.order ByteOrder/BIG_ENDIAN))
        dst (mac b) src (mac b)
        first-eth (u16 b)]
    ;; VLAN タグをすべてはぐ（QinQ 対応）
    (loop [eth first-eth
           tags (transient [])]
      (if (VLAN-TPIDs eth)
        (if (< (.remaining b) 4)
          ;; VLAN ヘッダ不足（TCI+次Ethertype で 4B必要）→ 安全に unknown を返却
          {:type :ethernet :src src :dst dst :eth eth
           :vlan-tags (persistent! tags)
           :l3 {:type :unknown-l3 :eth eth}}
          (let [tci (u16 b)
                next-eth (u16 b)
                tag {:tpid eth
                     :pcp  (bit-and (bit-shift-right tci 13) 0x7)    ;; 3bit
                     :dei  (pos? (bit-and tci 0x1000))               ;; 1bit
                     :vid  (bit-and tci 0x0FFF)}]                    ;; 12bit
            (recur next-eth (conj! tags tag))))
        ;; VLAN ではない → 最終 Ethertype が確定
        (let [final-eth eth
              vlan-tags (persistent! tags)]
          (cond
            (= final-eth ETH-IPv4)
            (let [l3 (ipv4 b)]
              (cond-> {:type :ethernet :src src :dst dst :eth final-eth :l3 l3}
                (seq vlan-tags) (assoc :vlan-tags vlan-tags)))

            (= final-eth ETH-IPv6)
            (let [l3 (ipv6 b)]
              (cond-> {:type :ethernet :src src :dst dst :eth final-eth :l3 l3}
                (seq vlan-tags) (assoc :vlan-tags vlan-tags)))

            (= final-eth ETH-ARP)
            (let [l3 (or (arp b) {:type :arp})]
              (cond-> {:type :ethernet :src src :dst dst :eth final-eth :l3 l3}
                (seq vlan-tags) (assoc :vlan-tags vlan-tags)))

            :else
            (cond-> {:type :ethernet :src src :dst dst :eth final-eth
                     :l3 {:type :unknown-l3 :eth final-eth}}
              (seq vlan-tags) (assoc :vlan-tags vlan-tags))))))))
