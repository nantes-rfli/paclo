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

(defn- ipv4-addr [^ByteBuffer b]
  (format "%d.%d.%d.%d" (u8 b) (u8 b) (u8 b) (u8 b)))

(defn- ipv6-addr [^ByteBuffer b]
  ;; 簡易表記。ゼロ圧縮はしていない（後で最適化可）
  (format "%x:%x:%x:%x:%x:%x:%x:%x"
          (u16 b) (u16 b) (u16 b) (u16 b)
          (u16 b) (u16 b) (u16 b) (u16 b)))

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

;; IPv6 拡張ヘッダをスキップして L4 へ（軽量）
(def ^:private ipv6-ext?
  #{0    ;; Hop-by-Hop Options
    43   ;; Routing
    44   ;; Fragment
    60   ;; Destination Options
    51}) ;; AH（ESP(50)は長さ取得が厄介なのでここでは止めるのが無難）

(defn- skip-ipv6-ext! [^ByteBuffer b nh]
  ;; 戻り値: [next-header buffer]  ＊bのpositionを進める
  (loop [next nh]
    (if (and next (ipv6-ext? next) (<= 2 (.remaining b)))
      (let [hdr-ext-len (u8 b)
            ;; 拡張ヘッダ長: (hdr-ext-len + 1) * 8 バイト（NHは直前で読み取る想定）
            ;; ここでは「NHを先に読み、次に Hdr Ext Len」を読むため、
            ;; position 調整のため最初に次ヘッダを読む処理を併せて持ちます。
            ;; 呼び出し側で `next-hdr` を先に read 済なので、ここでは
            ;;   b: [Hdr Ext Len][...] の位置にある前提にしておく。
            len-bytes (* (+ hdr-ext-len 1) 8)]
        ;; 既に Hdr Ext Len を読んだ前提のため、len-bytes-1 だけ進める（NH分は別で読まれている想定）
        ;; 実装簡略化のため、dupで安全に飛ばす
        (let [skip (- len-bytes 1)]
          (when (<= skip (.remaining b))
            (.position b (+ (.position b) skip))))
        ;; 次の Next Header を読む（拡張ヘッダ末尾先頭にある想定）
        (when (<= 1 (.remaining b))
          (recur (u8 b))))
      [next b])))

(defn- ipv6 [^ByteBuffer b]
  (let [vtcfl (u32 b)
        version (bit-shift-right vtcfl 28)
        tclass  (bit-and (bit-shift-right vtcfl 20) 0xFF)
        flabel  (bit-and vtcfl 0xFFFFF)
        payload-len (u16 b)
        next-hdr (u8 b)
        hop-limit (u8 b)
        src (ipv6-addr b)
        dst (ipv6-addr b)
        l4buf (or (limited-slice b payload-len) (.duplicate b))]
    ;; 拡張ヘッダを軽量スキップ（完全厳密ではなく、実用優先）
        (let [dup (.duplicate l4buf)
           [final-nh _] (skip-ipv6-ext! dup next-hdr)
           l4 (l4-parse final-nh dup)]
       {:type :ipv6 :version version :traffic-class tclass :flow-label flabel
        :payload-length payload-len :next-header final-nh :hop-limit hop-limit
        :src src :dst dst
        :flow-key (make-flow-key {:src src :dst dst :next-header final-nh} l4) ;; ★ 追加
        :l4 l4})))

(defn- tcp-header [^ByteBuffer b]
  (let [src (u16 b)
        dst (u16 b)
        seq (u32 b)
        ack (u32 b)
        off-flags (u16 b)
        data-off (* 4 (bit-shift-right off-flags 12))
        flags (bit-and off-flags 0x3F)
        win  (u16 b)
        csum (u16 b)
        urgp (u16 b)
        hdr-len data-off]
    (when (> hdr-len 20)
      (.position b (+ (.position b) (- hdr-len 20))))
    {:type :tcp
     :src-port src :dst-port dst
     :seq seq :ack ack
     :flags {:urg (pos? (bit-and flags 32))
             :ack (pos? (bit-and flags 16))
             :psh (pos? (bit-and flags 8))
             :rst (pos? (bit-and flags 4))
             :syn (pos? (bit-and flags 2))
             :fin (pos? (bit-and flags 1))}
     :window win :checksum csum :urgent-pointer urgp
     :header-len hdr-len
     :data-len (remaining-len b)           ;; ★ 追加：TCPペイロード長
     :payload (remaining-bytes b)}))


(defn- udp-header [^ByteBuffer b]
  (let [src (u16 b)
        dst (u16 b)
        len (u16 b)
        csum (u16 b)
        paylen (max 0 (- len 8))
        paybuf (or (limited-slice b paylen) (.duplicate b))]
    {:type :udp :src-port src :dst-port dst
     :length len :checksum csum
     :data-len (remaining-len paybuf)      ;; ★ 追加：UDPペイロード長
     :payload (remaining-bytes paybuf)}))


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
          id (.getShort bb)  ;; u16
          flags (.getShort bb)
          qd (.getShort bb)
          an (.getShort bb)
          ns (.getShort bb)
          ar (.getShort bb)]
      {:type :dns :id (bit-and id 0xFFFF) :qdcount (bit-and qd 0xFFFF)
       :ancount (bit-and an 0xFFFF) :nscount (bit-and ns 0xFFFF) :arcount (bit-and ar 0xFFFF)})))

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
   - Ethernet → IPv4/IPv6/ARP を識別
   - L4は TCP/UDP/ICMPv4/ICMPv6 を簡易解析（payload付与）
   - UDP:53 は最小DNS要約を :app に付与"
  [^bytes bytes]
  (let [b (-> (ByteBuffer/wrap bytes) (.order ByteOrder/BIG_ENDIAN))
        dst (mac b) src (mac b) eth (u16 b)]
    (cond
      (= eth ETH-IPv4) {:type :ethernet :src src :dst dst :eth eth :l3 (ipv4 b)}
      (= eth ETH-IPv6) {:type :ethernet :src src :dst dst :eth eth :l3 (ipv6 b)}
      (= eth ETH-ARP)  {:type :ethernet :src src :dst dst :eth eth :l3 (or (arp b) {:type :arp})}
      :else            {:type :ethernet :src src :dst dst :eth eth :l3 {:type :unknown-l3 :eth eth}})))


