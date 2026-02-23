(ns paclo.parse
  (:require
   [clojure.string :as str])
  (:import
   [java.nio ByteBuffer ByteOrder]))

(declare l4-parse)
(declare maybe-attach-dns)

(defn- u8  ^long [^ByteBuffer b] (bit-and (.get b) 0xFF))
(defn- u16 ^long [^ByteBuffer b] (bit-and (.getShort b) 0xFFFF))
(defn- u32 ^long [^ByteBuffer b] (bit-and (.getInt b) 0xFFFFFFFF))

(defn- mac [^ByteBuffer b]
  (format "%02x:%02x:%02x:%02x:%02x:%02x"
          (u8 b) (u8 b) (u8 b) (u8 b) (u8 b) (u8 b)))

(def ETH-IPv4 0x0800)
(def ETH-IPv6 0x86DD)
(def ETH-ARP  0x0806)

(def ETH-VLAN-8100 0x8100)  ;; 802.1Q
(def ETH-VLAN-88A8 0x88A8)  ;; 802.1ad (QinQ outer)
(def ETH-VLAN-9100 0x9100)  ;; Additional TPID seen on some environments
(def ETH-VLAN-9200 0x9200)
(def ^:private VLAN-TPIDs #{ETH-VLAN-8100 ETH-VLAN-88A8 ETH-VLAN-9100 ETH-VLAN-9200})

(defn- ipv4-addr [^ByteBuffer b]
  (format "%d.%d.%d.%d" (u8 b) (u8 b) (u8 b) (u8 b)))

(defn- ipv6-addr-words ^clojure.lang.IPersistentVector [^ByteBuffer b]
  (vector (u16 b) (u16 b) (u16 b) (u16 b)
          (u16 b) (u16 b) (u16 b) (u16 b)))

(defn- ipv6-full-str [ws]                   ;; Uncompressed form (legacy-compatible output)
  (clojure.string/join ":" (map #(format "%x" %) ws)))

(defn- ipv6-compress-str
  "Compress IPv6 words with a simple RFC5952-style rule.
   The longest zero run (length >= 2) becomes `::`."
  [ws]
  (let [n (count ws)
        [best-i best-len]
        (loop [i 0 cur-i nil cur-len (long 0) best-i nil best-len (long 0)]
          (if (= i n)
            (let [[best-i ^long best-len]
                  (if (and cur-i (>= (long cur-len) 2) (> (long cur-len) (long best-len)))
                    [cur-i cur-len] [best-i best-len])]
              [best-i best-len])
            (let [z? (zero? ^long (nth ws i))]
              (cond
                z?
                (recur (inc i)
                       (or cur-i i)
                       (long (inc cur-len))
                       best-i (long best-len))

                :else
                (let [[best-i ^long best-len]
                      (if (and cur-i (>= (long cur-len) 2) (> (long cur-len) (long best-len)))
                        [cur-i cur-len] [best-i best-len])]
                  (recur (inc i) nil (long 0) best-i (long best-len)))))))]
    (if (>= (long best-len) 2)
      (let [before (subvec ws 0 best-i)
            after  (subvec ws (unchecked-add (long best-i) (long best-len)) n)
            hexs   (fn [v] (map #(Integer/toHexString (int %)) v))
            s-before (clojure.string/join ":" (hexs before))
            s-after  (clojure.string/join ":" (hexs after))]
        (cond
          (and (empty? before) (empty? after)) "::"
          (empty? before)      (str "::" s-after)
          (empty? after)       (str s-before "::")
          :else                (str s-before "::" s-after)))
      (clojure.string/join ":" (map #(Integer/toHexString (int %)) ws)))))

(defn- limited-slice ^ByteBuffer [^ByteBuffer b ^long len]
  (when (and (<= 0 len) (<= len (.remaining b)))
    (doto (.duplicate b)
      (.limit (+ (.position b) len)))))

(defn- remaining-bytes ^bytes [^ByteBuffer b]
  (let [dup (.duplicate b)
        arr (byte-array (.remaining dup))]
    (.get dup arr)
    arr))

(defn- remaining-len ^long [^ByteBuffer b]
  (.remaining (.duplicate b)))

(defn- make-flow-key
  "Build a flow key from L3 src/dst and L4 ports.
   For non-TCP/UDP traffic, build a protocol+IP key without ports."
  [{:keys [src dst protocol next-header]} l4]
  (let [proto (long (or protocol next-header -1))]   ;; IPv4 uses :protocol, IPv6 uses :next-header
    (case proto
      6  {:proto :tcp  :src-ip src :src-port (:src-port l4) :dst-ip dst :dst-port (:dst-port l4)}
      17 {:proto :udp  :src-ip src :src-port (:src-port l4) :dst-ip dst :dst-port (:dst-port l4)}
      1  {:proto :icmp :src-ip src :dst-ip dst}
      58 {:proto :icmp6 :src-ip src :dst-ip dst}
      {:proto proto :src-ip src :dst-ip dst})))

;; ------------------------------------------------------------
;; ------------------------------------------------------------
(defn- valid-ipv6-options-tlv?
  [^ByteBuffer b ^long len]
  (if-let [^ByteBuffer opt (limited-slice b len)]
    (loop []
      (if (zero? (.remaining opt))
        true
        (let [t (u8 opt)]
          (if (= t 0) ;; Pad1 (1 byte)
            (recur)
            (if (zero? (.remaining opt)) ;; Missing length byte
              false
              (let [l (u8 opt)]
                (if (> l (.remaining opt)) ;; Value would overrun buffer
                  false
                  (do
                    (.position opt (+ (.position opt) l)) ;; Skip value bytes
                    (recur)))))))))
    false))

(defn- arp [^ByteBuffer b]
  (when (<= 8 (.remaining b))                             ;; Minimum fixed header size
    (let [_htype (u16 b) ptype (u16 b)
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
        proto (int (u8 b))
        hdr-csum (u16 b)
        src (ipv4-addr b)
        dst (ipv4-addr b)]
    (when (> ihl 20)
      (.position b (+ (.position b) (- ihl 20))))
    (let [mf? (pos? (bit-and flags-frag 0x2000))
          frag-off (bit-and flags-frag 0x1FFF)         ;; In 8-byte units
          frag? (or mf? (pos? frag-off))
          payload-len (max 0 (- total-len ihl))
          l4buf (or (limited-slice b payload-len) (.duplicate b))
          l4 (if (pos? frag-off)
               {:type :ipv4-fragment :offset frag-off :payload (remaining-bytes l4buf)}
               (l4-parse proto l4buf))]
      {:type :ipv4 :version version :ihl ihl
       :tos tos :total-length total-len
       :id id :flags-frag flags-frag
       :ttl ttl :protocol proto :header-checksum hdr-csum
       :src src :dst dst
       :frag? frag? :frag-offset (when frag? frag-off)       ;; Fragment metadata
       :flow-key (make-flow-key {:src src :dst dst :protocol proto} l4)
       :l4 l4})))

(def ^:private ipv6-ext?
  #{0   ;; Hop-by-Hop Options
    43  ;; Routing
    44  ;; Fragment
    60  ;; Destination Options
    50  ;; ESP (treated as terminal here)
    51}) ;; AH

(defn- parse-ipv6-ext-chain!
  "Parse IPv6 extension headers from `buf`.
   `buf` starts right after the base IPv6 header.
   Returns {:final-nh nh :buf dup :frag? bool :frag-offset int}.

   Non-fragment packets skip all extension headers and land at the L4 start.
   For fragments:
   - offset=0: continue to next header
   - offset>0: return early because L4 may be incomplete."
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
          {:final-nh nil :buf dup :frag? frag? :frag-offset frag-off}
          (let [next (bit-and 0xFF (.get dup)) ; Next Header
                _    (.get dup)                ; Reserved
                offfl (bit-and 0xFFFF (.getShort dup))
                _ident (.getInt dup)
                offset (bit-shift-right (bit-and offfl 0xFFF8) 3)]
            (if (zero? offset)
              (recur next true 0)
              {:final-nh next :buf dup :frag? true :frag-offset offset})))

        (= nh 51) ;; AH = NextHdr(1) + PayloadLen(1) + data((plen+2)*4 - 2)
        (if (< (.remaining dup) 2)
          {:final-nh nil :buf dup :frag? frag? :frag-offset frag-off}
          (let [next (bit-and 0xFF (.get dup))
                plen (bit-and 0xFF (.get dup))
                total (* (+ plen 2) 4)
                skip (max 0 (- total 2))              ; First 2 bytes already consumed
                adv  (min skip (.remaining dup))]
            (.position dup (+ (.position dup) adv))
            (if (< adv skip)
              {:final-nh nil :buf dup :frag? frag? :frag-offset frag-off}
              (recur next frag? frag-off))))

        (= nh 50) ;; ESP is terminal here (payload not decoded)
        {:final-nh nh :buf dup :frag? frag? :frag-offset frag-off}

        (ipv6-ext? nh)
        (if (< (.remaining dup) 2)
          {:final-nh nil :buf dup :frag? frag? :frag-offset frag-off}
          (let [next (bit-and 0xFF (.get dup))    ;; NextHdr
                hlen (bit-and 0xFF (.get dup))    ;; HdrExtLen
                total (* (+ hlen 1) 8)            ;; Total extension header length
                opt-len (max 0 (- total 2))]
            (cond
              (> opt-len (.remaining dup))
              {:final-nh nil :buf dup :frag? frag? :frag-offset frag-off}

              (or (= nh 0) (= nh 60))
              (if (valid-ipv6-options-tlv? dup opt-len)
                (do
                  (.position dup (+ (.position dup) opt-len))
                  (recur next frag? frag-off))
                {:final-nh nil :buf dup :frag? frag? :frag-offset frag-off})

              (= nh 43)
              (do
                (.position dup (+ (.position dup) opt-len))
                (recur next frag? frag-off))

              :else
              {:final-nh nil :buf dup :frag? frag? :frag-offset frag-off})))

        :else
        {:final-nh nh :buf dup :frag? frag? :frag-offset frag-off}))))

(defn- ipv6 [^ByteBuffer b]
  (let [vtcfl (u32 b)
        version (bit-shift-right vtcfl 28)
        tclass  (bit-and (bit-shift-right vtcfl 20) 0xFF)
        flabel  (bit-and vtcfl 0xFFFFF)
        payload-len (u16 b)
        next-hdr (u8 b)
        hop-limit (u8 b)
        src-w (ipv6-addr-words b)
        dst-w (ipv6-addr-words b)
        src   (ipv6-full-str src-w)          ;; Legacy-compatible (uncompressed)
        dst   (ipv6-full-str dst-w)
        srcC  (ipv6-compress-str src-w)      ;; Compressed representation
        dstC  (ipv6-compress-str dst-w)
        l4buf (or (limited-slice b payload-len) (.duplicate b))
        {:keys [final-nh buf frag? frag-offset]}
        (parse-ipv6-ext-chain! l4buf next-hdr)
        l4 (if (and frag? (pos? (long (or frag-offset 0))))
             {:type :ipv6-fragment :offset frag-offset :payload (remaining-bytes buf)}
             (l4-parse final-nh buf))
        flow-key (when final-nh
                   (make-flow-key {:src src :dst dst :next-header final-nh} l4))]
    {:type :ipv6
     :version version :traffic-class tclass :flow-label flabel
     :payload-length payload-len :next-header final-nh :hop-limit hop-limit
     :src src :dst dst
     :src-compact srcC :dst-compact dstC         ;; Additional compact fields
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

;; --- ICMP name helpers -------------------------------------------------------

(defn- icmpv4-type-name [^long t]
  (case t
    0  "echo-reply"
    3  "dest-unreachable"
    4  "source-quench"
    5  "redirect"
    8  "echo-request"
    9  "router-advertisement"
    10 "router-solicitation"
    11 "time-exceeded"
    12 "parameter-problem"
    13 "timestamp"
    14 "timestamp-reply"
    17 "address-mask-request"
    18 "address-mask-reply"
    (str "type-" t)))

(defn- icmpv4-code-name [^long t ^long c]
  (case t
    3  (case c
         0 "net-unreachable"
         1 "host-unreachable"
         2 "proto-unreachable"
         3 "port-unreachable"
         4 "frag-needed"
         5 "src-route-failed"
         9 "net-admin-prohibited"
         10 "host-admin-prohibited"
         13 "comm-admin-prohibited"
         (str "code-" c))
    5  (case c
         0 "redirect-net" 1 "redirect-host"
         2 "redirect-tos-net" 3 "redirect-tos-host"
         (str "code-" c))
    11 (case c
         0 "ttl-exceeded"
         1 "frag-reassembly-time-exceeded"
         (str "code-" c))
    12 (case c
         0 "pointer-indicates-error"
         1 "missing-required-option"
         2 "bad-length"
         (str "code-" c))
    (when (not= c 0) (str "code-" c))))

(defn- icmpv6-type-name [^long t]
  (case t
    1   "dest-unreachable"
    2   "packet-too-big"
    3   "time-exceeded"
    4   "parameter-problem"
    128 "echo-request"
    129 "echo-reply"
    133 "router-solicitation"
    134 "router-advertisement"
    135 "neighbor-solicitation"
    136 "neighbor-advertisement"
    137 "redirect"
    (str "type-" t)))

(defn- icmpv6-code-name [^long t ^long c]
  (case t
    1 (case c
        0 "no-route"
        1 "admin-prohibited"
        3 "addr-unreachable"
        4 "port-unreachable"
        (str "code-" c))
    3 (case c
        0 "hop-limit-exceeded"
        1 "frag-reassembly-time-exceeded"
        (str "code-" c))
    4 (case c
        0 "erroneous-header-field"
        1 "unknown-next-header"
        2 "unrecognized-ipv6-option"
        (str "code-" c))
    (when (not= c 0) (str "code-" c))))

(defn- icmpv4-header [^ByteBuffer b]
  (let [t (u8 b) code (u8 b) csum (u16 b)
        tname (icmpv4-type-name t)
        cname (icmpv4-code-name t code)
        summary (if cname (str tname "/" cname) tname)]
    {:type :icmpv4 :icmp-type t :code code :checksum csum
     :type-name tname :code-name cname :summary summary
     :data-len (remaining-len b)
     :payload (remaining-bytes b)}))

(defn- icmpv6-header [^ByteBuffer b]
  (let [t (u8 b) code (u8 b) csum (u16 b)
        tname (icmpv6-type-name t)
        cname (icmpv6-code-name t code)
        summary (if cname (str tname "/" cname) tname)]
    {:type :icmpv6 :icmp-type t :code code :checksum csum
     :type-name tname :code-name cname :summary summary
     :data-len (remaining-len b)
     :payload (remaining-bytes b)}))

;; --- DNS header helpers ------------------------------------------------------

(defn- dns-opcode-name [^long op]
  (case op
    0 "query"    ; standard query
    1 "iquery"   ; inverse query (obsolete)
    2 "status"
    4 "notify"
    5 "update"
    (str "opcode-" op)))

(defn- dns-rcode-name [^long rc]
  (case rc
    0  "noerror"
    1  "formerr"
    2  "servfail"
    3  "nxdomain"
    4  "notimp"
    5  "refused"
    6  "yxdomain"
    7  "yxrrset"
    8  "nxrrset"
    9  "notauth"
    10 "notzone"
    16 "badvers"
    22 "badcookie"
    (str "rcode-" rc)))

(defn- dns-min [^bytes payload]
  (when (<= 12 (alength payload))
    (let [bb (-> (ByteBuffer/wrap payload) (.order ByteOrder/BIG_ENDIAN))
          id (.getShort bb)
          flags (.getShort bb)
          qd (.getShort bb)
          an (.getShort bb)
          ns (.getShort bb)
          ar (.getShort bb)
          f (bit-and flags 0xFFFF)
          qr? (pos? (bit-and f 0x8000))
          opcode (bit-and (bit-shift-right f 11) 0x0F)
          aa? (pos? (bit-and f 0x0400))
          tc? (pos? (bit-and f 0x0200))
          rd? (pos? (bit-and f 0x0100))
          ra? (pos? (bit-and f 0x0080))
          rcode (bit-and f 0x000F)
          oname (dns-opcode-name opcode)
          rname (dns-rcode-name rcode)]
      {:type :dns
       :id (bit-and id 0xFFFF)
       :qdcount (bit-and qd 0xFFFF)
       :ancount (bit-and an 0xFFFF)
       :nscount (bit-and ns 0xFFFF)
       :arcount (bit-and ar 0xFFFF)
       :flags-raw f
       :qr? qr?
       :opcode opcode
       :opcode-name oname
       :aa? aa?
       :tc? tc?
       :rd? rd?
       :ra? ra?
       :rcode rcode
       :rcode-name rname
       :summary (str (if qr? "response" "query")
                     "/" oname
                     (when qr? (str "/" rname)))
       :flags {:raw f
               :qr qr?
               :opcode opcode
               :aa aa?
               :tc tc?
               :rd rd?
               :ra ra?
               :rcode rcode
               :rcode-name rname}})))

(defn- maybe-attach-dns [m]
  (if (and (= :udp (:type m))
           (or (= 53 (:src-port m)) (= 53 (:dst-port m)))
           (:payload m))
    (assoc m :app (dns-min (:payload m)))
    m))

(defn- l4-parse [proto ^ByteBuffer b]
  (let [m (if (nil? proto)
            {:type :unknown-l4 :proto proto :payload (remaining-bytes b)}
            (case (int proto)
              6  (tcp-header b)
              17 (udp-header b)
              1  (icmpv4-header b)
              58 (icmpv6-header b)
              {:type :unknown-l4 :proto proto :payload (remaining-bytes b)}))]
    (maybe-attach-dns m)))

(defn packet->clj
  "Decode bytes into a Clojure map.
   - Parses Ethernet and strips 0..N VLAN tags
   - Decodes minimal L3/L4 structures (IPv4/IPv6/ARP, TCP/UDP/ICMP)
   - Adds minimal DNS summary under `:app` for UDP/53 traffic
   - Adds `:vlan-tags` when tags exist"
  [^bytes bytes]
  (let [b (-> (ByteBuffer/wrap bytes) (.order ByteOrder/BIG_ENDIAN))
        dst (mac b) src (mac b)
        first-eth (u16 b)]
    (loop [eth first-eth
           tags (transient [])]
      (if (VLAN-TPIDs eth)
        (if (< (.remaining b) 4)
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
