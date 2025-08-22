# AI_HANDOFF (auto-generated)

- commit: 03487f3
- generated: 2025-08-22 13:00:24 UTC

## How to run
\`clj -M:test\` / \`clj -T:build jar\`

## Notes
- IPv6 HBH / Destination Options の HdrExtLen は **(n+1)\*8 バイト（総ヘッダ長）**。
  テストベクタ作成時は NextHdr/HdrExtLen の 2 バイトを除いた *オプション領域長* が (総長-2) に厳密一致するように Pad1/PadN で調整すること。

## Files
### script/make-ai-handoff.sh
```bash
#!/usr/bin/env bash
set -euo pipefail

out="AI_HANDOFF.md"
rev="$(git rev-parse --short HEAD || echo 'unknown')"
date="$(date -u '+%Y-%m-%d %H:%M:%S UTC')"

emit () {
  echo "\`\`\`$1"
  cat "$2"
  echo "\`\`\`"
  echo
}

{
  echo "# AI_HANDOFF (auto-generated)"
  echo
  echo "- commit: ${rev}"
  echo "- generated: ${date}"
  echo
  echo "## How to run"
  echo "\\\`clj -M:test\\\` / \\\`clj -T:build jar\\\`"
  echo
  echo "## Notes"
  echo "- IPv6 HBH / Destination Options の HdrExtLen は **(n+1)\*8 バイト（総ヘッダ長）**。"
  echo "  テストベクタ作成時は NextHdr/HdrExtLen の 2 バイトを除いた *オプション領域長* が (総長-2) に厳密一致するように Pad1/PadN で調整すること。"
  echo
  echo "## Files"
  echo "### script/make-ai-handoff.sh"
  emit bash script/make-ai-handoff.sh
  echo "### src/paclo/parse.clj"
  emit clojure src/paclo/parse.clj
  echo "### src/paclo/pcap.clj"
  emit clojure src/paclo/pcap.clj
  echo "### src/paclo/dev.clj"
  emit clojure src/paclo/dev.clj
  echo "### src-java/paclo/jnr/PcapLibrary.java"
  emit java src-java/paclo/jnr/PcapLibrary.java
  echo "### test/paclo/parse_test.clj"
  emit clojure test/paclo/parse_test.clj
  echo "### test/paclo/test_util.clj"
  emit clojure test/paclo/test_util.clj
} > "$out"

echo "Wrote $out"
```

### src/paclo/parse.clj
```clojure
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
        src (ipv6-addr b)
        dst (ipv6-addr b)
        l4buf (or (limited-slice b payload-len) (.duplicate b))]
    (let [l4buf (or (limited-slice b payload-len) (.duplicate b))
          {:keys [final-nh buf frag? frag-offset]}
          (parse-ipv6-ext-chain! l4buf next-hdr)
          l4 (if (and frag? (pos? frag-offset))
               {:type :ipv6-fragment :offset frag-offset :payload (remaining-bytes buf)}
               (l4-parse final-nh buf))]
      {:type :ipv6
       :version version :traffic-class tclass :flow-label flabel
       :payload-length payload-len :next-header final-nh :hop-limit hop-limit
       :src src :dst dst
       :frag? frag? :frag-offset (when frag? frag-offset)
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


```

### src/paclo/pcap.clj
```clojure
(ns paclo.pcap
  (:import
   [jnr.ffi LibraryLoader Memory Pointer]
   [jnr.ffi.byref PointerByReference IntByReference]
   [paclo.jnr PcapLibrary PcapHeader]
   ;; ★ 追加
   [java.util.concurrent LinkedBlockingQueue TimeUnit]))

(def ^:private ^jnr.ffi.Runtime rt (jnr.ffi.Runtime/getSystemRuntime))
(def ^:private ^PcapLibrary lib
  (let [os      (.. System (getProperty "os.name") toLowerCase)
        libname (if (.contains os "win") "wpcap" "pcap")
        loader  (LibraryLoader/create PcapLibrary)]
    (.load loader libname)))

(def PCAP_ERRBUF_SIZE 256)
(def ^:private BPF_PROG_BYTES 16)

(defn open-offline ^Pointer [path]
  (let [err (Memory/allocate rt PCAP_ERRBUF_SIZE)
        pcap (.pcap_open_offline lib path err)]
    (when (nil? pcap)
      (throw (ex-info "pcap_open_offline failed"
                      {:err (.getString err 0)})))
    pcap))

(defn open-live ^Pointer [{:keys [device snaplen promiscuous? timeout-ms]
                           :or {snaplen 65536 promiscuous? true timeout-ms 10}}]
  (let [err (Memory/allocate rt PCAP_ERRBUF_SIZE)
        promisc (if promiscuous? 1 0)
        pcap (.pcap_open_live lib device snaplen promisc timeout-ms err)]
    (when (nil? pcap)
      (throw (ex-info "pcap_open_live failed" {:err (.getString err 0)})))
    pcap))

(defn close! [^Pointer pcap] (.pcap_close lib pcap))

;; -----------------------------------------------------------------------------
;; ★ 追加: pcap_lookupnet のラッパ
;; -----------------------------------------------------------------------------
(defn lookupnet
  "デバイス名 dev のネットワークアドレス/マスクを取得。
   成功: {:net int :mask int}
   失敗: ex-info（:err に libpcap のメッセージ）"
  [dev]
  (let [net-ref  (IntByReference.)
        mask-ref (IntByReference.)
        err      (Memory/allocate rt PCAP_ERRBUF_SIZE)
        rc       (.pcap_lookupnet lib dev net-ref mask-ref err)]
    (if (zero? rc)
      {:net  (.getValue net-ref)
       :mask (.getValue mask-ref)}
      (throw (ex-info "pcap_lookupnet failed"
                      {:device dev
                       :rc     rc
                       :err    (.getString err 0)})))))

(defn set-bpf! [^Pointer pcap expr]
  (let [prog (paclo.jnr.BpfProgram. rt)]
    (try
      ;; optimize=1, netmask=0（未知のときは 0 が無難）
      (let [rc-compile (.pcap_compile lib pcap (.addr prog) expr 1 0)]
        (when (neg? rc-compile)
          (throw (ex-info "pcap_compile failed"
                          {:expr expr
                           :rc rc-compile
                           :err (.pcap_geterr lib pcap)}))))
      (let [rc-set (.pcap_setfilter lib pcap (.addr prog))]
        (when (neg? rc-set)
          (throw (ex-info "pcap_setfilter failed"
                          {:expr expr
                           :rc rc-set
                           :err (.pcap_geterr lib pcap)}))))
      (finally
        ;; 成否に関わらず bf_insn を解放
        (.pcap_freecode lib (.addr prog))))))

;; -----------------------------------------------------------------------------
;; ★ 追加: 明示 netmask を使って BPF を設定する安全版（既存を壊さない）
;; -----------------------------------------------------------------------------
(defn set-bpf-with-netmask!
  "pcap ハンドルに BPF を適用。optimize=1、netmask を明示指定。
   戻り値: true（例外がなければ成功）"
  [^Pointer pcap expr netmask]
  (let [prog (paclo.jnr.BpfProgram. rt)]
    (try
      (let [rc-compile (.pcap_compile lib pcap (.addr prog) expr 1 (int netmask))]
        (when (neg? rc-compile)
          (throw (ex-info "pcap_compile failed"
                          {:expr expr
                           :netmask netmask
                           :rc rc-compile
                           :err (.pcap_geterr lib pcap)}))))
      (let [rc-set (.pcap_setfilter lib pcap (.addr prog))]
        (when (neg? rc-set)
          (throw (ex-info "pcap_setfilter failed"
                          {:expr expr
                           :netmask netmask
                           :rc rc-set
                           :err (.pcap_geterr lib pcap)}))))
      true
      (finally
        (.pcap_freecode lib (.addr prog))))))

(defn set-bpf-on-device!
  "デバイス dev の netmask を lookup して BPF を適用するショートカット。"
  [^Pointer pcap dev expr]
  (let [{:keys [mask]} (lookupnet dev)]
    (set-bpf-with-netmask! pcap expr mask)))

(defn loop!
  "pcap_next_ex をポーリング。handlerは (fn {:ts-sec :ts-usec :caplen :len :bytes}) を受け取る。
   終端: rc<0（pcap EOF/err）で終了。"
  [^Pointer pcap handler]
  (let [hdr-ref (PointerByReference.)
        dat-ref (PointerByReference.)]
    (loop []
      (let [rc (.pcap_next_ex lib pcap hdr-ref dat-ref)]
        (cond
          (= rc 1)
          (let [hdr (.getValue hdr-ref)
                dat (.getValue dat-ref)
                ts-sec (PcapHeader/tv_sec hdr)
                ts-usec (PcapHeader/tv_usec hdr)
                caplen (PcapHeader/caplen hdr)
                len    (PcapHeader/len hdr)
                arr    (byte-array (int caplen))]
            (.get dat 0 arr 0 (alength arr))
            (handler {:ts-sec ts-sec :ts-usec ts-usec
                      :caplen caplen :len len :bytes arr})
            (recur))

          (= rc 0)  ; timeout (live capture)
          (recur)

          :else     ; -1 error / -2 EOF (offline)
          rc)))))

(defn breakloop! [^Pointer pcap] (.pcap_breakloop lib pcap))

(defn open-dumper ^Pointer [^Pointer pcap path]
  (let [d (.pcap_dump_open lib pcap path)]
    (when (nil? d)
      (throw (ex-info "pcap_dump_open failed" {:path path})))
    d))

(defn dump! [^Pointer dumper ^Pointer hdr ^Pointer data]
  (.pcap_dump lib dumper hdr data))

(defn flush-dumper! [^Pointer dumper]
  (.pcap_dump_flush lib dumper))

(defn close-dumper! [^Pointer dumper]
  (.pcap_dump_close lib dumper))

(defn capture->pcap
  "ライブでキャプチャして out.pcap に保存。
   opts:
   {:device \"en0\"
    :filter \"tcp port 80\"     ; 省略可
    :max 100                    ; 取れたパケット数がこの件数に達したら終了
    :snaplen 65536
    :promiscuous? true
    :timeout-ms 10              ; pcap_next_ex のタイムアウト
    :max-time-ms 10000          ; 壁時計タイム上限（ms）
    :idle-max-ms 3000}          ; 連続アイドル上限（ms）"
  [{:keys [device filter max snaplen promiscuous? timeout-ms max-time-ms idle-max-ms]
    :or {max 100 snaplen 65536 promiscuous? true timeout-ms 10
         max-time-ms 10000 idle-max-ms 3000}}
   out]
  (let [pcap   (open-live {:device device :snaplen snaplen :promiscuous? promiscuous? :timeout-ms timeout-ms})
        dumper (open-dumper pcap out)
        hdr-ref (PointerByReference.)
        dat-ref (PointerByReference.)
        t0 (System/currentTimeMillis)]
    (try
      ;; ★ 変更点：device+filter が両方ある場合は netmask を自動適用
      (when filter
        (if (some? device)
          (set-bpf-on-device! pcap device filter)
          (set-bpf! pcap filter)))
      (loop [n 0 idle 0]
        (let [now (System/currentTimeMillis)]
          (cond
            (>= n max) n
            (>= (- now t0) max-time-ms) n
            (>= idle idle-max-ms) n
            :else
            (let [rc (.pcap_next_ex lib pcap hdr-ref dat-ref)]
              (cond
                (= rc 1)
                (do
                  (dump! dumper (.getValue hdr-ref) (.getValue dat-ref))
                  (recur (inc n) 0))
                (= rc 0) ; timeout
                (recur n (+ idle timeout-ms))
                :else    ; -1 err / -2 EOF
                n)))))
      (finally
        (flush-dumper! dumper)
        (close-dumper! dumper)
        (close! pcap)))))

;; macOS だけ networksetup から “人間が読める名称” を補完
(defn- macos-device->desc []
  (let [os (.. System (getProperty "os.name") toLowerCase)]
    (if (not (.contains os "mac"))
      {}
      (let [pb   (java.lang.ProcessBuilder.
                  (into-array String ["networksetup" "-listallhardwareports"]))
            _    (.redirectErrorStream pb true)   ;; ← Redirect 定数は使わない
            proc (.start pb)
            rdr  (java.io.BufferedReader.
                  (java.io.InputStreamReader. (.getInputStream proc)))]
        (try
          (loop [m {}
                 cur-port nil
                 line (.readLine rdr)]
            (if (nil? line)
              m
              (cond
                (.startsWith line "Hardware Port: ")
                (recur m (subs line 14) (.readLine rdr))

                (.startsWith line "Device: ")
                (let [dev (subs line 8)]
                  (recur (assoc m dev cur-port) cur-port (.readLine rdr)))

                :else
                (recur m cur-port (.readLine rdr)))))
          (finally
            (.close rdr)
            (.waitFor proc)))))))

(defn list-devices
  "利用可能デバイスの簡易一覧。macOSでは networksetup で desc を補完する。"
  []
  (let [err (Memory/allocate rt PCAP_ERRBUF_SIZE)
        pp  (PointerByReference.)]
    (when (neg? (.pcap_findalldevs lib pp err))
      (throw (ex-info "pcap_findalldevs failed" {:err (.getString err 0)})))
    (let [head (.getValue pp)
          fallback (macos-device->desc)]
      (try
        (loop [p head, acc (transient [])]
          (if (or (nil? p) (= 0 (.address p)))
            (persistent! acc)
            (let [ifc (paclo.jnr.PcapLibrary$PcapIf. rt)]
              (.useMemory ifc p)
              (let [name-ptr (.get (.-name ifc))
                    desc-ptr (.get (.-desc ifc))
                    next-ptr (.get (.-next ifc))
                    name     (when (and name-ptr (not= 0 (.address name-ptr)))
                               (.getString name-ptr 0))
                    desc     (or (when (and desc-ptr (not= 0 (.address desc-ptr)))
                                   (.getString desc-ptr 0))
                                 (get fallback name))]
                (recur next-ptr (conj! acc {:name name :desc desc}))))))
        (finally
          (.pcap_freealldevs lib head))))))

;; --- handler 正規化（0引数でも受け付ける） -------------------------------
(defn- ->pkt-handler
  "渡された handler を『1引数を取る関数』に正規化する。
   - 1引数関数ならそのまま呼ぶ
   - 0引数関数なら ArityException を捕まえて fallback で呼ぶ
   - nil は no-op"
  [handler]
  (cond
    (nil? handler)
    (fn [_] nil)

    :else
    (fn [pkt]
      (try
        (handler pkt)                     ;; 1引数として呼ぶ
        (catch clojure.lang.ArityException _
          (handler))))))                  ;; 0引数で呼ぶ


;; -----------------------------------------
;; REPL用：小回りヘルパ（件数/時間/idleで停止）
;; -----------------------------------------
;; NOTE:
;; - :idle-max-ms を与えた場合のみ idle 監視を有効化。
;; - その場合、:timeout-ms（open-liveに渡した値）も渡すと精度が上がる。
;;   未指定なら 100ms を仮定して idle を積算します。

(defn loop-n!
  "pcap_next_ex を最大 n 件処理して停止。
   オプション: {:idle-max-ms <ms> :timeout-ms <ms>}
   例: (loop-n! h 10 handler) ; 従来どおり
       (loop-n! h 10 handler {:idle-max-ms 3000 :timeout-ms 100})"
    ([^Pointer pcap ^long n handler]
    (assert (pos? n) "n must be positive")
    (let [c (atom 0)
          handle (->pkt-handler handler)]
      (loop! pcap (fn [pkt]
                    (handle pkt)
                    (when (>= (swap! c inc) n)
                      (breakloop! pcap))))))
   ([^Pointer pcap ^long n handler {:keys [idle-max-ms timeout-ms]}]
    (if (nil? idle-max-ms)
      (loop-n! pcap n handler)
      (do
        (assert (pos? n) "n must be positive")
        (let [hdr-ref (PointerByReference.)
              dat-ref (PointerByReference.)
              idle-ms-target (long idle-max-ms)
              tick (long (or timeout-ms 100))
              handle (->pkt-handler handler)]
          (loop [count 0 idle 0]
            (when (< count n)
              (let [rc (.pcap_next_ex lib pcap hdr-ref dat-ref)]
                (cond
                  (= rc 1)
                  (let [hdr (.getValue hdr-ref)
                        dat (.getValue dat-ref)
                        ts-sec (PcapHeader/tv_sec hdr)
                        ts-usec (PcapHeader/tv_usec hdr)
                        caplen (PcapHeader/caplen hdr)
                        len    (PcapHeader/len hdr)
                        arr    (byte-array (int caplen))]
                    (.get dat 0 arr 0 (alength arr))
                    (handle {:ts-sec ts-sec :ts-usec ts-usec
                             :caplen caplen :len len :bytes arr})
                    (recur (inc count) 0))
  
                  (= rc 0)
                  (let [idle' (+ idle tick)]
                    (if (>= idle' idle-ms-target)
                      (breakloop! pcap)
                      (recur count idle')))
  
                  :else
                  (breakloop! pcap))))))))))


(defn loop-for-ms!
  "開始から duration-ms 経過したら停止（壁時計基準）。
   オプション: {:idle-max-ms <ms> :timeout-ms <ms>}
   例: (loop-for-ms! h 3000 handler)
       (loop-for-ms! h 3000 handler {:idle-max-ms 1000 :timeout-ms 50})"
    ([^Pointer pcap ^long duration-ms handler]
    (assert (pos? duration-ms) "duration-ms must be positive")
    (let [t0 (System/currentTimeMillis)
          handle (->pkt-handler handler)]
      (loop! pcap (fn [pkt]
                    (handle pkt)
                    (when (>= (- (System/currentTimeMillis) t0) duration-ms)
                      (breakloop! pcap))))))
   ([^Pointer pcap ^long duration-ms handler {:keys [idle-max-ms timeout-ms]}]
    (if (nil? idle-max-ms)
      (loop-for-ms! pcap duration-ms handler)
      (do
        (assert (pos? duration-ms) "duration-ms must be positive")
        (let [hdr-ref (PointerByReference.)
              dat-ref (PointerByReference.)
              t0 (System/currentTimeMillis)
              deadline (+ t0 (long duration-ms))
              idle-ms-target (long idle-max-ms)
              tick (long (or timeout-ms 100))
              handle (->pkt-handler handler)]
          (loop [idle 0]
            (when (< (System/currentTimeMillis) deadline)
              (let [rc (.pcap_next_ex lib pcap hdr-ref dat-ref)]
                (cond
                  (= rc 1)
                  (let [hdr (.getValue hdr-ref)
                        dat (.getValue dat-ref)
                        ts-sec (PcapHeader/tv_sec hdr)
                        ts-usec (PcapHeader/tv_usec hdr)
                        caplen (PcapHeader/caplen hdr)
                        len    (PcapHeader/len hdr)
                        arr    (byte-array (int caplen))]
                    (.get dat 0 arr 0 (alength arr))
                    (handle {:ts-sec ts-sec :ts-usec ts-usec
                             :caplen caplen :len len :bytes arr})
                    (recur 0))
  
                  (= rc 0)
                  (let [idle' (+ idle tick)]
                    (if (>= idle' idle-ms-target)
                      (breakloop! pcap)
                      (recur idle')))
  
                  :else
                  (breakloop! pcap))))))))))


(defn loop-n-or-ms!
  "n件到達 or duration-ms 経過の早い方で停止。
   conf: {:n <long> :ms <long> :idle-max-ms <ms-optional> :timeout-ms <ms-optional>}"
  [^Pointer pcap {:keys [n ms idle-max-ms timeout-ms] :as conf} handler]
  (when (nil? n) (throw (ex-info "missing :n" {})))
  (when (nil? ms) (throw (ex-info "missing :ms" {})))
  (assert (pos? n) "n must be positive")
  (assert (pos? ms) "ms must be positive")
  (let [handle (->pkt-handler handler)]
    (if (nil? idle-max-ms)
      (let [c  (atom 0)
            t0 (System/currentTimeMillis)]
        (loop! pcap (fn [pkt]
                      (handle pkt)
                      (let [stop-n? (>= (swap! c inc) n)
                            stop-t? (>= (- (System/currentTimeMillis) t0) ms)]
                        (when (or stop-n? stop-t?)
                          (breakloop! pcap))))))
      (let [hdr-ref (PointerByReference.)
            dat-ref (PointerByReference.)
            t0 (System/currentTimeMillis)
            deadline (+ t0 (long ms))
            tick (long (or timeout-ms 100))
            idle-target (long idle-max-ms)]
        (loop [count 0 idle 0]
          (when (and (< count n)
                     (< (System/currentTimeMillis) deadline))
            (let [rc (.pcap_next_ex lib pcap hdr-ref dat-ref)]
              (cond
                (= rc 1)
                (let [hdr (.getValue hdr-ref)
                      dat (.getValue dat-ref)
                      ts-sec (PcapHeader/tv_sec hdr)
                      ts-usec (PcapHeader/tv_usec hdr)
                      caplen (PcapHeader/caplen hdr)
                      len    (PcapHeader/len hdr)
                      arr    (byte-array (int caplen))]
                  (.get dat 0 arr 0 (alength arr))
                  (handle {:ts-sec ts-sec :ts-usec ts-usec
                           :caplen caplen :len len :bytes arr})
                  (recur (inc count) 0))

                (= rc 0)
                (let [idle' (+ idle tick)]
                  (if (>= idle' idle-target)
                    (breakloop! pcap)
                    (recur count idle')))

                :else
                (breakloop! pcap)))))))))



;; -----------------------------------------
;; REPL用：ワンショット実験（open→filter→loop→close）
;; -----------------------------------------

(defn run-live-n!
  "デバイスを開いて、必要ならBPFを設定して、n件だけ処理して閉じる。
   追加オプション: :idle-max-ms （:timeout-ms は open-live と共有）
   例: (run-live-n! {:device \"en1\" :filter \"tcp\" :timeout-ms 100}
                    50
                    handler
                    {:idle-max-ms 3000})"
  ([opts ^long n handler]
   (run-live-n! opts n handler {}))
  ([{:keys [device filter snaplen promiscuous? timeout-ms]
     :or {snaplen 65536 promiscuous? true timeout-ms 10}}
    ^long n
    handler
    {:keys [idle-max-ms] :as loop-opts}]
   (let [h (open-live {:device device :snaplen snaplen :promiscuous? promiscuous? :timeout-ms timeout-ms})]
     (try
       (when filter
         (if device (set-bpf-on-device! h device filter)
                    (set-bpf! h filter)))
       (if idle-max-ms
         (loop-n! h n handler {:idle-max-ms idle-max-ms :timeout-ms timeout-ms})
         (loop-n! h n handler))
       (finally (close! h))))))

(defn run-live-for-ms!
  "デバイスを開いて、必要ならBPFを設定して、duration-msだけ処理して閉じる。
   追加オプション: {:idle-max-ms <ms>}
   例: (run-live-for-ms! {:device \"en1\" :timeout-ms 50}
                         5000
                         handler
                         {:idle-max-ms 1000})"
  ([opts ^long duration-ms handler]
   (run-live-for-ms! opts duration-ms handler {}))
  ([{:keys [device filter snaplen promiscuous? timeout-ms]
     :or {snaplen 65536 promiscuous? true timeout-ms 10}}
    ^long duration-ms
    handler
    {:keys [idle-max-ms] :as loop-opts}]
   (let [h (open-live {:device device :snaplen snaplen :promiscuous? promiscuous? :timeout-ms timeout-ms})]
     (try
       (when filter
         (if device (set-bpf-on-device! h device filter)
                    (set-bpf! h filter)))
       (if idle-max-ms
         (loop-for-ms! h duration-ms handler {:idle-max-ms idle-max-ms :timeout-ms timeout-ms})
         (loop-for-ms! h duration-ms handler))
       (finally (close! h))))))


;; -----------------------------------------
;; 高レベルAPI：capture->seq
;; - ライブ/オフライン両対応
;; - デフォルトで安全に手仕舞い（:max/:max-time-ms/:idle-max-ms）
;; - バックグラウンドでキャプチャし、lazy-seq で取り出し
;; -----------------------------------------

(def ^:private ^:const default-max 100)
(def ^:private ^:const default-max-time-ms 10000)
(def ^:private ^:const default-idle-max-ms 3000)
(def ^:private ^:const default-queue-cap 1024)

(defn capture->seq
  "パケットを lazy-seq で返す高レベルAPI。
   opts:
   - ライブ:  {:device \"en1\" :filter \"tcp\" :snaplen 65536 :promiscuous? true :timeout-ms 10}
   - オフライン: {:path \"sample.pcap\" :filter \"...\"}  ; filterはオフラインでも使用可
   - 共有停止条件（指定なければ安全な既定値で自動手仕舞い）:
       :max <int>               ; 取得最大件数（default 100）
       :max-time-ms <int>       ; 経過時間上限（default 10000）
       :idle-max-ms <int>       ; 無通信連続上限（default 3000）
   - 内部キュー:
       :queue-cap <int>         ; バックグラウンド→呼び出し側のバッファ（default 1024）

   返り値: lazy-seq of packet-maps （loop! ハンドラで渡している {:ts-sec … :bytes …}）"
  [{:keys [device path filter snaplen promiscuous? timeout-ms
           max max-time-ms idle-max-ms queue-cap]
    :or   {snaplen 65536 promiscuous? true timeout-ms 10}}]
  (let [max         (or max default-max)
        max-time-ms (or max-time-ms default-max-time-ms)
        idle-max-ms (or idle-max-ms default-idle-max-ms)
        cap         (int (or queue-cap default-queue-cap))
        q           (LinkedBlockingQueue. cap)
        sentinel    ::end-of-capture
        ;; open
        h (if device
            (open-live {:device device :snaplen snaplen :promiscuous? promiscuous? :timeout-ms timeout-ms})
            (open-offline path))]
    ;; バックグラウンドでキャプチャしてキューに流す
    (future
      (try
        (when filter
          (if device
            (set-bpf-on-device! h device filter)
            (set-bpf! h filter)))
        ;; 取得条件の組合せ：:max と :max-time-ms を併用し、無通信でも終わる
        (loop-n-or-ms! h {:n max :ms max-time-ms :idle-max-ms idle-max-ms :timeout-ms timeout-ms}
          (fn [pkt]
            ;; キュー満杯なら待つ（キャンセル時は take されないと詰まる想定だが
            ;; デフォルト上限と既定の停止条件でリスクは低い）
            (.put q pkt)))
        (finally
          ;; キャプチャ終了通知とクローズ
          (.put q sentinel)
          (close! h))))
    ;; lazy-seq を返す
    (letfn [(drain []
              (lazy-seq
                (let [x (.take q)]
                  (if (identical? x sentinel)
                    ;; sentinelは消費。以降は空のseq
                    '()
                    (cons x (drain))))))]
      (drain))))
```

### src/paclo/dev.clj
```clojure
(ns paclo.dev
  "REPLでの即席デバッグ/実験ヘルパ。
   - (parse-hex s)       ; 16進文字列→パケットmap
   - (summarize pktmap)  ; 要約表示
   - (hexd pktmap)       ; :bytes を16進で表示（L2生データ）

   例:
   (-> HBH-OK parse-hex summarize)
   (-> HBH-BAD parse-hex summarize)"
  (:require [clojure.string :as str]
            [paclo.parse :as parse])
  (:import [java.util Formatter]))

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
  (let [{:keys [type l3]} pkt
        l3t (:type l3)
        proto (or (:protocol l3) (:next-header l3))
        l4 (:l4 l3)]
    (println "L2:" type)
    (when (= :ethernet type)
      (println "  src/dst:" (:src pkt) "->" (:dst pkt) "eth" (format "0x%04X" (:eth pkt))))
    (println "L3:" l3t)
    (case l3t
      :ipv4 (println "  proto" proto "src" (:src l3) "dst" (:dst l3))
      :ipv6 (println "  nh" proto "src" (:src l3) "dst" (:dst l3)
                     (when (:frag? l3) (str "frag@" (:frag-offset l3))))
      :arp  (println "  op" (:op l3) "spa" (:spa l3) "tpa" (:tpa l3))
      nil)
    (println "L4:" (:type l4)
             (cond
               (= :udp (:type l4)) (str (:src-port l4) "->" (:dst-port l4) " len=" (:data-len l4))
               (= :tcp (:type l4)) (str (:src-port l4) "->" (:dst-port l4) " len=" (:data-len l4))
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
```

### src-java/paclo/jnr/PcapLibrary.java
```java
package paclo.jnr;

import jnr.ffi.Pointer;
import jnr.ffi.byref.PointerByReference;
import jnr.ffi.byref.IntByReference;

public interface PcapLibrary {
  // open/close
  Pointer pcap_open_offline(String fname, Pointer errbuf);
  Pointer pcap_open_live(String device, int snaplen, int promisc, int to_ms, Pointer errbuf);
  void    pcap_close(Pointer pcap);

  // poll (no callback)
  int     pcap_next_ex(Pointer pcap, PointerByReference headerRef, PointerByReference dataRef);

  // control
  void    pcap_breakloop(Pointer pcap);

  // BPF
  int     pcap_compile(Pointer pcap, Pointer bpfProgram, String expr, int optimize, int netmask);
  int     pcap_setfilter(Pointer pcap, Pointer bpfProgram);
  void    pcap_freecode(Pointer bpfProgram);

  // misc
  String  pcap_lib_version();

  // 追加: dumper（pcap_dump_*）
  Pointer pcap_dump_open(Pointer pcap, String fname);
  void    pcap_dump(Pointer dumper, Pointer hdr, Pointer data);
  void    pcap_dump_flush(Pointer dumper);
  void    pcap_dump_close(Pointer dumper);

  String pcap_geterr(Pointer pcap);

  // 構造体ヘルパー（最小限）
  public static final class PcapIf extends jnr.ffi.Struct {
    public final jnr.ffi.Struct.Pointer  next = new jnr.ffi.Struct.Pointer();
    public final jnr.ffi.Struct.Pointer  name = new jnr.ffi.Struct.Pointer();
    public final jnr.ffi.Struct.Pointer  desc = new jnr.ffi.Struct.Pointer();
    public PcapIf(jnr.ffi.Runtime r) { super(r); }
  }

  int     pcap_findalldevs(jnr.ffi.byref.PointerByReference alldevs, jnr.ffi.Pointer errbuf);
  void    pcap_freealldevs(jnr.ffi.Pointer alldevs);

  int     pcap_lookupnet(String device, IntByReference netp, IntByReference maskp, Pointer errbuf);
}
```

### test/paclo/parse_test.clj
```clojure
(ns paclo.parse-test
  (:require [clojure.test :refer :all]
            [paclo.parse :as parse]
            [paclo.test-util :as tu]))

;; 1) IPv4/TCP（payload="hello"）
(deftest ipv4-tcp-min-test
  (let [pkt (tu/hex->bytes
              "00 11 22 33 44 55 66 77 88 99 AA BB 08 00
               45 00 00 2D 00 01 40 00 40 06 00 00
               0A 00 00 01 0A 00 00 02
               30 39 00 50 00 00 00 00 00 00 00 00 50 18 00 20 00 00 00 00
               68 65 6C 6C 6F")
        m (parse/packet->clj pkt)]
    (is (= :ethernet (:type m)))
    (is (= :ipv4 (get-in m [:l3 :type])))
    (is (= 6 (get-in m [:l3 :protocol])))
    (is (= :tcp (get-in m [:l3 :l4 :type])))
    (is (= 5 (get-in m [:l3 :l4 :data-len])))))

;; 2) IPv4/UDP + 最小DNSヘッダ（16B）
(deftest ipv4-udp-dns-min-test
  (let [pkt (tu/hex->bytes
              "FF FF FF FF FF FF 00 00 00 00 00 01 08 00
               45 00 00 30 00 02 00 00 40 11 00 00
               C0 A8 01 64 08 08 08 08
               13 88 00 35 00 18 00 00
               00 3B 01 00 00 01 00 00 00 00 00 00 00 00 00 00")
        m (parse/packet->clj pkt)]
    (is (= :ipv4 (get-in m [:l3 :type])))
    (is (= :udp  (get-in m [:l3 :l4 :type])))
    (is (= :dns  (get-in m [:l3 :l4 :app :type])))
    (is (= 59    (get-in m [:l3 :l4 :app :id])))
    (is (= 1     (get-in m [:l3 :l4 :app :qdcount])))))

;; 3) ARP request（IPv4）
(deftest arp-request-test
  (let [pkt (tu/hex->bytes
              "FF FF FF FF FF FF 00 11 22 33 44 55 08 06
               00 01 08 00 06 04 00 01
               00 11 22 33 44 55 C0 A8 01 64
               66 77 88 99 AA BB C0 A8 01 01")
        m (parse/packet->clj pkt)]
    (is (= :arp (get-in m [:l3 :type])))
    (is (= :request (get-in m [:l3 :op])))
    (is (= "192.168.1.100" (get-in m [:l3 :spa])))
    (is (= "192.168.1.1"   (get-in m [:l3 :tpa])))))

;; 4) IPv6/UDP（payload=4B）
(deftest ipv6-udp-min-test
  (let [pkt (tu/hex->bytes
              "00 11 22 33 44 55 66 77 88 99 AA BB 86 DD
               60 00 00 00 00 0C 11 40
               20 01 0D B8 00 00 00 00 00 00 00 00 00 00 00 01
               20 01 0D B8 00 00 00 00 00 00 00 00 00 00 00 02
               12 34 56 78 00 0C 00 00
               DE AD BE EF")
        m (parse/packet->clj pkt)]
    (is (= :ipv6 (get-in m [:l3 :type])))
    (is (= :udp  (get-in m [:l3 :l4 :type])))
    (is (= 4     (get-in m [:l3 :l4 :data-len])))))

;; 5) IPv6 Hop-by-Hop → UDP へ到達できるか（PL=24, HBH=16, UDP=8）
(deftest ipv6-hbh-udp-test
  (let [pkt (tu/hex->bytes
              "00 11 22 33 44 55 66 77 88 99 AA BB 86 DD
               60 00 00 00 00 18 00 40
               20 01 0D B8 00 00 00 00 00 00 00 00 00 00 00 01
               20 01 0D B8 00 00 00 00 00 00 00 00 00 00 00 02
               11 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00
               12 34 56 78 00 08 00 00")
        m (parse/packet->clj pkt)]
    (is (= :ipv6 (get-in m [:l3 :type])))
    (is (= :udp  (get-in m [:l3 :l4 :type])))))

;; 6) IPv6 Fragment (offset>0) は L4を解さず :ipv6-fragment で返す
(deftest ipv6-frag-nonfirst-test
  (let [pkt (tu/hex->bytes
              "00 11 22 33 44 55 66 77 88 99 AA BB 86 DD
               60 00 00 00 00 08 2C 40
               20 01 0D B8 00 00 00 00 00 00 00 00 00 00 00 01
               20 01 0D B8 00 00 00 00 00 00 00 00 00 00 00 02
               06 00 00 08 12 34 56 78")
        m (parse/packet->clj pkt)]
    (is (= :ipv6 (get-in m [:l3 :type])))
    (is (= true  (get-in m [:l3 :frag?])))
    (is (= :ipv6-fragment (get-in m [:l3 :l4 :type])))))

;; HBH: PadN(12B)でオプション領域14Bを“ちょうど”埋めてUDPに到達
(deftest ipv6-hbh-udp-padn-exact-test
  (let [pkt (tu/hex->bytes
              "00 11 22 33 44 55 66 77 88 99 AA BB 86 DD
               60 00 00 00 00 18 00 40
               20 01 0D B8 00 00 00 00 00 00 00 00 00 00 00 01
               20 01 0D B8 00 00 00 00 00 00 00 00 00 00 00 02
               11 01 01 0C
               00 00 00 00 00 00 00 00 00 00 00 00
               12 34 56 78 00 08 00 00")
        m (parse/packet->clj pkt)]
    (is (= :udp (get-in m [:l3 :l4 :type])))))

;; HBH: TLV過走（lenが残りを超える）→ 安全に上位へ進まず unknown-l4
(deftest ipv6-hbh-bad-tlv-overrun-test
  (let [pkt (tu/hex->bytes
              "00 11 22 33 44 55 66 77 88 99 AA BB 86 DD
               60 00 00 00 00 18 00 40
               20 01 0D B8 00 00 00 00 00 00 00 00 00 00 00 01
               20 01 0D B8 00 00 00 00 00 00 00 00 00 00 00 02
               11 01 01 0D
               00 00 00 00 00 00 00 00 00 00 00 00
               12 34 56 78 00 08 00 00")
        m (parse/packet->clj pkt)]
    (is (= :unknown-l4 (get-in m [:l3 :l4 :type])))))

;; DestOpt: PadN(12B)でオプション領域14Bを“ちょうど”埋め、UDPに到達
(deftest ipv6-destopt-udp-padn-exact-test
  (let [pkt (tu/hex->bytes
              "00 11 22 33 44 55 66 77 88 99 AA BB 86 DD
               60 00 00 00 00 18 3C 40
               20 01 0D B8 00 00 00 00 00 00 00 00 00 00 00 01
               20 01 0D B8 00 00 00 00 00 00 00 00 00 00 00 02
               11 01 01 0C
               00 00 00 00 00 00 00 00 00 00 00 00
               12 34 56 78 00 08 00 00")
        m (parse/packet->clj pkt)]
    (is (= :udp (get-in m [:l3 :l4 :type])))))

;; DestOpt: TLV過走（lenが残りを超える）→ 安全に上位へ進まず unknown-l4
(deftest ipv6-destopt-bad-tlv-overrun-test
  (let [pkt (tu/hex->bytes
              "00 11 22 33 44 55 66 77 88 99 AA BB 86 DD
               60 00 00 00 00 18 3C 40
               20 01 0D B8 00 00 00 00 00 00 00 00 00 00 00 01
               20 01 0D B8 00 00 00 00 00 00 00 00 00 00 00 02
               11 01 01 0D
               00 00 00 00 00 00 00 00 00 00 00 00
               12 34 56 78 00 08 00 00")
        m (parse/packet->clj pkt)]
    (is (= :unknown-l4 (get-in m [:l3 :l4 :type])))))

;; 先頭フラグメント(offset=0, M=1) + UDP(8B) → L4は正しくUDPに到達しつつ fragフラグは立つ
(deftest ipv6-frag-first-udp-test
  (let [pkt (tu/hex->bytes
              "00 11 22 33 44 55 66 77 88 99 AA BB 86 DD
               60 00 00 00 00 10 2C 40
               20 01 0D B8 00 00 00 00 00 00 00 00 00 00 00 01
               20 01 0D B8 00 00 00 00 00 00 00 00 00 00 00 02
               11 00 00 01 12 34 56 78       ; Fragment: NH=UDP(17), res=0, offfl=(offset=0,M=1)->0x0001
               12 34 56 78 00 08 00 00")     ; UDP: src=0x1234, dst=0x5678, len=8, csum=0
        m (parse/packet->clj pkt)]
    (is (= :ipv6 (get-in m [:l3 :type])))
    (is (= true  (get-in m [:l3 :frag?])))
    (is (= 0     (get-in m [:l3 :frag-offset])))
    (is (= :udp  (get-in m [:l3 :l4 :type])))))

;; フラグメントヘッダが8B未満で途切れ → 上位に進まず :unknown-l4
(deftest ipv6-frag-header-truncated-test
  (let [pkt (tu/hex->bytes
              "00 11 22 33 44 55 66 77 88 99 AA BB 86 DD
               60 00 00 00 00 07 2C 40
               20 01 0D B8 00 00 00 00 00 00 00 00 00 00 00 01
               20 01 0D B8 00 00 00 00 00 00 00 00 00 00 00 02
               11 00 00 00 00 00 00")          ; ← Fragmentヘッダを7Bで途切らせる
        m (parse/packet->clj pkt)]
    (is (= :ipv6 (get-in m [:l3 :type])))
    (is (= :unknown-l4 (get-in m [:l3 :l4 :type])))))
```

### test/paclo/test_util.clj
```clojure
(ns paclo.test-util
  (:require [clojure.string :as str]))

(defn hex->bytes ^bytes [^String s]
  (let [no-line-comments (str/replace s #"(?m);.*$" "")     ;; 行内 ;コメントを削除
        no-block-comments (str/replace no-line-comments #"(?s)/\*.*?\*/" "") ;; /* ... */ も一応対応
        cleaned (-> no-block-comments
                    str/lower-case
                    (str/replace #"[^0-9a-f]" ""))]         ;; 16進以外は全部削除
    (when (odd? (count cleaned))
      (throw (ex-info "Odd number of hex digits" {:len (count cleaned)})))
    (byte-array
     (map (fn [[a b]]
            (unchecked-byte (Integer/parseInt (str a b) 16)))
          (partition 2 cleaned)))))
```

