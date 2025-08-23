(ns paclo.parse-test
  (:require
   [clojure.test :refer :all]
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

;; DNS flags: Query (QR=0, RD=1)
(deftest ipv4-udp-dns-flags-query-test
  (let [pkt (tu/hex->bytes
             "FF FF FF FF FF FF 00 00 00 00 00 01 08 00
               45 00 00 30 00 02 00 00 40 11 00 00
               C0 A8 01 64 08 08 08 08
               13 88 00 35 00 18 00 00
               00 3B 01 00 00 01 00 00 00 00 00 00 00 00 00 00")
        m (parse/packet->clj pkt)
        flags (get-in m [:l3 :l4 :app :flags])]
    (is (= :dns  (get-in m [:l3 :l4 :app :type])))
    (is (= false (:qr flags)))
    (is (= 0     (:opcode flags)))
    (is (= true  (:rd flags)))
    (is (= false (:ra flags)))
    (is (= 0     (:rcode flags)))))

;; DNS flags: Response NXDOMAIN (QR=1, RD=1, RA=1, RCODE=3)
(deftest ipv4-udp-dns-flags-response-nxdomain-test
  (let [pkt (tu/hex->bytes
             "FF FF FF FF FF FF 00 00 00 00 00 01 08 00
               45 00 00 30 00 02 00 00 40 11 00 00
               C0 A8 01 64 08 08 08 08
               13 88 00 35 00 18 00 00
               00 2A 81 83 00 01 00 00 00 00 00 00 00 00 00 00")
        m (parse/packet->clj pkt)
        flags (get-in m [:l3 :l4 :app :flags])]
    (is (= :dns  (get-in m [:l3 :l4 :app :type])))
    (is (= true  (:qr flags)))
    (is (= 0     (:opcode flags)))
    (is (= true  (:rd flags)))
    (is (= true  (:ra flags)))
    (is (= 3     (:rcode flags)))))

;; IPv6/UDP で flow-key が :udp とポートを含む
(deftest ipv6-udp-flow-key-test
  (let [pkt (tu/hex->bytes
             "00 11 22 33 44 55 66 77 88 99 AA BB 86 DD
               60 00 00 00 00 0C 11 40
               20 01 0D B8 00 00 00 00 00 00 00 00 00 00 00 01
               20 01 0D B8 00 00 00 00 00 00 00 00 00 00 00 02
               12 34 56 78 00 0C 00 00
               DE AD BE EF")
        m (parse/packet->clj pkt)
        fk (get-in m [:l3 :flow-key])]
    (is (= :udp (:proto fk)))
    (is (= "2001:db8:0:0:0:0:0:1" (:src-ip fk)))
    (is (= "2001:db8:0:0:0:0:0:2" (:dst-ip fk)))
    (is (= 4660 (:src-port fk)))
    (is (= 22136 (:dst-port fk)))))

;; 非先頭フラグメント（L4ヘッダ無し）でも proto は載る（ここでは TCP）
(deftest ipv6-frag-nonfirst-flow-key-test
  (let [pkt (tu/hex->bytes
             "00 11 22 33 44 55 66 77 88 99 AA BB 86 DD
               60 00 00 00 00 08 2C 40
               20 01 0D B8 00 00 00 00 00 00 00 00 00 00 00 01
               20 01 0D B8 00 00 00 00 00 00 00 00 00 00 00 02
               06 00 00 08 12 34 56 78")
        m (parse/packet->clj pkt)
        fk (get-in m [:l3 :flow-key])]
    (is (= :tcp (:proto fk)))
    (is (= "2001:db8:0:0:0:0:0:1" (:src-ip fk)))
    (is (= "2001:db8:0:0:0:0:0:2" (:dst-ip fk)))
    ;; ポートは無い（nil）ことを確認
    (is (nil? (:src-port fk)))
    (is (nil? (:dst-port fk)))))

;; IPv6 圧縮表記（ゼロ連続を :: に）
(deftest ipv6-addr-compact-basic-test
  (let [pkt (tu/hex->bytes
             "00 11 22 33 44 55 66 77 88 99 AA BB 86 DD
               60 00 00 00 00 0C 11 40
               20 01 0D B8 00 00 00 00 00 00 00 00 00 00 00 01
               20 01 0D B8 00 00 00 00 00 00 00 00 00 00 00 02
               12 34 56 78 00 0C 00 00
               DE AD BE EF")
        m (parse/packet->clj pkt)]
    ;; 既存の非圧縮は維持
    (is (= "2001:db8:0:0:0:0:0:1" (get-in m [:l3 :src])))
    (is (= "2001:db8:0:0:0:0:0:2" (get-in m [:l3 :dst])))
    ;; 新フィールドは圧縮
    (is (= "2001:db8::1" (get-in m [:l3 :src-compact])))
    (is (= "2001:db8::2" (get-in m [:l3 :dst-compact])))))

;; 全ゼロは :: になる
(deftest ipv6-addr-compact-all-zero-test
  (let [pkt (tu/hex->bytes
             "00 11 22 33 44 55 66 77 88 99 AA BB 86 DD
               60 00 00 00 00 08 11 40
               00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
               00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
               12 34 56 78 00 08 00 00")
        m (parse/packet->clj pkt)]
    (is (= "::" (get-in m [:l3 :src-compact])))
    (is (= "::" (get-in m [:l3 :dst-compact])))))

;; 802.1Q (0x8100) 単一タグ → IPv4 に到達し、:vlan-tags を付与
(deftest ipv4-udp-vlan-single-test
  (let [pkt (tu/hex->bytes
             "FF FF FF FF FF FF 00 00 00 00 00 01 81 00 00 64 08 00
               45 00 00 30 00 02 00 00 40 11 00 00
               C0 A8 01 64 08 08 08 08
               13 88 00 35 00 18 00 00
               00 3B 01 00 00 01 00 00 00 00 00 00 00 00 00 00")
        m (parse/packet->clj pkt)
        tag (first (:vlan-tags m))]
    (is (= :ipv4 (get-in m [:l3 :type])))
    (is (= 0x8100 (:tpid tag)))
    (is (= 100   (:vid tag)))
    (is (= 0     (:pcp tag)))
    (is (= false (:dei tag)))
    (is (= :dns  (get-in m [:l3 :l4 :app :type])))))

;; QinQ: 802.1ad(0x88A8, VID=200) の下に 802.1Q(0x8100, VID=100) → IPv6/UDP 到達
(deftest ipv6-udp-vlan-qinq-test
  (let [pkt (tu/hex->bytes
             "00 11 22 33 44 55 66 77 88 99 AA BB 88 A8 00 C8 81 00 00 64 86 DD
               60 00 00 00 00 0C 11 40
               20 01 0D B8 00 00 00 00 00 00 00 00 00 00 00 01
               20 01 0D B8 00 00 00 00 00 00 00 00 00 00 00 02
               12 34 56 78 00 0C 00 00
               DE AD BE EF")
        m (parse/packet->clj pkt)
        tags (:vlan-tags m)]
    (is (= :ipv6 (get-in m [:l3 :type])))
    (is (= 2 (count tags)))
    (is (= 0x88A8 (:tpid (first tags))))
    (is (= 200   (:vid  (first tags))))
    (is (= 0x8100 (:tpid (second tags))))
    (is (= 100    (:vid  (second tags))))
    (is (= :udp (get-in m [:l3 :l4 :type])))
    (is (= 4     (get-in m [:l3 :l4 :data-len])))))

;; TCP flags の短縮表記: 既存のIPv4/TCP最小テストは ACK+PSH（0x18） → "AP"
(deftest ipv4-tcp-flags-ap-test
  (let [pkt (tu/hex->bytes
             "00 11 22 33 44 55 66 77 88 99 AA BB 08 00
               45 00 00 28 00 01 40 00 40 06 00 00
               0A 00 00 01 0A 00 00 02
               30 39 00 50 00 00 00 00 00 00 00 00 50 18 00 20 00 00 00 00")
        m (parse/packet->clj pkt)]
    (is (= :tcp (get-in m [:l3 :l4 :type])))
    (is (= "AP" (get-in m [:l3 :l4 :flags-str])))))

;; TCP flags: SYNのみ（0x02）→ "S"
(deftest ipv4-tcp-flags-syn-test
  (let [pkt (tu/hex->bytes
             "00 11 22 33 44 55 66 77 88 99 AA BB 08 00
               45 00 00 28 00 01 40 00 40 06 00 00
               0A 00 00 01 0A 00 00 02
               30 39 00 50 00 00 00 00 00 00 00 00 50 02 00 20 00 00 00 00")
        m (parse/packet->clj pkt)]
    (is (= :tcp (get-in m [:l3 :l4 :type])))
    (is (= "S" (get-in m [:l3 :l4 :flags-str])))))

;; ICMPv4 Echo Request → type-name/summary を確認
(deftest ipv4-icmp-echo-request-flags-test
  (let [pkt (tu/hex->bytes
             "FF FF FF FF FF FF 00 11 22 33 44 55 08 00
               45 00 00 1C 00 01 00 00 40 01 00 00
               0A 00 00 01 0A 00 00 02
               08 00 00 00 00 00 00 00")
        m (parse/packet->clj pkt)
        l4 (get-in m [:l3 :l4])]
    (is (= :icmpv4 (:type l4)))
    (is (= "echo-request" (:type-name l4)))
    (is (= "echo-request" (:summary l4)))))

;; ICMPv6 Time Exceeded (code=0=hop-limit-exceeded) → type/code-name/summary を確認
(deftest ipv6-icmp6-time-exceeded-test
  (let [pkt (tu/hex->bytes
             "00 11 22 33 44 55 66 77 88 99 AA BB 86 DD
               60 00 00 00 00 08 3A 40
               20 01 0D B8 00 00 00 00 00 00 00 00 00 00 00 01
               20 01 0D B8 00 00 00 00 00 00 00 00 00 00 00 02
               03 00 00 00 00 00 00 00")
        m (parse/packet->clj pkt)
        l4 (get-in m [:l3 :l4])]
    (is (= :icmpv6 (:type l4)))
    (is (= "time-exceeded" (:type-name l4)))
    (is (= "hop-limit-exceeded" (:code-name l4)))
    (is (= "time-exceeded/hop-limit-exceeded" (:summary l4)))))

;; IPv4 先頭フラグメント（offset=0, MF=1）でも L4(UDP) に到達できる
(deftest ipv4-frag-first-udp-test
  (let [pkt (tu/hex->bytes
             "00 11 22 33 44 55 66 77 88 99 AA BB 08 00
               45 00 00 1C 00 01 20 00 40 11 00 00        ; ver/ihl, tos, total=28, id=1, flags+frag=0x2000(MF=1), ttl=64, proto=17(UDP)
               0A 00 00 01 0A 00 00 02                    ; src=10.0.0.1 dst=10.0.0.2
               12 34 00 35 00 08 00 00")                  ; UDP: 0x1234 -> 53, len=8, csum=0
        m (parse/packet->clj pkt)]
    (is (= :ipv4 (get-in m [:l3 :type])))
    (is (= true  (get-in m [:l3 :frag?])))
    (is (= 0     (get-in m [:l3 :frag-offset])))
    (is (= :udp  (get-in m [:l3 :l4 :type])))))

;; IPv4 非先頭フラグメント（offset>0）は L4を解かず :ipv4-fragment で返す
(deftest ipv4-frag-nonfirst-test
  (let [pkt (tu/hex->bytes
             "00 11 22 33 44 55 66 77 88 99 AA BB 08 00
               45 00 00 18 00 02 00 01 40 11 00 00        ; total=24, id=2, flags+frag=0x0001(offset=1*8B), proto=UDP
               0A 00 00 01 0A 00 00 02
               DE AD BE EF")                               ; 4Bだけ適当に
        m (parse/packet->clj pkt)]
    (is (= :ipv4 (get-in m [:l3 :type])))
    (is (= true  (get-in m [:l3 :frag?])))
    (is (= 1     (get-in m [:l3 :frag-offset])))
    (is (= :ipv4-fragment (get-in m [:l3 :l4 :type])))))

;; DNS フラグ（クエリ）: QR=0, RD=1（0x0100）
(deftest ipv4-udp-dns-flags-query-test
  (let [pkt (tu/hex->bytes
             "FF FF FF FF FF FF 00 00 00 00 00 01 08 00
               45 00 00 28 00 02 00 00 40 11 00 00
               C0 A8 01 64 08 08 08 08
               13 88 00 35 00 14 00 00
               00 3B 01 00 00 01 00 00 00 00 00 00")
        m (parse/packet->clj pkt)
        app (get-in m [:l3 :l4 :app])]
    (is (= :dns (:type app)))
    (is (= false (:qr? app)))
    (is (= "query" (:opcode-name app)))
    (is (= true (:rd? app)))
    (is (= false (:ra? app)))))

;; DNS フラグ（レスポンス）: QR=1, RA=1, RD=1（0x8180）
(deftest ipv4-udp-dns-flags-response-test
  (let [pkt (tu/hex->bytes
             "FF FF FF FF FF FF 00 00 00 00 00 01 08 00
               45 00 00 28 00 03 00 00 40 11 00 00
               08 08 08 08 C0 A8 01 64
               00 35 13 88 00 14 00 00
               00 3B 81 80 00 01 00 00 00 00 00 00")
        m (parse/packet->clj pkt)
        app (get-in m [:l3 :l4 :app])]
    (is (= :dns (:type app)))
    (is (= true (:qr? app)))
    (is (= "query" (:opcode-name app)))
    (is (= "noerror" (:rcode-name app)))
    (is (= true (:ra? app)))))
