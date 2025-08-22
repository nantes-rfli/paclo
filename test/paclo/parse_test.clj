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
