(ns paclo.golden-test
  (:require
   [clojure.test :refer [deftest is testing]]
   [paclo.core :as core]
   [paclo.test-util :as tu]))

(deftest golden-roundtrip-and-decode
  (let [tmp  (-> (java.io.File/createTempFile "paclo-gold" ".pcap")
                 .getAbsolutePath)
        ;; 1) 60-byte Ethernet frame
        ether60 (byte-array (repeat 60 (byte 0)))
        ;; 2) IPv4/UDP/DNS sample payload
        ipv4-udp-dns
        (tu/hex->bytes
         "FF FF FF FF FF FF 00 00 00 00 00 01 08 00
          45 00 00 30 00 02 00 00 40 11 00 00
          C0 A8 01 64 08 08 08 08
          13 88 00 35 00 18 00 00
          00 3B 01 00 00 01 00 00 00 00 00 00 00 00 00 00")
        ;; 3) IPv6/UDP with 4-byte payload
        ipv6-udp-min
        (tu/hex->bytes
         "00 11 22 33 44 55 66 77 88 99 AA BB 86 DD
          60 00 00 00 00 0C 11 40
          20 01 0D B8 00 00 00 00 00 00 00 00 00 00 00 01
          20 01 0D B8 00 00 00 00 00 00 00 00 00 00 00 02
          12 34 56 78 00 0C 00 00
          DE AD BE EF")]
    ;; write -> read roundtrip
    (core/write-pcap! [ether60 ipv4-udp-dns ipv6-udp-min] tmp)

    (testing "decode? false keeps raw bytes"
      (let [xs (vec (core/packets {:path tmp}))]
        (is (= 3 (count xs)))
        (is (every? #(contains? % :bytes) xs))))

    (testing "decode? true returns :decoded or :decode-error"
      (let [xs (vec (core/packets {:path tmp :decode? true}))]
        (is (= 3 (count xs)))
        (is (every? #(or (contains? % :decoded)
                         (contains? % :decode-error)) xs))
        ;; second packet: IPv4/UDP/DNS
        (let [m (nth xs 1)]
          (is (= :ipv4 (get-in m [:decoded :l3 :type])))
          (is (= :udp  (get-in m [:decoded :l3 :l4 :type])))
          (is (= :dns  (get-in m [:decoded :l3 :l4 :app :type]))))
        ;; third packet: IPv6/UDP
        (let [m (nth xs 2)]
          (is (= :ipv6 (get-in m [:decoded :l3 :type])))
          (is (= :udp  (get-in m [:decoded :l3 :l4 :type])))
          (is (= 4     (get-in m [:decoded :l3 :l4 :data-len]))))))))
