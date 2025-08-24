(ns paclo.decode-ext-test
  (:require
   [clojure.test :refer :all]
   [paclo.core :as core]
   [paclo.decode-ext :as dx]
   [paclo.proto.dns-ext :as dns-ext]
   [paclo.test-util :as tu]))

(deftest post-decode-hook-annotates
  (dns-ext/register!)
  (try
    (let [pcap (-> (java.io.File/createTempFile "paclo-dx" ".pcap")
                   .getAbsolutePath)
          ;; IPv4/UDP/DNS 最小（既存 golden と同系）
          ipv4-udp-dns
          (tu/hex->bytes
           "FF FF FF FF FF FF 00 00 00 00 00 01 08 00
            45 00 00 30 00 02 00 00 40 11 00 00
            C0 A8 01 64 08 08 08 08
            13 88 00 35 00 18 00 00
            00 3B 01 00 00 01 00 00 00 00 00 00 00 00 00 00")]
      (core/write-pcap! [ipv4-udp-dns] pcap)
      (let [xs (vec (core/packets {:path pcap :decode? true}))]
        (is (= 1 (count xs)))
        (is (= "DNS message"
               (get-in (first xs) [:decoded :l3 :l4 :app :summary])))))
    (finally
      (dx/unregister! ::dns-summary))))
