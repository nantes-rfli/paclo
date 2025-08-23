(ns paclo.core-test
  (:require
   [clojure.test :refer :all]
   [paclo.core :as sut])
  (:import
   [java.io File]))

(deftest pcap-roundtrip
  (let [f    (File/createTempFile "paclo" ".pcap")
        path (.getAbsolutePath f)
        ;; 60Bのダミーフレーム（Ethernet最小相当）
        ba1  (byte-array (repeat 60 (byte 0)))
        ba2  (byte-array (repeat 60 (byte -1)))]
    (sut/write-pcap! [ba1 {:bytes ba2 :sec 1700000000 :usec 123456}] path)
    ;; デコードなし: 2件読めること
    (let [xs (vec (sut/packets {:path path}))]
      (is (= 2 (count xs)))
      (is (every? #(contains? % :bytes) xs)))
    ;; デコードあり: 例外を出さず、:decoded か :decode-error のどちらかが付くこと
    (let [xs (vec (sut/packets {:path path :decode? true}))]
      (is (= 2 (count xs)))
      (is (every? #(or (contains? % :decoded)
                       (contains? % :decode-error)) xs)))))

(deftest bpf-dsl
  (is (= "(udp) and (port 53)"
         (sut/bpf [:and [:udp] [:port 53]])))
  (is (= "not (host 8.8.8.8)"
         (sut/bpf [:not [:host "8.8.8.8"]])))
  (is (= "tcp" (sut/bpf :tcp))))
