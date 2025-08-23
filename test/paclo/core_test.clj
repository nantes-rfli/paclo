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

(deftest packets-xform-filters-and-maps
  (let [pcap "target/xform-test.pcap"]
    ;; 3パケット: 60B / 42B / 60B
    (sut/write-pcap! [(byte-array (repeat 60 (byte 0)))
                      (byte-array (repeat 42 (byte 0)))
                      (byte-array (repeat 60 (byte 0)))]
                     pcap)
    (let [xs (sut/packets {:path pcap
                           :decode? false
                           :xform (comp
                                   (filter #(>= (:caplen %) 60))
                                   (map :caplen))})]
      (is (= [60 60] (into [] xs))))))

(deftest bpf-dsl-extended
  ;; :proto + :ipv6 / :ip
  (is (= "ip6" (sut/bpf [:proto :ipv6])))
  (is (= "ip"  (sut/bpf [:proto :ip])))
  (is (= "ip6" (sut/bpf :ip6)))
  (is (= "ip"  (sut/bpf :ipv4)))

  ;; src/dst net
  (is (= "src net 10.0.0.0/8" (sut/bpf [:src-net "10.0.0.0/8"])))
  (is (= "dst net 192.168.0.0/16" (sut/bpf [:dst-net "192.168.0.0/16"])))

  ;; portrange
  (is (= "portrange 1000-2000" (sut/bpf [:port-range 1000 2000])))
  (is (= "src portrange 53-60" (sut/bpf [:src-port-range 53 60])))
  (is (= "dst portrange 8080-8088" (sut/bpf [:dst-port-range 8080 8088])))

  ;; 論理と併用
  (is (= "(ip6) and (udp) and (dst portrange 8000-9000)"
         (sut/bpf [:and [:ipv6] [:udp] [:dst-port-range 8000 9000]])))

  ;; not と組み合わせ（ユーザ要望例）
  (is (= "(net 10.0.0.0/8) and (not (port 22))"
         (sut/bpf [:and [:net "10.0.0.0/8"] [:not [:port 22]]]))))

(deftest packets-xform-filters-and-maps
  (let [pcap (-> (java.io.File/createTempFile "paclo-xf" ".pcap")
                 .getAbsolutePath)]
    ;; 3パケット: 60B / 42B / 60B
    (sut/write-pcap! [(byte-array (repeat 60 (byte 0)))
                      (byte-array (repeat 42 (byte 0)))
                      (byte-array (repeat 60 (byte 0)))]
                     pcap)
    (let [xs (sut/packets {:path pcap
                           :decode? false
                           :xform (comp
                                   (filter #(>= (:caplen %) 60))
                                   (map :caplen))})]
      (is (= [60 60] (into [] xs))))))

(deftest bpf-dsl-error-cases
  ;; フォーム型が不正
  (is (thrown-with-msg? clojure.lang.ExceptionInfo #"unsupported bpf form"
                        (sut/bpf 123)))
  ;; 未知のトップレベルキーワード（実装により "unknown keyword" or "unknown proto keyword"） 
  (is (thrown-with-msg? clojure.lang.ExceptionInfo #"unknown (proto )?keyword"
                        (sut/bpf :foo)))
  ;; 未知の演算子
  (is (thrown-with-msg? clojure.lang.ExceptionInfo #"unknown op"
                        (sut/bpf [:huh 1 2 3]))))
