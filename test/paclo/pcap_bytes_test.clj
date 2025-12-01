(ns paclo.pcap-bytes-test
  (:require
   [clojure.test :refer [deftest is testing]]
   [paclo.pcap :as p]))

(deftest ensure-bytes-timestamp-validates
  (let [f (deref #'p/ensure-bytes-timestamp)]
    (testing "map with bytes and explicit timestamps"
      (let [[ba sec usec] (f {:bytes (byte-array [1 2]) :sec 10 :usec 20})]
        (is (= [1 2] (map #(bit-and 0xFF %) ba)))
        (is (= 10 sec))
        (is (= 20 usec))))
    (testing "map missing :bytes throws"
      (is (thrown-with-msg? clojure.lang.ExceptionInfo #"missing :bytes"
                            (f {:sec 1 :usec 2}))))
    (testing "byte-array input gets timestamp"
      (let [[ba sec usec] (f (byte-array [3 4]))]
        (is (= [3 4] (map #(bit-and 0xFF %) ba)))
        (is (number? sec))
        (is (number? usec))))))
