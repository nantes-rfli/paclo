(ns paclo.dev-test
  (:require
   [clojure.test :refer [deftest is testing]]
   [paclo.dev :as dev]))

(deftest hex->bytes-cleans-and-parses
  (testing "whitespace/comments are stripped"
    (let [s "AA bb ; line comment\n/*block*/ CC\nDD"
          bs (dev/hex->bytes s)]
      (is (= [0xaa 0xbb 0xcc 0xdd]
             (map #(bit-and 0xFF %) bs)))))
  (testing "odd digit count throws"
    (is (thrown-with-msg? clojure.lang.ExceptionInfo
                          #"Odd number of hex digits"
                          (dev/hex->bytes "AAA")))))

(deftest hexd-renders-bytes
  (let [pkt {:bytes (byte-array [1 2 10])}]
    (is (= "01 02 0a" (dev/hexd pkt)))))

(deftest parse-and-summarize-hbh-ok
  (let [pkt (dev/parse-hex dev/HBH-OK)
        out (with-out-str (dev/summarize pkt))]
    ;; summarizing does not mutate
    (is (= pkt (dev/summarize pkt)))
    ;; key lines are present
    (is (re-find #"L2: :ethernet" out))
    (is (re-find #"L3: :ipv6" out))
    (is (re-find #"L4: :udp" out))))
