(ns paclo.pcap-pure-test
  (:require
   [clojure.test :refer [deftest is testing]]
   [paclo.pcap :as p]))

(deftest valid-filter-string?-cases
  (let [f (deref #'p/valid-filter-string?)]
    (testing "accepts non-blank string"
      (is (true? (f "udp and port 53"))))
    (testing "rejects nil / blank / whitespace"
      (doseq [v [nil "" "   "]]
        (is (false? (boolean (f v))))))
    (testing "rejects non-string"
      (is (false? (boolean (f 123)))))))
