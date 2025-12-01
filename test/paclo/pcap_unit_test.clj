(ns paclo.pcap-unit-test
  (:require
   [clojure.test :refer [deftest is testing]]
   [paclo.pcap :as p]))

(deftest blank-str?-basics
  (let [f (deref #'p/blank-str?)]
    (testing "nil is blank"
      (is (true? (f nil))))
    (testing "whitespace string is blank"
      (is (f "   \t")))
    (testing "non-blank string is falsey"
      (is (false? (boolean (f "abc")))))))

(deftest normalize-desc-trims-and-filters
  (let [f (deref #'p/normalize-desc)]
    (testing "trims surrounding whitespace"
      (is (= "eth0" (f "  eth0  "))))
    (testing "blank becomes nil"
      (is (nil? (f "   "))))
    (testing "nil stays nil"
      (is (nil? (f nil))))))
