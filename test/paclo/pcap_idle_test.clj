(ns paclo.pcap-idle-test
  (:require
   [clojure.test :refer [deftest is testing]]
   [paclo.pcap :as p]))

(deftest idle-next-behavior
  (let [f (deref #'p/idle-next)]
    (testing "under target"
      (is (= {:idle 30 :break? false} (f 10 20 100))))
    (testing "at threshold"
      (is (= {:idle 100 :break? true} (f 80 20 100))))
    (testing "over threshold"
      (is (= {:idle 120 :break? true} (f 90 30 100))))))
