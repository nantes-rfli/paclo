(ns paclo.pcap-rc-test
  (:require
   [clojure.test :refer [deftest is]]
   [paclo.pcap :as pcap]))

(deftest rc->status-classifies
  (let [f pcap/rc->status]
    (is (= :packet (f 1)))
    (is (= :timeout (f 0)))
    (is (= :eof (f -2)))
    (is (= :error (f -1)))
    (is (= :error (f 42)))))
