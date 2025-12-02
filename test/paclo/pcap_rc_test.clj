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

(deftest rc->status-detail-adds-summary-for-stop-codes
  (let [f pcap/rc->status-detail]
    (is (= {:rc -2 :status :eof :summary "pcap_next_ex reached EOF (rc=-2)"}
           (f -2)))
    (is (= {:rc -1 :status :error :summary "pcap_next_ex returned error (rc=-1)"}
           (f -1)))
    (is (= {:rc 1 :status :packet :summary nil}
           (f 1)))))
