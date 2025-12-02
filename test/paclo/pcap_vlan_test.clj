(ns paclo.pcap-vlan-test
  (:require
   [clojure.test :refer [deftest is]]
   [paclo.pcap :as pcap]))

(deftest vlan-tag->str-formats-fields
  (let [tag {:tpid 0x8100 :vid 100 :pcp 5 :dei true}]
    (is (= "[TPID=0x8100 VID=100 PCP=5 DEI=true]"
           (pcap/vlan-tag->str tag)))))
