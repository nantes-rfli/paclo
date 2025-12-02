(ns paclo.pcap-vlan-test
  (:require
   [clojure.test :refer [deftest is]]
   [paclo.pcap :as pcap]))

(deftest vlan-tag->str-formats-fields
  (let [tag {:tpid 0x8100 :vid 100 :pcp 5 :dei true}]
    (is (= "[TPID=0x8100 VID=100 PCP=5 DEI=true]"
           (pcap/vlan-tag->str tag)))))

(deftest vlan-tag->str-handles-dei-false
  (let [tag {:tpid 0x88A8 :vid 200 :pcp 0 :dei false}]
    (is (= "[TPID=0x88A8 VID=200 PCP=0 DEI=false]"
           (pcap/vlan-tag->str tag)))))
