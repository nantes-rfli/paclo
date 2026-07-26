(ns examples.flow-topn-test
  (:require
   [clojure.test :refer [deftest is testing]]
   [examples.flow-topn :as flow-topn]))

(deftest numeric-addresses-use-compatible-display-format
  (testing "IPv4 is rendered in dotted-decimal notation"
    (is (= "192.168.1.100"
           ((deref #'flow-topn/ip->str) 3232235876))))
  (testing "IPv6 keeps the full legacy representation"
    (is (= "2001:db8:0:0:0:0:0:1"
           ((deref #'flow-topn/ip->str)
            [2306139568115548160 1])))))

(deftest numeric-projection-builds-compatible-flow-key
  (is (= {:proto :udp
          :src-ip 167772161
          :src-port 12000
          :dst-ip 167772162
          :dst-port 5300}
         ((deref #'flow-topn/packet->flow-key)
          {:protocol 17
           :src-ip 167772161
           :src-port 12000
           :dst-ip 167772162
           :dst-port 5300}
          false)))
  (is (= :icmp
         (:proto
          ((deref #'flow-topn/packet->flow-key)
           {:protocol 1
            :src-ip 167772161
            :dst-ip 167772162}
           false))))
  (is (= 132
         (:proto
          ((deref #'flow-topn/packet->flow-key)
           {:protocol 132
            :src-ip 167772161
            :dst-ip 167772162}
           false)))))

(deftest bidirectional-flow-key-is-canonical
  (let [projected {:protocol 6
                   :src-ip 167772162
                   :src-port 443
                   :dst-ip 167772161
                   :dst-port 12000}]
    (is (= {:proto :tcp
            :src-ip 167772161
            :src-port 12000
            :dst-ip 167772162
            :dst-port 443}
           ((deref #'flow-topn/packet->flow-key) projected true)))))
