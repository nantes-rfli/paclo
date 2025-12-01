(ns paclo.dev-hbh-test
  (:require
   [clojure.test :refer [deftest is]]
   [paclo.dev :as dev]))

(deftest hbh-ok-parses-and-flags-layers
  (let [pkt (dev/parse-hex dev/HBH-OK)]
    (is (= :ethernet (:type pkt)))
    (is (= :ipv6 (get-in pkt [:l3 :type])))
    (is (= :udp (get-in pkt [:l3 :l4 :type])))
    (is (false? (get-in pkt [:l3 :frag?])))))

(deftest hbh-bad-overrun-stops-safely
  (let [pkt (dev/parse-hex dev/HBH-BAD-OVERRUN)]
    ;; bad TLV should not throw and should mark next-header unresolved
    (is (= :ethernet (:type pkt)))
    (is (= :ipv6 (get-in pkt [:l3 :type])))
    (is (= :unknown-l4 (get-in pkt [:l3 :l4 :type])))
    (is (nil? (get-in pkt [:l3 :flow-key])))))
