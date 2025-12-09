(ns paclo.dev-test
  (:require
   [clojure.test :refer [deftest is testing]]
   [paclo.dev :as dev]))

(deftest hex->bytes-cleans-and-parses
  (testing "whitespace/comments are stripped"
    (let [s "AA bb ; line comment\n/*block*/ CC\nDD"
          bs (dev/hex->bytes s)]
      (is (= [0xaa 0xbb 0xcc 0xdd]
             (map #(bit-and 0xFF (int %)) bs)))))
  (testing "odd digit count throws"
    (is (thrown-with-msg? clojure.lang.ExceptionInfo
                          #"Odd number of hex digits"
                          (dev/hex->bytes "AAA")))))

(deftest hexd-renders-bytes
  (let [pkt {:bytes (byte-array [1 2 10])}]
    (is (= "01 02 0a" (dev/hexd pkt)))))

(deftest fragment-note-builds-offset
  (is (= "frag@10" (dev/fragment-note {:frag? true :frag-offset 10})))
  (is (= "frag@0" (dev/fragment-note {:frag? true})))
  (is (nil? (dev/fragment-note {:frag? false}))))

(deftest vlan-summary-renders-tags
  (let [tags [{:tpid 0x8100 :vid 100 :pcp 5 :dei true}
              {:tpid 0x88A8 :vid 200 :pcp 1 :dei false}]]
    (is (= "VLAN: [TPID=0x8100 VID=100 PCP=5 DEI=true] [TPID=0x88A8 VID=200 PCP=1 DEI=false]"
           (dev/vlan-summary tags)))
    (is (nil? (dev/vlan-summary nil)))))

(deftest parse-and-summarize-hbh-ok
  (let [pkt (dev/parse-hex dev/HBH-OK)
        out (with-out-str (dev/summarize pkt))]
    ;; summarizing does not mutate
    (is (= pkt (dev/summarize pkt)))
    ;; key lines are present
    (is (re-find #"L2: :ethernet" out))
    (is (re-find #"L3: :ipv6" out))
    (is (re-find #"L4: :udp" out))))

(deftest summarize-covers-l4-branches
  (let [tcp-pkt {:type :ethernet
                 :src "aa:aa:aa:aa:aa:aa" :dst "bb:bb:bb:bb:bb:bb" :eth 0x0800
                 :l3 {:type :ipv4 :protocol 6 :src "1.1.1.1" :dst "2.2.2.2" :frag? true :frag-offset 5
                      :l4 {:type :tcp :src-port 1000 :dst-port 2000 :flags-str "S" :data-len 0}}}
        icmp-pkt {:type :ethernet :src "c" :dst "d" :eth 0x0800
                  :l3 {:type :ipv4 :protocol 1 :src "3.3.3.3" :dst "4.4.4.4"
                       :l4 {:type :icmpv4 :summary "echo-request" :data-len 0}}}
        app-pkt {:type :ethernet :src "e" :dst "f" :eth 0x0800
                 :l3 {:type :ipv4 :protocol 17 :src "5.5.5.5" :dst "6.6.6.6"
                      :l4 {:type :udp :src-port 53 :dst-port 5353 :data-len 12
                           :app {:type :dns}}}}]
    (is (re-find #"frag@5" (with-out-str (dev/summarize tcp-pkt))))
    (is (re-find #"tcp" (with-out-str (dev/summarize tcp-pkt))))
    (is (re-find #"echo-request" (with-out-str (dev/summarize icmp-pkt))))
    (is (re-find #"App: :dns" (with-out-str (dev/summarize app-pkt))))))

(deftest summarize-more-flags-and-fragments
  (let [tcp-pkt {:type :ethernet
                 :src "aa" :dst "bb" :eth 0x0800
                 :l3 {:type :ipv4 :protocol 6 :src "9.9.9.9" :dst "8.8.8.8"
                      :l4 {:type :tcp :src-port 123 :dst-port 80 :flags-str "FA" :data-len 10}}}
        frag-pkt {:type :ethernet
                  :src "aa" :dst "bb" :eth 0x0800
                  :l3 {:type :ipv4 :protocol 17 :src "1.1.1.1" :dst "2.2.2.2" :frag? true :frag-offset 1
                       :l4 {:type :ipv4-fragment}}}]
    (is (re-find #"FA" (with-out-str (dev/summarize tcp-pkt))))
    (is (re-find #"frag@1" (with-out-str (dev/summarize frag-pkt))))))
