(ns paclo.perf-test
  (:require
   [clojure.test :refer [deftest is testing]]
   [paclo.dev.perf-data :as data]
   [paclo.dev.perf-metrics :as metrics]
   [paclo.parse :as parse]
   [paclo.pcap :as pcap])
  (:import
   [paclo.jnr PcapStatsLibrary]))

(deftest generated-frames-are-valid-and-deterministic
  (doseq [[traffic expected-l4] [[:udp :udp] [:tcp :tcp]]]
    (testing (name traffic)
      (let [first-frame (data/ethernet-ipv4-frame 64 traffic)
            second-frame (data/ethernet-ipv4-frame 64 traffic)
            decoded (parse/packet->clj first-frame)]
        (is (= 64 (alength first-frame)))
        (is (= (vec first-frame) (vec second-frame)))
        (is (= :ethernet (:type decoded)))
        (is (= :ipv4 (get-in decoded [:l3 :type])))
        (is (= expected-l4 (get-in decoded [:l3 :l4 :type])))))))

(deftest generated-dataset-has-expected-size
  (let [file (java.io.File/createTempFile "paclo-perf-test" ".pcap")
        config {:count 5 :frame-size 64 :traffic :udp}]
    (try
      (.delete file)
      (data/ensure-dataset! (.getAbsolutePath file) config)
      (is (= (data/expected-pcap-size 5 64) (.length file)))
      (is (= 5 (count (pcap/capture->seq
                       {:path (.getAbsolutePath file) :max 5}))))
      (finally
        (when (.exists file)
          (.delete file))))))

(deftest mixed-dataset-size-accounts-for-both-frame-sizes
  (let [config {:count 3
                :frame-size 64
                :alternate-frame-size 512
                :traffic :mixed}]
    (is (= (+ 24 16 64 16 512 16 64)
           (data/expected-case-pcap-size config)))
    (is (= (+ 64 512 64)
           (data/expected-captured-bytes config)))))

(deftest every-profile-covers-all-traffic-shapes
  (is (= {:quick 50000 :reference 1000000 :stress 10000000}
         (into {} (map (fn [[profile config]]
                         [profile (:count config)]))
               data/profiles)))
  (doseq [[_ {:keys [cases]}] data/profiles]
    (is (= #{:udp-64 :tcp-512 :mixed}
           (set (map :id cases))))))

(deftest metric-summary-uses-medians
  (is (= 2 (metrics/median [3 1 2])))
  (is (= 2.5 (metrics/median [4 1 2 3])))
  (is (nil? (metrics/median [])))
  (is (= {:median 20 :min 10 :max 30}
         (get (metrics/summarize-runs
               [{:elapsed-ns 10} {:elapsed-ns 30} {:elapsed-ns 20}])
              :elapsed-ns))))

(deftest capture-stats-reads-portable-counters
  (with-redefs [pcap/stats-lib
                (reify PcapStatsLibrary
                  (pcap_stats [_ _ stats]
                    (.putInt stats 0 11)
                    (.putInt stats 4 2)
                    (.putInt stats 8 1)
                    0))]
    (is (= {:received 11 :dropped 2 :interface-dropped 1}
           (pcap/capture-stats nil)))))

(deftest capture-stats-reports-libpcap-errors
  (with-redefs [pcap/stats-lib
                (reify PcapStatsLibrary
                  (pcap_stats [_ _ _] -1))]
    (is (thrown-with-msg? clojure.lang.ExceptionInfo
                          #"pcap_stats failed"
                          (pcap/capture-stats nil)))))
