(ns paclo.perf-test
  (:require
   [clojure.test :refer [deftest is testing]]
   [paclo.dev.perf :as perf]
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
              :elapsed-ns)))
  (is (= {:median 200.0 :min 100.0 :max 300.0}
         (get (metrics/summarize-runs
               [{:sustained-processed-pps 100.0}
                {:sustained-processed-pps 300.0}])
              :sustained-processed-pps)))
  (is (= {:median 0.01 :min 0.0 :max 0.02}
         (get (metrics/summarize-runs
               [{:send-loss-rate 0.0}
                {:send-loss-rate 0.02}])
              :send-loss-rate))))

(deftest live-sustainability-separates-drop-stages
  (let [sustainable? (deref #'perf/sustainable-run?)
        annotate (deref #'perf/annotate-sustainability)
        clean {:capture-errors []
               :send-loss-rate 0.0005
               :kernel-drop-rate 0.0
               :interface-drop-rate 0.0
               :queue-drop-rate 0.0005
               :consumer-gap-rate 0.0
               :sustained-processed-pps 250000.0}
        queue-drop (assoc clean :queue-drop-rate 0.01)
        send-loss (assoc clean :send-loss-rate 0.01)
        result (annotate {:runs [clean queue-drop]})]
    (is (true? (sustainable? clean)))
    (is (false? (sustainable? queue-drop)))
    (is (false? (sustainable? send-loss)))
    (is (= {:drop-threshold 0.001
            :passing-runs 1
            :total-runs 2
            :all-runs-pass? false
            :max-passing-processed-pps 250000.0}
           (:sustainability result)))))

(deftest live-summary-selects-fastest-sustainable-result
  (let [summarize (deref #'perf/max-sustainable-by-scenario)
        candidate (fn [target processed passes?]
                    {:scenario :live-sync-raw
                     :config {:target-pps target :source :loopback}
                     :summary {:sustained-processed-pps {:median processed}
                               :realized-send-pps {:median target}}
                     :sustainability {:all-runs-pass? passes?}})
        summary (summarize [(candidate 100000 99000.0 true)
                            (candidate 500000 450000.0 true)
                            (candidate 1000000 700000.0 false)])]
    (is (= {:target-pps 500000
            :processed-pps 450000.0
            :realized-send-pps 500000
            :source :loopback}
           (:live-sync-raw summary)))))

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
