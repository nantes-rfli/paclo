(ns paclo.perf-test
  (:require
   [clojure.java.shell :as shell]
   [clojure.test :refer [deftest is testing]]
   [paclo.dev.perf :as perf]
   [paclo.dev.perf-data :as data]
   [paclo.dev.perf-generator :as generator]
   [paclo.dev.perf-metrics :as metrics]
   [paclo.dev.perf-worker :as worker]
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
               :sent-source :internal-observed
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
            :end-to-end? true
            :passing-runs 1
            :total-runs 2
            :all-runs-pass? false
            :max-passing-processed-pps 250000.0}
           (:sustainability result)))))

(deftest external-live-sustainability-requires-a-send-count
  (let [sustainable? (deref #'perf/sustainable-run?)
        annotate (deref #'perf/annotate-sustainability)
        capture-only {:capture-errors []
                      :sent-source :unavailable
                      :send-loss-rate nil
                      :kernel-drop-rate 0.0
                      :interface-drop-rate 0.0
                      :queue-drop-rate 0.0
                      :consumer-gap-rate 0.0
                      :sustained-processed-pps 100000.0}
        measured (assoc capture-only
                        :sent-source :external-expected
                        :send-loss-rate 0.0005)]
    (is (false? (sustainable? capture-only)))
    (is (true? (sustainable? measured)))
    (is (false? (get-in (annotate {:runs [capture-only]})
                        [:sustainability :end-to-end?])))
    (is (true? (get-in (annotate {:runs [measured]})
                       [:sustainability :end-to-end?])))))

(deftest external-expected-count-requires-one-coordinated-run
  (let [validate! (deref #'perf/validate-external-run-shape!)]
    (is (nil? (validate! 15000000 [:live-sync-raw] 0 1)))
    (is (thrown-with-msg? clojure.lang.ExceptionInfo
                          #"requires one scenario"
                          (validate! 15000000
                                     [:live-sync-raw :live-sync-full]
                                     0
                                     1)))
    (is (thrown-with-msg? clojure.lang.ExceptionInfo
                          #"requires one scenario"
                          (validate! 15000000 [:live-sync-raw] 1 1)))
    (is (nil? (validate! nil [:live-sync-raw :live-sync-full] 1 5)))))

(deftest external-expected-count-requires-an-offered-rate
  (let [validate! (deref #'perf/validate-opts!)
        valid {:mode :live
               :profile :quick
               :port 39053
               :source :external
               :rates "250000"
               :expected-packets 15000000}]
    (is (nil? (validate! valid)))
    (is (thrown-with-msg? clojure.lang.ExceptionInfo
                          #"requires an external offered rate"
                          (validate! (dissoc valid :rates))))
    (is (thrown-with-msg? clojure.lang.ExceptionInfo
                          #"requires source=external"
                          (validate! (assoc valid :source :loopback))))))

(deftest external-expected-count-bounds-live-capture
  (let [capture-max (deref #'worker/live-capture-max)]
    (is (= 2000000 (capture-max :external 2000000)))
    (is (= Long/MAX_VALUE (capture-max :external nil)))
    (is (= Long/MAX_VALUE (capture-max :loopback 2000000)))))

(deftest external-worker-signals-capture-readiness
  (let [worker! (deref #'perf/worker!)
        ready-path (atom nil)]
    (with-redefs [shell/sh
                  (fn [& arguments]
                    (let [arguments (vec arguments)
                          ready-index (.indexOf ^java.util.List arguments
                                                "--ready-file")
                          path (nth arguments (inc ready-index))]
                      (reset! ready-path path)
                      (spit path "ready\n")
                      {:exit 0 :out "{:mode :live}" :err ""}))]
      (is (= {:mode :live}
             (worker! ["--mode" "live"] true)))
      (is (string? @ready-path))
      (is (false? (.exists (java.io.File. ^String @ready-path)))))))

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

(deftest generator-splits-an-exact-packet-count
  (let [split-counts (deref #'generator/split-counts)]
    (is (= [4 3 3] (split-counts 10 3)))
    (is (= 1000 (reduce + (split-counts 1000 8))))
    (is (every? pos? (split-counts 5 5)))))

(deftest generator-validates-exact-count-options
  (let [validate! (deref #'generator/validate-opts!)
        valid {:host "192.0.2.10"
               :packets 1000
               :rate 100000
               :port 39053
               :frame-size 64
               :senders 2
               :start-delay-ms 0}]
    (is (nil? (validate! valid)))
    (is (thrown-with-msg? clojure.lang.ExceptionInfo
                          #"host is required"
                          (validate! (assoc valid :host ""))))
    (is (thrown-with-msg? clojure.lang.ExceptionInfo
                          #"senders cannot exceed packets"
                          (validate! (assoc valid :packets 1 :senders 2))))
    (is (thrown-with-msg? clojure.lang.ExceptionInfo
                          #"start-delay-ms cannot be negative"
                          (validate! (assoc valid :start-delay-ms -1))))))

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
