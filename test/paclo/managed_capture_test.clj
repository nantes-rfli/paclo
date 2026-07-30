(ns paclo.managed-capture-test
  (:require
   [clojure.test :refer [deftest is testing]]
   [paclo.core :as core]
   [paclo.dev.perf-data :as data]
   [paclo.pcap :as pcap]))

(defn- with-pcap-file [packet-count f]
  (let [file (java.io.File/createTempFile "paclo-managed-capture" ".pcap")
        frame (data/ethernet-ipv4-frame 64 :udp)]
    (try
      (core/write-pcap! (repeat packet-count frame)
                        (.getAbsolutePath file))
      (f (.getAbsolutePath file))
      (finally
        (when (.exists file)
          (.delete file))))))

(deftest reduce-packets-report-matches-reduce-packets
  (with-pcap-file
    4
    (fn [path]
      (let [opts {:path path
                  :max 10
                  :max-time-ms 60000}
            expected (core/reduce-packets opts
                                          (fn [^long total packet]
                                            (unchecked-add
                                             total
                                             (long (:caplen packet))))
                                          0)
            {:keys [result stats]}
            (core/reduce-packets-report opts
                                        (fn [^long total packet]
                                          (unchecked-add
                                           total
                                           (long (:caplen packet))))
                                        0)]
        (is (= expected result))
        (is (= 1 (:schema-version stats)))
        (is (= :closed (:state stats)))
        (is (= :eof (:stop-reason stats)))
        (is (= 4 (get-in stats [:packets :captured])))
        (is (= 4 (get-in stats [:packets :processed])))
        (is (= 0 (get-in stats [:packets :decode-errors])))
        (is (nil? (:queue stats)))
        (is (nil? (:pcap stats)))
        (is (nil? (:error stats)))))))

(deftest reduce-packets-report-records-reduced-stop
  (with-pcap-file
    10
    (fn [path]
      (let [{:keys [result stats]}
            (core/reduce-packets-report
             {:path path :max 10 :max-time-ms 60000}
             (fn [^long count _]
               (let [next-count (unchecked-inc count)]
                 (if (= next-count 3)
                   (reduced next-count)
                   next-count)))
             0)]
        (is (= 3 result))
        (is (= :reduced (:stop-reason stats)))
        (is (= 3 (get-in stats [:packets :captured])))))))

(deftest reduce-packets-report-pass-mode-records-background-error
  (let [closed (atom 0)]
    (with-redefs [pcap/open-offline (fn [_] :handle)
                  pcap/close! (fn [_] (swap! closed inc))
                  pcap/loop-n-or-ms!
                  (fn [_ _ handler]
                    (handler {:caplen 2})
                    (throw (RuntimeException. "capture failed")))]
      (let [{:keys [result stats]}
            (core/reduce-packets-report
             {:path "dummy"
              :error-mode :pass}
             (fn [^long total packet]
               (unchecked-add total (long (:caplen packet))))
             0)]
        (is (= 2 result))
        (is (= :failed (:state stats)))
        (is (= :error (:stop-reason stats)))
        (is (= "capture failed" (get-in stats [:error :message])))
        (is (= 1 @closed))))))

(deftest managed-offline-capture-has-one-stream-and-final-stats
  (with-pcap-file
    3
    (fn [path]
      (let [capture (core/start-capture
                     {:path path
                      :max 10
                      :max-time-ms 60000})]
        (try
          (is (= 3 (count (core/capture-packets capture))))
          (is (thrown-with-msg?
               clojure.lang.ExceptionInfo
               #"only be acquired once"
               (core/capture-packets capture)))
          (let [stats (core/capture-stats capture)]
            (is (= :closed (:state stats)))
            (is (= :eof (:stop-reason stats)))
            (is (= 3 (get-in stats [:packets :captured])))
            (is (= 3 (get-in stats [:packets :enqueued])))
            (is (= 3 (get-in stats [:packets :delivered])))
            (is (= 3 (get-in stats [:packets :processed])))
            (is (= 0 (get-in stats [:packets :decode-errors])))
            (Thread/sleep 2)
            (is (= (get-in stats [:timing :elapsed-ms])
                   (get-in (core/capture-stats capture)
                           [:timing :elapsed-ms]))))
          (finally
            (.close ^java.io.Closeable capture)
            ;; Closing an already completed capture is explicitly idempotent.
            (.close ^java.io.Closeable capture)))))))

(deftest managed-capture-startup-is-synchronous-through-open
  (let [events (atom [])
        release-loop (promise)
        closed (promise)]
    (with-redefs [pcap/open-offline
                  (fn [_ _]
                    (swap! events conj :open)
                    :handle)
                  pcap/loop-n-or-ms!
                  (fn [_ _ _]
                    @release-loop)
                  pcap/close!
                  (fn [_]
                    (swap! events conj :close)
                    (deliver closed true))
                  pcap/breakloop!
                  (fn [_]
                    (deliver release-loop true))]
      (let [capture (core/start-capture
                     {:path "dummy.pcap"
                      :on-ready #(swap! events conj :ready)})]
        (try
          (is (= [:open :ready] @events))
          (is (= :running (:state (core/capture-stats capture))))
          (finally
            (.close ^java.io.Closeable capture)))
        (is (true? (deref closed 1000 false)))
        (is (= [:open :ready :close] @events))))))

(deftest managed-capture-startup-failure-closes-handle
  (let [closed (atom 0)]
    (with-redefs [pcap/open-offline (fn [_ _] :handle)
                  pcap/close! (fn [_] (swap! closed inc))]
      (is (thrown-with-msg?
           RuntimeException
           #"ready failed"
           (core/start-capture
            {:path "dummy.pcap"
             :on-ready #(throw (RuntimeException. "ready failed"))})))
      (is (= 1 @closed)))))

(deftest managed-capture-decodes-and-applies-xform
  (with-pcap-file
    3
    (fn [path]
      (with-open [^java.io.Closeable capture
                  (core/start-capture
                   {:path path
                    :max 10
                    :decode-mode :flow
                    :xform (map :protocol)})]
        (is (= [17 17 17]
               (vec (core/capture-packets capture))))
        (let [stats (core/capture-stats capture)]
          (is (= 3 (get-in stats [:packets :processed])))
          (is (= 0 (get-in stats [:packets :decode-errors]))))))))

(deftest managed-capture-close-unblocks-full-blocking-queue
  (let [entered-second-packet (promise)
        closed (promise)]
    (with-redefs [pcap/open-offline (fn [_ _] :handle)
                  pcap/loop-n-or-ms!
                  (fn [_ _ handler]
                    (handler {:id 1})
                    (deliver entered-second-packet true)
                    (handler {:id 2}))
                  pcap/close!
                  (fn [_] (deliver closed true))
                  pcap/breakloop! (fn [_] nil)]
      (let [capture (core/start-capture
                     {:path "dummy.pcap"
                      :queue-cap 1
                      :queue-mode :blocking})]
        (is (true? (deref entered-second-packet 1000 false)))
        (.close ^java.io.Closeable capture)
        (is (true? (deref closed 1000 false)))
        (let [stats (core/capture-stats capture)]
          (is (= :closed (:state stats)))
          (is (= :closed (:stop-reason stats)))
          (is (= 1 (get-in stats [:queue :blocked-events])))
          (is (<= 0 (get-in stats [:queue :blocked-ns]))))))))

(deftest managed-capture-stop-is-idempotent
  (let [loop-started (promise)]
    (with-redefs [pcap/open-offline (fn [_ _] :handle)
                  pcap/loop-n-or-ms!
                  (fn [_ config _]
                    (deliver loop-started true)
                    (loop []
                      (when-not ((:stop? config) nil)
                        (Thread/sleep 1)
                        (recur))))
                  pcap/close! (fn [_] nil)
                  pcap/breakloop! (fn [_] nil)]
      (with-open [^java.io.Closeable capture
                  (core/start-capture {:path "dummy.pcap"})]
        (is (true? (deref loop-started 1000 false)))
        (is (nil? (core/stop-capture! capture)))
        (is (nil? (core/stop-capture! capture)))
        (is (= [] (vec (core/capture-packets capture))))
        (is (= :consumer
               (:stop-reason (core/capture-stats capture))))))))

(deftest managed-capture-validates-public-contract
  (testing "source validation"
    (is (thrown-with-msg? clojure.lang.ExceptionInfo
                          #"requires either"
                          (core/start-capture {})))
    (is (thrown-with-msg? clojure.lang.ExceptionInfo
                          #"not both"
                          (core/start-capture
                           {:device "en0" :path "trace.pcap"}))))
  (testing "queue validation"
    (is (thrown-with-msg? clojure.lang.ExceptionInfo
                          #"queue-mode"
                          (core/start-capture
                           {:path "trace.pcap" :queue-mode :unknown})))
    (is (thrown-with-msg? clojure.lang.ExceptionInfo
                          #"queue-cap"
                          (core/start-capture
                           {:path "trace.pcap" :queue-cap 0}))))
  (testing "lifecycle validation"
    (is (thrown-with-msg? clojure.lang.ExceptionInfo
                          #":max"
                          (core/start-capture
                           {:path "trace.pcap" :max 0})))
    (is (thrown-with-msg? clojure.lang.ExceptionInfo
                          #":error-mode"
                          (core/start-capture
                           {:path "trace.pcap" :error-mode :ignore})))
    (is (thrown-with-msg? clojure.lang.ExceptionInfo
                          #":stop\\?"
                          (core/start-capture
                           {:path "trace.pcap" :stop? 42})))))
