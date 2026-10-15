(ns paclo.capture-lifecycle-test
  (:require
   [clojure.test :refer [deftest is testing]]
   [paclo.core :as core]
   [paclo.dev.perf-data :as data]
   [paclo.pcap :as pcap])
  (:import
   [java.io Closeable]
   [java.util.concurrent CountDownLatch]))

(defn- await-condition [pred]
  (let [deadline (+ (System/nanoTime) 5000000000)]
    (loop []
      (cond
        (pred) true
        (>= (System/nanoTime) deadline) false
        :else (do (Thread/sleep 1) (recur))))))

(defn- with-fixture [f]
  (let [file (java.io.File/createTempFile "paclo-lifecycle" ".pcap")
        frame (data/ethernet-ipv4-frame 64 :udp)]
    (try
      (core/write-pcap!
       (map (fn [i] {:bytes frame :ts-sec 1 :ts-usec i}) (range 128))
       (.getAbsolutePath file))
      (f {:path (.getAbsolutePath file) :max 1000 :max-time-ms 60000
          :queue-cap 1})
      (finally (.delete file)))))

(defn- with-native-probe
  "Observe real native reads and close; only intercept calls to record progress.
   Always interrupt/await a stranded test producer before restoring the Vars."
  [f]
  (let [read-loop pcap/loop-n-or-ms!
        close pcap/close!
        start-future clojure.core/future-call
        producer (atom nil)
        thread (atom nil)
        attempts (atom 0)
        accepted (atom 0)
        closed (atom 0)
        finished (promise)]
    (with-redefs [pcap/loop-n-or-ms!
                  (fn [h opts handler]
                    (reset! thread (Thread/currentThread))
                    (read-loop h opts
                               (fn [packet]
                                 (swap! attempts inc)
                                 (handler packet)
                                 (swap! accepted inc))))
                  pcap/close! (fn [h] (close h) (swap! closed inc))
                  clojure.core/future-call
                  (fn [task]
                    (let [running (start-future
                                   #(try (task)
                                         (finally (deliver finished true))))]
                      (reset! producer running)
                      running))]
      (try
        (f {:producer producer :thread thread :attempts attempts :start-future start-future
            :accepted accepted :closed closed :finished finished})
        (finally
          (when @producer
            (future-cancel @producer)
            (is (true? (deref finished 5000 false))
              "test producer must finish before native probes are removed")))))))

(defn- parked-in-put? [thread]
  (when-let [^Thread producer @thread]
    (some (fn [^StackTraceElement frame]
            (and (= "java.util.concurrent.LinkedBlockingQueue" (.getClassName frame))
                 (= "put" (.getMethodName frame))))
          (.getStackTrace producer))))

(deftest lazy-prefix-abandonment-retains-real-native-source
  (with-fixture
    (fn [opts]
      (with-native-probe
        (fn [{:keys [producer thread attempts accepted closed]}]
          (let [stop? (atom false)
                queue-stats (promise)
                packets (core/packets
                         (assoc opts :max-time-ms 1000 :stop? (fn [_] @stop?)
                                :on-queue-stats #(deliver queue-stats %)))]
            (is (= [0] (mapv :ts-usec (take 1 packets))))
            (is (await-condition #(parked-in-put? thread)))
            (is (= 3 @attempts))
            (is (= 2 @accepted))
            ;; One delivered + one queued + one in put. A changed predicate
            ;; and an elapsed deadline cannot run while that put is parked.
            (reset! stop? true)
            (Thread/sleep 1100)
            (is (parked-in-put? thread))
            (is (not (future-done? @producer)))
            (is (zero? @closed))
            (is (not (realized? queue-stats)))
            ;; Test-only recovery: resuming the SAME sequence frees a slot.
            ;; This is not an early cancellation API for ordinary callers.
            (is (= [1 2] (mapv :ts-usec (rest packets))))
            (is (not= ::timeout (deref @producer 5000 ::timeout)))
            (is (= 1 @closed))
            (is (= {:capacity 1 :enqueued 3 :dropped 0 :max-depth 1}
                   (select-keys @queue-stats
                                [:capacity :enqueued :dropped :max-depth])))))))))

(deftest lazy-backpressure-preserves-order-and-dropping-can-finish-unconsumed
  (with-fixture
    (fn [opts]
      (doseq [mode [:blocking :dropping]]
        (with-native-probe
          (fn [{:keys [producer thread closed]}]
            (let [stats (promise)
                  packets (core/packets (assoc opts :queue-mode mode
                                               :on-queue-stats #(deliver stats %)))]
              (if (= mode :blocking)
                (do
                  (is (await-condition #(parked-in-put? thread)))
                  (is (zero? @closed))
                  (is (= (vec (range 128)) (mapv :ts-usec packets))))
                (do
                  (is (not= ::timeout (deref @producer 5000 ::timeout)))
                  (is (= [0] (mapv :ts-usec packets)))))
              (is (not= ::timeout (deref @producer 5000 ::timeout)))
              (is (= 1 @closed))
              (is (= 1 (:max-depth @stats)))
              (is (= (if (= mode :blocking) 0 127) (:dropped @stats)))
              (is (= 128 (+ (long (:enqueued @stats)) (long (:dropped @stats))))))))))))

(deftest managed-prefix-stop-and-close-release-real-native-source
  (with-fixture
    (fn [opts]
      (doseq [action [:close :stop :concurrent]]
        (with-native-probe
          (fn [{:keys [producer closed start-future]}]
            (let [capture (core/start-capture opts)]
              (try
                ;; sequence may read ahead; the fixture exceeds that prefix.
                (is (= [0] (mapv :ts-usec (take 1 (core/capture-packets capture)))))
                (is (await-condition
                     #(pos? (long (get-in (core/capture-stats capture)
                                          [:queue :blocked-events])))))
                (is (= :running (:state (core/capture-stats capture))))
                (case action
                  :close (.close ^Closeable capture)
                  :stop (do
                          (core/stop-capture! capture)
                          ;; Stop alone must finish even with no further drain.
                          (is (not= ::timeout (deref @producer 5000 ::timeout)))
                          (is (= 1 @closed)))
                  :concurrent
                  (let [gate (CountDownLatch. 1)
                        ;; Use the original executor entry point so the probe
                        ;; still identifies only the capture producer.
                        workers (mapv (fn [i]
                                        (start-future
                                         #(do (.await gate)
                                              (if (even? (long i))
                                                (core/stop-capture! capture)
                                                (.close ^Closeable capture)))))
                                      (range 8))]
                    (.countDown gate)
                    (doseq [worker workers]
                      (is (not= ::timeout (deref worker 5000 ::timeout))))))
                (finally (.close ^Closeable capture)))
              (is (= 1 @closed))
              (is (= :closed (:state (core/capture-stats capture))))
              (is (zero? (long (get-in (core/capture-stats capture) [:queue :depth]))))
              (is (contains? #{:consumer :closed}
                             (:stop-reason (core/capture-stats capture))))
              (is (nil? (:error (core/capture-stats capture)))))))))))

(deftest managed-stop-does-not-race-native-close
  (let [loop-release (promise)
        breaking (promise)
        break-release (promise)
        finalizing (promise)
        closed (promise)
        producer-thread (atom nil)
        close-during-break? (atom false)
        break-active? (atom false)
        start-future clojure.core/future-call]
    (with-redefs [pcap/open-offline (fn [& _] :handle)
                  pcap/datalink (constantly 1)
                  pcap/loop-n-or-ms! (fn [& _]
                                       (reset! producer-thread (Thread/currentThread))
                                       @loop-release)
                  pcap/breakloop! (fn [_]
                                    (reset! break-active? true)
                                    (deliver breaking true)
                                    @break-release
                                    (reset! break-active? false))
                  pcap/close! (fn [_]
                                (reset! close-during-break? @break-active?)
                                (deliver closed true))]
      (let [capture (core/start-capture
                     {:path "dummy" :on-queue-stats #(deliver finalizing %)})
            stopping (start-future #(core/stop-capture! capture))]
        (try
          (is (true? (deref breaking 5000 false)))
          (deliver loop-release true)
          (is (map? (deref finalizing 5000 nil)))
          (testing "native close waits for an in-flight breakloop call"
            ;; Observe either the old unsafe close or the fixed producer
            ;; blocked acquiring the lifecycle monitor, without a timed guess.
            (is (await-condition #(or (realized? closed)
                                      (= Thread$State/BLOCKED
                                         (.getState ^Thread @producer-thread)))))
            (is (not (realized? closed))))
          (finally
            (deliver loop-release true)
            (deliver break-release true)
            (is (not= ::timeout (deref stopping 5000 ::timeout)))
            (.close ^Closeable capture)))
        (is (true? (deref closed 5000 false)))
        (is (false? @close-during-break?))))))

(deftest managed-normal-completion-and-dropping-close-once
  (with-fixture
    (fn [opts]
      (doseq [mode [:blocking :dropping]]
        (with-native-probe
          (fn [{:keys [producer closed]}]
            (with-open [capture (core/start-capture (assoc opts :queue-mode mode))]
              (when (= mode :dropping)
                (is (not= ::timeout (deref @producer 5000 ::timeout))))
              (let [packets (vec (core/capture-packets capture))
                    stats (core/capture-stats capture)]
                (is (= (if (= mode :blocking) 128 1) (count packets)))
                (is (= :eof (:stop-reason stats)))
                (is (= :closed (:state stats)))
                (is (= 128 (+ (long (get-in stats [:queue :enqueued]))
                              (long (get-in stats [:queue :dropped])))))
                (is (= 1 @closed))))))))))

(deftest lazy-count-limit-that-fits-queue-releases-source-without-consumer
  (with-fixture
    (fn [opts]
      (with-native-probe
        (fn [{:keys [producer closed]}]
          (let [packets (core/packets (assoc opts :max 1))]
            (is (not= ::timeout (deref @producer 5000 ::timeout)))
            (is (= 1 @closed))
            (is (= [0] (mapv :ts-usec packets)))))))))

(deftest managed-stop-retains-queued-prefix-for-draining
  (with-fixture
    (fn [opts]
      (with-native-probe
        (fn [{:keys [producer closed]}]
          (with-open [capture (core/start-capture opts)]
            (is (await-condition #(pos? (long (get-in (core/capture-stats capture)
                                                      [:queue :blocked-events])))))
            (core/stop-capture! capture)
            (is (not= ::timeout (deref @producer 5000 ::timeout)))
            (is (= 1 @closed))
            (is (= 1 (get-in (core/capture-stats capture) [:queue :depth])))
            (is (= [0] (mapv :ts-usec (core/capture-packets capture))))))))))

(deftest early-reduction-and-consumer-exceptions-release-native-source
  (with-fixture
    (fn [opts]
      (doseq [mode [:reduced :reducer-error :managed-error]]
        (with-native-probe
          (fn [{:keys [closed]}]
            (let [error (Exception. "consumer failed")]
              (case mode
                :reduced
                (let [{:keys [result stats]}
                      (core/reduce-packets-report opts (fn [_ p] (reduced (:ts-usec p))) nil)]
                  (is (= 0 result))
                  (is (= :reduced (:stop-reason stats))))
                :reducer-error
                (try
                  (core/reduce-packets opts (fn [_ _] (throw error)) nil)
                  (is false "expected reducer failure")
                  (catch Exception caught (is (identical? error caught))))
                :managed-error
                (try
                  (with-open [capture (core/start-capture
                                       (assoc opts :xform (map (fn [_] (throw error)))))]
                    (first (core/capture-packets capture)))
                  (is false "expected transformation failure")
                  (catch Exception caught (is (identical? error caught)))))
              (is (= 1 @closed)))))))))
