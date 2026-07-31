(ns paclo.stream-impl-test
  (:require
   [clojure.edn :as edn]
   [clojure.test :refer [deftest is]]
   [paclo.stream.impl :as stream])
  (:import
   [java.io Closeable]
   [java.lang.ref WeakReference]))

(defn- config
  ([mode]
   (config mode 16))
  ([mode capacity]
   {:buffer-mode mode
    :buffer-cap capacity}))

(defn- eventually [^long timeout-ms pred]
  (let [deadline (+ (System/currentTimeMillis) timeout-ms)]
    (loop []
      (cond
        (pred) true
        (< (System/currentTimeMillis) deadline)
        (do
          (Thread/sleep 5)
          (recur))
        :else false))))

(defn- thrown-by [f]
  (try
    (f)
    nil
    (catch Throwable error
      error)))

(defn- sum3 ^long [^long a ^long b ^long c]
  (unchecked-add a (unchecked-add b c)))

(defn- assert-branch-invariants [branch-stats]
  (let [{:keys [offered enqueued delivered dropped cancelled abandoned buffer]}
        branch-stats]
    (is (= offered
           (sum3 (long enqueued) (long dropped) (long cancelled))))
    (is (= enqueued
           (sum3 (long delivered)
                 (long abandoned)
                 (long (:depth buffer)))))
    (is (<= 0 (:depth buffer) (:capacity buffer)))
    (is (<= 0 (:max-depth buffer) (:capacity buffer)))
    (when (= :blocking (:mode buffer))
      (is (zero? dropped)))))

(defn- marker-stream []
  (let [marker (Object.)
        marker-ref (WeakReference. marker)
        fanout (stream/start
                (lazy-seq (cons marker (range 10000)))
                {:values (config :blocking 32)})]
    {:fanout fanout
     :values (stream/branch fanout :values)
     :marker-ref marker-ref}))

(defn- slow-count [values]
  (reduce
   (fn [^long count _]
     (when (zero? (bit-and count 255))
       (Thread/sleep 1))
     (unchecked-inc count))
   0
   values))

(defn- non-decreasing? [values]
  (or (empty? values)
      (apply <= values)))

(deftest start-validates-the-internal-contract
  (is (thrown-with-msg?
       clojure.lang.ExceptionInfo
       #"source must be seqable"
       (stream/start 42 {:a (config :blocking)})))
  (is (thrown-with-msg?
       clojure.lang.ExceptionInfo
       #"non-empty branch map"
       (stream/start [] {})))
  (is (thrown-with-msg?
       clojure.lang.ExceptionInfo
       #"branch id"
       (stream/start [] {"a" (config :blocking)})))
  (is (thrown-with-msg?
       clojure.lang.ExceptionInfo
       #"config must be a map"
       (stream/start [] {:a nil})))
  (is (thrown-with-msg?
       clojure.lang.ExceptionInfo
       #"buffer-mode"
       (stream/start [] {:a {:buffer-mode :unknown}})))
  (is (thrown-with-msg?
       clojure.lang.ExceptionInfo
       #"buffer-cap"
       (stream/start [] {:a (config :blocking 0)})))
  (is (thrown-with-msg?
       clojure.lang.ExceptionInfo
       #"cancel"
       (stream/start [] {:a (config :blocking)} {:cancel! 42})))
  (is (thrown-with-msg?
       clojure.lang.ExceptionInfo
       #"close-timeout-ms"
       (stream/start [] {:a (config :blocking)}
                     {:close-timeout-ms 0}))))

(deftest branches-compose-with-seq-reduce-and-transduce
  (with-open [^Closeable fanout
              (stream/start
               [nil :a nil :b]
               {:values (config :blocking)})
              ^Closeable values
              (stream/branch fanout :values)]
    (is (= [nil :a nil :b] (vec values)))
    (is (true? (stream/await! fanout)))
    (assert-branch-invariants
     (get-in (stream/stats fanout) [:branches :values])))

  (with-open [^Closeable fanout
              (stream/start (range 10) {:values (config :blocking)})
              ^Closeable values
              (stream/branch fanout :values)]
    (is (= 45 (reduce + 0 values))))

  (with-open [^Closeable fanout
              (stream/start (range 10) {:values (config :blocking)})
              ^Closeable values
              (stream/branch fanout :values)]
    (is (= 55 (transduce (map inc) + 0 values)))))

(deftest two-blocking-branches-receive-every-value-in-order
  (with-open [^Closeable fanout
              (stream/start
               (range 1000)
               {:left (config :blocking 32)
                :right (config :blocking 32)})
              ^Closeable left
              (stream/branch fanout :left)
              ^Closeable right
              (stream/branch fanout :right)]
    (let [left-result (future (vec left))
          right-result (future (vec right))]
      (is (= (vec (range 1000)) @left-result @right-result))
      (is (true? (stream/await! fanout)))
      (let [stats (stream/stats fanout)]
        (is (= :closed (:state stats)))
        (is (= :source-exhausted (:stop-reason stats)))
        (is (= 1000 (get-in stats [:source :received])))
        (doseq [id [:left :right]]
          (is (= :completed (get-in stats [:branches id :state])))
          (assert-branch-invariants (get-in stats [:branches id])))))))

(deftest consumed-lazy-source-head-is-not-retained
  (let [{:keys [fanout values marker-ref]} (marker-stream)]
    (try
      (is (= 10001
             (reduce
              (fn [^long count _]
                (unchecked-inc count))
              0
              values)))
      (is (true? (stream/await! fanout)))
      (is (true?
           (eventually
            2000
            #(do
               (System/gc)
               (nil? (.get ^WeakReference marker-ref))))))
      (finally
        (.close ^Closeable values)
        (.close ^Closeable fanout)))))

(deftest running-stats-snapshots-are-data-and-monotonic
  (with-open [^Closeable fanout
              (stream/start
               (range 20000)
               {:left (config :blocking 32)
                :right (config :blocking 32)})
              ^Closeable left (stream/branch fanout :left)
              ^Closeable right (stream/branch fanout :right)]
    (let [left-task (future (slow-count left))
          right-task (future (slow-count right))
          snapshots
          (loop [result []]
            (let [snapshot (stream/stats fanout)
                  result* (conj result snapshot)]
              (if (and (realized? left-task) (realized? right-task))
                result*
                (do
                  (Thread/sleep 1)
                  (recur result*)))))
          paths [[:source :received]
                 [:branches :left :offered]
                 [:branches :left :enqueued]
                 [:branches :left :delivered]
                 [:branches :right :offered]
                 [:branches :right :enqueued]
                 [:branches :right :delivered]]]
      (is (= 20000 @left-task @right-task))
      (is (< 5 (count snapshots)))
      (is (every? #(= % (edn/read-string (pr-str %))) snapshots))
      (doseq [path paths]
        (is (non-decreasing? (map #(get-in % path) snapshots))))
      (is
       (every?
        (fn [snapshot]
          (every?
           (fn [id]
             (let [{:keys [depth max-depth capacity]}
                   (get-in snapshot [:branches id :buffer])]
               (and (<= 0 depth capacity)
                    (<= 0 max-depth capacity))))
           [:left :right]))
        snapshots))
      (let [final-stats (stream/stats fanout)]
        (doseq [id [:left :right]]
          (assert-branch-invariants
           (get-in final-stats [:branches id])))))))

(deftest branch-handle-and-consumer-have-single-ownership
  (with-open [^Closeable fanout
              (stream/start (range 4) {:values (config :blocking)})
              ^Closeable values
              (stream/branch fanout :values)]
    (is (thrown-with-msg?
         clojure.lang.ExceptionInfo
         #"unknown stream branch"
         (stream/branch fanout :missing)))
    (is (thrown-with-msg?
         clojure.lang.ExceptionInfo
         #"handle may only be acquired once"
         (stream/branch fanout :values)))
    (is (= [0 1 2 3] (vec values)))
    (let [error (thrown-by #(reduce + 0 values))]
      (is (instance? clojure.lang.ExceptionInfo error))
      (is (re-find #"consumed once"
                   (.getMessage ^Throwable error))))))

(deftest reduced-closes-the-last-branch-and-cancels-once
  (let [cancel-count (atom 0)]
    (with-open [^Closeable fanout
                (stream/start
                 (range 100000)
                 {:values (config :blocking 4)}
                 {:cancel! #(swap! cancel-count inc)})
                ^Closeable values
                (stream/branch fanout :values)]
      (is (= 3
             (reduce
              (fn [^long count _]
                (let [next-count (unchecked-inc count)]
                  (if (= 3 next-count)
                    (reduced next-count)
                    next-count)))
              0
              values)))
      (is (true? (stream/await! fanout)))
      (is (= 1 @cancel-count))
      (let [stats (stream/stats fanout)
            branch-stats (get-in stats [:branches :values])]
        (is (= :no-branches (:stop-reason stats)))
        (is (= :reduced (:state branch-stats)))
        (is (= :reduced (:stop-reason branch-stats)))
        (assert-branch-invariants branch-stats)))))

(deftest consumer-error-does-not-stop-another-branch
  (with-open [^Closeable fanout
              (stream/start
               (range 200)
               {:healthy (config :blocking 32)
                :failing (config :blocking 32)})
              ^Closeable healthy
              (stream/branch fanout :healthy)
              ^Closeable failing
              (stream/branch fanout :failing)]
    (let [healthy-result (future (vec healthy))
          error
          (thrown-by
           #(reduce
             (fn [^long count value]
               (when (= 3 value)
                 (throw (RuntimeException. "consumer failed")))
               (unchecked-inc count))
             0
             failing))]
      (is (instance? RuntimeException error))
      (is (= (vec (range 200)) @healthy-result))
      (is (true? (stream/await! fanout)))
      (let [stats (stream/stats fanout)]
        (is (= :failed (get-in stats [:branches :failing :state])))
        (is (= "consumer failed"
               (get-in stats [:branches :failing :error :message])))
        (is (= 200 (get-in stats [:branches :healthy :delivered])))
        (doseq [id [:healthy :failing]]
          (assert-branch-invariants (get-in stats [:branches id])))))))

(deftest source-error-reaches-stats-and-open-branches
  (let [source
        (lazy-seq
         (cons :first
               (lazy-seq
                (throw (RuntimeException. "source failed")))))]
    (with-open [^Closeable fanout
                (stream/start source {:values (config :blocking 4)})
                ^Closeable values
                (stream/branch fanout :values)]
      (let [error (thrown-by #(vec values))]
        (is (instance? clojure.lang.ExceptionInfo error))
        (is (re-find #"source failed" (.getMessage ^Throwable error))))
      (is (true? (stream/await! fanout)))
      (let [stats (stream/stats fanout)
            branch-stats (get-in stats [:branches :values])]
        (is (= :failed (:state stats)))
        (is (= :error (:stop-reason stats)))
        (is (= "source failed" (get-in stats [:error :message])))
        (is (= :failed (:state branch-stats)))
        (is (= :source-error (:stop-reason branch-stats)))
        (assert-branch-invariants branch-stats)))))

(deftest slow-dropping-branch-is-isolated
  (with-open [^Closeable fanout
              (stream/start
               (range 2000)
               {:fast (config :blocking 64)
                :slow (config :dropping 1)})
              ^Closeable fast
              (stream/branch fanout :fast)
              ^Closeable slow
              (stream/branch fanout :slow)]
    (let [fast-result (future (vec fast))]
      (is (= (vec (range 2000)) @fast-result))
      (is (true? (stream/await! fanout)))
      (is (<= (count (vec slow)) 1))
      (let [stats (stream/stats fanout)
            slow-stats (get-in stats [:branches :slow])]
        (is (= 2000 (get-in stats [:branches :fast :delivered])))
        (is (pos? (:dropped slow-stats)))
        (is (zero? (get-in slow-stats [:buffer :blocked-events])))
        (is (zero? (get-in slow-stats [:buffer :blocked-ns])))
        (doseq [id [:fast :slow]]
          (assert-branch-invariants (get-in stats [:branches id])))))))

(deftest closing-a-full-runtime-is-bounded-and-idempotent
  (let [cancel-count (atom 0)
        fanout
        (stream/start
         (range)
         {:blocked (config :blocking 1)}
         {:cancel! #(swap! cancel-count inc)})]
    (try
      (is (true?
           (eventually
            1000
            #(= 1
                (get-in (stream/stats fanout)
                        [:branches :blocked :buffer :max-depth])))))
      (let [started (System/nanoTime)]
        (.close ^Closeable fanout)
        (is (< (/ (- (System/nanoTime) started) 1000000.0)
               1000.0)))
      (is (true? (stream/await! fanout)))
      (is (= 1 @cancel-count))
      (.close ^Closeable fanout)
      (is (= 1 @cancel-count))
      (let [branch-stats (get-in (stream/stats fanout)
                                 [:branches :blocked])]
        (is (pos? (get-in branch-stats [:buffer :blocked-events])))
        (assert-branch-invariants branch-stats))
      (finally
        (.close ^Closeable fanout)))))

(deftest cancel-unblocks-an-externally-waiting-source
  (let [released (promise)
        source
        (lazy-seq
         (cons :first
               (lazy-seq
                @released
                nil)))
        fanout
        (stream/start
         source
         {:values (config :blocking 4)}
         {:cancel! #(deliver released true)})]
    (try
      (is (true?
           (eventually
            1000
            #(= 1 (get-in (stream/stats fanout)
                          [:source :received])))))
      (.close ^Closeable fanout)
      (is (true? (stream/await! fanout)))
      (finally
        (deliver released true)
        (.close ^Closeable fanout)))))

(deftest close-timeout-is-an-explicit-failure
  (let [released (promise)
        source (lazy-seq @released nil)
        fanout
        (stream/start
         source
         {:values (config :blocking)}
         {:close-timeout-ms 25})]
    (try
      (let [error (thrown-by #(.close ^Closeable fanout))]
        (is (instance? clojure.lang.ExceptionInfo error))
        (is (re-find #"dispatcher did not stop"
                     (.getMessage ^Throwable error))))
      (let [stats (stream/stats fanout)]
        (is (= :failed (:state stats)))
        (is (= :close-timeout (:stop-reason stats)))
        (is (re-find #"dispatcher did not stop"
                     (get-in stats [:error :message]))))
      (finally
        (deliver released true)
        (is (true? (stream/await! fanout)))
        (.close ^Closeable fanout)))))

(deftest cancel-callback-failure-is-data
  (let [released (promise)
        source (lazy-seq @released nil)
        fanout
        (stream/start
         source
         {:values (config :blocking)}
         {:cancel! #(do
                      (deliver released true)
                      (throw (RuntimeException. "cancel failed")))})]
    (try
      (.close ^Closeable fanout)
      (is (true? (stream/await! fanout)))
      (let [stats (stream/stats fanout)]
        (is (= :closed (:state stats)))
        (is (= :closed (:stop-reason stats)))
        (is (= "cancel failed"
               (get-in stats [:cancel-error :message]))))
      (finally
        (deliver released true)
        (.close ^Closeable fanout)))))
