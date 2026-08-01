(ns paclo.stream-spike-test
  (:require
   [clojure.test :refer [deftest is testing]]
   [paclo.dev.stream-spike :as spike])
  (:import
   [java.io Closeable]))

(def ^:private backends [:jdk-array :jdk-linked :core-async])

(defn- config
  ([mode]
   (config mode 16))
  ([mode capacity]
   {:buffer-mode mode
    :buffer-cap capacity}))

(defn- eventually [^long timeout-ms pred]
  (let [deadline
        (unchecked-add (System/currentTimeMillis) timeout-ms)]
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

(deftest fan-out-validates-input
  (is (thrown-with-msg?
       clojure.lang.ExceptionInfo
       #"source must be seqable"
       (spike/fan-out 42 {:a (config :blocking)})))
  (is (thrown-with-msg?
       clojure.lang.ExceptionInfo
       #"non-empty branch map"
       (spike/fan-out [] {})))
  (is (thrown-with-msg?
       clojure.lang.ExceptionInfo
       #"branch id"
       (spike/fan-out [] {"a" (config :blocking)})))
  (is (thrown-with-msg?
       clojure.lang.ExceptionInfo
       #"buffer-mode"
       (spike/fan-out [] {:a {:buffer-mode :unknown}})))
  (is (thrown-with-msg?
       clojure.lang.ExceptionInfo
       #"buffer-cap"
       (spike/fan-out [] {:a {:buffer-mode :blocking
                              :buffer-cap 0}})))
  (is (thrown-with-msg?
       clojure.lang.ExceptionInfo
       #"cancel"
       (spike/fan-out [] {:a (config :blocking)} {:cancel! 42}))))

(deftest branch-preserves-values-including-nil
  (doseq [backend backends]
    (testing (name backend)
      (with-open [^Closeable fanout
                  (spike/fan-out
                   [nil :a nil :b]
                   {:values (config :blocking)}
                   {:backend backend})
                  ^Closeable values
                  (spike/branch fanout :values)]
        (is (= [nil :a nil :b] (vec values)))
        (is (true? (spike/await! fanout)))
        (let [stats (spike/stats fanout)]
          (is (= :source-exhausted (:stop-reason stats)))
          (is (= 4 (get-in stats [:source :received])))
          (is (= 4 (get-in stats [:branches :values :delivered])))
          (is (zero? (get-in stats [:branches :values :dropped]))))))))

(deftest branch-supports-seq-reduce-and-transduce
  (doseq [backend backends]
    (testing (name backend)
      (with-open [^Closeable fanout
                  (spike/fan-out
                   (range 10)
                   {:values (config :blocking 16)}
                   {:backend backend})
                  ^Closeable values
                  (spike/branch fanout :values)]
        (is (= (vec (range 10)) (vec values))))

      (with-open [^Closeable fanout
                  (spike/fan-out
                   (range 10)
                   {:values (config :blocking 16)}
                   {:backend backend})
                  ^Closeable values
                  (spike/branch fanout :values)]
        (is (= 45 (reduce + 0 values))))

      (with-open [^Closeable fanout
                  (spike/fan-out
                   (range 10)
                   {:values (config :blocking 16)}
                   {:backend backend})
                  ^Closeable values
                  (spike/branch fanout :values)]
        (is (= 55 (transduce (map inc) + 0 values)))))))

(deftest branch-handle-and-consumer-are-single-use
  (doseq [backend backends]
    (testing (name backend)
      (with-open [^Closeable fanout
                  (spike/fan-out
                   (range 4)
                   {:values (config :blocking 8)}
                   {:backend backend})
                  ^Closeable values
                  (spike/branch fanout :values)]
        (is (thrown-with-msg?
             clojure.lang.ExceptionInfo
             #"handle may only be acquired once"
             (spike/branch fanout :values)))
        (is (= [0 1 2 3] (vec values)))
        (let [error (thrown-by #(reduce + 0 values))]
          (is (instance? clojure.lang.ExceptionInfo error))
          (is (re-find #"consumed once" (.getMessage ^Throwable error))))))))

(deftest reduced-closes-branch-and-cancels-last-source
  (doseq [backend backends]
    (testing (name backend)
      (let [cancel-count (atom 0)]
        (with-open [^Closeable fanout
                    (spike/fan-out
                     (range 100000)
                     {:values (config :blocking 4)}
                     {:backend backend
                      :cancel! #(swap! cancel-count inc)})
                    ^Closeable values
                    (spike/branch fanout :values)]
          (is (= 3
                 (reduce
                  (fn [^long count _]
                    (let [next-count (unchecked-inc count)]
                      (if (= 3 next-count)
                        (reduced next-count)
                        next-count)))
                  0
                  values)))
          (is (true? (spike/await! fanout)))
          (is (= 1 @cancel-count))
          (let [stats (spike/stats fanout)]
            (is (= :no-branches (:stop-reason stats)))
            (is (= :reduced
                   (get-in stats [:branches :values :state])))
            (is (= :reduced
                   (get-in stats [:branches :values :stop-reason])))))))))

(deftest consumer-error-isolated-from-other-branch
  (doseq [backend backends]
    (testing (name backend)
      (with-open [^Closeable fanout
                  (spike/fan-out
                   (range 200)
                   {:healthy (config :blocking 32)
                    :failing (config :blocking 32)}
                   {:backend backend})
                  ^Closeable healthy
                  (spike/branch fanout :healthy)
                  ^Closeable failing
                  (spike/branch fanout :failing)]
        (let [healthy-result (future (vec healthy))]
          (let [error
                (thrown-by
                 #(reduce
                   (fn [^long count value]
                     (when (= 3 value)
                       (throw (RuntimeException. "consumer failed")))
                     (unchecked-inc count))
                   0
                   failing))]
            (is (instance? RuntimeException error))
            (is (re-find #"consumer failed"
                         (.getMessage ^Throwable error))))
          (is (= (vec (range 200)) @healthy-result))
          (is (true? (spike/await! fanout)))
          (let [stats (spike/stats fanout)]
            (is (= :failed
                   (get-in stats [:branches :failing :state])))
            (is (= "consumer failed"
                   (get-in stats [:branches :failing :error :message])))
            (is (= 200
                   (get-in stats [:branches :healthy :delivered])))))))))

(deftest source-error-reaches-stats-and-branches
  (doseq [backend backends]
    (testing (name backend)
      (let [source
            (lazy-seq
             (cons :first
                   (lazy-seq
                    (throw (RuntimeException. "source failed")))))]
        (with-open [^Closeable fanout
                    (spike/fan-out
                     source
                     {:values (config :blocking 4)}
                     {:backend backend})
                    ^Closeable values
                    (spike/branch fanout :values)]
          (let [error (thrown-by #(vec values))]
            (is (instance? clojure.lang.ExceptionInfo error))
            (is (re-find #"source failed"
                         (.getMessage ^Throwable error))))
          (is (true? (spike/await! fanout)))
          (let [stats (spike/stats fanout)]
            (is (= :error (:stop-reason stats)))
            (is (= :failed (:state stats)))
            (is (= "source failed" (get-in stats [:error :message])))
            (is (= :failed
                   (get-in stats [:branches :values :state])))
            (is (= :source-error
                   (get-in stats
                           [:branches :values :stop-reason])))))))))

(deftest closing-one-branch-unblocks-it-without-stopping-others
  (doseq [backend backends]
    (testing (name backend)
      (with-open [^Closeable fanout
                  (spike/fan-out
                   (range 1000)
                   {:healthy (config :blocking 32)
                    :abandoned (config :blocking 1)}
                   {:backend backend})
                  ^Closeable healthy
                  (spike/branch fanout :healthy)
                  ^Closeable abandoned
                  (spike/branch fanout :abandoned)]
        (let [healthy-result (future (vec healthy))]
          (is (true?
               (eventually
                1000
                #(= 1
                    (get-in (spike/stats fanout)
                            [:branches :abandoned :buffer :max-depth])))))
          (.close abandoned)
          (is (= (vec (range 1000)) @healthy-result))
          (is (true? (spike/await! fanout)))
          (let [stats (spike/stats fanout)]
            (is (= :closed
                   (get-in stats [:branches :abandoned :state])))
            (is (= :closed
                   (get-in stats
                           [:branches :abandoned :stop-reason])))
            (is (= 1000
                   (get-in stats [:branches :healthy :delivered])))))))))

(deftest slow-dropping-branch-does-not-block-fast-branch
  (doseq [backend backends]
    (testing (name backend)
      (with-open [^Closeable fanout
                  (spike/fan-out
                   (range 2000)
                   {:fast (config :blocking 64)
                    :slow (config :dropping 1)}
                   {:backend backend})
                  ^Closeable fast
                  (spike/branch fanout :fast)
                  ^Closeable slow
                  (spike/branch fanout :slow)]
        (let [fast-result (future (vec fast))]
          (is (= (vec (range 2000)) @fast-result))
          (is (true? (spike/await! fanout)))
          ;; Drain the one value that may remain after the source closes.
          (let [slow-values (vec slow)
                stats (spike/stats fanout)]
            (is (<= (count slow-values) 1))
            (is (= 2000
                   (get-in stats [:branches :fast :delivered])))
            (is (pos? (get-in stats [:branches :slow :dropped])))
            (is (zero?
                 (get-in stats
                         [:branches :slow :buffer :blocked-events])))
            (is (zero?
                 (get-in stats
                         [:branches :slow :buffer :blocked-ns])))))))))

(deftest close-unblocks-full-blocking-buffer
  (doseq [backend backends]
    (testing (name backend)
      (let [cancel-count (atom 0)
            fanout
            (spike/fan-out
             (range)
             {:blocked (config :blocking 1)}
             {:backend backend
              :cancel! #(swap! cancel-count inc)})]
        (try
          (is (true?
               (eventually
                1000
                #(= 1
                    (get-in (spike/stats fanout)
                            [:branches :blocked :buffer :max-depth])))))
          (let [started (System/nanoTime)]
            (.close ^Closeable fanout)
            (is (< (/ (- (System/nanoTime) started) 1000000.0)
                   1000.0)))
          (is (= 1 @cancel-count))
          (is (true? (spike/await! fanout)))
          (is (pos?
               (get-in (spike/stats fanout)
                       [:branches :blocked :buffer :blocked-events])))
          ;; Explicitly verify idempotence.
          (.close ^Closeable fanout)
          (is (= 1 @cancel-count))
          (finally
            (.close ^Closeable fanout)))))))

(deftest cancel-unblocks-a-source-that-is-waiting
  (doseq [backend backends]
    (testing (name backend)
      (let [released (promise)
            source
            (lazy-seq
             (cons :first
                   (lazy-seq
                    @released
                    nil)))
            fanout
            (spike/fan-out
             source
             {:values (config :blocking 4)}
             {:backend backend
              :cancel! #(deliver released true)})]
        (try
          (is (true?
               (eventually
                1000
                #(= 1 (get-in (spike/stats fanout)
                              [:source :received])))))
          (.close ^Closeable fanout)
          (is (true? (spike/await! fanout)))
          (finally
            (deliver released true)
            (.close ^Closeable fanout)))))))
