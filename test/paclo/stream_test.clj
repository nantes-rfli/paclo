(ns paclo.stream-test
  (:require
   [clojure.test :refer [deftest is]]
   [paclo.stream :as stream])
  (:import
   [java.io Closeable]))

(defn- blocking-branch
  []
  {:buffer-mode :blocking
   :buffer-cap 16})

(deftest public-fan-out-requires-at-least-two-branches
  (doseq [branches [nil {} {:only (blocking-branch)}]]
    (is (thrown-with-msg?
         clojure.lang.ExceptionInfo
         #"at least two branches"
         (stream/fan-out [] branches)))))

(deftest public-branches-compose-with-standard-reduction
  (with-open [^Closeable fanout
              (stream/fan-out
               [nil false :packet]
               {:left (blocking-branch)
                :right (blocking-branch)})
              ^Closeable left (stream/branch fanout :left)
              ^Closeable right (stream/branch fanout :right)]
    (let [left-result (future (vec left))
          right-result (future (transduce (map identity) conj [] right))]
      (is (= [nil false :packet] @left-result))
      (is (= [nil false :packet] @right-result)))
    (let [snapshot (stream/stats fanout)]
      (is (= 1 (:schema-version snapshot)))
      (is (= 3 (get-in snapshot [:source :received])))
      (is (= 3 (get-in snapshot [:branches :left :delivered])))
      (is (= 3 (get-in snapshot [:branches :right :delivered]))))))

(deftest public-branch-errors-remain-explicit
  (with-open [^Closeable fanout
              (stream/fan-out
               []
               {:left (blocking-branch)
                :right (blocking-branch)})]
    (is (thrown-with-msg?
         clojure.lang.ExceptionInfo
         #"unknown stream branch"
         (stream/branch fanout :missing)))
    (with-open [^Closeable left (stream/branch fanout :left)]
      (is (instance? Closeable left))
      (is (thrown-with-msg?
           clojure.lang.ExceptionInfo
           #"only be acquired once"
           (stream/branch fanout :left))))))
