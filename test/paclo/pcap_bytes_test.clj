(ns paclo.pcap-bytes-test
  (:require
   [clojure.test :refer [deftest is testing]]
   [paclo.pcap :as p])
  (:import
   [paclo.jnr PcapHeader]))

(defn- normalize [metadata]
  (#'p/ensure-bytes-timestamp (assoc metadata :bytes (byte-array [1 2]))))

(deftest timestamp-precedence-and-boundaries
  (doseq [[metadata expected]
          [[{:ts-sec 10 :ts-usec 20} [10 20]]
           [{:sec 10 :usec 20} [10 20]]
           [{:ts-sec 10 :ts-usec 20 :sec 10 :usec 20} [10 20]]
           [{:ts-sec 10 :ts-usec 20 :sec 30 :usec 40} [10 20]]
           [{:ts-sec 10 :ts-usec 20 :sec nil :usec "ignored"} [10 20]]
           [{:ts-sec 0 :ts-usec 0} [0 0]]
           [{:sec 0 :usec 0} [0 0]]
           [{:ts-sec 4294967295N :ts-usec 999999} [4294967295 999999]]
           [{:sec 4294967295 :usec 999999} [4294967295 999999]]]]
    (testing (str metadata)
      (is (= expected (subvec (normalize metadata) 1 3))))))

(deftest invalid-timestamps
  (doseq [keys-pair [[:ts-sec :ts-usec] [:sec :usec]]
          [field values] [[(first keys-pair) [-1 4294967296N 1.5 "1" nil false]]
                          [(second keys-pair) [-1 1000000 2.5 "2" nil false]]]
          value values]
    (let [metadata (assoc (zipmap keys-pair [1 2]) field value)]
      (testing (str metadata)
        (is (thrown? clojure.lang.ExceptionInfo (normalize metadata))))))
  (doseq [metadata [{:ts-sec 1} {:ts-usec 2} {:ts-sec nil} {:ts-usec nil}
                    {:ts-sec 1 :sec 3 :usec 4}
                    {:ts-usec 2 :sec 3 :usec 4}
                    {:ts-sec nil :ts-usec nil :sec 3 :usec 4}]]
    (is (thrown? clojure.lang.ExceptionInfo (normalize metadata)))))

(deftest omitted-and-partial-legacy-timestamps-use-now
  (with-redefs [p/now-sec-usec (fn [] [123 456])]
    (doseq [metadata [{} {:sec 10} {:usec 20} {:sec nil} {:usec nil}]]
      (is (= [123 456] (subvec (normalize metadata) 1 3))))
    (is (= [123 456] (subvec (#'p/ensure-bytes-timestamp (byte-array [3])) 1 3))))
  (let [before (System/currentTimeMillis)]
    (doseq [input [(byte-array [3 4]) {:bytes (byte-array [3 4])}]]
      (let [[ba sec usec] (#'p/ensure-bytes-timestamp input)
            after (System/currentTimeMillis)]
        (is (= [3 4] (vec ba)))
        (is (<= before (+ (* (long sec) 1000) (quot (long usec) 1000)) after))
        (is (<= 0 usec 999999))))))

(deftest lengths-and-byte-input
  (doseq [[metadata expected] [[{} [2 2]]
                               [{:caplen 2} [2 2]]
                               [{:len 2} [2 2]]
                               [{:caplen 2 :len 1500} [2 1500]]
                               [{:len 4294967295N} [2 4294967295]]]]
    (is (= expected (subvec (normalize metadata) 3 5))))
  (is (= [2 2] (subvec (#'p/ensure-bytes-timestamp (byte-array [1 2])) 3 5)))
  (is (= [0 0] (subvec (#'p/ensure-bytes-timestamp {:bytes (byte-array 0)}) 3 5)))
  (doseq [metadata [{:caplen 1} {:caplen 3} {:len 1}]]
    (is (thrown? clojure.lang.ExceptionInfo (normalize metadata))))
  (doseq [field [:caplen :len]
          value [-1 1.5 "2" nil false 4294967296N]]
    (is (thrown? clojure.lang.ExceptionInfo (normalize {field value}))))
  (is (thrown-with-msg? clojure.lang.ExceptionInfo #"missing :bytes"
                        (#'p/ensure-bytes-timestamp {:sec 1 :usec 2})))
  (doseq [input [nil 1 "bytes" [1 2] (int-array [1 2])
                 {:bytes nil} {:bytes [1 2]} {:bytes "bytes"}]]
    (is (thrown? clojure.lang.ExceptionInfo (#'p/ensure-bytes-timestamp input)))))

(deftest native-header-keeps-distinct-unsigned-lengths
  (let [hdr (#'p/mk-hdr 4294967295 999999 2 4294967295)]
    (is (= 4294967295 (PcapHeader/tv_sec hdr)))
    (is (= 999999 (PcapHeader/tv_usec hdr)))
    (is (= 2 (PcapHeader/caplen hdr)))
    (is (= 4294967295 (PcapHeader/len hdr)))))
