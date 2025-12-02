(ns paclo.core-unit-test
  (:require
   [clojure.test :refer [deftest is]]
   [paclo.core :as core]
   [paclo.decode-ext :as dx]
   [paclo.parse :as parse]
   [paclo.pcap :as pcap]))

(deftest bpf-dsl-basic
  (is (= "udp" (core/bpf :udp)))
  (is (= "tcp" (core/bpf [:proto :tcp])))
  (is (= "portrange 100-200" (core/bpf [:port-range 100 200])))
  (is (= "(udp) and (tcp)" (core/bpf [:and :udp :tcp]))))

(deftest bpf-throws-on-unknown
  (is (thrown? clojure.lang.ExceptionInfo (core/bpf [:foo 1])))
  (is (thrown? clojure.lang.ExceptionInfo (core/bpf 1234))))

(deftest packets-decodes-and-hooks
  (let [parse-called (atom 0)
        hook-called (atom 0)
        seq-out [{:bytes (byte-array (repeat 20 0)) :id 1}
                 {:bytes (byte-array 5) :id 2}]]
    (with-redefs [pcap/capture->seq (fn [_] seq-out)
                  parse/packet->clj (fn [_] (swap! parse-called inc) {:parsed true})
                  dx/apply! (fn [m] (swap! hook-called inc) (assoc m :hook true))]
      (let [out (doall (core/packets {:path "dummy" :decode? true}))]
        (is (= 1 @parse-called))
        (is (= 1 @hook-called)) ; only decoded path
        (is (= true (get-in (first out) [:decoded :parsed])))
        (is (= true (get-in (first out) [:hook])))
        (is (re-find #"frame too short" (get-in (second out) [:decode-error])))))))

(deftest packets-invalid-filter-throws
  (is (thrown? clojure.lang.ExceptionInfo
               (core/packets {:filter {:bad true}}))))

(deftest write-pcap-forwards-opts
  (let [called (atom nil)]
    (with-redefs [pcap/bytes-seq->pcap! (fn [ps opts] (reset! called [ps opts]))]
      (core/write-pcap! [(byte-array 1)] "out.pcap")
      (let [[ps opts] @called]
        (is (= [0] (vec (first ps))))
        (is (= {:out "out.pcap"} opts))))))
