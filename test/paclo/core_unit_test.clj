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

(deftest bpf-host-and-port-variants
  (is (= "(udp) or (tcp)" (core/bpf [:or :udp :tcp])))
  (is (= "src host 1.2.3.4" (core/bpf [:src-host "1.2.3.4"])))
  (is (= "dst host 5.6.7.8" (core/bpf [:dst-host "5.6.7.8"])))
  (is (= "src port 80" (core/bpf [:src-port "80"])))
  (is (= "dst port 443" (core/bpf [:dst-port 443]))))

(deftest decode-result-captures-errors
  (let [f (deref #'core/decode-result)
        res (with-redefs [parse/packet->clj (fn [_] (throw (Exception. "oops")))]
              (f (byte-array 0)))]
    (is (false? (:ok res)))
    (is (re-find #"oops" (:error res)))))

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
  (try
    (core/packets {:filter {:bad true}})
    (is false "must throw ex-info")
    (catch clojure.lang.ExceptionInfo e
      (is (= "invalid :filter" (ex-message e)))
      (is (= {:filter {:bad true}} (ex-data e))))))

(deftest write-pcap-forwards-opts
  (let [called (atom nil)]
    (with-redefs [pcap/bytes-seq->pcap! (fn [ps opts] (reset! called [ps opts]))]
      (core/write-pcap! [(byte-array 1)] "out.pcap")
      (let [[ps opts] @called]
        (is (= [0] (vec (first ps))))
        (is (= {:out "out.pcap"} opts))))))

(deftest list-devices-delegates
  (with-redefs [pcap/list-devices (fn [] [:devs])]
    (is (= [:devs] (core/list-devices)))))
