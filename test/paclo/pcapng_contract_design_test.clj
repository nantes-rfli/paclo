(ns paclo.pcapng-contract-design-test
  "E1 characterization only; no future reader/writer API is implemented."
  (:require
   [clojure.java.shell :as shell]
   [clojure.test :refer [deftest is]]
   [paclo.core :as core]))

(deftest physical-corpus-and-exact-arithmetic-oracle
  (doseq [command [["python3" "test/resources/make_pcapng_contract_fixtures.py" "--check"]
                   ["python3" "test/resources/test_pcapng_contract_fixtures.py"]]]
    (let [{:keys [exit out err]} (apply shell/sh command)]
      (println out err)
      (is (= 0 exit) (str command "\n" err)))))

(deftest native-metadata-loss-is-explicit
  (let [packets (core/reduce-packets
                 {:path "test/resources/pcapng-contracts/rich.pcapng"
                  :max 10 :max-time-ms 10000} conj [])]
    (println "P08-E1 native rich timestamps" (mapv (juxt :ts-sec :ts-usec) packets))
    (is (= [[1699999993 123456] [1700000000 125976] [-7 0]]
           (mapv (juxt :ts-sec :ts-usec) packets)))
    (is (= [[64 1500] [64 64] [64 64]] (mapv (juxt :caplen :len) packets)))
    (is (every? #(= #{:bytes :ts-sec :ts-usec :caplen :len :linktype}
                    (set (keys %))) packets))
    (is (= [1 1 1] (mapv :linktype packets)))))

(deftest native-mixed-section-prefix-is-a-failure
  (let [report (core/reduce-packets-report
                {:path "test/resources/pcapng-contracts/mixed-sections.pcapng"
                 :max 10 :max-time-ms 10000 :error-mode :pass} conj [])]
    (is (= 1 (count (:result report))))
    (is (= :error (get-in report [:stats :stop-reason])))
    (is (= :pcap-read-failed (get-in report [:stats :error :reason])))))
