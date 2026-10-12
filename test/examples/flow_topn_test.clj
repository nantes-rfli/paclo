(ns examples.flow-topn-test
  (:require
   [clojure.core.async :as async]
   [clojure.edn :as edn]
   [clojure.test :refer [deftest is testing]]
   [examples.flow-topn :as flow-topn]
   [paclo.core :as core]
   [paclo.flow :as flow]))

(deftest numeric-addresses-use-compatible-display-format
  (testing "IPv4 is rendered in dotted-decimal notation"
    (is (= "192.168.1.100"
           ((deref #'flow-topn/ip->str) 3232235876))))
  (testing "IPv6 keeps the full legacy representation"
    (is (= "2001:db8:0:0:0:0:0:1"
           ((deref #'flow-topn/ip->str)
            [2306139568115548160 1])))))

(deftest library-results-use-compatible-cli-display
  (let [rf (flow/aggregate-rf {:max-flows 10 :direction :bidir})
        packet {:ip-version 4 :protocol 6 :src-ip 167772162 :src-port 443
                :dst-ip 167772161 :dst-port 12000 :caplen 40 :len 50}]
    (is (= [{:flow {:proto :tcp :src "10.0.0.1:12000" :dst "10.0.0.2:443"}
             :packets 1 :bytes 40}]
           (#'flow-topn/display-rows (reduce rf (rf) [packet]) :bytes 10)))))

(defn- run-main [& args]
  (let [out (java.io.StringWriter.) err (java.io.StringWriter.)]
    (binding [*out* out *err* err] (apply flow-topn/-main args))
    {:out (str out) :err (str err)}))

(deftest bounded-sync-and-async-cli
  (doseq [flags [[] ["--async" "--async-buffer" "1"]
                 ["--async" "--async-mode" "dropping" "--async-buffer" "100"]]]
    (let [result (apply run-main "test/resources/dns-sample.pcap" "_" "10" "bidir" "bytes" "edn"
                        (concat flags ["--max-flows" "100"]))]
      (is (seq (edn/read-string (:out result))))))
  (doseq [flags [[] ["--async" "--async-buffer" "1"]]]
    (is (thrown-with-msg? clojure.lang.ExceptionInfo #"cardinality"
                          (apply run-main "test/resources/dns-sample.pcap" "_" "10" "unidir" "packets" "edn"
                                 (concat flags ["--max-flows" "1"])))))
  (doseq [value ["0" "-1" "no-number"]]
    (is (thrown? clojure.lang.ExceptionInfo
                 (run-main "test/resources/dns-sample.pcap" "--max-flows" value))))
  (with-redefs [async/timeout (fn [_] (throw (ex-info "zero timeout must not schedule a timer" {})))]
    (let [result (run-main "test/resources/dns-sample.pcap" "--async" "--async-timeout-ms" "0")]
      (is (= [] (edn/read-string (:out result))))
      (is (re-find #"cancelled= true" (:err result)))))
  (is (:async? (#'flow-topn/parse-flags ["--async" "--max-flows" "42"])))
  (is (= 42 (:max-flows (#'flow-topn/parse-flags ["--max-flows" "42"])))))

(deftest async-reader-failures-and-drop-accounting
  (let [error (ex-info "reader failed" {})]
    (with-redefs [core/reduce-packets (fn [& _] (throw error))]
      (try
        (#'flow-topn/async-aggregate {} (flow/aggregate-rf {:max-flows 1})
                                     {:async-buffer 1 :async-mode :buffer})
        (is false "reader exception must propagate")
        (catch clojure.lang.ExceptionInfo actual
          (is (identical? error actual))))))
  (let [produced (promise)
        packet {:ip-version 4 :protocol 17 :src-ip 1 :dst-ip 2
                :src-port 53 :dst-port 54 :caplen 40 :len 50}
        rf (flow/aggregate-rf {:max-flows 1})
        delayed-init (fn
                       ([] (is (= :done (deref produced 10000 :timeout))) (rf))
                       ([state] (rf state))
                       ([state p] (rf state p)))]
    (with-redefs [core/reduce-packets (fn [_ step init]
                                        (try (reduce step init (repeat 5 packet))
                                             (finally (deliver produced :done))))]
      (let [result (#'flow-topn/async-aggregate {} delayed-init
                                                {:async-buffer 1 :async-mode :dropping})]
        (is (= 5 (:total result)))
        (is (= 4 (:dropped result)))
        (is (= 1 (get-in result [:result :summary :aggregated])))))))
