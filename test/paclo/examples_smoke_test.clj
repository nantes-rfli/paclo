(ns paclo.examples-smoke-test
  (:require
   [clojure.data.json :as json]
   [clojure.string :as str]
   [clojure.test :refer [deftest is]]
   [examples.pcap-filter :as pf]))

(deftest pcap-filter-jsonl-meta-smoke
  (let [tmp   (java.io.File/createTempFile "paclo-pf" ".pcap")
        out   (.getAbsolutePath tmp)
        _     (.deleteOnExit tmp)
        stdout (with-out-str
                 (pf/-main "test/resources/dns-sample.pcap"
                           out
                           "_"   ; bpf (skip)
                           "_"   ; min-caplen (skip)
                           "jsonl"))
        meta-line (last (str/split-lines stdout))
        meta      (json/read-str meta-line :key-fn keyword)]
    (is (.isFile (java.io.File. out)))
    (is (= "test/resources/dns-sample.pcap" (:in meta)))
    (is (= out (:out meta)))
    (is (number? (:in-packets meta)))
    (is (number? (:out-packets meta)))
    (is (number? (:drop-pct meta)))))

