(ns paclo.pcap-error-messages-test
  (:require
   [clojure.test :refer [deftest is]]
   [paclo.pcap :as p]))

(deftest open-offline-not-found
  (is (thrown-with-msg? clojure.lang.ExceptionInfo
                        #"pcap file not found:"
                        (p/open-offline "no/such/file/definitely-not-found.pcap"))))

(deftest open-offline-empty
  (let [f (java.io.File/createTempFile "empty" ".pcap")]
    (spit f "" :append false)
    (try
      (is (thrown-with-msg? clojure.lang.ExceptionInfo
                            #"pcap file is empty:"
                            (p/open-offline (.getAbsolutePath f))))
      (finally (.delete f)))))
