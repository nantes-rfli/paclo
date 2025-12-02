(ns paclo.core-bpf-test
  (:require
   [clojure.test :refer [deftest is]]
   [paclo.core :as core]))

(deftest bpf-nested-not-and-ports
  (is (= "not (portrange 10-20)" (core/bpf [:not [:port-range 10 20]])))
  (is (= "src portrange 1-2" (core/bpf [:src-port-range 1 2])))
  (is (= "dst portrange 3-4" (core/bpf [:dst-port-range 3 4]))))

(deftest bpf-invalid-op-throws
  (is (thrown? clojure.lang.ExceptionInfo (core/bpf [:proto :unknown]))))
