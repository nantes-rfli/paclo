(ns paclo.core-bpf-test
  (:require
   [clojure.test :refer [deftest is testing]]
   [paclo.core :as core]))

(deftest bpf-nested-not-and-ports
  (is (= "not (portrange 10-20)" (core/bpf [:not [:port-range 10 20]])))
  (is (= "src portrange 1-2" (core/bpf [:src-port-range 1 2])))
  (is (= "dst portrange 3-4" (core/bpf [:dst-port-range 3 4]))))

(deftest bpf-invalid-op-throws
  (is (thrown? clojure.lang.ExceptionInfo (core/bpf [:proto :unknown]))))

(deftest bpf-error-contract
  (testing "unknown proto keyword keeps :proto in ex-data"
    (try
      (core/bpf [:proto :unknown])
      (is false "must throw ex-info")
      (catch clojure.lang.ExceptionInfo e
        (is (= "unknown proto keyword" (ex-message e)))
        (is (= {:proto :unknown} (ex-data e))))))

  (testing "unknown op keeps :op and :form in ex-data"
    (let [form [:huh 1 2 3]]
      (try
        (core/bpf form)
        (is false "must throw ex-info")
        (catch clojure.lang.ExceptionInfo e
          (is (= "unknown op in bpf" (ex-message e)))
          (is (= form (:form (ex-data e))))
          (is (= :huh (:op (ex-data e))))))))

  (testing "unsupported form keeps :form in ex-data"
    (try
      (core/bpf 123)
      (is false "must throw ex-info")
      (catch clojure.lang.ExceptionInfo e
        (is (= "unsupported bpf form" (ex-message e)))
        (is (= {:form 123} (ex-data e))))))

  (testing "invalid port value throws NumberFormatException"
    (is (thrown? NumberFormatException (core/bpf [:port "abc"])))))
