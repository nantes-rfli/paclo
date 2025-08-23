(ns paclo.core-test
  (:require
   [clojure.test :refer :all]
   [paclo.core :as sut]))

(deftest hello-works
  (is (.startsWith (sut/hello) "paclo ready")))
