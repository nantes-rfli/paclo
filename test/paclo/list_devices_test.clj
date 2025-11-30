(ns paclo.list-devices-test
  (:require
   [clojure.test :refer [deftest is]]
   [paclo.core :as sut]))

(deftest list-devices-basic-shape
  ;; 実環境に依存しない緩めの検証：
  ;; - 例外を投げないこと
  ;; - ベクタであること
  ;; - 各要素は {:name string, :desc (string|nil)} の形
  (let [xs (sut/list-devices)]
    (is (vector? xs))
    (doseq [m xs]
      (is (map? m))
      (is (contains? m :name))
      (is (string? (:name m)))
      (is (not (re-find #"^\s*$" (:name m))))
      (is (contains? m :desc))
      (when-let [d (:desc m)]
        (is (string? d))))))
