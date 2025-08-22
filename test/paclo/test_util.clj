(ns paclo.test-util
  (:require [clojure.string :as str]))

(defn hex->bytes ^bytes [^String s]
  (let [clean (str/replace s #"(?is)[^0-9a-f]" "")] ; 数字/英字(16進)以外を全削除
    (when (odd? (count clean))
      (throw (ex-info "Odd number of hex digits" {:len (count clean)})))
    (byte-array
     (map (fn [[a b]]
            (unchecked-byte (Integer/parseInt (str a b) 16)))
          (partition 2 clean)))))
