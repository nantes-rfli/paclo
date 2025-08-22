(ns paclo.core
  (:gen-class))

(defn hello []
  (str "paclo ready on Clojure " (clojure-version)))

(defn -main [& _]
  (println (hello)))
