(ns paclo.dev.dns-perf-summary
  "Validate paired Issue #37 raw rows and print machine-readable summaries."
  (:require
   [clojure.data.json :as json]
   [clojure.edn :as edn]
   [clojure.java.io :as io]))

(defn- median [xs] (nth (vec (sort xs)) (quot (count xs) 2)))

(defn- summarize [rows]
  (let [ns-values (map :ns rows) units (:units (first rows)) elapsed (median ns-values)
        mean (/ (double (reduce + ns-values)) (count rows))]
    {:samples (count rows) :units units :median-ms (/ elapsed 1e6)
     :units-per-second (/ (* 1e9 units) elapsed)
     :thread-cpu-ns-per-unit (/ (double (median (map :thread-cpu-ns rows))) units)
     :process-cpu-ns-per-unit (/ (double (median (map :process-cpu-ns rows))) units)
     :allocated-bytes-per-unit (/ (double (median (map :live-thread-allocated-bytes rows))) units)
     :gc-count (reduce + (map :gc-count rows)) :gc-ms (reduce + (map :gc-ms rows))
     :min-ms (/ (apply min ns-values) 1e6) :max-ms (/ (apply max ns-values) 1e6)
     :elapsed-cv-percent (* 100 (/ (Math/sqrt (double (/ (reduce + (map #(let [d (- % mean)] (* d d)) ns-values))
                                                         (count rows)))) mean))}))

(defn -main [& paths]
  (doseq [path paths]
    (let [rows (with-open [reader (io/reader path)] (mapv edn/read-string (line-seq reader)))
          header (first rows) samples (filter :scenario rows)]
      (doseq [[scenario pair] (sort-by (comp pr-str key) (group-by :scenario samples))]
        (assert (every? :equal? pair) (str path " unequal result"))
        (let [by-impl (group-by :implementation pair)
              a (:baseline by-impl) b (:current by-impl)]
          (assert (= (:runs header) (count a) (count b)) (str path " incomplete samples " scenario))
          (assert (apply = (map :units pair)))
          (let [a (summarize a) b (summarize b)]
            (println (json/write-str {:file path :scenario scenario :baseline a :current b
                                      :throughput-percent (* 100 (dec (/ (:units-per-second b) (:units-per-second a))))}))))))))
