(ns paclo.dev.ethernet-perf-summary
  "Summarize raw Issue #44 records without dropping negative/noisy samples."
  (:require
   [clojure.edn :as edn]
   [clojure.java.io :as io]
   [clojure.string :as str]))

(defn- records [path]
  (with-open [r (io/reader path)]
    (mapv edn/read-string (remove str/blank? (line-seq r)))))

(defn- change [before after]
  (* 100.0 (dec (/ (double after) (double before)))))

(defn comparisons [path]
  (let [rows (filter #(= :measurement (:type %)) (records path))]
    (mapcat
     (fn [[scenario rows]]
       (let [current (first (filter #(= "working-tree" (:id %)) rows))]
         (for [baseline rows :when (not= "working-tree" (:id baseline))]
           {:file path :scenario scenario :baseline (:id baseline)
            :before-kpps (/ (:packets-per-second baseline) 1000.0)
            :after-kpps (/ (:packets-per-second current) 1000.0)
            :throughput-change-pct (change (:packets-per-second baseline) (:packets-per-second current))
            :before-cpu-ns (:cpu-ns-per-packet baseline) :after-cpu-ns (:cpu-ns-per-packet current)
            :cpu-change-pct (change (:cpu-ns-per-packet baseline) (:cpu-ns-per-packet current))
            :before-allocation (:allocation-bytes-per-packet baseline)
            :after-allocation (:allocation-bytes-per-packet current)
            :before-gc-count (:gc-count baseline) :after-gc-count (:gc-count current)
            :before-gc-ms (:gc-ms baseline) :after-gc-ms (:gc-ms current)})))
     (sort-by (comp pr-str key) (group-by :scenario rows)))))

(defn- csv-cell [v]
  (str "\"" (str/replace (str v) "\"" "\"\"") "\""))

(defn -main [& paths]
  (let [rows (vec (mapcat comparisons paths))
        columns [:file :scenario :baseline :before-kpps :after-kpps :throughput-change-pct
                 :before-cpu-ns :after-cpu-ns :cpu-change-pct :before-allocation :after-allocation
                 :before-gc-count :after-gc-count :before-gc-ms :after-gc-ms]]
    (println (str/join "," (map name columns)))
    (doseq [row rows] (println (str/join "," (map #(csv-cell (get row %)) columns))))))
