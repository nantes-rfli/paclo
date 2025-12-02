(ns paclo.dev.jacoco-gate
  "Simple coverage gate: checks line coverage in target/jacoco.xml."
  (:require
   [clojure.data.xml :as xml]
   [clojure.java.io :as io]))

(defn- parse-report [f]
  (xml/parse (io/reader f)))

(defn- bundle-counters [root]
  (->> (tree-seq :content :content root)
       (filter #(= :counter (:tag %)))
       (map :attrs)))

(defn line-coverage []
  (let [report (parse-report "target/jacoco.xml")
        counters (bundle-counters report)
        line-counters (filter #(= "LINE" (:type %)) counters)
        covered (reduce + (map #(Double/parseDouble (:covered %)) line-counters))
        missed  (reduce + (map #(Double/parseDouble (:missed %)) line-counters))
        total (+ covered missed)]
    (if (pos? total)
      (/ covered total)
      1.0)))

(defn -main [& _]
  (let [min-threshold (Double/parseDouble (or (System/getenv "JACOCO_MIN_LINE") "0.25"))
        ratio (line-coverage)]
    (println (format "[jacoco-gate] line coverage %.1f%% (threshold %.1f%%)" (* 100 ratio) (* 100 min-threshold)))
    (when (< ratio min-threshold)
      (println "[jacoco-gate] FAIL: line coverage below threshold")
      (System/exit 1))
    (println "[jacoco-gate] PASS")))
