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
        covered (double (reduce (fn ^double [^double acc ^double v] (+ acc v))
                                0.0
                                (map #(Double/parseDouble (:covered %)) line-counters)))
        missed  (double (reduce (fn ^double [^double acc ^double v] (+ acc v))
                                0.0
                                (map #(Double/parseDouble (:missed %)) line-counters)))
        total (double (+ covered missed))]
    (if (> total 0.0)
      (/ covered total)
      1.0)))

(defn -main [& _]
  (let [min-threshold (Double/parseDouble (or (System/getenv "JACOCO_MIN_LINE") "0.25"))
        ratio (line-coverage)]
    (println (format "[jacoco-gate] line coverage %.1f%% (threshold %.1f%%)" (* 100.0 (double ratio)) (* 100.0 min-threshold)))
    (when (< (double ratio) min-threshold)
      (println "[jacoco-gate] FAIL: line coverage below threshold")
      (System/exit 1))
    (println "[jacoco-gate] PASS")))
