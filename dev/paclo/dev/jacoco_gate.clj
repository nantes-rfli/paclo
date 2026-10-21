(ns paclo.dev.jacoco-gate
  "Simple coverage gate: checks line coverage in target/jacoco.xml."
  (:require
   [clojure.data.xml :as xml]
   [clojure.java.io :as io]))

(defn line-coverage []
  (with-open [reader (io/reader "target/jacoco.xml")]
    (let [report (xml/parse reader)
          counters (filter #(and (= :counter (:tag %))
                                 (= "LINE" (get-in % [:attrs :type])))
                           (:content report))]
      ;; Use the bundle counter once, not class/package/sourcefile duplicates.
      (when-not (and (= :report (:tag report)) (= 1 (count counters)))
        (throw (ex-info "Missing or duplicate JaCoCo report LINE counter" {})))
      (let [{:keys [covered missed]} (:attrs (first counters))
            covered (Long/parseLong covered)
            missed (Long/parseLong missed)
            total (+' covered missed)]
        (when-not (and (<= 0 covered) (<= 0 missed) (pos? total))
          (throw (ex-info "Invalid or empty JaCoCo LINE counter" {})))
        (/ (double covered) (double total))))))

(defn -main [& _]
  (let [min-threshold (Double/parseDouble (or (System/getenv "JACOCO_MIN_LINE") "0.25"))
        _ (when-not (<= 0.25 min-threshold 1.0)
            (throw (ex-info "JACOCO_MIN_LINE must be between 0.25 and 1.0" {})))
        ratio (line-coverage)]
    (println (format "[jacoco-gate] line coverage %.1f%% (threshold %.1f%%)" (* 100.0 (double ratio)) (* 100.0 min-threshold)))
    (when (< (double ratio) min-threshold)
      (println "[jacoco-gate] FAIL: line coverage below threshold")
      (System/exit 1))
    (println "[jacoco-gate] PASS")))
