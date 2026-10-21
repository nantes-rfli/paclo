(ns paclo.dev.spotbugs
  "SpotBugs runner: findings are reported; incomplete analysis fails."
  (:require [clojure.java.io :as io]
            [clojure.java.shell :as sh]
            [clojure.xml :as xml]
            [paclo.dev.java-quality :as quality]))

(defn- run-spotbugs []
  (io/delete-file "target/spotbugs.xml" true)
  (let [cp (quality/classpath "-A:spotbugs")
        target "target/spotbugs.xml"
        exclude "dev/resources/spotbugs-exclude.xml"]
    (println "[spotbugs] analyzing target/classes ->" target)
    (let [{:keys [exit out err] :as result}
          (sh/sh "java" "-cp" cp
                 "edu.umd.cs.findbugs.LaunchAppropriateUI"
                 "-textui" "-effort:max" "-low" "-exitcode"
                 "-auxclasspath" cp "-exclude" exclude
                 "-xml:withMessages" "-output" target "target/classes")]
      (print out)
      (binding [*out* *err*] (print err))
      ;; SpotBugs bit 1 means findings, preserving the existing reporting policy.
      ;; Bits 4/2 (analysis errors/missing classes), signals and launcher errors fail.
      (when-not (#{0 1} exit)
        (throw (ex-info "SpotBugs analysis failed" result)))
      (let [report (xml/parse target)
            summary (first (filter #(= :FindBugsSummary (:tag %)) (:content report)))
            errors (first (filter #(= :Errors (:tag %)) (:content report)))]
        (when-not (and (= :BugCollection (:tag report))
                       (pos? (Long/parseLong (get-in summary [:attrs :total_classes] "0")))
                       (= "0" (get-in errors [:attrs :errors]))
                       (= "0" (get-in errors [:attrs :missingClasses])))
          (throw (ex-info "Incomplete SpotBugs report" {}))))
      (when (= 1 exit)
        (println "[spotbugs] findings reported; inspect" target))))
  (println "[spotbugs] done"))

(defn -main [& _]
  (try
    (run-spotbugs)
    (finally (shutdown-agents))))
