(ns paclo.dev.spotbugs
  "Minimal SpotBugs runner via tools.build."
  (:require
   [clojure.java.shell :as sh]
   [clojure.string :as str]))

(defn- java-cp []
  ;; reuse deps.edn classpath with :spotbugs alias
  (-> (sh/sh "clojure" "-Spath" "-A:spotbugs") :out str/trim))

(defn- run-spotbugs []
  (let [cp (java-cp)
        target "target/spotbugs.xml"
        exclude "dev/resources/spotbugs-exclude.xml"]
    (println "[spotbugs] analyzing target/classes ->" target)
    (let [{:keys [exit err]} (sh/sh "java"
                                    "-cp" cp
                                    "edu.umd.cs.findbugs.LaunchAppropriateUI"
                                    "-textui" "-effort:max"
                                    "-low"
                                    "-auxclasspath" cp
                                    "-exclude" exclude
                                    "-xml:withMessages"
                                    "-output" target
                                    "target/classes")]
      (when (pos? exit)
        (println err)
        (System/exit exit))))
  (println "[spotbugs] done"))

(defn -main [& _]
  (run-spotbugs))
