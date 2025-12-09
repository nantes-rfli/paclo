(ns paclo.dev.jacoco
  "Run JUnit with JaCoCo agent and emit XML/HTML reports."
  (:require
   [clojure.java.io :as io]
   [clojure.java.shell :as sh]
   [clojure.string :as str]))

(defn- cp [aliases]
  (-> (sh/sh "clojure" "-Spath" aliases) :out str/trim))

(defn- find-in-cp [cp substr]
  (some #(when (str/includes? % substr) %) (str/split cp #":")))

(defn -main [& _]
  (let [cp-all (cp "-A:junit:jacoco")
        ;; include compiled outputs explicitly
        cp-run (str cp-all ":target/classes:target/test-classes")
        agent (or (find-in-cp cp-all "org.jacoco.agent")
                  (find-in-cp cp-all "jacocoagent"))
        _ (when-not agent (throw (ex-info "jacoco agent jar not found on classpath" {})))
        exec "target/jacoco.exec"
        xml  "target/jacoco.xml"
        html "target/jacoco-html"
        _ (io/make-parents xml)]
    (println "[jacoco] running tests with agent ->" exec)
    (let [{:keys [exit err]} (sh/sh "java"
                                    (str "-javaagent:" agent "=destfile=" exec)
                                    "-cp" cp-run
                                    "org.junit.platform.console.ConsoleLauncher"
                                    "--class-path" "target/classes:target/test-classes"
                                    "--scan-classpath")]
      (when (pos? (long exit))
        (println err)
        (System/exit exit)))
    (println "[jacoco] generating reports ->" xml "and" html)
    (let [{:keys [exit err]} (sh/sh "java"
                                    "-cp" cp-run
                                    "org.jacoco.cli.internal.Main" "report" exec
                                    "--classfiles" "target/classes"
                                    "--sourcefiles" "src-java"
                                    "--xml" xml
                                    "--html" html)]
      (when (pos? (long exit))
        (println err)
        (System/exit exit)))
    (println "[jacoco] done")))
