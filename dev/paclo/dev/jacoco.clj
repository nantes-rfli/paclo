 (ns paclo.dev.jacoco
   "Run JUnit with JaCoCo agent and emit XML/HTML reports."
   (:require
    [clojure.java.io :as io]
    [clojure.string :as str]
    [paclo.dev.java-quality :as quality]))

(def ^:private path-sep (System/getProperty "path.separator"))

(defn- find-in-cp [cp substr]
  (let [sep-regex (re-pattern (java.util.regex.Pattern/quote path-sep))]
    (some #(when (str/includes? % substr) %) (str/split cp sep-regex))))

(defn- run-java! [& args]
  (let [{:keys [out err]} (apply quality/process! "java" args)]
    (print out)
    (binding [*out* *err*] (print err))))

(defn- run-cli [& _]
  (doseq [path ["target/jacoco.exec" "target/jacoco.xml"]] (io/delete-file path true))
  (let [cp-base   (quality/classpath)
        cp-junit  (quality/classpath "-A:junit")
        cp-jacoco (quality/classpath "-A:jacoco")
        ;; jars
        console (or (find-in-cp cp-junit "junit-platform-console-standalone")
                    (throw (ex-info "ConsoleLauncher jar not found on classpath" {})))
        agent   (or (find-in-cp cp-jacoco "org.jacoco.agent")
                    (find-in-cp cp-jacoco "jacocoagent"))
        cli-cp  cp-jacoco
        _ (when-not agent (throw (ex-info "jacoco agent jar not found on classpath" {})))
        exec "target/jacoco.exec"
        xml  "target/jacoco.xml"
        html "target/jacoco-html"
        test-cp (str "target/test-classes" path-sep "target/classes" path-sep cp-base)
        _ (io/make-parents xml)]
    (println "[jacoco] running tests with agent ->" exec)
    ;; Never reuse execution data or a successful report from an earlier run.
    (run-java!
     (str "-javaagent:" agent "=destfile=" exec ",append=false,includes=paclo.jnr.*")
     "-jar" console "--class-path" test-cp
     "--scan-class-path" "--fail-if-no-tests")
    (println "[jacoco] generating reports ->" xml "and" html)
    (run-java! "-cp" (str cli-cp path-sep test-cp)
               "org.jacoco.cli.internal.Main" "report" exec
               "--classfiles" "target/classes"
               "--sourcefiles" "src-java" "--xml" xml "--html" html)
    (println "[jacoco] done")))

;; clojure.java.shell starts agent-backed I/O workers; close them on CLI exit.
(defn -main [& args]
  (try
    (apply run-cli args)
    (finally
      (shutdown-agents))))
