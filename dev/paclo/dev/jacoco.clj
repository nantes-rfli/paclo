 (ns paclo.dev.jacoco
   "Run JUnit with JaCoCo agent and emit XML/HTML reports."
   (:require
    [clojure.java.io :as io]
    [clojure.java.shell :as sh]
    [clojure.string :as str]))

(def ^:private path-sep (System/getProperty "path.separator"))

(defn- classpath
  ([] (-> (sh/sh "clojure" "-Spath") :out str/trim))
  ([alias-arg] (-> (sh/sh "clojure" alias-arg "-Spath") :out str/trim)))

(defn- find-in-cp [cp substr]
  (let [sep-regex (re-pattern (java.util.regex.Pattern/quote path-sep))]
    (some #(when (str/includes? % substr) %) (str/split cp sep-regex))))

(defn -main [& _]
  (let [cp-base   (classpath)
        cp-junit  (classpath "-A:junit")
        cp-jacoco (classpath "-A:jacoco")
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
    (let [{:keys [exit err]} (sh/sh "java"
                                    (str "-javaagent:" agent "=destfile=" exec)
                                    "-jar" console
                                    "--class-path" test-cp
                                    "--scan-class-path")]
      (when (pos? (long exit))
        (println err)
        (System/exit exit)))
    (println "[jacoco] generating reports ->" xml "and" html)
    (let [{:keys [exit err]} (sh/sh "java"
                                    "-cp" (str cli-cp path-sep test-cp)
                                    "org.jacoco.cli.internal.Main" "report" exec
                                    "--classfiles" "target/classes"
                                    "--sourcefiles" "src-java"
                                    "--xml" xml
                                    "--html" html)]
      (when (pos? (long exit))
        (println err)
        (System/exit exit)))
    (println "[jacoco] done")))
