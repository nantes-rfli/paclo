(ns paclo.dev.checkstyle
  "Minimal CheckStyle runner (warning-level)."
  (:require
   [clojure.java.shell :as sh]
   [clojure.string :as str]))

(defn- java-cp []
  (-> (sh/sh "clojure" "-Spath" "-A:checkstyle") :out str/trim))

(defn- run-cli [& _]
  (let [cp (java-cp)
        config "dev/resources/checkstyle.xml"
        out    "target/checkstyle.xml"
        {:keys [exit err]} (sh/sh "java"
                                  "-cp" cp
                                  "com.puppycrawl.tools.checkstyle.Main"
                                  "-c" config
                                  "-f" "xml"
                                  "-o" out
                                  "src-java" "test-java")]
    (println "[checkstyle] report ->" out)
    (when (pos? (long exit))
      (println err)
      (System/exit exit))))

;; clojure.java.shell starts agent-backed I/O workers; close them on CLI exit.
(defn -main [& args]
  (try
    (apply run-cli args)
    (finally
      (shutdown-agents))))
