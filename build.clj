(ns build
  (:require [clojure.tools.build.api :as b]
            [clojure.java.shell :as sh]
            [clojure.string :as str]))

(def lib 'io.github.nantes-rfli/paclo)
(def version "0.2.0")
(def class-dir "target/classes")
(def test-class-dir "target/test-classes")
(def basis (b/create-basis {:project "deps.edn"}))
(def jar-file (format "target/%s-%s.jar" (name lib) version))

(defn clean [_]
  (b/delete {:path "target"}))

(defn jar [_]
  (clean nil)
  ;; Clojure/リソースをコピー
  (b/copy-dir {:src-dirs ["src" "resources"]
               :target-dir class-dir})
  ;; ★ Java をコンパイル（src-java → target/classes）
  (when (.exists (java.io.File. "src-java"))
    (b/javac {:src-dirs ["src-java"]
              :class-dir class-dir
              :basis basis
              :javac-opts ["-Xlint:all" "-Werror" "-proc:none"]}))
  ;; Jar 作成
  (b/jar {:class-dir class-dir
          :jar-file jar-file
          :lib lib
          :version version}))

(defn javac
  "Compile Java sources under src-java into target/classes."
  [_]
  (let [basis (b/create-basis {:project "deps.edn"})]
    (b/javac {:src-dirs   ["src-java"]
              :class-dir  class-dir
              :basis      basis
              :javac-opts ["-Xlint:all" "-Werror" "-proc:none"]})))

(defn spotbugs
  "Run SpotBugs on compiled classes (target/classes)."
  [_]
  (let [basis (b/create-basis {:project "deps.edn" :aliases [:spotbugs]})]
    (b/process {:command-args ["clojure" "-M:spotbugs" "-m" "paclo.dev.spotbugs"]
                :basis basis})))

(defn checkstyle
  "Run CheckStyle on Java sources (src-java, test-java)."
  [_]
  (let [basis (b/create-basis {:project "deps.edn" :aliases [:checkstyle]})]
    (b/process {:command-args ["clojure" "-M:checkstyle" "-m" "paclo.dev.checkstyle"]
                :basis basis})))

(defn jacoco
  "Run JUnit with JaCoCo agent and generate reports."
  [_]
  (let [basis (b/create-basis {:project "deps.edn" :aliases [:jacoco]})]
    (b/process {:command-args ["clojure" "-M:jacoco" "-m" "paclo.dev.jacoco"]
                :basis basis})))

(defn jacoco-gate
  "Fail if line coverage is below threshold (default 60%)."
  [_]
  (let [basis (b/create-basis {:project "deps.edn" :aliases [:jacoco-gate]})]
    (b/process {:command-args ["clojure" "-M:jacoco-gate" "-m" "paclo.dev.jacoco-gate"]
                :basis basis})))

(defn javadoc
  "Generate Javadoc for src-java into target/javadoc." 
  [_]
  (let [cp (-> (sh/sh "clojure" "-Spath") :out str/trim)]
    (b/process {:command-args ["javadoc"
                               "-d" "target/javadoc"
                               "-cp" cp
                               "-sourcepath" "src-java"
                               "-subpackages" "paclo.jnr"]})))

(defn javac-test
  "Compile Java test sources under test-java into target/test-classes."
  [_]
  (let [basis (b/create-basis {:project "deps.edn" :aliases [:junit]})]
    (b/javac {:src-dirs   ["src-java" "test-java"]
              :class-dir  test-class-dir
              :basis      basis
              :javac-opts ["-Xlint:all" "-Werror" "-proc:none"]})))
