(ns build
  (:require [clojure.tools.build.api :as b]
            [clojure.java.io :as io]
            [clojure.java.shell :as sh]
            [clojure.string :as str]))

(def ^:private path-sep (System/getProperty "path.separator"))

(defn- classpath
  "Return classpath string. When alias-arg is provided (e.g. \"-A:junit\"),
   it is appended to the clojure -Spath invocation."
  ([] (-> (sh/sh "clojure" "-Spath") :out str/trim))
  ([alias-arg] (-> (sh/sh "clojure" alias-arg "-Spath") :out str/trim)))

(defn- find-in-cp
  "Find first classpath entry containing the given substring."
  [cp substr]
  (let [sep-regex (re-pattern (java.util.regex.Pattern/quote path-sep))]
    (some #(when (str/includes? % substr) %) (str/split cp sep-regex))))

(defn- tagged-version
  "Return version from tag like v1.2.3 when running on a tag ref."
  []
  (let [ref-name (System/getenv "GITHUB_REF_NAME")]
    (when (and ref-name (re-matches #"v\d+\.\d+\.\d+([-\.].+)?" ref-name))
      (subs ref-name 1))))

(defn- resolve-version []
  (or (System/getenv "PACLO_VERSION")
      (tagged-version)
      "1.0.0-SNAPSHOT"))

(def lib 'org.clojars.nanto/paclo)
(def version (resolve-version))
(def class-dir "target/classes")
(def test-class-dir "target/test-classes")
(def basis (b/create-basis {:project "deps.edn"}))
(def jar-file (format "target/%s-%s.jar" (name lib) version))

(defn- pom-params []
  {:basis basis
   :lib lib
   :version version
   :src-dirs (filter #(.exists (io/file %)) ["src"])
   :resource-dirs (filter #(.exists (io/file %)) ["resources"])
   :scm {:url "https://github.com/nantes-rfli/paclo"
         :connection "scm:git:https://github.com/nantes-rfli/paclo.git"
         :developerConnection "scm:git:git@github.com:nantes-rfli/paclo.git"
         :tag (str "v" version)}
   :pom-data [[:licenses
               [:license
                [:name "MIT License"]
                [:url "https://opensource.org/license/mit/"]
                [:distribution "repo"]]]
              [:description "Paclo is a Clojure library for packet capture (pcap) I/O and filtering."]
              [:url "https://github.com/nantes-rfli/paclo"]]})

(defn pom
  "Generate pom.xml under target/maven/ for publishing tools."
  [_]
  (b/write-pom (assoc (pom-params) :target "target/maven")))

(defn clean [_]
  (b/delete {:path "target"}))

(defn jar [_]
  (clean nil)
  (let [src-dirs (filter #(.exists (io/file %))
                         ["src" "extensions/dns/src" "resources"])]
    (b/copy-dir {:src-dirs src-dirs
                 :target-dir class-dir}))
  (when (.exists (java.io.File. "src-java"))
    (b/javac {:src-dirs ["src-java"]
              :class-dir class-dir
              :basis basis
              :javac-opts ["-Xlint:all" "-Werror" "-proc:none"]}))
  (b/write-pom (assoc (pom-params) :class-dir class-dir))
  (b/jar {:class-dir class-dir
          :jar-file jar-file
          :lib lib
          :version version}))

(defn install
  "Build and install jar/pom into local Maven repository (~/.m2)."
  [_]
  (jar nil)
  (b/install {:basis basis
              :lib lib
              :version version
              :jar-file jar-file
              :class-dir class-dir}))

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

(defn junit
  "Run JUnit Platform (Java tests). Assumes javac-test has been executed."
  [_]
  (let [cp-base (classpath)
        cp-junit (classpath "-A:junit")
        console (or (find-in-cp cp-junit "junit-platform-console-standalone")
                    (throw (ex-info "ConsoleLauncher jar not found on classpath" {})))
        test-cp (str "target/test-classes" path-sep "target/classes" path-sep cp-base)]
    (b/process {:command-args ["java"
                               "-jar" console
                               "--class-path" test-cp
                               "--scan-class-path"
                               "--fail-if-no-tests"]
                :inherit true})))
