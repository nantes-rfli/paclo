(ns build
  (:require [clojure.tools.build.api :as b]))

(def lib 'io.github.yourname/paclo)
(def version "0.1.0-SNAPSHOT")
(def class-dir "target/classes")
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
              :javac-opts ["-Xlint:all" "-proc:none"]}))
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
              :javac-opts ["-Xlint:deprecation"]})))