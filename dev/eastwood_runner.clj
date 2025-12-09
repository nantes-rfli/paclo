(ns eastwood-runner
  (:require
   [eastwood.lint :as lint]))

(defn -main [& _]
  ;; Lint both source and tests. Adjust paths if you add new roots.
  (lint/eastwood {:source-paths ["src" "dev"]
                  :test-paths   ["test"]
                  :linters      [:all]
                  ;; キーワード表記の揺れは意図的に許容
                  :exclude-linters [:keyword-typos :non-clojure-file]}))
