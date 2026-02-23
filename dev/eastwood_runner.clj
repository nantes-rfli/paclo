(ns eastwood-runner
  (:require
   [eastwood.lint :as lint]))

(defn -main [& _]
  ;; Lint both source and tests. Adjust paths if you add new roots.
  (lint/eastwood {:source-paths ["src" "dev" "extensions/dns/src"]
                  :test-paths   ["test"]
                  :linters      [:all]
                  ;; Accept this naming style intentionally.
                  :exclude-linters [:keyword-typos :non-clojure-file]}))
