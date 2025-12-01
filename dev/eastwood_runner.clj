(ns eastwood-runner
  (:require
   [eastwood.lint :as lint]))

(defn -main [& _]
  ;; Lint both source and tests. Adjust paths if you add new roots.
  (lint/eastwood {:source-paths ["src" "dev"]
                  :test-paths   ["test"]
                  :linters      [:all]
                  :exclude-linters [:keyword-typos]}))
