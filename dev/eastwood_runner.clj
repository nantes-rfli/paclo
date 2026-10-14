(ns eastwood-runner
  (:require
   [eastwood.lint :as lint]))

(def lint-options
  ;; Lint both source and tests. Adjust paths if you add new roots.
  {:source-paths ["src" "dev" "extensions/dns/src"]
   :test-paths   ["test"]
   :linters      [:all]
   ;; Accept this naming style intentionally.
   :exclude-linters [:keyword-typos :non-clojure-file]})

(defn -main [& _]
  (try
    (let [result (lint/eastwood lint-options)]
      ;; Eastwood 1.4.3 returns errors instead of throwing by default. This
      ;; includes analyzer/linter exceptions and an aborted namespace traversal.
      ;; Keep existing warnings informational, but require explicit success.
      (when-not (false? (:some-errors result))
        (throw (ex-info "Eastwood analysis failed" result))))
    (finally
      (shutdown-agents))))
