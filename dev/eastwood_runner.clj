(ns eastwood-runner
  (:require
   [eastwood.lint :as lint]))

(defn -main [& _]
  ;; Lint both source and tests. Adjust paths if you add new roots.
  (lint/eastwood {:source-paths ["src" "dev"]
                  :test-paths   ["test"]
                  :linters      [:all]
                  ;; キーワード表記の揺れは意図的に許容
                  ;; パフォーマンス系/boxed/reflection は現行設計で許容するため除外し、
                  ;; ノイズ警告ゼロで CI を通す。
                  :exclude-linters [:keyword-typos :non-clojure-file
                                    :boxed-math :reflection :performance
                                    :unused-meta-on-macro]}))
