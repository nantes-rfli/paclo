(ns eastwood-runner
  (:require
   [eastwood.lint :as lint]))

(defn -main [& _]
  ;; Lint both source and tests. Adjust paths if you add new roots.
  (lint/eastwood {:source-paths ["src" "dev"]
                  :test-paths   ["test"]
                  :linters      [:all]
                  :exclude-linters [:keyword-typos
                                    :boxed-math       ;; 数値演算のボクシングはJITで十分と判断
                                    :reflection       ;; jnr-ffi周りの反射は回避が困難なため除外
                                    :performance]     ;; case/recur のプリミティブ最適化は後回し
                  }))
