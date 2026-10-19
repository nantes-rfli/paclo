(require '[clojure.data.json :as json]
         '[clojure.edn :as edn]
         '[clojure.java.io :as io]
         '[nvd.task.check :as check])

(let [[config-file output-dir data-dir refresh classpath] *command-line-args*
      config (edn/read-string (slurp config-file))
      effective-file (str (io/file output-dir "effective-config.edn"))]
  (when (or (not (contains? #{"true" "false"} refresh))
            (:nvd config)
            (not= 7.0 (:fail-threshold config))
            (not= "ALL" (:output-format config))
            (not= true (:auto-update config))
            (not= 24 (get-in config [:nvd-api :valid-for-hours]))
            (:suppression-file config))
    (throw (ex-info "Unexpected audit policy" {})))
  (spit effective-file
        (pr-str (cond-> (assoc config :output-dir output-dir :data-directory data-dir)
                  (= "true" refresh) (assoc-in [:nvd-api :valid-for-hours] 0))))
  (spit (str (io/file output-dir "tool-versions.json"))
        (json/write-str @check/version))
  (check/-main effective-file classpath))
