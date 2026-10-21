(ns paclo.dev.java-quality
  "Shared subprocess checks for Java quality commands."
  (:require [clojure.java.shell :as sh]
            [clojure.string :as str]))

(defn process! [& args]
  (let [{:keys [exit] :as result} (apply sh/sh args)]
    (when-not (zero? exit)
      (throw (ex-info "Java quality subprocess failed" (assoc result :command args))))
    result))

(defn classpath
  ([] (classpath nil))
  ([alias-arg]
   (-> (apply process! (cond-> ["clojure"]
                         alias-arg (conj alias-arg)
                         true (conj "-Spath")))
       :out str/trim)))
