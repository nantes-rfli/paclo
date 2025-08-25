(ns examples.common
  (:require
   [clojure.data.json :as json]))

;; ----- tiny utils -----

(defn blank? [s] (or (nil? s) (= "" s) (= "_" s)))

(defn parse-long* [s]
  (try (when-not (blank? s) (Long/parseLong s)) (catch Exception _ nil)))

(defn parse-double* [s]
  (try (when-not (blank? s) (Double/parseDouble s)) (catch Exception _ nil)))

(defn require-file! ^String [path]
  (let [f (java.io.File. (str path))]
    (when-not (.isFile f)
      (binding [*out* *err*] (println "ERROR:" (str "input PCAP not found: " (.getAbsolutePath f))))
      (System/exit 2))
    (.getAbsolutePath f)))

(defn ensure-one-of! [^String what x allowed]
  (when-not (contains? allowed x)
    (binding [*out* *err*]
      (println "ERROR:" (format "invalid %s: %s (allowed: %s)"
                                what x (str (seq allowed)))))
    (System/exit 3)))

(defn emit
  "fmt = :edn | :jsonl。ベクタ/シーケンスは :jsonl で1行ずつ。"
  [fmt data]
  (case fmt
    :jsonl (cond
             (sequential? data) (doseq [row data] (json/write row *out*) (println))
             (map? data) (do (json/write data *out*) (println))
             :else (do (json/write {:value data} *out*) (println)))
    (println (pr-str data))))
