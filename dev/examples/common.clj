(ns examples.common
  (:require
   [clojure.data.json :as json]))

;; ----- tiny utils -----

(defn error-exit! [msg code]
  (binding [*out* *err*]
    (println "ERROR:" msg))
  (System/exit code))

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

(defn parse-format
  "fmt-str -> :edn/:jsonl（nil や \"_\" はデフォルトedn）。不正なら usage エラーを出して終了。"
  [fmt-str]
  (let [fmt (keyword (or (when-not (blank? fmt-str) fmt-str) "edn"))]
    (ensure-one-of! "format" fmt #{:edn :jsonl})
    fmt))

(defn emit
  "fmt = :edn | :jsonl。ベクタ/シーケンスは :jsonl で1行ずつ。"
  [fmt data]
  (case fmt
    :jsonl (cond
             (sequential? data) (doseq [row data] (json/write row *out*) (println))
             (map? data) (do (json/write data *out*) (println))
             :else (do (json/write {:value data} *out*) (println)))
    (println (pr-str data))))

(defn parse-async-opts
  "共通 async フラグのパーサ。
  args -> {:async? bool :async-buffer long :async-mode :buffer|:dropping :async-timeout-ms long|nil}
  defaults 省略時: buffer=1024, mode=:buffer"
  [args {:keys [default-buffer default-mode] :or {default-buffer 1024 default-mode :buffer}}]
  (loop [opts {:async? false
               :async-buffer default-buffer
               :async-mode default-mode
               :async-timeout-ms nil}
         xs   args]
    (if (empty? xs)
      opts
      (let [[k & more] xs]
        (case k
          "--async" (recur (assoc opts :async? true) more)
          "--async-buffer"
          (let [n (parse-long* (first more))]
            (when-not n (error-exit! "--async-buffer requires a number" 4))
            (recur (assoc opts :async-buffer n) (rest more)))
          "--async-mode"
          (let [m (keyword (or (first more) ""))]
            (when-not (contains? #{:buffer :dropping} m)
              (error-exit! "--async-mode must be buffer|dropping" 4))
            (recur (assoc opts :async-mode m) (rest more)))
          "--async-timeout-ms"
          (let [n (parse-long* (first more))]
            (when-not n (error-exit! "--async-timeout-ms requires a number" 4))
            (recur (assoc opts :async-timeout-ms n) (rest more)))
          (error-exit! (str "unknown flag: " k) 4))))))
