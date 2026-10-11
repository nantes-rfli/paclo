(ns paclo.dev.perf-merge
  "Validate and reassemble offline benchmark shards without libpcap or Java bindings."
  (:require
   [clojure.data.json :as json]
   [clojure.edn :as edn]
   [clojure.java.io :as io]
   [clojure.string :as str]
   [paclo.dev.perf-spec :as spec])
  (:import
   [java.time Instant]))

(defn- json-key [value]
  (if (keyword? value) (name value) (str value)))

(defn write-results!
  [output result]
  (let [edn-path (io/file output "results.edn")
        json-path (io/file output "results.json")]
    (io/make-parents edn-path)
    (spit edn-path (str (pr-str result) "\n"))
    (spit json-path (str (json/write-str result :key-fn json-key) "\n"))
    {:edn (.getAbsolutePath edn-path)
     :json (.getAbsolutePath json-path)}))

(defn- validate-offline-result!
  [result config]
  (let [expected-packets (long (:count config))
        expected-bytes (long (spec/expected-captured-bytes config))]
    (doseq [run (:runs result)]
      (when-not (and (= expected-packets (long (:packets run)))
                     (= expected-bytes (long (:bytes run)))
                     (zero? (long (:decode-errors run))))
        (throw (ex-info "offline benchmark result failed consistency checks"
                        {:scenario (:scenario result)
                         :expected {:packets expected-packets
                                    :bytes expected-bytes
                                    :decode-errors 0}
                         :actual (select-keys
                                  run
                                  [:packets :bytes :decode-errors])})))))
  result)

(defn merge-offline-results!
  "Reassemble independently measured cases in original order. Fail closed
   on absent, duplicate or corrupt results before writing combined artifacts."
  [{:keys [profile output merge-inputs]}]
  (let [{:keys [cases] :as profile-config} (get spec/profiles profile)
        packet-count (:count profile-config)
        paths (when (string? merge-inputs)
                (str/split merge-inputs #"," -1))
        ids (mapv :id cases)]
    (when-not (and cases
                   (string? output)
                   (not (str/blank? output))
                   (= (count ids) (count paths))
                   (not-any? str/blank? paths))
      (throw (ex-info "expected one input per offline traffic case"
                      {:profile profile :output output
                       :paths paths :cases ids})))
    (let [parts (mapv (fn [path]
                        (edn/read-string (slurp (io/file path))))
                      paths)
          by-case
          (reduce
           (fn [acc part]
             (when-not (and (= 2 (:schema-version part))
                            (= profile (:profile part))
                            (string? (:created-at part))
                            (nil? (:live part))
                            (nil? (:max-sustainable-by-scenario part))
                            (vector? (:offline part))
                            (= (count spec/offline-scenarios)
                               (count (:offline part))))
               (throw (ex-info "invalid performance shard envelope"
                               {:profile profile})))
             (let [results (:offline part)
                   names (set (map #(some-> (:path %) io/file .getName)
                                   results))
                   [case-config] (filter
                                  #(= names
                                      #{(str (name profile) "-" (name (:id %))
                                             ".pcap")})
                                  cases)
                   scenario-ids (mapv :scenario results)]
               (when-not (and case-config
                              (= (count scenario-ids)
                                 (count (set scenario-ids)))
                              (= (set scenario-ids)
                                 (set spec/offline-scenarios))
                              (every? #(and (= :offline (:mode %))
                                            (map? (:summary %))
                                            (= (if (= profile :quick) 1 5)
                                               (count (:runs %))))
                                      results))
                 (throw (ex-info "invalid or incomplete performance shard"
                                 {:paths (mapv :path results)
                                  :scenarios scenario-ids})))
               (when (contains? acc (:id case-config))
                 (throw (ex-info "duplicate performance traffic case"
                                 {:case (:id case-config)})))
               (doseq [result results]
                 (validate-offline-result!
                  result
                  (assoc case-config :count packet-count)))
               (assoc acc (:id case-config)
                      (into {} (map (juxt :scenario identity)) results))))
           {}
           parts)]
      (when-not (= (set ids) (set (keys by-case)))
        (throw (ex-info "missing performance traffic cases"
                        {:expected ids :actual (keys by-case)})))
      (let [result {:schema-version 2
                    :created-at (str (Instant/now))
                    :profile profile
                    :offline (vec (for [id ids
                                        scenario spec/offline-scenarios]
                                    (get-in by-case [id scenario])))
                    :live nil
                    :max-sustainable-by-scenario nil}
            paths (write-results! output result)]
        (println "[perf] merged" (count (:offline result))
                 "offline scenarios")
        (println "[perf] wrote" (:edn paths))
        (println "[perf] wrote" (:json paths))
        (assoc result :result-paths paths)))))

(defn- parse-args [args]
  (when (odd? (count args))
    (throw (ex-info "expected --name value arguments" {:args args})))
  (let [known {"--profile" :profile
               "--output" :output
               "--merge-inputs" :merge-inputs}
        opts (reduce
              (fn [m [flag value]]
                (when-not (contains? known flag)
                  (throw (ex-info "unknown merge argument" {:flag flag})))
                (assoc m (get known flag) value))
              {}
              (partition 2 args))]
    (update opts :profile keyword)))

(defn -main [& args]
  (try
    (merge-offline-results! (parse-args args))
    (finally
      (shutdown-agents))))
