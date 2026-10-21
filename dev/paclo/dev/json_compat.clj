(ns paclo.dev.json-compat
  "Offline, deterministic JSON upgrade comparison. Run in separate old/new JVMs."
  (:require
   [clojure.data.json :as json]
   [clojure.java.io :as io]
   [examples.common :as common]
   [examples.dns-qps :as qps]
   [examples.dns-rtt :as rtt]
   [examples.dns-topn :as topn]
   [examples.flow-topn :as flow]
   [examples.pcap-stats :as stats]
   [examples.tls-sni-scan :as tls]
   [paclo.dev.perf-merge :as perf-merge])
  (:import
   [java.io PushbackReader StringReader StringWriter]))

(defn- outcome [f]
  (try
    {:value (f)}
    (catch Exception e
      {:exception (.getName (class e)) :message (ex-message e)})))

(defn- cli-output [f & args]
  (binding [*err* (StringWriter.)]
    (with-out-str (apply f args))))

(defn -main [& [output]]
  (try
    (let [sample "test/resources/dns-sample.pcap"
          values [nil false true 0 Long/MIN_VALUE Long/MAX_VALUE 9223372036854775808N
                  1.25 1.234567890123456789M "日本語 café 😀" "\"\\/\b\f\n\r\t"
                  (apply str (map char (range 32)))
                  {:count 4 :missing nil :rows [true false "dns"]}]
          report (array-map :schema-version 2 :created-at "2026-01-01T00:00:00Z"
                            :profile :quick :live nil :offline
                            [{:scenario :full-reduce :path "日本語\n.pcap"
                              :runs [{:packets 50000 :bytes 3200000 :decode-errors 0
                                      :elapsed-ns 123456789 :queue-drop-rate 0.0}]}])
          paths (perf-merge/write-results! output report)
          result
          {:writes (mapv json/write-str values)
           :reads (mapv (fn [value]
                          (let [decoded (json/read-str (json/write-str value))]
                            {:value decoded :class (some-> decoded class .getName)})) values)
           :cli {:stats (cli-output stats/-main sample "_" "_" "jsonl")
                 :flow (cli-output flow/-main sample "_" "10" "unidir" "packets" "jsonl")
                 :qps (cli-output qps/-main sample "_" "1000" "qname" "jsonl")
                 :rtt (cli-output rtt/-main sample "_" "_" "stats" "_" "jsonl")
                 :pairs (cli-output rtt/-main sample "_" "_" "pairs" "_" "jsonl")
                 :qstats (cli-output rtt/-main sample "_" "_" "qstats" "_" "jsonl")
                 :topn (cli-output topn/-main sample "_" "10" "qname" "jsonl")
                 :tls (cli-output tls/-main "test/resources/tls-sni-alpn-sample.pcap" "_" "_" "jsonl")
                 :escaped (with-out-str (common/emit :jsonl {:qname "日本語\n\"\\😀" :count 4}))}
           :performance (slurp (:json paths))
           :malformed (mapv (fn [text] [text (outcome #(json/read-str text))])
                            ["" " \n\t" "[" "{" "\"" "01" "1e" "[1,]" "{\"x\":}" "\"\\q\""])
           :controls (mapv (fn [code]
                             [code (outcome #(json/read-str (str (char code))))])
                           (remove #{9 10 13} (range 32)))
           :quoted-controls (outcome #(json/read-str (str "\"a" (char 0) "b\"")))
           :numeric-eof (mapv (fn [text]
                                (with-open [reader (PushbackReader. (StringReader. text) 64)]
                                  [text (json/read reader)
                                   (outcome #(json/read reader :eof-error? false :eof-value :eof))]))
                              ["0" "-1" "9223372036854775808" "1.25" "1e3"])}]
      (spit (io/file output "compatibility.edn") (str (pr-str result) "\n")))
    (finally (shutdown-agents))))
