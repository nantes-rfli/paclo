(ns paclo.dev.environment-check
  "Executable readiness checks for development environments, without live capture."
  (:require
   [paclo.core :as core]
   [paclo.decode-ext :as dx]
   [paclo.proto.dns-ext :as dns]))

(defn- ensure! [condition message data]
  (when-not condition
    (throw (ex-info message data))))

(defn- sample-packets []
  (core/reduce-packets
   {:path "test/resources/dns-sample.pcap"
    :decode? true
    :max Long/MAX_VALUE
    :max-time-ms 60000}
   conj
   []))

(defn- check-sample! []
  (let [packets (sample-packets)
        packet-count (count packets)
        byte-count (reduce + (map :caplen packets))]
    (ensure! (= 4 packet-count) "Unexpected DNS fixture packet count"
             {:actual packet-count})
    (ensure! (= 438 byte-count) "Unexpected DNS fixture byte count"
             {:actual byte-count})
    (ensure! (every? :decoded packets) "DNS fixture did not decode" {})
    (ensure! (not-any? :decode-error packets) "DNS fixture has decode errors" {})
    packets))

(defn- check-write! [packets]
  (let [file (java.io.File/createTempFile "paclo-environment-" ".pcap")]
    (try
      (core/write-pcap! packets (.getAbsolutePath file))
      (let [saved (core/reduce-packets
                   {:path (.getAbsolutePath file) :max Long/MAX_VALUE
                    :max-time-ms 60000}
                   conj [])
            comparable (fn [packet]
                         (assoc (select-keys packet [:ts-sec :ts-usec :caplen :len])
                                :bytes (vec (:bytes packet))))]
        (ensure! (= (mapv comparable packets) (mapv comparable saved))
                 "Offline writer smoke failed" {}))
      (finally
        (.delete file)))))

(defn -main [& [mode]]
  (try
    (ensure! (contains? #{"doctor" "smoke"} mode) "Unknown check mode" {:mode mode})
    (let [jdk (System/getProperty "java.specification.version")]
      (ensure! (contains? #{"17" "21"} jdk) "Use a supported JDK (17 or 21)" {:jdk jdk})
      (ensure! (= "1.12" (str (:major *clojure-version*) "." (:minor *clojure-version*)))
               "Use the project's Clojure 1.12.x dependency" {:clojure (clojure-version)})
      (let [packets (check-sample!)]
        (when (= "smoke" mode)
          (check-write! packets)
          (let [hook-key (dns/register!)]
            (try
              (ensure! (some #(get-in % [:decoded :l3 :l4 :app :qname])
                             (check-sample!))
                       "DNS extension did not annotate the fixture" {})
              (finally
                (dx/unregister! hook-key)))))
        (prn {:check (keyword mode)
              :status :ok
              :jdk jdk
              :clojure (clojure-version)
              :os (System/getProperty "os.name")
              :arch (System/getProperty "os.arch")
              :native-pcap :offline-read-ok
              :packets (count packets)
              :bytes (reduce + (map :caplen packets))})))
    (finally
      (shutdown-agents))))
