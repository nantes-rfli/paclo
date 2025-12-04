(ns make-synth-pcap
  (:require
   [clojure.string :as str]
   [paclo.pcap :as pcap]))

(defn- usage []
  (binding [*out* *err*]
    (println "Usage:")
    (println "  clojure -M:dev -m make-synth-pcap <out.pcap> [<count>] [<caplen>]")
    (println "Defaults: <count>=50000, <caplen>=74 (bytes)")
    (println "Tips   : use '_' to skip optional args (e.g., '_' for <caplen>)")))

(defn- parse-long* [s]
  (try (when (and s (not= s "") (not= s "_")) (Long/parseLong s)) (catch Exception _ nil)))

(defn- gen-bytes [n fill]
  (let [b (byte fill)]
    (byte-array (repeat n b))))

(defn -main [& args]
  (let [[out cnt-str caplen-str] args]
    (when (str/blank? out)
      (usage)
      (System/exit 1))
    (let [cnt    (or (parse-long* cnt-str) 50000)
          caplen (or (parse-long* caplen-str) 74)
          pkt    (gen-bytes caplen 0)]
      (println "writing" cnt "packets" "caplen=" caplen "to" out)
      (pcap/bytes-seq->pcap! (repeat cnt pkt) {:out out})
      (println "done:" out " (" cnt " packets )"))))
