(ns examples.dns-summary
  (:require
   [clojure.string :as str]
   [paclo.core :as core]
   [paclo.proto.dns-ext :as dns-ext]))

(defn -main
  "Usage:
    clojure -M -m examples.dns-summary <pcap-path>

  Prints a tiny vector of DNS packets with :summary added by the decode extension."
  [& args]
  (when (empty? args)
    (binding [*out* *err*]
      (println "Usage: clojure -M -m examples.dns-summary <pcap-path>"))
    (System/exit 1))
  (let [pcap (first args)]
    ;; enable DNS summary extension
    (dns-ext/register!)
    (let [xf (comp
              (filter #(= :dns (get-in % [:decoded :l3 :l4 :app :type])))
              (map #(select-keys % [:caplen :decoded])))
          xs (into [] (core/packets {:path pcap :decode? true :xform xf}))]
      (println (pr-str xs)))))
