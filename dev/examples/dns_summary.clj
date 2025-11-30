(ns examples.dns-summary
  (:require
   [clojure.java.io :as io]
   [paclo.core :as core]
   [paclo.proto.dns-ext :as dns-ext]))

(defn -main
  "Usage:
    clojure -M:dev -m examples.dns-summary <pcap-path>

  Prints compact DNS summaries as EDN vector.
  Example element:
    {:dir :query|:response
     :id  26905
     :rcode :noerror
     :questions 1
     :answers   6
     :src \"192.168.4.28:58555\"
     :dst \"1.1.1.1:53\"}"
  [& args]
  (when (empty? args)
    (binding [*out* *err*]
      (println "Usage: clojure -M:dev -m examples.dns-summary <pcap-path>"))
    (System/exit 1))
  (let [pcap (first args)
        abs  (.getAbsolutePath (io/file pcap))]
    (println "reading:" abs)
    (dns-ext/register!)
    (let [summarize
          (fn [pkt]
            (let [app     (get-in pkt [:decoded :l3 :l4 :app])
                  l4      (get-in pkt [:decoded :l3 :l4])
                  dir     (if (:qr? app) :response :query)
                  id      (:id app)
                  rcode   (some-> (:rcode-name app) keyword)
                  qd      (:qdcount app)
                  an      (:ancount app)
                  qname   (:qname app)
                  qtype   (:qtype-name app)
                  src     (str (get-in pkt [:decoded :l3 :src]) ":" (:src-port l4))
                  dst     (str (get-in pkt [:decoded :l3 :dst]) ":" (:dst-port l4))]
              (cond-> {:dir dir :id id :rcode rcode
                       :questions qd :answers an
                       :src src :dst dst}
                qname (assoc :qname qname)
                qtype (assoc :qtype qtype))))]
      (println
       (pr-str
        (into []
              (comp
               (filter #(= :dns (get-in % [:decoded :l3 :l4 :app :type])))
               (map summarize))
              (core/packets {:path abs
                             :filter "udp and port 53"
                             :decode? true})))))))
