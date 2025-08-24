(ns examples.dns-summary
  (:require
   [clojure.java.io :as io]
   [paclo.core :as core]
   [paclo.proto.dns-ext :as dns-ext]))


(defn -main
  "Usage:
    clojure -M:dev -m examples.dns-summary <pcap-path>

  Prints a tiny vector of DNS packets with :summary added by the decode extension."
  [& args]
  (when (empty? args)
    (binding [*out* *err*]
      (println "Usage: clojure -M:dev -m examples.dns-summary <pcap-path>"))
    (System/exit 1))
  (let [pcap (first args)
        abs  (.getAbsolutePath (io/file pcap))]
    (println "reading:" abs)
    (dns-ext/register!)
    (let [xf (comp
              (filter #(= :dns (get-in % [:decoded :l3 :l4 :app :type])))
              (map #(select-keys % [:caplen :decoded])))
          ;; ここは BPF 文字列で絞る（core はDSLもOKだが混乱防止で文字列に）
          xs (into [] (core/packets {:path abs
                                     :filter "udp and port 53"
                                     :decode? true
                                     :xform xf}))]
      (println (pr-str xs)))))
