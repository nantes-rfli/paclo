(ns examples.tls-sni-scan
  (:require
   [examples.common :as ex]
   [paclo.core :as core]
   [paclo.proto.tls-ext :as tls-ext]))

(defn- usage []
  (binding [*out* *err*]
    (println "Usage:")
    (println "  clojure -M:dev -m examples.tls-sni-scan <in.pcap> [<bpf-string>] [<topN>] [<format>]")
    (println "Defaults: <bpf-string>='tcp and port 443', topN=50, format=edn")
    (println "Formats : edn | jsonl")
    (println "Tips    : use \"_\" to skip an optional arg (e.g., '_' for <bpf-string>)")))

(defn -main [& args]
  (let [[in bpf-str topn-str fmt-str] args]
    (when (nil? in) (usage) (System/exit 1))
    (let [in* (ex/require-file! in)
          bpf (if (ex/blank? bpf-str) "tcp and port 443" bpf-str)
          n   (or (ex/parse-long* topn-str) 50)
          fmt (ex/parse-format fmt-str)]
      (tls-ext/register!)
      (let [cnts (reduce
                  (fn [m p]
                    (if-let [sni (get-in p [:decoded :l3 :l4 :app :sni])]
                      (update m sni (fnil inc 0))
                      m))
                  {}
                  (core/packets {:path in* :filter bpf :decode? true :max Long/MAX_VALUE}))
            rows (->> cnts (sort-by val >) (take n)
                      (map (fn [[k v]] {:sni k :count v})) vec)]
        (ex/emit fmt rows)
        (binding [*out* *err*]
          (println "sni-unique=" (count cnts) " topN=" n " bpf=" (pr-str bpf) " format=" (name fmt)))))))
