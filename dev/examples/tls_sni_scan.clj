(ns examples.tls-sni-scan
  (:require
   [clojure.data.json :as json]
   [paclo.core :as core]
   [paclo.proto.tls-ext :as tls-ext]))

(defn- usage []
  (binding [*out* *err*]
    (println "Usage:")
    (println "  clojure -M:dev -m examples.tls-sni-scan <in.pcap> [<bpf-string>] [<topN>] [<format>]")
    (println "Defaults: <bpf-string>='tcp and port 443', topN=50, format=edn")))

(defn- topN [m n] (->> m (sort-by val >) (take n) (map (fn [[k v]] {:sni k :count v})) vec))

(defn -main [& args]
  (let [[in bpf-str topn-str fmt-str] args]
    (when (nil? in) (usage) (System/exit 1))
    (let [bpf (or bpf-str "tcp and port 443")
          n   (long (or (some-> topn-str Long/parseLong) 50))
          fmt (keyword (or fmt-str "edn"))]
      (tls-ext/register!)
      (let [cnts (reduce
                  (fn [m p]
                    (if-let [sni (get-in p [:decoded :l3 :l4 :app :sni])]
                      (update m sni (fnil inc 0))
                      m))
                  {}
                  (core/packets {:path in :filter bpf :decode? true :max Long/MAX_VALUE}))
            out  (topN cnts n)]
        (case fmt
          :jsonl (doseq [row out] (json/write row *out*) (println))
          (println (pr-str out)))
        (binding [*out* *err*]
          (println "sni-unique=" (count cnts) " topN=" n " bpf=" (pr-str bpf) " format=" (name fmt)))))))
