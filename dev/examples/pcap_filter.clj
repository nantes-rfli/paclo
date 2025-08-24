(ns examples.pcap-filter
  (:require
   [paclo.core :as core]))

(defn -usage []
  (binding [*out* *err*]
    (println "Usage:")
    (println "  clojure -M:dev -m examples.pcap-filter <in.pcap> <out.pcap> [<bpf-string>] [<min-caplen>]")))

(defn -main
  "Read a PCAP, (optionally) apply BPF and a caplen filter, and write out a new PCAP
   while preserving timestamps. Prints how many packets were written.

   Examples:
     clojure -M:dev -m examples.pcap-filter in.pcap out.pcap
     clojure -M:dev -m examples.pcap-filter in.pcap out.pcap 'udp and port 53'
     clojure -M:dev -m examples.pcap-filter in.pcap out.pcap 'udp and port 53' 60"
  [& args]
  (let [[in out bpf-str min-caplen-str] args]
    (when (or (nil? in) (nil? out))
      (-usage) (System/exit 1))
    (let [min-caplen (when min-caplen-str (long (Long/parseLong min-caplen-str)))
          wrote      (volatile! 0)
          ;; ★ 修正点：filter を map より「前」に置く
          make-out   (fn [m]
                       (vswap! wrote inc)                     ; ← フィルタ通過後にカウント
                       (let [ba (:bytes m)
                             s  (:sec m)
                             us (:usec m)]
                         (cond-> {:bytes ba}
                           s  (assoc :sec s)
                           us (assoc :usec us))))
          xf         (if min-caplen
                       (comp
                        (filter #(>= (:caplen %) min-caplen))
                        (map make-out))
                       (map make-out))]
      (println "reading:" in)
      (println "writing:" out)
      (let [opts (cond-> {:path in
                          :decode? false
                          :xform xf
                          :max Long/MAX_VALUE}
                   bpf-str (assoc :filter bpf-str))
            stream (core/packets opts)]
        (core/write-pcap! stream out)
        (println "done. wrote packets =" @wrote)))))
