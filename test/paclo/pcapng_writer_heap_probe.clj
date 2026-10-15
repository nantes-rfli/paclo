(ns paclo.pcapng-writer-heap-probe
  "Reader-to-writer acceptance in a separate constrained heap; no collection."
  (:require
   [paclo.pcapng :as pcapng]
   [paclo.pcapng.cursor :as cursor]))

(defn -main [input output]
  (let [accept cursor/accept-body maxima (atom [0 0])]
    (with-open [source (pcapng/open-source {:path input})]
      (with-redefs [cursor/accept-body
                    (fn [& args]
                      (let [[state :as result] (apply accept args)]
                        (swap! maxima (fn [[interfaces metadata]]
                                        [(max interfaces (count (:interfaces state)))
                                         (max metadata (:metadata-bytes state))]))
                        result))]
        (let [report (pcapng/write-pcapng! source output)]
          (assert (= 24000 (:blocks-written report)))
          (assert (= [2 33572] @maxima) (str @maxima))
          (assert (= :eof (:terminal (pcapng/source-info source))))
          (assert (= {} (:loss-counts report)))
          (println "PCAPNG writer bounded heap OK" @maxima (:bytes-written report)))))))
