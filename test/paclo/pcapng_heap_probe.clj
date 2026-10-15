(ns paclo.pcapng-heap-probe
  "Separate constrained-heap acceptance probe; no event collection."
  (:require
   [paclo.pcapng :as pcapng]))

(defn -main [path]
  (with-open [s (pcapng/open-source {:path path})]
    (let [maxima (reduce (fn [[events interfaces metadata] _]
                           (let [info (pcapng/source-info s)]
                             [(inc events) (max interfaces (:active-interfaces info))
                              (max metadata (:active-metadata-bytes info))])) [0 0 0] s)
          info (pcapng/source-info s)]
      (assert (= [24000 2 33584] maxima) (str maxima))
      (assert (= :eof (:terminal info)))
      (assert (= 6000 (:opaque-blocks info)))
      (assert (zero? (:active-metadata-bytes info)))
      (println "PCAPNG bounded heap OK" maxima (:bytes-read info)))))
