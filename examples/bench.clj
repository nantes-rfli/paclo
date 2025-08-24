(ns examples.bench
   (:require
    [paclo.core :as core]))

 (defn- nanos->ms [n] (double (/ n 1e6)))

 (defn- gen-bytes [^long n ^byte fill]
   (byte-array (repeat n fill)))

 (defn -main
   "Synthetic micro-bench:
   - writes N packets (default: 100000) into a temp PCAP
   - reads them twice:
       (a) plain         → count
       (b) with :xform   → filter caplen>=60 then count
   - prints elapsed times in ms.

   Usage:
     clojure -M -m examples.bench [N]"
   [& args]
   (let [n   (long (or (some-> args first Long/parseLong) 100000))
         tmp (-> (java.io.File/createTempFile "paclo-bench" ".pcap")
                 .getAbsolutePath)
         pkt60 (gen-bytes 60 (byte 0))
         pkt42 (gen-bytes 42 (byte 1))
        ;; ~50% pass / 50% drop for :xform filter
         data (take n (cycle [pkt60 pkt42]))]
     (println "Writing" n "packets to" tmp)
     (core/write-pcap! data tmp)
    ;; (a) plain
     (let [t0 (System/nanoTime)
           c1 (count (core/packets {:path tmp}))
           t1 (- (System/nanoTime) t0)]
       (println "plain count =" c1 "elapsed(ms)=" (format "%.1f" (nanos->ms t1))))
    ;; (b) with :xform
     (let [xf (filter #(>= (:caplen %) 60))
           t0 (System/nanoTime)
           c2 (count (core/packets {:path tmp :xform xf}))
           t1 (- (System/nanoTime) t0)]
       (println "xform  count =" c2 "elapsed(ms)=" (format "%.1f" (nanos->ms t1)))))))
