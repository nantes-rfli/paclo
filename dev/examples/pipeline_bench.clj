(ns examples.pipeline-bench
  (:require
   [clojure.string :as str]
   [examples.common :as ex]
   [paclo.core :as core]))

(defn- usage []
  (binding [*out* *err*]
    (println "Usage:")
    (println "  clojure -M:dev -m examples.pipeline-bench <in.pcap> [<bpf>] [<max>] [<out.pcap>] [decode?]")
    (println "Defaults: <bpf>=nil, <max>=100000, <out>=<tmp file>, decode?=false")
    (println "Pipeline: packets -> :xform (drop small frames) -> write-pcap! (count + elapsed)")))

(defn- tmp-out []
  (-> (java.io.File/createTempFile "paclo-pipeline" ".pcap")
      .getAbsolutePath))

(defn- nanos->ms [n]
  (double (/ (long n) 1e6)))

(defn- fmt-num [n]
  (when n (format "%,d" (long n))))

(defn- mk-xf [counter]
  ;; drop 小サイズフレームを例にした軽フィルタ。:bytes だけ残して write-pcap! へ渡す。
  (comp
   (filter #(>= (long (or (:caplen %) 0)) 60))
   (map (fn [m]
          (vswap! counter (fn ^long [^long n] (unchecked-inc n)))
          (select-keys m [:bytes :sec :usec])))))

(defn -main [& args]
  (let [[in bpf max-str out* decode-str] args]
    (when (nil? in) (usage) (System/exit 1))
    (let [in*   (ex/require-file! in)
          max-n (or (ex/parse-long* max-str) 100000)
          out   (or out* (tmp-out))
          decode? (boolean (some #{"true" "decode" "1" "yes"} [decode-str]))
          cnt   (volatile! 0)
          xf    (mk-xf cnt)
          opts  {:path in* :filter (when-not (ex/blank? bpf) bpf) :decode? decode? :xform xf :max max-n}
          t0    (System/nanoTime)]
      (core/write-pcap! (core/packets opts) out)
      (let [elapsed-ms (nanos->ms (- (System/nanoTime) t0))
            summary    (str/join " "
                                 ["filter=" (pr-str bpf)
                                  "max=" (str max-n)
                                  (str "decode?=" decode?)
                                  "(:xform drop<60B>)"])]
        (println "pipeline done:" (fmt-num @cnt) "packets ->" out
                 "elapsed(ms)=" (format "%.1f" elapsed-ms))
        (println "  opts:" summary)))
    (System/exit 0)))
