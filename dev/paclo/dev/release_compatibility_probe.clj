(ns paclo.dev.release-compatibility-probe
  (:require
   [clojure.java.io :as io]
   [paclo.core :as core]))

(def ^:private baseline
  {'paclo.core {'bpf [1] 'packet-xf [1] 'packets [1] 'reduce-packets [3]
                'reduce-packets-report [3] 'start-capture [1] 'capture-packets [1]
                'stop-capture! [1] 'capture-stats [1] 'write-pcap! [2] 'list-devices [0]}
   'paclo.stream {'fan-out [2 3] 'branch [2] 'stats [1]}
   'paclo.decode-ext {'register! [2] 'unregister! [1] 'installed [0] 'apply! [1]}})
(defn -main [& _]
  (try
    ;; Run unchanged against each JAR; never compile/load Paclo from the checkout.
    (doseq [resource ["paclo/core.clj" "paclo/jnr/PcapLibrary.class"]]
      (assert (= "jar" (.getProtocol (io/resource resource))) resource))

    (doseq [[n functions] baseline]
      (require n)
      (doseq [[f arities] functions]
        (let [v (ns-resolve n f) m (meta v) actual (set (map count (:arglists m)))]
          (assert (and v (not (:private m)) (every? actual arities)) (str n "/" f)))))
    (assert (= '& (ffirst (:arglists (meta #'core/-main)))))
    (prn [:supported-names-and-arities :retained])

    (doseq [[label extra] [[:legacy {:sec 1700000000 :usec 123}]
                           [:captured {:ts-sec 1700000001 :ts-usec 456}]
                           [:both {:sec 1700000000 :usec 123 :ts-sec 1700000001 :ts-usec 456}]
                           [:partial-new {:sec 1700000000 :usec 123 :ts-sec 1700000001}]
                           [:partial-legacy {:sec 1700000000}]
                           [:nil-legacy {:sec nil :usec nil}]
                           [:fractional-legacy {:sec 1700000000.5 :usec 123.5}]
                           [:negative {:sec -1 :usec 0}]
                           [:bad-usec {:sec 1700000000 :usec 1000000}]
                           [:truncated {:sec 1700000000 :usec 123 :caplen 60 :len 120}]
                           [:bad-caplen {:sec 1700000000 :usec 123 :caplen 59}]
                           [:bad-len {:sec 1700000000 :usec 123 :len 59}]
                           [:mismatch {:sec 1700000000 :usec 123 :linktype 113}]
                           [:snaplen-excess {:sec 1700000000 :usec 123}]]]
      (let [file (java.io.File/createTempFile "paclo-compatibility-" ".pcap")
            before (quot (System/currentTimeMillis) 1000)]
        (try
          (core/write-pcap! [(merge {:bytes (byte-array (if (= label :snaplen-excess) 65537 60))} extra)]
                            (.getPath file))
          ;; Inspect wire header directly: native libpcap may reject an invalid old record.
          (let [data (java.nio.ByteBuffer/wrap (java.nio.file.Files/readAllBytes (.toPath file)))
                _ (.order data java.nio.ByteOrder/LITTLE_ENDIAN)
                sec (Integer/toUnsignedLong (.getInt data 24))
                usec (Integer/toUnsignedLong (.getInt data 28))]
            (prn [label :written {:time (if (<= before sec (quot (System/currentTimeMillis) 1000))
                                          :wall-clock [sec usec])
                                  :caplen (Integer/toUnsignedLong (.getInt data 32))
                                  :len (Integer/toUnsignedLong (.getInt data 36))}]))
          (catch Exception e (prn [label :rejected (.getMessage e)]))
          (finally (.delete file)))))

    (let [packet {:bytes (byte-array 10) :ts-sec 1 :ts-usec 0 :caplen 10 :len 10}]
      (doseq [opts [{:decode? true} {:decode-mode :flow}]
              linktype [:absent 999]]
        (prn [:decode opts linktype
              (dissoc (first (sequence (core/packet-xf opts)
                                       [(cond-> packet (= linktype 999) (assoc :linktype 999))]))
                      :bytes)])))

    (try
      (let [r (core/reduce-packets-report {:path "broken.pcap" :max Long/MAX_VALUE}
                                          (fn [n _] (inc n)) 0)]
        (prn [:native-read :returned (:result r) (get-in r [:stats :stop-reason])]))
      (catch Exception e (prn [:native-read :thrown (.getMessage e) (ex-data e)])))
    (finally (shutdown-agents))))
