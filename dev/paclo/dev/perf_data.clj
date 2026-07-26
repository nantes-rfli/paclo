(ns paclo.dev.perf-data
  "Deterministic Ethernet frame and benchmark PCAP generation."
  (:require
   [clojure.java.io :as io]
   [paclo.pcap :as pcap]))

(def ^:private traffic-cases
  [{:id :udp-64 :frame-size 64 :traffic :udp}
   {:id :tcp-512 :frame-size 512 :traffic :tcp}
   {:id :mixed :frame-size 64
    :alternate-frame-size 512
    :traffic :mixed}])

(def profiles
  "Named benchmark profiles. Large files are generated under target on demand."
  {:quick {:count 50000
           :cases traffic-cases}
   :reference {:count 1000000
               :cases traffic-cases}
   :stress {:count 10000000
            :cases traffic-cases}})

(defn- put-u16!
  [^bytes frame ^long offset ^long value]
  (aset-byte frame (int offset)
             (unchecked-byte (bit-shift-right value 8)))
  (aset-byte frame (int (inc offset)) (unchecked-byte value))
  frame)

(defn- put-u32!
  [^bytes frame ^long offset ^long value]
  (dotimes [i 4]
    (aset-byte frame
               (int (+ offset i))
               (unchecked-byte (bit-shift-right value (* 8 (- 3 i))))))
  frame)

(defn- fill-ethernet!
  [^bytes frame]
  (dotimes [i 6]
    (aset-byte frame i (byte (+ 0x10 i)))
    (aset-byte frame (+ 6 i) (byte (+ 0x20 i))))
  (put-u16! frame 12 0x0800))

(defn- fill-ipv4!
  [^bytes frame ^long protocol]
  (let [ip-length (- (alength frame) 14)]
    (aset-byte frame 14 (unchecked-byte 0x45))
    (put-u16! frame 16 ip-length)
    (put-u16! frame 18 1)
    (put-u16! frame 20 0x4000)
    (aset-byte frame 22 (unchecked-byte 64))
    (aset-byte frame 23 (unchecked-byte protocol))
    ;; Parser benchmarks do not validate checksums.
    (put-u16! frame 24 0)
    (doseq [[offset value] [[26 10] [27 0] [28 0] [29 1]
                            [30 10] [31 0] [32 0] [33 2]]]
      (aset-byte frame offset (unchecked-byte value))))
  frame)

(defn- fill-udp!
  [^bytes frame]
  (let [offset 34
        udp-length (- (alength frame) offset)]
    (put-u16! frame offset 12000)
    (put-u16! frame (+ offset 2) 5300)
    (put-u16! frame (+ offset 4) udp-length)
    (put-u16! frame (+ offset 6) 0))
  frame)

(defn- fill-tcp!
  [^bytes frame]
  (let [offset 34]
    (put-u16! frame offset 12000)
    (put-u16! frame (+ offset 2) 443)
    (put-u32! frame (+ offset 4) 1)
    (put-u32! frame (+ offset 8) 0)
    (put-u16! frame (+ offset 12) 0x5002)
    (put-u16! frame (+ offset 14) 65535)
    (put-u16! frame (+ offset 16) 0)
    (put-u16! frame (+ offset 18) 0))
  frame)

(defn ethernet-ipv4-frame
  "Build a deterministic Ethernet/IPv4 TCP or UDP frame of `frame-size` bytes."
  [frame-size traffic]
  (when-not (and (integer? frame-size) (>= (long frame-size) 64))
    (throw (ex-info "frame-size must be an integer >= 64"
                    {:frame-size frame-size})))
  (when-not (contains? #{:tcp :udp} traffic)
    (throw (ex-info "traffic must be :tcp or :udp" {:traffic traffic})))
  (let [frame (byte-array frame-size)
        protocol (if (= traffic :tcp) 6 17)]
    (fill-ethernet! frame)
    (fill-ipv4! frame protocol)
    (if (= traffic :tcp)
      (fill-tcp! frame)
      (fill-udp! frame))
    frame))

(defn frames-for-case
  "Return the finite deterministic frame sequence for a benchmark case."
  [{:keys [count frame-size alternate-frame-size traffic]}]
  (let [udp (ethernet-ipv4-frame (long frame-size) :udp)
        tcp (when (#{:tcp :mixed} traffic)
              (ethernet-ipv4-frame
               (long (or alternate-frame-size frame-size))
               :tcp))
        frames (case traffic
                 :udp [udp]
                 :tcp [tcp]
                 :mixed [udp tcp]
                 (throw (ex-info "unknown traffic shape" {:traffic traffic})))]
    (take count (cycle frames))))

(defn expected-pcap-size
  "Return classic-PCAP file size for fixed-size captured frames."
  [count frame-size]
  (+ 24 (* (long count) (+ 16 (long frame-size)))))

(defn expected-case-pcap-size
  [{:keys [count frame-size alternate-frame-size traffic]}]
  (if (= traffic :mixed)
    (+ 24
       (reduce +
               (take count
                     (cycle [(+ 16 (long frame-size))
                             (+ 16 (long (or alternate-frame-size
                                             frame-size)))]))))
    (expected-pcap-size count frame-size)))

(defn expected-captured-bytes
  [{:keys [count frame-size alternate-frame-size traffic]}]
  (if (= traffic :mixed)
    (reduce +
            (take count
                  (cycle [(long frame-size)
                          (long (or alternate-frame-size frame-size))])))
    (* (long count) (long frame-size))))

(defn dataset-path
  [root profile case-id]
  (str (io/file root (str (name profile) "-" (name case-id) ".pcap"))))

(defn ensure-dataset!
  "Generate a deterministic PCAP unless an existing file has the expected size."
  [path case-config]
  (let [file (io/file path)
        expected (expected-case-pcap-size case-config)]
    (if (and (.isFile file) (= expected (.length file)))
      path
      (do
        (io/make-parents file)
        (pcap/bytes-seq->pcap!
         (map-indexed
          (fn [index frame]
            {:bytes frame
             :sec 1700000000
             :usec (mod index 1000000)})
          (frames-for-case case-config))
         {:out path})
        (when-not (= expected (.length file))
          (throw (ex-info "generated PCAP has unexpected size"
                          {:path path
                           :expected expected
                           :actual (.length file)})))
        path))))
