(ns paclo.raw-ip-test
  (:require
   [clojure.data.json :as json]
   [clojure.edn :as edn]
   [clojure.test :refer [deftest is testing]]
   [clojure.test.check.clojure-test :refer [defspec]]
   [clojure.test.check.generators :as gen]
   [clojure.test.check.properties :as prop]
   [paclo.cooked-test :as cooked]
   [paclo.core :as core]
   [paclo.flow :as flow]
   [paclo.flow.project :as project]
   [paclo.linktype :as linktype]
   [paclo.parse :as parse]
   [paclo.proto.dns-ext :as dns-ext]
   [paclo.proto.tls-ext :as tls-ext]
   [paclo.stream :as stream]
   [paclo.test-util :as util])
  (:import
   [java.io Closeable File]
   [java.util Arrays]))

(declare raw-ip-prefixes-preserve-input-and-absolute-locations)

(def records (json/read-str (slurp "test/resources/raw-ip/manifest.json") :key-fn keyword))
(defn options [file] {:path (str "test/resources/raw-ip/" file) :max 100 :max-time-ms 60000})
(defn packet [row] {:bytes (util/hex->bytes (:hex row)) :linktype 12})

(deftest bare-ip-protocols-fragments-and-diagnostics
  (doseq [row records]
    (testing (:name row)
      (let [input (packet row)
            snapshot (vec (:bytes input))
            full (cooked/transform cooked/full-config input)
            projected (cooked/transform cooked/flow-config input)
            l3 (get-in full [:decoded :l3])]
        (is (identical? (:bytes input) (:bytes full)))
        (is (= snapshot (vec (:bytes input))))
        (is (not-any? #(contains? projected %) [:bytes :decoded]))
        (when-let [version (:version row)]
          (is (nil? (:decode-error full)))
          (is (nil? (:diagnostics full)))
          (is (nil? (:diagnostics projected)))
          (is (= version (:version l3) (:ip-version projected)))
          (is (= #{:type :l3} (set (keys (:decoded full)))))
          (is (= :raw-ip (get-in full [:decoded :type])))
          (is (= (keyword (:l4 row)) (get-in l3 [:l4 :type])))
          (is (= (:transport row) (or (:protocol l3) (:next-header l3)) (:protocol projected)))
          (is (= (get-in l3 [:l4 :src-port]) (:src-port projected)))
          (is (= (get-in l3 [:l4 :dst-port]) (:dst-port projected)))
          ;; Identical IP/L4 data under existing Ethernet framing.
          (let [bytes (:bytes input)
                ethernet (byte-array (+ 14 (alength ^bytes bytes)))]
            (aset-byte ethernet 12 (unchecked-byte (if (= version 4) 8 0x86)))
            (aset-byte ethernet 13 (unchecked-byte (if (= version 4) 0 0xdd)))
            (System/arraycopy bytes 0 ethernet 14 (alength ^bytes bytes))
            (is (= (cooked/as-data l3)
                   (cooked/as-data (get-in (cooked/transform cooked/full-config {:bytes ethernet}) [:decoded :l3]))))
            (is (= (dissoc projected :linktype)
                   (dissoc (cooked/transform cooked/flow-config {:bytes ethernet}) :linktype)))))
        (when-let [reason (:reason row)]
          (is (= (keyword reason) (cooked/reason full) (cooked/reason projected))))
        (doseq [result [full projected]]
          (is (= (:diagnostics result) (edn/read-string (pr-str (:diagnostics result))))))))))

(deftest raw-ip-native-paths-and-classic-writer-roundtrip
  (let [raw (core/reduce-packets (options "raw.pcap") conj [])
        out (File/createTempFile "paclo-raw-ip" ".pcap")]
    (try
      (is (= (count records) (count raw)))
      (is (every? #(= 12 (:linktype %)) raw))
      (is (= (mapv #(vec (util/hex->bytes (:hex %))) records) (mapv #(vec (:bytes %)) raw)))
      (core/write-pcap! raw (.getAbsolutePath out) {:linktype 12})
      (let [written (java.nio.file.Files/readAllBytes (.toPath out))]
        (is (= 101 (bit-and (aget written 20) 0xff)) "libpcap writes LINKTYPE_RAW, not native DLT"))
      (is (= (cooked/as-data raw)
             (cooked/as-data (core/reduce-packets {:path (.getAbsolutePath out)} conj []))))
      (doseq [config [cooked/full-config cooked/flow-config]
              file ["raw.pcap" "raw-big-endian.pcap" "raw.pcapng"]]
        (let [opts (merge (options file) config)
              expected (cooked/as-data (into [] (core/packet-xf config) raw))
              report (core/reduce-packets-report opts conj [])]
          (is (= expected (cooked/as-data (:result report))
                 (cooked/as-data (core/reduce-packets opts conj []))
                 (cooked/as-data (vec (core/packets opts)))))
          (with-open [^Closeable capture (core/start-capture opts)]
            (is (= expected (cooked/as-data (vec (core/capture-packets capture)))))
            (is (= (get-in report [:stats :packets :decode-errors])
                   (get-in (core/capture-stats capture) [:packets :decode-errors]))))))
      (let [p08-a (first (core/reduce-packets {:path "test/resources/capture-formats/raw.pcap"} conj []))]
        (is (= 12 (:linktype p08-a)))
        (is (= :raw-ip (get-in (cooked/transform cooked/full-config p08-a) [:decoded :type])))
        (is (= 53 (:dst-port (cooked/transform cooked/flow-config p08-a)))))
      (finally (.delete out)))))

(deftest raw-ip-absolute-header-locations
  (doseq [[bytes expected] [[nil {:offset 0 :required 1 :available 0}]
                            [(byte-array 0) {:offset 0 :required 1 :available 0}]
                            [(util/hex->bytes "45") {:offset 0 :required 20 :available 1}]
                            [(util/hex->bytes "60") {:offset 0 :required 40 :available 1}]]
          config [cooked/full-config cooked/flow-config]]
    (let [result (cooked/transform config {:bytes bytes :linktype 12})]
      (is (= expected (-> result :diagnostics first :location)))
      (is (= (if (or (nil? bytes) (zero? (alength ^bytes bytes))) :short-frame :truncated-header)
             (cooked/reason result)))))
  (doseq [row (filter #(contains? #{"short-tcp" "short-udp" "short-ipv6-extension"} (:name %)) records)
          config [cooked/full-config cooked/flow-config]]
    (is (= (if (= "short-ipv6-extension" (:name row)) 40 20)
           (-> (cooked/transform config (packet row)) :diagnostics first :location :offset)))))

(deftest extensions-fanout-and-p06-p07-composition
  (let [raw (core/reduce-packets (assoc (options "raw.pcap") :max 8) conj [])
        config {:decode? true :extensions [dns-ext/annotate-dns tls-ext/annotate-tls-sni]}
        full (into [] (core/packet-xf config) raw)
        projected (into [] (core/packet-xf cooked/flow-config) raw)]
    (is (= ["example.com" "example.com"] (keep #(get-in % [:decoded :l3 :l4 :app :sni]) full)))
    (is (= [:match :match] (mapv :kind (:dns (cooked/analyze full)))))
    (is (= [1 1] (mapv :rtt-us (:dns (cooked/analyze full)))))
    (is (= 8 (get-in (cooked/analyze full) [:windows 0 :groups :all :packets])))
    (is (= 8 (reduce + (map :packets (flow/top-n (cooked/aggregate projected) 100)))))
    (is (every? map? (map flow/key projected)))
    (with-open [^Closeable capture (core/start-capture (assoc (options "raw.pcap") :max 8))
                ^Closeable fanout (stream/fan-out (core/capture-packets capture)
                                                  {:full {:buffer-mode :blocking :buffer-cap 1}
                                                   :flow {:buffer-mode :blocking :buffer-cap 1}}
                                                  {:cancel! #(core/stop-capture! capture)})
                ^Closeable decoded (stream/branch fanout :full)
                ^Closeable flows (stream/branch fanout :flow)]
      (let [full-job (future (into [] (core/packet-xf config) decoded))
            flow-job (future (into [] (core/packet-xf cooked/flow-config) flows))
            full* (deref full-job 10000 ::timeout)
            projected* (deref flow-job 10000 ::timeout)]
        (is (= (cooked/as-data full) (cooked/as-data full*)))
        (is (= projected projected*))
        (is (= (cooked/analyze full) (cooked/analyze full*)))
        (is (= (cooked/aggregate projected) (cooked/aggregate projected*)))
        (is (zero? (get-in (stream/stats fanout) [:branches :full :dropped])))
        (is (zero? (get-in (stream/stats fanout) [:branches :flow :dropped])))))))

(deftest version-and-dlt-boundaries-and-projection-depth
  (is (= 1 (linktype/minimum-size 12)))
  (is (zero? (unsigned-bit-shift-right (linktype/payload (:bytes (packet (first records))) 12) 32)))
  (doseq [version (remove #{4 6} (range 16))
          config [cooked/full-config cooked/flow-config]]
    (let [bytes (byte-array 80)
          _ (aset-byte bytes 0 (unchecked-byte (bit-shift-left version 4)))
          result (cooked/transform config {:bytes bytes :linktype 12})]
      (is (nil? (:decoded result)))
      (is (nil? (:ip-version result)))
      (is (= :malformed-packet (cooked/reason result)))
      (is (= {:offset 0 :required 1 :available 80} (-> result :diagnostics first :location)))
      (is (= version (-> result :diagnostics first :value)))))
  (doseq [dlt [101 14 0 108 -1 nil "12" 12.0]
          config [cooked/full-config cooked/flow-config]]
    (is (= :unsupported-linktype (cooked/reason (cooked/transform config (assoc (packet (first records)) :linktype dlt))))))
  (doseq [config [cooked/full-config cooked/flow-config]]
    (let [bytes (util/hex->bytes (:hex (first records)))]
      (is (= (cooked/as-data (dissoc (cooked/transform config {:bytes bytes}) :linktype))
             (cooked/as-data (dissoc (cooked/transform config {:bytes bytes :linktype 1}) :linktype)))
        "missing DLT retains Ethernet")))
  (let [tcp (packet (nth records 2))
        short (assoc tcp :bytes (Arrays/copyOf ^bytes (:bytes tcp) 24))]
    (is (= :truncated-header (cooked/reason (cooked/transform cooked/full-config short))))
    (with-redefs [parse/packet->clj (fn [& _] (throw (AssertionError. "flow called full decoder")))]
      (is (= 12000 (:src-port (project/project-packet short)))))))

(defspec raw-ip-prefixes-preserve-input-and-absolute-locations 200
  (prop/for-all [original (gen/one-of [(gen/fmap #(util/hex->bytes (:hex %)) (gen/elements records))
                                       (gen/fmap byte-array (gen/vector gen/byte 0 200))])
                 length (gen/choose 0 200)]
                (let [bytes (Arrays/copyOf ^bytes original (min length (alength ^bytes original)))
                      snapshot (vec bytes)
                      input {:bytes bytes :linktype 12 :ts-sec 0 :ts-usec 0 :caplen (alength bytes) :len (alength ^bytes original)}
                      full (cooked/transform cooked/full-config input)
                      projected (cooked/transform cooked/flow-config input)]
                  (and (identical? bytes (:bytes full)) (= snapshot (vec bytes))
                       (= (select-keys input [:linktype :ts-sec :ts-usec :caplen :len])
                          (select-keys projected [:linktype :ts-sec :ts-usec :caplen :len]))
                       (not (contains? projected :bytes))
                       (every? (fn [result]
                                 (and (= (:diagnostics result) (edn/read-string (pr-str (:diagnostics result))))
                                      (every? (fn [{:keys [location]}]
                                                (or (nil? location)
                                                    (and (<= 0 (:offset location) (alength bytes))
                                                         (pos? (:required location)) (<= 0 (:available location)))))
                                              (:diagnostics result)))) [full projected])))))
