(ns paclo.null-loop-test
  (:require
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
   [paclo.null-loop-native-test :as probe]
   [paclo.parse :as parse]
   [paclo.proto.dns-ext :as dns-ext]
   [paclo.proto.tls-ext :as tls-ext]
   [paclo.stream :as stream]
   [paclo.test-util :as util])
  (:import
   [java.io Closeable File]
   [java.util Arrays]))

(declare null-loop-prefixes-preserve-input-and-diagnostics
         unknown-families-never-infer-ip-from-version)

(defn options [file] {:path (str probe/directory file) :max 100 :max-time-ms 60000})
(defn packet [row dlt] {:bytes (util/hex->bytes (:hex row)) :linktype dlt})

(deftest full-flow-af-endian-protocols-and-failure-contracts
  (doseq [{:keys [file linktype records]} probe/cases
          row records]
    (testing (str file " " (:name row))
      (let [input (packet row linktype)
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
          (is (= #{:type :address-family :l3} (set (keys (:decoded full)))))
          (is (= (if (zero? linktype) :null :loop) (get-in full [:decoded :type])))
          (is (= (:address-family row) (get-in full [:decoded :address-family])))
          (is (= (keyword (:l4 row)) (get-in l3 [:l4 :type])))
          (is (= (:transport row) (or (:protocol l3) (:next-header l3)) (:protocol projected)))
          (is (= (get-in l3 [:l4 :src-port]) (:src-port projected)))
          (is (= (get-in l3 [:l4 :dst-port]) (:dst-port projected)))
          ;; Both decoders reuse the same IP/L4 semantics as bare IP.
          (let [bare {:bytes (Arrays/copyOfRange ^bytes (:bytes input) 4 (count snapshot)) :linktype 12}]
            (is (= (cooked/as-data l3)
                   (cooked/as-data (get-in (cooked/transform cooked/full-config bare) [:decoded :l3]))))
            (is (= (dissoc projected :linktype)
                   (dissoc (cooked/transform cooked/flow-config bare) :linktype)))))
        (when-let [reason (:reason row)]
          (is (= (keyword reason) (cooked/reason full) (cooked/reason projected))))
        (doseq [result [full projected]]
          (is (= (:diagnostics result) (edn/read-string (pr-str (:diagnostics result))))))))))

(deftest all-capture-paths-and-native-write-roundtrip
  (doseq [{:keys [file linktype records] :as fixture} probe/cases]
    (let [raw (core/reduce-packets (options file) conj [])
          out (File/createTempFile "paclo-null-loop" ".pcap")]
      (try
        (is (= (mapv :hex records) (mapv #(probe/hex (:bytes %)) raw)))
        (core/write-pcap! raw (.getAbsolutePath out) {:linktype linktype})
        (is (= (cooked/as-data raw)
               (cooked/as-data (core/reduce-packets {:path (.getAbsolutePath out)} conj []))))
        ;; Physical writer bytes also stay unchanged, including opposite-order NULL.
        (is (= (mapv :hex records)
               (probe/stored-hex (assoc fixture :file (.getAbsolutePath out)
                                        :container-order (if (= java.nio.ByteOrder/LITTLE_ENDIAN
                                                                (java.nio.ByteOrder/nativeOrder)) "<" ">")))))
        (doseq [config [cooked/full-config cooked/flow-config]]
          (let [opts (merge (options file) config)
                expected (cooked/as-data (into [] (core/packet-xf config) raw))
                report (core/reduce-packets-report opts conj [])]
            (is (= expected (cooked/as-data (:result report))
                   (cooked/as-data (core/reduce-packets opts conj []))
                   (cooked/as-data (vec (core/packets opts)))))
            (is (pos? (get-in report [:stats :packets :decode-errors])))
            (with-open [^Closeable capture (core/start-capture opts)]
              (is (= expected (cooked/as-data (vec (core/capture-packets capture)))))
              (is (= (get-in report [:stats :packets :decode-errors])
                     (get-in (core/capture-stats capture) [:packets :decode-errors]))))))
        (finally (.delete out))))))

(deftest absolute-framing-and-ip-l4-locations
  (doseq [dlt [0 108]
          config [cooked/full-config cooked/flow-config]
          [hex reason location] [[nil :short-frame {:offset 0 :required 4 :available 0}]
                                 ["020000" :short-frame {:offset 0 :required 4 :available 3}]
                                 ["00000002" :truncated-header {:offset 4 :required 1 :available 0}]
                                 ["0000000245" :truncated-header {:offset 4 :required 20 :available 1}]
                                 ["0000001e60" :truncated-header {:offset 4 :required 40 :available 1}]
                                 ["0000000250" :malformed-packet {:offset 4 :required 1 :available 1}]
                                 ["0000001e45" :address-family-mismatch {:offset 4 :required 1 :available 1}]
                                 ["0000000a60" :unsupported-address-family {:offset 0 :required 4 :available 5}]]]
    (let [result (cooked/transform config {:bytes (when hex (util/hex->bytes hex)) :linktype dlt})]
      (is (= reason (cooked/reason result)))
      (is (= location (-> result :diagnostics first :location)))))
  (doseq [{:keys [linktype records]} probe/cases
          row (filter #(contains? #{"short-tcp-af2" "short-udp-af2" "short-ipv6-extension-af30"} (:name %)) records)
          config [cooked/full-config cooked/flow-config]]
    (is (= (if (= "short-ipv6-extension-af30" (:name row)) 44 24)
           (-> (cooked/transform config (packet row linktype)) :diagnostics first :location :offset)))))

(deftest extensions-independent-fanout-and-p06-p07-composition
  (doseq [{:keys [file records]} (filter #(.endsWith ^String (:file %) "file-le.pcap") probe/cases)]
    (let [selected (->> records (filter #(and (:version %) (contains? #{2 30} (:address-family %)))) (take 8))
          hexes (set (map :hex selected))
          opts (assoc (options file) :xform (filter #(contains? hexes (probe/hex (:bytes %)))))
          raw (core/reduce-packets opts conj [])
          config {:decode? true :extensions [dns-ext/annotate-dns tls-ext/annotate-tls-sni]}
          full (into [] (core/packet-xf config) raw)
          projected (into [] (core/packet-xf cooked/flow-config) raw)]
      (is (= 8 (count raw)))
      (is (= ["example.com" "example.com"] (keep #(get-in % [:decoded :l3 :l4 :app :sni]) full)))
      (is (= [:match :match] (mapv :kind (:dns (cooked/analyze full)))))
      (is (= [1 3] (mapv :rtt-us (:dns (cooked/analyze full)))))
      (is (= 8 (get-in (cooked/analyze full) [:windows 0 :groups :all :packets])))
      (is (= 8 (reduce + (map :packets (flow/top-n (cooked/aggregate projected) {:n 100})))))
      (is (every? map? (map flow/key projected)))
      (with-open [^Closeable capture (core/start-capture opts)
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
          (is (zero? (get-in (stream/stats fanout) [:branches :flow :dropped]))))))))

(deftest numeric-projection-does-not-build-full-decode
  (doseq [dlt [0 108]]
    (is (= 4 (linktype/minimum-size dlt)))
    (let [row (first (:records (first (filter #(= dlt (:linktype %)) probe/cases))))
          input (packet row dlt)]
      (is (= 4 (unsigned-bit-shift-right (linktype/payload (:bytes input) dlt) 32)))
      (with-redefs [parse/packet->clj (fn [& _] (throw (AssertionError. "flow called full decoder")))
                    linktype/header (fn [& _] (throw (AssertionError. "flow built link map")))]
        (is (= 53 (:dst-port (project/project-packet input))))))))

(defspec null-loop-prefixes-preserve-input-and-diagnostics 300
  (prop/for-all [dlt (gen/elements [0 108])
                 original (gen/one-of [(gen/fmap #(util/hex->bytes (:hex %))
                                                 (gen/elements (mapcat :records probe/cases)))
                                       (gen/fmap byte-array (gen/vector gen/byte 0 200))])
                 length (gen/choose 0 200)]
                (let [bytes (Arrays/copyOf ^bytes original (min length (alength ^bytes original)))
                      snapshot (vec bytes)
                      input {:bytes bytes :linktype dlt :ts-sec 0 :ts-usec 0 :caplen (alength bytes) :len (alength ^bytes original)}
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

(deftest invalid-versions-fields-and-platform-boundary
  (doseq [dlt [0 108]
          version (remove #{4 6} (range 16))
          config [cooked/full-config cooked/flow-config]]
    (let [bytes (byte-array 44)
          _ (aset-byte bytes 3 (byte 2))
          _ (aset-byte bytes 4 (unchecked-byte (bit-shift-left version 4)))
          result (cooked/transform config {:bytes bytes :linktype dlt})]
      (is (= :malformed-packet (cooked/reason result)))
      (is (= :ip-version (-> result :diagnostics first :field)))
      (is (= version (-> result :diagnostics first :value)))
      (is (nil? (:ip-version result)))))
  (doseq [config [cooked/full-config cooked/flow-config]]
    (let [result (cooked/transform config {:bytes (util/hex->bytes "0000001e45") :linktype 0})]
      (is (= {:address-family 30 :expected-version 6 :field :ip-version :value 4}
             (select-keys (first (:diagnostics result)) [:address-family :expected-version :field :value])))))
  (with-redefs [linktype/native-ip-supported? false]
    (doseq [dlt [0 12 108]
            config [cooked/full-config cooked/flow-config]]
      (is (= :unsupported-linktype
             (cooked/reason (cooked/transform config {:bytes (byte-array 0) :linktype dlt})))))))

(defspec unknown-families-never-infer-ip-from-version 200
  (prop/for-all [family (gen/such-that
                         #(and (not (contains? #{2 24 28 30} %))
                               (not (contains? #{2 24 28 30}
                                               (bit-and (long (Integer/reverseBytes (unchecked-int %))) 0xffffffff))))
                         (gen/large-integer* {:min 0 :max 0xffffffff}))
                 version (gen/elements [4 6])
                 dlt (gen/elements [0 108])]
                (let [bytes (byte-array 44)
                      _ (.putInt (java.nio.ByteBuffer/wrap bytes) (unchecked-int family))
                      _ (aset-byte bytes 4 (unchecked-byte (bit-shift-left version 4)))
                      full (cooked/transform cooked/full-config {:bytes bytes :linktype dlt})
                      projected (cooked/transform cooked/flow-config {:bytes bytes :linktype dlt})]
                  (and (= :unsupported-address-family (cooked/reason full) (cooked/reason projected))
                       (nil? (:decoded full)) (nil? (:ip-version projected))
                       (= family (-> full :diagnostics first :value))))))
