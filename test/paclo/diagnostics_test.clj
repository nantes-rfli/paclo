(ns paclo.diagnostics-test
  (:require
   [clojure.edn :as edn]
   [clojure.test :refer [deftest is testing]]
   [clojure.test.check.clojure-test :refer [defspec]]
   [clojure.test.check.generators :as gen]
   [clojure.test.check.properties :as prop]
   [paclo.capture :as capture]
   [paclo.core :as core]
   [paclo.decode-ext :as dx]
   [paclo.dev.perf-data :as data]
   [paclo.parse :as parse]
   [paclo.pcap :as pcap]
   [paclo.proto.dns-ext :as dns]
   [paclo.proto.tls-ext :as tls]
   [paclo.stream :as stream]
   [paclo.test-util :as util]))

(declare arbitrary-input-is-bounded-data reporting-is-deterministic-and-isolates-failures)

(defn- transform [opts packet]
  (first (into [] (core/packet-xf opts) [packet])))

(defn- frame [^long size ^long ethertype]
  (let [ba (byte-array size)]
    (when (>= size 14)
      (aset-byte ba 12 (unchecked-byte (bit-shift-right (long ethertype) 8)))
      (aset-byte ba 13 (unchecked-byte ethertype)))
    ba))

(defn- ipv6 ^bytes []
  (util/hex->bytes
   "00 11 22 33 44 55 66 77 88 99 AA BB 86 DD
    60 00 00 00 00 08 11 40
    20 01 0D B8 00 00 00 00 00 00 00 00 00 00 00 01
    20 01 0D B8 00 00 00 00 00 00 00 00 00 00 00 02
    12 34 56 78 00 08 00 00"))

(defn- ordinary [x]
  (cond
    (bytes? x) (vec x)
    (map? x) (update-vals x ordinary)
    (sequential? x) (mapv ordinary x)
    :else x))

(defn- edn-data? [x]
  (cond
    (map? x) (every? edn-data? (mapcat identity x))
    (vector? x) (every? edn-data? x)
    :else (or (nil? x) (keyword? x) (string? x) (number? x) (boolean? x))))

(deftest classifies-known-failures-and-preserves-messages
  (doseq [[ba reason full-error flow-error location]
          [[(byte-array 8) :short-frame "frame too short: 8 bytes"
            "truncated ethernet header" {:offset 0 :required 14 :available 8}]
           [(frame 22 0x0800) :truncated-header "java.nio.BufferUnderflowException"
            "truncated IPv4 header" {:offset 14 :required 20 :available 8}]
           [(frame 30 0x86dd) :truncated-header "java.nio.BufferUnderflowException"
            "truncated IPv6 header" {:offset 14 :required 40 :available 16}]
           [(java.util.Arrays/copyOf ^bytes (data/ethernet-ipv4-frame 64 :tcp) 36)
            :truncated-header "java.nio.BufferUnderflowException"
            "truncated transport header" nil]]]
    (doseq [[opts stage message] [[{:decode? true :extensions []} :decode full-error]
                                  [{:decode-mode :flow} :flow flow-error]]]
      (let [packet {:bytes ba :ts-sec 42 :ts-usec 123456 :caplen (alength ^bytes ba) :len 1500}
            result (transform opts packet)
            diagnostic (first (:diagnostics result))]
        (is (= message (:decode-error result)))
        (is (= stage (:stage diagnostic)))
        (is (= reason (:reason diagnostic)))
        (when location (is (= location (:location diagnostic))))
        (is (= (select-keys packet [:ts-sec :ts-usec :caplen :len])
               (select-keys result [:ts-sec :ts-usec :caplen :len])))))))

(deftest unsupported-and-best-effort-values
  (let [unknown (frame 14 0x1234)
        full (transform {:decode? true :extensions []} {:bytes unknown})
        flow (transform {:decode-mode :flow} {:bytes unknown})]
    (is (= :unknown-l3 (get-in full [:decoded :l3 :type])))
    (is (not (contains? full :decode-error)))
    (is (= "unsupported flow ethertype" (:decode-error flow)))
    (doseq [m [full flow]]
      (is (= :unsupported-ethertype (get-in m [:diagnostics 0 :reason])))
      (is (= 0x1234 (get-in m [:diagnostics 0 :ethertype])))))
  (let [udp (java.util.Arrays/copyOf ^bytes (data/ethernet-ipv4-frame 64 :udp) 36)
        result (transform {:decode? true :extensions []} {:bytes udp})]
    (is (= :unknown-l4 (get-in result [:decoded :l3 :l4 :type])))
    (is (= :truncated-udp (get-in result [:decoded :l3 :l4 :reason])))
    (is (= {:stage :decode :reason :truncated-header
            :location {:offset 34 :required 8 :available 2}}
           (first (:diagnostics result))))
    (is (not (contains? result :decode-error))))
  (let [^bytes ba (data/ethernet-ipv4-frame 64 :udp)]
    (aset-byte ba 23 (byte 99))
    (let [result (transform {:decode? true :extensions []} {:bytes ba})]
      (is (= :unknown-l4 (get-in result [:decoded :l3 :l4 :type])))
      (is (not (contains? result :diagnostics)))))
  (let [^bytes ba (data/ethernet-ipv4-frame 64 :udp)]
    (aset-byte ba 14 (byte 0x35))
    (doseq [opts [{:decode? true :extensions []} {:decode-mode :flow}]]
      (is (= :malformed-packet (get-in (transform opts {:bytes ba}) [:diagnostics 0 :reason])))))
  (with-redefs [parse/packet->clj (fn [_] (throw (ex-info "unclassified" {:reason :not-known :location {:offset identity}})))]
    (let [result (transform {:decode? true} {:bytes (byte-array 14)})]
      (is (= "unclassified" (:decode-error result)))
      (is (= [{:stage :decode :reason :unexpected-failure}] (:diagnostics result))))))

(deftest packet-and-flow-contracts
  (let [^bytes ba (data/ethernet-ipv4-frame 64 :udp)
        packet {:bytes ba :ts-sec 0 :ts-usec 999999 :caplen 64 :len 1500}
        full (transform {:decode? true :extensions []} packet)
        flow (transform {:decode-mode :flow} packet)]
    (is (identical? packet (transform {} packet)))
    (is (identical? ba (:bytes full)))
    (is (= (dissoc packet :bytes) (select-keys full [:ts-sec :ts-usec :caplen :len])))
    (is (= :ethernet (get-in full [:decoded :type])))
    (is (not (contains? full :diagnostics)))
    (is (= [4 17 167772161 167772162 12000 5300]
           (mapv flow [:ip-version :protocol :src-ip :dst-ip :src-port :dst-port])))
    (is (not-any? #(contains? flow %) [:bytes :decoded :diagnostics]))
    (is (not (contains? (transform {:decode? true :extensions []} {:bytes ba}) :ts-sec)))
    (is (= {:ts-sec nil :ts-usec nil :caplen nil :len nil}
           (select-keys (transform {:decode-mode :flow} {:bytes ba}) [:ts-sec :ts-usec :caplen :len])))
    (doseq [offset [23 20]]
      (let [copy (aclone ba)]
        (aset-byte copy offset (byte (if (= offset 23) 1 0)))
        (when (= offset 20) (aset-byte copy 21 (byte 1)))
        (let [result (transform {:decode-mode :flow} {:bytes copy})]
          (is (nil? (:src-port result)))
          (is (nil? (:dst-port result)))))))
  (let [result (transform {:decode-mode :flow} {:bytes (ipv6)})]
    (is (= [2306139568115548160 1] (:src-ip result)))
    (is (= [2306139568115548160 2] (:dst-ip result)))
    (is (= [4660 22136] (mapv result [:src-port :dst-port])))))

(defn- failing-extensions []
  [(fn [_] (throw (ex-info "hook failed" {:unsafe (byte-array 2)})))
   (constantly nil)
   (fn [m] (assoc m :continued true))])

(deftest reports-hooks-in-order-including-global-and-legacy-arities
  (let [packet {:bytes (data/ethernet-ipv4-frame 64 :udp)}
        extensions (failing-extensions)
        opts {:decode? true :extensions extensions}
        ignored (transform opts packet)
        reported (transform (assoc opts :extension-error-mode :report) packet)]
    (is (= (ordinary ignored) (ordinary (transform (assoc opts :extension-error-mode :ignore) packet))))
    (is (not (contains? ignored :diagnostics)))
    (is (:continued reported))
    (is (not (contains? reported :decode-error)))
    (is (= [0 1] (mapv :index (:diagnostics reported))))
    (is (= [:extension-exception :extension-non-map] (mapv :reason (:diagnostics reported))))
    (is (edn-data? (:diagnostics reported)))
    (is (= (:diagnostics reported) (edn/read-string (pr-str (:diagnostics reported)))))
    (try
      (doseq [[i f] (map-indexed vector extensions)] (dx/register! [::test i] f))
      (let [global (transform {:decode? true :extension-error-mode :report} packet)]
        (is (:continued global))
        (is (= [:extension-exception :extension-non-map]
               (mapv :reason (:diagnostics global)))))
      (is (not (contains? (dx/apply! {:decoded {}}) :diagnostics)))
      (is (= {:decoded {}} (dx/apply! {:decoded {}} nil)))
      (is (not (contains? (dx/apply! {:decoded {}} extensions) :diagnostics)))
      (finally
        (doseq [i (range 3)] (dx/unregister! [::test i]))))))

(deftest rejects-policy-before-source-open
  (let [opens (atom 0)]
    (with-redefs [pcap/capture->seq (fn [& _] (swap! opens inc))
                  pcap/reduce-capture (fn [& _] (swap! opens inc))
                  pcap/reduce-capture-report (fn [& _] (swap! opens inc))
                  capture/start (fn [& _] (swap! opens inc))]
      (doseq [opts [{:extension-error-mode :ignore}
                    {:decode-mode :flow :extension-error-mode :report}
                    {:decode? :truthy :extension-error-mode :report}
                    {:decode? true :extension-error-mode nil}
                    {:decode? true :extension-error-mode :throw}]]
        (doseq [run [core/packet-xf core/packets core/start-capture
                     #(core/reduce-packets % conj []) #(core/reduce-packets-report % conj [])]]
          (is (thrown-with-msg? clojure.lang.ExceptionInfo #"extension-error-mode" (run opts)))))
      (is (zero? @opens)))))

(defn- compare-paths [path opts]
  (let [source {:path path :max Long/MAX_VALUE :max-time-ms 60000}
        raw (core/reduce-packets source conj [])
        expected (ordinary (into [] (core/packet-xf opts) raw))
        config (merge source opts)
        report (core/reduce-packets-report config conj [])]
    (is (= expected (ordinary (core/packets config))))
    (is (= expected (ordinary (core/reduce-packets config conj []))))
    (is (= expected (ordinary (:result report))))
    (is (= 1 (get-in report [:stats :schema-version])))
    (is (= (count (filter :decode-error expected)) (get-in report [:stats :packets :decode-errors])))
    (is (= :eof (get-in report [:stats :stop-reason])))
    (is (= (:stats report) (edn/read-string (pr-str (:stats report)))))
    (with-open [^java.io.Closeable capture (core/start-capture config)]
      (is (= expected (ordinary (into [] (core/capture-packets capture)))))
      (is (= (count (filter :decode-error expected)) (get-in (core/capture-stats capture) [:packets :decode-errors]))))
    (doseq [packet expected :when (:diagnostics packet)]
      (is (= (:diagnostics packet) (edn/read-string (pr-str (:diagnostics packet))))))))

(deftest offline-contract-and-diagnostics-match-all-five-paths
  (doseq [path ["test/resources/dns-sample.pcap" "test/resources/tls-sni-alpn-sample.pcap"
                "test/resources/metadata-roundtrip.pcap"]
          opts [{:decode? true :extensions (into [dns/annotate-dns tls/annotate-tls-sni] (failing-extensions))
                 :extension-error-mode :report}
                {:decode-mode :flow}]]
    (testing (str path " " opts) (compare-paths path opts)))
  (let [file (java.io.File/createTempFile "paclo-diagnostics-" ".pcap")]
    (try
      (core/write-pcap! [(ipv6) (byte-array 8) (frame 22 0x0800) (frame 30 0x86dd)
                         (frame 14 0x1234)] (.getAbsolutePath file))
      (doseq [opts [{:decode? true :extensions []} {:decode-mode :flow}]]
        (compare-paths (.getAbsolutePath file) opts))
      (finally (.delete file))))
  (let [raw (core/reduce-packets {:path "test/resources/metadata-roundtrip.pcap"} conj [])]
    (is (= 4 (count raw)))
    (is (some #(< (long (:caplen %)) (long (:len %))) raw))
    (is (= [0 0] (mapv (first raw) [:ts-sec :ts-usec])))
    (is (= [1700000001 654321] (mapv (nth raw 2) [:ts-sec :ts-usec])))
    (doseq [m raw]
      (is (bytes? (:bytes m)))
      (is (every? integer? (map m [:ts-sec :ts-usec :caplen :len])))
      (is (= (:caplen m) (alength ^bytes (:bytes m)))))))

(deftest fan-out-keeps-diagnostics-independent-and-shares-read-only-bytes
  (let [raw (core/reduce-packets {:path "test/resources/dns-sample.pcap"} conj [])
        before (ordinary raw)]
    (with-open [^java.io.Closeable fanout (stream/fan-out raw {:a {:buffer-mode :blocking :buffer-cap 1}
                                                               :b {:buffer-mode :blocking :buffer-cap 1}})
                ^java.io.Closeable a (stream/branch fanout :a)
                ^java.io.Closeable b (stream/branch fanout :b)]
      (let [fa (future (into [] (core/packet-xf {:decode? true :extensions (failing-extensions)
                                                 :extension-error-mode :report}) a))
            fb (future (into [] (core/packet-xf {:decode? true :extensions []}) b))]
        (try
          (let [ra (deref fa 10000 ::timeout) rb (deref fb 10000 ::timeout)]
            (is (vector? ra)) (is (vector? rb))
            (when (and (vector? ra) (vector? rb))
              (is (= 4 (count ra) (count rb)))
              (is (every? :diagnostics ra))
              (is (not-any? :diagnostics rb))
              (is (every? true? (map #(identical? (:bytes %1) (:bytes %2)) ra rb)))
              (is (= before (ordinary raw))))
            (is (= 1 (:schema-version (stream/stats fanout)))))
          (finally (future-cancel fa) (future-cancel fb)))))))

(defspec arbitrary-input-is-bounded-data 200
  (prop/for-all [values (gen/vector gen/byte 0 200)
                 ethertype (gen/elements [0x0800 0x86dd 0x8100 0x0806 0x1234])]
                (let [ba (byte-array values)
                      _ (when (>= (alength ba) 14)
                          (aset-byte ba 12 (unchecked-byte (bit-shift-right (long ethertype) 8)))
                          (aset-byte ba 13 (unchecked-byte ethertype)))
                      before (vec ba)]
                  (every? true?
                          (for [opts [{:decode? true :extensions []} {:decode-mode :flow}]
                                :let [result (transform opts {:bytes ba}) ds (:diagnostics result)]]
                            (and (= before (vec ba))
                                 (or (nil? ds)
                                     (and (vector? ds) (edn-data? ds)
                                          (= ds (edn/read-string (pr-str ds)))
                                          (every? #(and (keyword? (:stage %)) (keyword? (:reason %))) ds)))))))))

(defspec reporting-is-deterministic-and-isolates-failures 100
  (prop/for-all [steps (gen/vector (gen/elements [:ok :nil :throw]) 0 30)
                 sec gen/nat usec (gen/choose 0 999999)]
                (let [^bytes ba (data/ethernet-ipv4-frame 64 :udp)
                      packet {:bytes ba :ts-sec sec :ts-usec usec :caplen 64 :len 1500}
                      extensions (mapv (fn [kind]
                                         (case kind
                                           :ok #(update % :successes (fnil inc 0))
                                           :nil (constantly nil)
                                           :throw (fn [_] (throw (Exception. "property failure"))))) steps)
                      opts {:decode? true :extensions extensions :extension-error-mode :report}
                      a (transform opts packet) b (transform opts packet)
                      failures (keep-indexed #(when (not= :ok %2) %1) steps)]
                  (and (= (ordinary a) (ordinary b))
                       (= (vec failures) (mapv :index (:diagnostics a)))
                       (= (count (filter #{:ok} steps)) (or (:successes a) 0))
                       (= (dissoc packet :bytes) (select-keys a [:ts-sec :ts-usec :caplen :len]))
                       (identical? ba (:bytes a)) (edn-data? (:diagnostics a))))))

(deftest diagnoses-partial-vlan-and-ipv6-chains-without-changing-best-effort-values
  (let [result (transform {:decode? true :extensions []} {:bytes (frame 16 0x8100)})]
    (is (= :unknown-l3 (get-in result [:decoded :l3 :type])))
    (is (= [] (get-in result [:decoded :vlan-tags])))
    (is (= {:stage :decode :reason :truncated-header
            :location {:offset 14 :required 4 :available 2}}
           (first (:diagnostics result)))))
  (doseq [[next-header body reason location]
          [[44 [17 0] :truncated-header {:offset 54 :required 8 :available 2}]
           [0 [17] :truncated-header {:offset 54 :required 2 :available 1}]
           [0 [17 1 0 0 0 0 0 0] :truncated-header {:offset 56 :required 14 :available 6}]
           [51 [17 2 0 0] :truncated-header {:offset 56 :required 14 :available 2}]
           [60 [17 0 2 5 0 0 0 0] :malformed-packet nil]]]
    (let [ba (java.util.Arrays/copyOf (ipv6) (+ 54 (count body)))]
      (aset-byte ba 20 (byte next-header))
      (aset-byte ba 19 (byte (count body)))
      (doseq [[i value] (map-indexed vector body)] (aset-byte ba (+ 54 (long i)) (byte value)))
      (let [result (transform {:decode? true :extensions []} {:bytes ba})]
        (is (not (contains? result :decode-error)))
        (is (nil? (get-in result [:decoded :l3 :next-header])))
        (is (nil? (get-in result [:decoded :l3 :flow-key])))
        (is (= :unknown-l4 (get-in result [:decoded :l3 :l4 :type])))
        (is (= reason (get-in result [:diagnostics 0 :reason])))
        (when location (is (= location (get-in result [:diagnostics 0 :location]))))))))

(deftest metadata-and-diagnostics-precede-user-transforms
  (let [report (core/reduce-packets-report
                {:path "test/resources/dns-sample.pcap" :decode? true
                 :extensions (failing-extensions) :extension-error-mode :report
                 :xform (map #(select-keys % [:diagnostics :continued]))}
                (fn [acc packet] (reduced (conj acc packet))) [])]
    (is (= 1 (count (:result report))))
    (is (:continued (first (:result report))))
    (is (= 2 (count (:diagnostics (first (:result report))))))
    (is (= :reduced (get-in report [:stats :stop-reason])))
    (is (zero? (get-in report [:stats :packets :decode-errors])))))

(deftest successful-tcp-ports-agree-with-full-decode
  (let [packet {:bytes (data/ethernet-ipv4-frame 64 :tcp)}
        flow (transform {:decode-mode :flow} packet)
        full (transform {:decode? true :extensions []} packet)]
    (is (= 6 (:protocol flow)))
    (is (= [12000 443] (mapv flow [:src-port :dst-port])))
    (is (= [12000 443] (mapv (get-in full [:decoded :l3 :l4]) [:src-port :dst-port])))
    (is (not-any? #(contains? % :diagnostics) [flow full]))))
