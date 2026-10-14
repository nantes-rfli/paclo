(ns paclo.linktype-test
  (:require
   [clojure.edn :as edn]
   [clojure.test :refer [deftest is]]
   [clojure.test.check.clojure-test :refer [defspec]]
   [clojure.test.check.generators :as gen]
   [clojure.test.check.properties :as prop]
   [clojure.walk :as walk]
   [paclo.core :as core]
   [paclo.decode-ext :as dx]
   [paclo.dev.perf-data :as data]
   [paclo.parse :as parse]
   [paclo.pcap :as pcap]
   [paclo.stream :as stream])
  (:import
   [java.io Closeable]
   [jnr.ffi Memory Pointer]
   [paclo.jnr PcapConfigLibrary PcapLibrary]))

(declare unsupported-input-never-decodes-as-ethernet)

(def ^:private fixtures
  ;; DLT_EN10MB / DLT_LINUX_SLL / DLT_NULL have these values on the supported
  ;; Linux/macOS matrix. Do not generalize savefile LINKTYPE values to all DLTs.
  [["test/resources/dns-sample.pcap" 1 4]
   ["test/resources/linktype-sll.pcap" 113 3]
   ["test/resources/linktype-null.pcap" 0 3]])

(defn- opts [path]
  {:path path :max 100 :max-time-ms 60000})

(defn- transform [config packet]
  (first (into [] (core/packet-xf config) [packet])))

(defn- data-value [value]
  (walk/postwalk #(if (bytes? %) (vec %) %) value))

(deftest native-offline-dlt-and-raw-records
  (doseq [[path dlt count*] fixtures]
    (let [handle (pcap/open-offline path)]
      (try (is (= dlt (pcap/datalink handle)))
           (finally (pcap/close! handle))))
    (let [packets (core/reduce-packets (opts path) conj [])]
      (is (= count* (count packets)))
      (is (every? #(= dlt (:linktype %)) packets))
      (is (every? #(= (:caplen %) (alength ^bytes (:bytes %))) packets))
      (is (every? #(identical? % (transform {} %)) packets))
      (when (not= 1 dlt)
        (is (= [[1700000000 123456] [1700000001 654321] [1700000002 0]]
               (mapv (juxt :ts-sec :ts-usec) packets)))
        (is (= (if (= 113 dlt) [66 2 64] [54 2 64]) (mapv :caplen packets)))
        (is (= (if (= 113 dlt) [66 1500 64] [54 1500 64]) (mapv :len packets)))
        (is (= (if (= 113 dlt) [0 0] [2 0]) (vec (:bytes (second packets)))))
        ;; The adversarial record could parse as Ethernet without the guard.
        (is (= :ethernet (:type (parse/packet->clj (:bytes (last packets))))))))))

(deftest transformations-agree-across-all-public-capture-paths
  (doseq [[path dlt count*] fixtures
          config [{} {:decode? true :extensions []} {:decode-mode :flow}]]
    (let [raw (core/reduce-packets (opts path) conj [])
          expected (data-value (into [] (core/packet-xf config) raw))
          capture-opts (merge (opts path) config)
          lazy-result (data-value (vec (core/packets capture-opts)))
          reduce-result (data-value (core/reduce-packets capture-opts conj []))
          report (core/reduce-packets-report capture-opts conj [])
          [managed-result stats]
          (with-open [^Closeable capture (core/start-capture capture-opts)]
            [(data-value (vec (core/capture-packets capture)))
             (core/capture-stats capture)])]
      (is (= expected lazy-result reduce-result (data-value (:result report)) managed-result))
      (is (= 1 (:schema-version (:stats report)) (:schema-version stats)))
      (is (= count* (get-in report [:stats :packets :captured])))
      (is (= (if (and (not= 1 dlt) (seq config)) 2 0)
             (get-in report [:stats :packets :decode-errors])
             (get-in stats [:packets :decode-errors])))
      (when (and (= 0 dlt) (seq config))
        (is (nil? (:decode-error (first (:result report)))))
        (is (= [nil :short-frame :unsupported-address-family]
               (mapv #(-> % :diagnostics first :reason) (:result report))))))))

(deftest linktype-precedes-length-and-skips-all-extension-policies
  (let [calls (atom [])
        hook #(do (swap! calls conj :hook) %)
        frame (data/ethernet-ipv4-frame 64 :udp)]
    (dx/register! ::hook hook)
    (try
      (doseq [dlt [9999 -1 nil "1" 1.0 :ethernet]
              bytes [frame (byte-array 2)]
              config [{:decode? true} {:decode? true :extensions [hook]}
                      {:decode? true :extension-error-mode :report}
                      {:decode? true :extensions [hook] :extension-error-mode :report}
                      {:decode-mode :flow}]]
        (let [packet {:bytes bytes :linktype dlt :decoded {:type :ethernet}
                      :ts-sec 1 :ts-usec 2 :caplen (alength ^bytes bytes) :len 100}
              result (transform config packet)]
          (is (= :unsupported-linktype (-> result :diagnostics first :reason)))
          (is (= dlt (:linktype result)))
          (is (= (select-keys packet [:ts-sec :ts-usec :caplen :len])
                 (select-keys result [:ts-sec :ts-usec :caplen :len])))
          (is (not (contains? result :decoded)))
          (when (:decode? config) (is (identical? bytes (:bytes result))))))
      (is (empty? @calls))
      (doseq [config [{:decode? true :extensions []} {:decode-mode :flow}]]
        (let [missing (transform config {:bytes frame})
              ethernet (transform config {:bytes frame :linktype 1})]
          (is (= (data-value (dissoc missing :linktype))
                 (data-value (dissoc ethernet :linktype))))))
      (finally (dx/unregister! ::hook)))))

(deftest unsupported-dispatch-retains-diagnostic-order-without-calling-parser
  (let [calls (atom 0)
        prior {:stage :extension :reason :extension-non-map :hook-index 0}
        packet {:bytes (data/ethernet-ipv4-frame 64 :udp) :linktype 9999
                :diagnostics [prior]}]
    (with-redefs [parse/packet->clj (fn [_] (swap! calls inc) {:type :ethernet})]
      (doseq [[config stage] [[{:decode? true :extensions []} :decode]
                              [{:decode-mode :flow} :flow]]]
        (is (= [prior {:stage stage :reason :unsupported-linktype :linktype 9999}]
               (:diagnostics (transform config packet)))))
      (is (zero? @calls)))))

(deftest stop-and-user-transform-observe-native-linktype
  (doseq [[path dlt _] fixtures
          mode [:lazy :reduce :report :managed]]
    (let [observed (atom [])
          options (assoc (opts path)
                         :stop? #(do (swap! observed conj [:stop (:linktype %)]) false)
                         :xform (map #(do (swap! observed conj [:xform (:linktype %)]) %)))]
      (case mode
        :lazy (doall (core/packets options))
        :reduce (core/reduce-packets options conj [])
        :report (core/reduce-packets-report options conj [])
        :managed (with-open [^Closeable capture (core/start-capture options)]
                   (doall (core/capture-packets capture))))
      (is (= #{:stop :xform} (set (map first @observed))))
      (is (every? #(= dlt (second %)) @observed)))))

(deftest bounded-fan-out-keeps-raw-full-and-flow-independent
  (doseq [[path dlt count*] (rest fixtures)]
    (with-open [^Closeable capture (core/start-capture (opts path))
                ^Closeable fanout
                (stream/fan-out (core/capture-packets capture)
                                {:raw {:buffer-mode :blocking :buffer-cap 1}
                                 :full {:buffer-mode :blocking :buffer-cap 1}
                                 :flow {:buffer-mode :blocking :buffer-cap 1}}
                                {:cancel! #(core/stop-capture! capture)})
                ^Closeable raw (stream/branch fanout :raw)
                ^Closeable full (stream/branch fanout :full)
                ^Closeable flow (stream/branch fanout :flow)]
      (let [raw-job (future (into [] raw))
            full-job (future (into [] (core/packet-xf {:decode? true :extensions []}) full))
            flow-job (future (into [] (core/packet-xf {:decode-mode :flow}) flow))
            raw-result (deref raw-job 10000 ::timeout)
            full-result (deref full-job 10000 ::timeout)
            flow-result (deref flow-job 10000 ::timeout)]
        (is (every? vector? [raw-result full-result flow-result]))
        (when (every? vector? [raw-result full-result flow-result])
          (is (= count* (count raw-result) (count full-result) (count flow-result)))
          (is (every? true? (map #(identical? (:bytes %1) (:bytes %2)) raw-result full-result)))
          (is (= (mapv :linktype raw-result) (mapv :linktype full-result) (mapv :linktype flow-result)))
          (is (every? #(= dlt (:linktype %)) raw-result))
          (is (not-any? :decode-error raw-result))
          (is (= 2 (count (filter :decode-error full-result))))
          (is (= 2 (count (filter :decode-error flow-result))))
          (is (= 1 (:schema-version (stream/stats fanout)))))))))

(defn- pointer ^Pointer []
  (Memory/allocateDirect (jnr.ffi.Runtime/getSystemRuntime) 1))

(defn- native-lib [handle calls result]
  (reify PcapLibrary
    (pcap_open_offline [_ _ _] (swap! calls conj :open-offline) handle)
    (pcap_open_live [_ _ _ _ _ _] (swap! calls conj :open-live) handle)
    (pcap_lookupnet [_ _ _ _ _] 0)
    (pcap_datalink [_ p]
      (is (identical? handle p))
      (swap! calls conj :datalink)
      (if (instance? Throwable result) (throw result) result))
    (pcap_geterr [_ _] "native error")
    (pcap_next_ex [_ _ _ _] (swap! calls conj :read) -2)
    (pcap_breakloop [_ _] nil)
    (pcap_close [_ p] (is (identical? handle p)) (swap! calls conj :close))))

(deftest capture-setup-failures-close-and-propagate-before-readiness
  (doseq [mode [:reduce :report :lazy :managed]
          source [{:path "test/resources/linktype-null.pcap"} {:device "fake"}]
          result [-3 (UnsatisfiedLinkError. "native missing")]]
    (let [calls (atom [])
          handle (pointer)]
      (with-redefs [pcap/lib (native-lib handle calls result)]
        (let [options (assoc source
                             :on-ready #(swap! calls conj :ready))]
          (try
            (case mode
              :reduce (core/reduce-packets options conj [])
              :report (core/reduce-packets-report options conj [])
              :lazy (doall (core/packets options))
              :managed (core/start-capture options))
            (is false "expected native failure")
            (catch Throwable error
              (let [cause (if (= :lazy mode) (.getCause error) error)]
                (if (integer? result)
                  (is (= {:phase :pcap-datalink :rc -3 :err "native error"} (ex-data cause)))
                  (is (identical? result cause))))))))
      (is (= [(if (:device source) :open-live :open-offline) :datalink :close] @calls)))))

(deftest legacy-async-pass-mode-keeps-error-policy-on-datalink-failure
  (let [calls (atom [])
        errors (atom [])]
    (with-redefs [pcap/lib (native-lib (pointer) calls -3)]
      (is (empty? (doall (core/packets (assoc (opts "test/resources/linktype-null.pcap")
                                              :error-mode :pass :on-error #(swap! errors conj %)))))))
    (is (= [:open-offline :datalink :close] @calls))
    (is (= :pcap-datalink (:phase (ex-data (first @errors)))))))

(deftest live-acquisition-follows-activation-and-precedes-ready
  (doseq [configured? [false true]
          activation-rc [0 -1]]
    (when (or configured? (zero? (long activation-rc)))
      (let [calls (atom [])
            handle (pointer)
            config-lib
            (reify PcapConfigLibrary
              (pcap_create [_ _ _] (swap! calls conj :create) handle)
              (pcap_set_snaplen [_ _ _] 0)
              (pcap_set_promisc [_ _ _] 0)
              (pcap_set_timeout [_ _ _] 0)
              (pcap_set_buffer_size [_ _ _] 0)
              (pcap_set_immediate_mode [_ _ _] 0)
              (pcap_activate [_ _] (swap! calls conj :activate) activation-rc))]
        (with-redefs [pcap/lib (native-lib handle calls 113)
                      pcap/config-lib config-lib
                      pcap/capture-stats (constantly nil)]
          (let [options (cond-> {:device "fake" :max 100 :max-time-ms 60000
                                 :on-ready #(swap! calls conj :ready)}
                          configured? (assoc :buffer-size 4096))]
            (if (neg? (long activation-rc))
              (is (thrown-with-msg? clojure.lang.ExceptionInfo #"pcap-activate failed"
                                    (core/start-capture options)))
              (with-open [^Closeable capture (core/start-capture options)]
                (is (empty? (doall (core/capture-packets capture))))))))
        (is (= (if (neg? (long activation-rc))
                 [:create :activate :close]
                 (if configured?
                   [:create :activate :datalink :ready :read :close]
                   [:open-live :datalink :ready :read :close]))
               @calls))))))

(deftest native-lookup-is-once-per-capture-not-per-packet
  (let [original pcap/datalink
        calls (atom [])]
    (with-redefs [pcap/datalink (fn [handle]
                                  (let [dlt (original handle)]
                                    (swap! calls conj dlt)
                                    dlt))]
      (doseq [[path _ count*] fixtures]
        (is (= count* (count (core/reduce-packets (opts path) conj []))))
        (is (= count* (count (doall (core/packets (opts path))))))
        (is (= count* (count (:result (core/reduce-packets-report (opts path) conj [])))))
        (with-open [^Closeable capture (core/start-capture (opts path))]
          (is (= count* (count (doall (core/capture-packets capture))))))))
    (is (= [1 1 1 1 113 113 113 113 0 0 0 0] @calls))))

(defspec unsupported-input-never-decodes-as-ethernet 150
  (prop/for-all [dlt (gen/one-of [(gen/such-that #(not (contains? #{0 1 12 108 113 276} %)) gen/small-integer)
                                  (gen/elements [nil "1" :ethernet 1.0])])
                 octets (gen/vector gen/byte 0 160)
                 sec gen/small-integer
                 usec (gen/choose 0 999999)]
                (let [bytes (byte-array octets)
                      packet {:bytes bytes :linktype dlt :ts-sec sec :ts-usec usec
                              :caplen (count octets) :len (+ 20 (count octets))}
                      full (transform {:decode? true :extensions []} packet)
                      flow (transform {:decode-mode :flow} packet)]
                  (and (= octets (vec bytes))
                       (identical? bytes (:bytes full))
                       (not (contains? full :decoded))
                       (not-any? #(contains? flow %) [:bytes :decoded :ip-version :src-ip :dst-ip :src-port :dst-port])
                       (every? (fn [[stage result]]
                                 (and (= (select-keys packet [:linktype :ts-sec :ts-usec :caplen :len])
                                         (select-keys result [:linktype :ts-sec :ts-usec :caplen :len]))
                                      (= [{:stage stage :reason :unsupported-linktype :linktype dlt}]
                                         (:diagnostics result))
                                      (= (:diagnostics result) (edn/read-string (pr-str (:diagnostics result))))))
                               [[:decode full] [:flow flow]])))))
