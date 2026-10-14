(ns paclo.cooked-test
  (:require
   [clojure.data.json :as json]
   [clojure.edn :as edn]
   [clojure.test :refer [deftest is testing]]
   [clojure.test.check.clojure-test :refer [defspec]]
   [clojure.test.check.generators :as gen]
   [clojure.test.check.properties :as prop]
   [clojure.walk :as walk]
   [paclo.core :as core]
   [paclo.dns :as dns]
   [paclo.flow :as flow]
   [paclo.flow.project :as project]
   [paclo.parse :as parse]
   [paclo.proto.dns-ext :as dns-ext]
   [paclo.proto.tls-ext :as tls-ext]
   [paclo.stream :as stream]
   [paclo.test-util :as test-util]
   [paclo.window :as window])
  (:import
   [java.io Closeable File]
   [java.util Arrays]))

(declare same-ip-data-independent-of-link-header cooked-prefixes-are-bounded-and-preserve-bytes)

(def cases (json/read-str (slurp "test/resources/cooked/manifest.json") :key-fn keyword))
(def full-config {:decode? true :extensions []})
(def flow-config {:decode-mode :flow})
(defn options [file] {:path (str "test/resources/cooked/" file) :max 100 :max-time-ms 60000})
(defn transform [config packet] (first (into [] (core/packet-xf config) [packet])))
(defn as-data [x] (walk/postwalk #(if (bytes? %) (vec %) %) x))
(defn reason [packet] (-> packet :diagnostics first :reason))

(deftest fixture-decode-protocols-fragments-and-diagnostics
  (doseq [{:keys [file linktype records]} cases]
    (let [raw (core/reduce-packets (options file) conj [])]
      (is (= (count records) (count raw)))
      (doseq [[packet expected] (map vector raw records)]
        (testing (str file " " (:name expected))
          (let [snapshot (vec (:bytes packet))
                full (transform full-config packet)
                projected (transform flow-config packet)
                l3 (get-in full [:decoded :l3])
                header (:decoded full)]
            (is (= snapshot (vec (test-util/hex->bytes (:hex expected)))))
            (is (= snapshot (vec (:bytes packet))))
            (is (identical? (:bytes packet) (:bytes full)))
            (is (= linktype (:linktype full) (:linktype projected)))
            (is (not-any? #(contains? projected %) [:bytes :decoded]))
            (when (:version expected)
              (is (nil? (:decode-error full)))
              (is (nil? (:diagnostics full)))
              (is (nil? (:diagnostics projected)))
              (is (= (:version expected) (:version l3) (:ip-version projected)))
              (is (= (:transport expected) (or (:protocol l3) (:next-header l3)) (:protocol projected)))
              (is (= (keyword (:l4 expected)) (get-in l3 [:l4 :type])))
              (when (contains? #{"ipv4-first-fragment" "ipv4-later-fragment"
                                 "ipv6-extension-first-fragment" "ipv6-later-fragment"
                                 "ipv6-later-fragment-extension"} (:name expected))
                (is (true? (:frag? l3)))
                (is (= (if (contains? #{"ipv4-first-fragment" "ipv6-extension-first-fragment"}
                                      (:name expected)) 0 1)
                       (:frag-offset l3))))
              (is (= (get-in l3 [:l4 :src-port]) (:src-port projected)))
              (is (= (get-in l3 [:l4 :dst-port]) (:dst-port projected)))
              (is (= (if (= 113 linktype) :linux-sll :linux-sll2) (:type header)))
              (is (= 4 (:packet-type header)))
              (is (= 1 (:hardware-type header)))
              (is (not-any? #(contains? header %) [:src :dst :eth]))
              (when (= 276 linktype)
                (is (= 9 (:reserved header)))
                (is (= 4026531847 (:interface-index header))))
              (case (:name expected)
                "address-length-0" (is (= "" (:address header)))
                "address-length-8" (is (= "00:01:02:03:04:05:06:07" (:address header)))
                (is (= "00:01:02:03:04:05" (:address header)))))
            (when (:reason expected)
              (let [expected-reason (keyword (:reason expected))]
                (is (= expected-reason (reason full) (reason projected)))
                (is (= (:diagnostics full) (edn/read-string (pr-str (:diagnostics full)))))
                (is (= (:diagnostics projected) (edn/read-string (pr-str (:diagnostics projected)))))
                (when (contains? #{:short-frame :truncated-header} expected-reason)
                  (is (= (-> full :diagnostics first :location :offset)
                         (-> projected :diagnostics first :location :offset))))
                (case (:name expected)
                  "short-link-header"
                  (is (= {:offset 0 :required (if (= 113 linktype) 16 20)
                          :available (dec (if (= 113 linktype) 16 20))}
                         (-> full :diagnostics first :location)
                         (-> projected :diagnostics first :location)))
                  "invalid-address-length"
                  (do (is (= :address-length (-> full :diagnostics first :field)))
                      (is (= 9 (-> projected :diagnostics first :value))))
                  "unknown-protocol"
                  (do (is (= {:type :unknown-l3 :protocol 4660} l3))
                      (is (= 4660 (-> projected :diagnostics first :protocol))))
                  "ethernet-looking"
                  (do (is (nil? (:decoded full))) (is (nil? (:ip-version projected))))
                  nil)))))))))

(deftest real-capture-paths-and-classic-roundtrip
  (doseq [{:keys [file linktype]} cases]
    (let [raw (core/reduce-packets (options file) conj [])
          out (File/createTempFile "paclo-cooked" ".pcap")]
      (try
        (core/write-pcap! raw (.getAbsolutePath out) {:linktype linktype})
        (is (= (as-data raw) (as-data (core/reduce-packets {:path (.getAbsolutePath out)} conj []))))
        (doseq [config [full-config flow-config]]
          (let [opts (merge (options file) config)
                expected (as-data (into [] (core/packet-xf config) raw))
                report (core/reduce-packets-report opts conj [])]
            (is (= expected (as-data (:result report))
                   (as-data (vec (core/packets opts)))
                   (as-data (core/reduce-packets opts conj []))
                   (as-data (core/reduce-packets (merge (options (str file "ng")) config) conj []))))
            (with-open [^Closeable capture (core/start-capture opts)]
              (is (= expected (as-data (vec (core/capture-packets capture)))))
              (is (= (get-in report [:stats :packets :decode-errors])
                     (get-in (core/capture-stats capture) [:packets :decode-errors]))))))
        (finally (.delete out))))))

(defn aggregate [packets]
  (let [rf (flow/aggregate-rf {:max-flows 100})]
    (reduce rf (rf) packets)))

(defn analyze [packets]
  (let [initial {:state (dns/init {:timeout-us 1000000 :reuse-delay-us 1000000
                                   :max-pending 10 :max-retired 10}) :events []}
        result (reduce (fn [{:keys [state events] :as acc} packet]
                         (if-let [event (dns/packet->event packet)]
                           (let [r (dns/step state event)]
                             {:state (:state r) :events (into events (:events r))})
                           acc)) initial packets)
        finished (dns/finish (:state result))
        windows (reduce (fn [state packet]
                          (:state (window/step state {:time-us (dns/packet-time-us packet)
                                                      :group :all :captured-bytes (:caplen packet)})))
                        (window/init {:width-us 1000000 :max-windows 10 :max-groups 10}) packets)]
    {:dns (into (:events result) (:events finished)) :windows (:events (window/finish windows))}))

(deftest independent-full-flow-fanout-extensions-and-analysis
  (doseq [{:keys [file records]} cases]
    (let [raw (core/reduce-packets (options file) conj [])
          selected (vec (take 8 raw))
          config {:decode? true :extensions [dns-ext/annotate-dns tls-ext/annotate-tls-sni]}
          expected (into [] (core/packet-xf config) selected)
          projected (into [] (core/packet-xf flow-config) selected)]
      (is (= 8 (count selected)))
      (is (= 8 (get-in (analyze expected) [:windows 0 :groups :all :packets])))
      (is (= 2 (count (filter #(get-in % [:decoded :l3 :l4 :app :sni]) expected))))
      (is (= ["example.com" "example.com"]
             (keep #(get-in % [:decoded :l3 :l4 :app :sni]) expected)))
      (is (= [:match :match] (mapv :kind (:dns (analyze expected)))))
      (is (= [1 1] (mapv :rtt-us (:dns (analyze expected)))))
      (is (= 8 (reduce + (map :packets (flow/top-n (aggregate projected) 100)))))
      (is (every? map? (map flow/key projected)))
      (with-open [^Closeable capture (core/start-capture (assoc (options file) :max 8))
                  ^Closeable fanout (stream/fan-out (core/capture-packets capture)
                                                    {:full {:buffer-mode :blocking :buffer-cap 1}
                                                     :flow {:buffer-mode :blocking :buffer-cap 1}}
                                                    {:cancel! #(core/stop-capture! capture)})
                  ^Closeable full (stream/branch fanout :full)
                  ^Closeable flows (stream/branch fanout :flow)]
        (let [full-job (future (into [] (core/packet-xf config) full))
              flow-job (future (into [] (core/packet-xf flow-config) flows))
              decoded (deref full-job 10000 ::timeout)
              projected* (deref flow-job 10000 ::timeout)]
          (is (= (as-data expected) (as-data decoded)))
          (is (= projected projected*))
          (is (= (analyze expected) (analyze decoded)))
          (is (= (aggregate projected) (aggregate projected*)))
          (is (zero? (get-in (stream/stats fanout) [:branches :full :dropped])))))
      (is (= (analyze expected)
             (analyze (core/reduce-packets (merge (options file) config {:max 8}) conj []))))
      (is (= (count records) (count raw))))))

(deftest projection-depth-and-no-full-parser-or-input-copy
  (doseq [{:keys [file linktype]} cases]
    (let [raw (core/reduce-packets (options file) conj [])
          offset (if (= 113 linktype) 16 20)
          tcp (nth raw 2)
          short (assoc tcp :bytes (Arrays/copyOf ^bytes (:bytes tcp) (+ offset 20 4)))
          snapshot (vec (:bytes short))]
      (is (= :truncated-header (reason (transform full-config short))))
      (with-redefs [parse/packet->clj (fn [& _] (throw (AssertionError. "flow called full decoder")))]
        (is (= 12000 (:src-port (project/project-packet short)))))
      (is (= snapshot (vec (:bytes short)))))))

(defspec same-ip-data-independent-of-link-header 150
  (prop/for-all [case-index (gen/choose 0 1)
                 packet-index (gen/choose 0 12)
                 address-length (gen/choose 0 8)
                 address (gen/vector gen/byte 8)]
                (let [{:keys [linktype records]} (nth cases case-index)
                      bytes (test-util/hex->bytes (:hex (nth records packet-index)))
                      offset (if (= 113 linktype) 16 20)
                      ethernet (byte-array (+ 14 (- (alength bytes) offset)))
                      protocol-offset (if (= 113 linktype) 14 0)
                      cooked {:bytes bytes :linktype linktype}]
                  (aset-byte bytes (if (= 113 linktype) 5 11) (byte address-length))
                  (dotimes [i 8] (aset-byte bytes (+ (if (= 113 linktype) 6 12) i) (nth address i)))
                  (System/arraycopy bytes protocol-offset ethernet 12 2)
                  (System/arraycopy bytes offset ethernet 14 (- (alength bytes) offset))
                  (and (= (as-data (get-in (transform full-config cooked) [:decoded :l3]))
                          (as-data (get-in (transform full-config {:bytes ethernet}) [:decoded :l3])))
                       (= (dissoc (transform flow-config cooked) :linktype)
                          (dissoc (transform flow-config {:bytes ethernet}) :linktype))))))

(deftest cooked-length-boundaries-and-truncation-depth
  (doseq [{:keys [linktype records]} cases
          length [9 255 256 65535]
          :when (or (= 113 linktype) (< length 256))]
    (let [bytes (test-util/hex->bytes (:hex (first records)))
          offset (if (= 113 linktype) 4 11)
          width (if (= 113 linktype) 2 1)]
      (if (= 113 linktype)
        (do (aset-byte bytes 4 (unchecked-byte (bit-shift-right length 8)))
            (aset-byte bytes 5 (unchecked-byte length)))
        (aset-byte bytes 11 (unchecked-byte length)))
      (doseq [config [full-config flow-config]]
        (let [result (transform config {:bytes bytes :linktype linktype})
              diagnostic (first (:diagnostics result))]
          (is (= :malformed-packet (:reason diagnostic)))
          (is (= :address-length (:field diagnostic)))
          (is (= length (:value diagnostic)))
          (is (= {:offset offset :required width :available (- (alength bytes) offset)}
                 (:location diagnostic)))))))
  (doseq [{:keys [linktype records]} cases]
    (let [packet {:bytes (test-util/hex->bytes (:hex (first records))) :linktype linktype}
          offset (if (= 113 linktype) 16 20)
          bytes (Arrays/copyOf ^bytes (:bytes packet) (+ offset 20 4))
          short (assoc packet :bytes bytes)]
      (is (= :truncated-header (reason (transform full-config short))))
      (is (= 12000 (:src-port (transform flow-config short)))))))

(defspec cooked-prefixes-are-bounded-and-preserve-bytes 150
  (prop/for-all [case-index (gen/choose 0 1)
                 packet-index (gen/choose 0 12)
                 prefix-length (gen/choose 0 200)]
                (let [{:keys [linktype records]} (nth cases case-index)
                      original (test-util/hex->bytes (:hex (nth records packet-index)))
                      bytes (Arrays/copyOf original (min prefix-length (alength original)))
                      snapshot (vec bytes)
                      packet {:bytes bytes :linktype linktype :caplen (alength bytes)
                              :len (alength original) :ts-sec 0 :ts-usec 0}
                      full (transform full-config packet)
                      projected (transform flow-config packet)
                      minimum (if (= 113 linktype) 16 20)]
                  (and (identical? bytes (:bytes full)) (= snapshot (vec bytes))
                       (= (select-keys packet [:caplen :len :ts-sec :ts-usec :linktype])
                          (select-keys projected [:caplen :len :ts-sec :ts-usec :linktype]))
                       (not (contains? projected :bytes))
                       (every? (fn [result]
                                 (and (= (:diagnostics result)
                                         (edn/read-string (pr-str (:diagnostics result))))
                                      (every? (fn [{:keys [location]}]
                                                (or (nil? location)
                                                    (and (<= 0 (:offset location) (alength bytes))
                                                         (pos? (:required location))
                                                         (<= 0 (:available location)))))
                                              (:diagnostics result)))) [full projected])
                       (or (>= (alength bytes) minimum)
                           (= :short-frame (reason full) (reason projected)))))))
