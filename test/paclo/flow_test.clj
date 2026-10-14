(ns paclo.flow-test
  (:require
   [clojure.edn :as edn]
   [clojure.test :refer [deftest is testing]]
   [clojure.test.check.clojure-test :refer [defspec]]
   [clojure.test.check.generators :as gen]
   [clojure.test.check.properties :as prop]
   [paclo.core :as core]
   [paclo.flow :as flow]
   [paclo.stream :as stream])
  (:import
   [java.io Closeable]))

(declare bidirectional-reversal-and-edn aggregation-and-ranking-ignore-input-order
         unidirectional-keys-do-not-collide exact-counter-totals)

(def packet {:ip-version 4 :protocol 17
             :src-ip 167772161 :src-port 12000
             :dst-ip 167772162 :dst-port 53
             :caplen 40 :len 50})

(defn- reverse-packet [p]
  (assoc p :src-ip (:dst-ip p) :src-port (:dst-port p)
         :dst-ip (:src-ip p) :dst-port (:src-port p)))

(deftest canonical-key-contract
  (let [fk (flow/key packet)]
    (is (= (dissoc packet :caplen :len) fk))
    (is (= fk (edn/read-string (pr-str fk))))
    (is (not= fk (flow/key (reverse-packet packet))))
    (is (= fk (flow/key (reverse-packet packet) {:direction :bidir})))
    (is (= fk (flow/key (assoc packet :ts-sec 50 :bytes (byte-array 5)))))
    (is (thrown? clojure.lang.ExceptionInfo (flow/key packet {:direction :other}))))
  (doseq [protocol [1 58 132]]
    (let [p (assoc packet :protocol protocol :src-port nil :dst-port nil)]
      (is (= protocol (:protocol (flow/key p))))))
  (let [p (assoc packet :ip-version 6 :src-ip [-1 0] :dst-ip [0 -1])]
    (is (= [0 -1] (:src-ip (flow/key p {:direction :bidir}))))
    (is (= (flow/key p {:direction :bidir})
           (flow/key (reverse-packet p) {:direction :bidir}))))
  (let [p (assoc packet :src-ip 1 :dst-ip 1 :src-port 0 :dst-port nil)]
    (is (nil? (:src-port (flow/key p {:direction :bidir}))))))

(deftest invalid-flow-is-ineligible
  (doseq [p [nil {} (dissoc packet :src-port) (dissoc packet :dst-ip)
             (assoc packet :ip-version 5) (assoc packet :src-ip -1)
             (assoc packet :src-ip 4294967296) (assoc packet :protocol 256)
             (assoc packet :src-port 65536) (assoc packet :dst-port -1)
             (assoc packet :ip-version 6 :src-ip [0 0] :dst-ip 1)
             (assoc packet :ip-version 6 :src-ip [0 0] :dst-ip [0 9223372036854775808N])
             (assoc packet :protocol 1) (assoc packet :decode-error nil)
             (assoc packet :diagnostics [{:stage :flow :reason :unsupported-linktype}])]]
    (is (nil? (flow/key p)) (pr-str p))))

(deftest aggregates-exact-immutable-data
  (let [rf (flow/aggregate-rf {:max-flows 2 :direction :bidir})
        initial (rf)
        first-state (rf initial packet)
        result (reduce rf initial [packet (reverse-packet packet) {}])]
    (is (= {:flows {} :summary {:seen 0 :aggregated 0 :skipped 0}} initial))
    (is (= {:packets 1 :captured-bytes 40 :wire-bytes 50}
           (get-in first-state [:flows (flow/key packet)])))
    (is (= {:packets 2 :captured-bytes 80 :wire-bytes 100}
           (get-in result [:flows (flow/key packet)])))
    (is (= {:seen 3 :aggregated 2 :skipped 1} (:summary result)))
    (is (= result (rf result)))
    (is (= result (transduce identity rf [packet (reverse-packet packet) {}])))
    (is (= result (edn/read-string (pr-str result))))
    (is (= first-state (reduce rf (rf) [packet])))
    (is (= initial (transduce identity rf []))))
  (doseq [p [(dissoc packet :len) (assoc packet :caplen nil)
             (assoc packet :len 39) (assoc packet :caplen -1)
             (assoc packet :caplen 1.5) (assoc packet :len 4294967296)]]
    (let [rf (flow/aggregate-rf {:max-flows 1})]
      (is (thrown-with-msg? clojure.lang.ExceptionInfo #"valid :caplen"
                            (rf (rf) p)))))
  (let [rf (flow/aggregate-rf {:max-flows 1})]
    (is (= 1 (get-in (rf (rf) {:decode-error "unsupported linktype"}) [:summary :skipped])))))

(deftest cardinality-and-overflow
  (doseq [limit [nil 0 -1 1.5]]
    (is (thrown? clojure.lang.ExceptionInfo (flow/aggregate-rf {:max-flows limit}))))
  (let [rf (flow/aggregate-rf {:max-flows 1})
        state (rf (rf) packet)]
    (is (= 2 (get-in (rf state packet) [:flows (flow/key packet) :packets])))
    (try
      (rf state (reverse-packet packet))
      (is false "new flow must exceed limit")
      (catch clojure.lang.ExceptionInfo error
        (is (= :max-flows (:reason (ex-data error))))))
    (let [state (-> state
                    (assoc-in [:flows (flow/key packet)]
                              {:packets Long/MAX_VALUE :captured-bytes Long/MAX_VALUE :wire-bytes Long/MAX_VALUE})
                    (assoc :summary {:seen Long/MAX_VALUE :aggregated Long/MAX_VALUE :skipped 0}))
          result (rf state packet)]
      (is (= 9223372036854775808N (get-in result [:flows (flow/key packet) :packets])))
      (is (= (+' Long/MAX_VALUE 40) (get-in result [:flows (flow/key packet) :captured-bytes])))
      (is (= (+' Long/MAX_VALUE 50) (get-in result [:flows (flow/key packet) :wire-bytes])))
      (is (= 9223372036854775808N (get-in result [:summary :seen]))))))

(deftest stable-top-n
  (let [rf (flow/aggregate-rf {:max-flows 10})
        packets [packet (reverse-packet packet)
                 (assoc packet :ip-version 6 :src-ip [0 1] :dst-ip [-1 0])
                 (assoc packet :src-port nil :dst-port nil)]
        result (reduce rf (rf) packets)]
    (is (= [nil 12000 53 12000] (mapv #(get-in % [:flow :src-port]) (flow/top-n result {}))))
    (is (= (flow/top-n result {}) (flow/top-n (reduce rf (rf) (reverse packets)) {})))
    (doseq [metric [:packets :captured-bytes :wire-bytes]]
      (is (= 2 (count (flow/top-n result {:n 2 :metric metric})))))
    (is (= [] (flow/top-n result {:n 0})))
    (is (= [] (flow/top-n (rf) {})))
    (is (thrown? clojure.lang.ExceptionInfo (flow/top-n result {:metric :bytes})))
    (is (thrown? clojure.lang.ExceptionInfo (flow/top-n result {:n -1}))))
  (let [rf (flow/aggregate-rf {:max-flows 3})
        result (reduce rf (rf) [packet packet (assoc (reverse-packet packet) :caplen 90 :len 100)])]
    (is (= 12000 (get-in (first (flow/top-n result {:metric :packets})) [:flow :src-port])))
    (is (= 53 (get-in (first (flow/top-n result {:metric :captured-bytes})) [:flow :src-port])))
    (is (= 12000 (get-in (first (flow/top-n result {:metric :wire-bytes})) [:flow :src-port])))))

(def flow-gen
  (gen/let [version (gen/elements [4 6])
            protocol (gen/elements [1 6 17 58 132])
            a (gen/choose 0 4294967295) b (gen/choose 0 4294967295)
            high-a gen/large-integer high-b gen/large-integer
            low-a gen/large-integer low-b gen/large-integer
            port-a (gen/one-of [(gen/return nil) (gen/choose 0 65535)])
            port-b (gen/one-of [(gen/return nil) (gen/choose 0 65535)])]
    (assoc packet :ip-version version :protocol protocol
           :src-ip (if (= version 4) a [high-a low-a])
           :dst-ip (if (= version 4) b [high-b low-b])
           :src-port (when (contains? #{6 17} protocol) port-a)
           :dst-port (when (contains? #{6 17} protocol) port-b))))

(defspec bidirectional-reversal-and-edn 200
  (prop/for-all [p flow-gen]
                (let [fk (flow/key p {:direction :bidir})]
                  (and (some? fk) (= fk (flow/key (reverse-packet p) {:direction :bidir}))
                       (= fk (flow/key fk {:direction :bidir}))
                       (= fk (edn/read-string (pr-str fk)))
                       (= (flow/key p) (flow/key (assoc p :caplen 200 :len 300)))))))

(defspec aggregation-and-ranking-ignore-input-order 150
  (prop/for-all [packets (gen/vector flow-gen 0 30)]
                (let [rf (flow/aggregate-rf {:max-flows 100 :direction :bidir})
                      a (reduce rf (rf) packets)
                      b (transduce identity rf (reverse packets))]
                  (and (= a b) (= a (edn/read-string (pr-str a)))
                       (= (flow/top-n a {:n 100}) (flow/top-n b {:n 100}))))))

(defspec unidirectional-keys-do-not-collide 150
  (prop/for-all [a flow-gen b flow-gen]
                (= (= (select-keys a [:ip-version :protocol :src-ip :src-port :dst-ip :dst-port])
                      (select-keys b [:ip-version :protocol :src-ip :src-port :dst-ip :dst-port]))
                   (= (flow/key a) (flow/key b)))))

(deftest real-pcap-processing-paths
  (let [opts {:path "test/resources/dns-sample.pcap" :decode-mode :flow :max Long/MAX_VALUE}
        rf (flow/aggregate-rf {:max-flows 100 :direction :bidir})
        packets (vec (core/packets opts))
        expected (reduce rf (rf) packets)]
    (is (= 4 (get-in expected [:summary :aggregated])))
    (is (= expected (transduce identity rf packets)))
    (is (= expected (core/reduce-packets opts rf (rf))))
    (is (= expected (:result (core/reduce-packets-report opts rf (rf)))))
    (with-open [^Closeable capture (core/start-capture opts)]
      (is (= expected (reduce rf (rf) (core/capture-packets capture)))))
    (with-open [^Closeable capture (core/start-capture opts)
                ^Closeable fanout (stream/fan-out (core/capture-packets capture)
                                                  {:a {:buffer-mode :blocking :buffer-cap 1}
                                                   :b {:buffer-mode :blocking :buffer-cap 1}}
                                                  {:cancel! #(core/stop-capture! capture)})
                ^Closeable a (stream/branch fanout :a) ^Closeable b (stream/branch fanout :b)]
      (let [left (future (reduce rf (rf) a))
            right (future (transduce identity rf b))]
        (is (= expected (deref left 10000 :timeout)))
        (is (= expected (deref right 10000 :timeout)))))
    (testing "P05 cooked fixture decodes its valid record and skips malformed records"
      (let [result (core/reduce-packets-report (assoc opts :path "test/resources/linktype-sll.pcap") rf (rf))]
        (is (= {:seen 3 :aggregated 1 :skipped 2} (get-in result [:result :summary])))
        (is (= 2 (get-in result [:stats :packets :decode-errors])))))))

(deftest ipv6-word-order-and-ip-version-identity
  (doseq [[a b] [[[0 2] [0 1]] [[0 -1] [0 1]] [[-1 0] [0 -1]]]]
    (let [p (assoc packet :ip-version 6 :src-ip a :dst-ip b)]
      (is (= b (:src-ip (flow/key p {:direction :bidir}))))))
  (is (not= (flow/key packet)
            (flow/key (assoc packet :ip-version 6 :src-ip [0 167772161]
                             :dst-ip [0 167772162])))))

(defspec exact-counter-totals 150
  (prop/for-all [packets (gen/vector flow-gen 0 40)
                 lengths (gen/vector (gen/choose 0 10000) 40)]
                (let [packets (mapv #(assoc %1 :caplen %2 :len (+ (long %2) 20)) packets lengths)
                      rf (flow/aggregate-rf {:max-flows 100 :direction :bidir})
                      result (transduce identity rf packets)
                      values (vals (:flows result))]
                  (and (= (count packets) (get-in result [:summary :seen])
                          (get-in result [:summary :aggregated]) (reduce + (map :packets values)))
                       (= (reduce + (map :caplen packets)) (reduce + (map :captured-bytes values)))
                       (= (reduce + (map :len packets)) (reduce + (map :wire-bytes values)))))))

(deftest real-truncated-record-lengths-and-shared-bytes
  (let [file (java.io.File/createTempFile "paclo-flow-lengths" ".pcap")
        raw (first (core/packets {:path "test/resources/dns-sample.pcap" :max 1}))
        original (vec (:bytes raw))
        rf (flow/aggregate-rf {:max-flows 10})]
    (try
      (core/write-pcap! [(assoc raw :len 1500)] (.getAbsolutePath file))
      (let [result (core/reduce-packets {:path (.getAbsolutePath file) :decode-mode :flow} rf (rf))
            aggregate (first (vals (:flows result)))]
        (is (= (:caplen raw) (:captured-bytes aggregate)))
        (is (= 1500 (:wire-bytes aggregate))))
      (transduce (core/packet-xf {:decode-mode :flow}) rf [raw raw])
      (is (= original (vec (:bytes raw))))
      (finally (.delete file)))))
