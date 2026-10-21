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
         unidirectional-keys-do-not-collide exact-counter-totals
         map-boundary-snapshots-fork-and-resume)

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
    ;; Deliberate invalid input verifies the public runtime validation.
    (is (thrown? clojure.lang.ExceptionInfo #_{:clj-kondo/ignore [:type-mismatch]}
                 (flow/top-n result {:n -1}))))
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

(deftest reducer-snapshots-can-fork-and-resume
  (doseq [direction [:unidir :bidir]]
    (let [rf (flow/aggregate-rf {:max-flows 2 :direction direction})
          initial (with-meta (assoc (rf) :owner :caller) {:snapshot :initial})
          prefix (-> (rf initial packet)
                     (assoc :summary (with-meta {:seen Long/MAX_VALUE
                                                 :aggregated Long/MAX_VALUE
                                                 :skipped Long/MAX_VALUE
                                                 :owner :summary}
                                       {:snapshot :summary})))
          saved (pr-str prefix)
          left (rf prefix packet)
          right (rf prefix {})
          resumed (rf (edn/read-string saved) packet)]
      (is (= saved (pr-str prefix)) "both branches leave the published prefix unchanged")
      (is (= left resumed) "EDN-restored state resumes with the same reducer")
      (is (= {:seen 9223372036854775808N :aggregated 9223372036854775808N
              :skipped Long/MAX_VALUE :owner :summary} (:summary left)))
      (is (= {:seen 9223372036854775808N :aggregated Long/MAX_VALUE
              :skipped 9223372036854775808N :owner :summary} (:summary right)))
      (doseq [state [left right]]
        (is (= :caller (:owner state)))
        (is (= (meta initial) (meta state)))
        (is (= (meta (:summary prefix)) (meta (:summary state))))
        (is (identical? state (rf state))))
      (is (= (rf (rf) packet) (transduce identity rf [packet]))
        "reusing the reducer does not retain either branch"))))

(deftest exact-totals-continue-after-promotion
  (let [rf (flow/aggregate-rf {:max-flows 1N :direction :bidir})
        fk (flow/key packet {:direction :bidir})
        big (bigint (.shiftLeft java.math.BigInteger/ONE 100))
        initial {:flows {fk {:packets big :captured-bytes big :wire-bytes big}}
                 :summary {:seen big :aggregated big :skipped big}}
        result (reduce rf initial [packet (reverse-packet packet) {}])]
    (is (= {:packets (+' big 2) :captured-bytes (+' big 80) :wire-bytes (+' big 100)}
           (get-in result [:flows fk])))
    (is (= {:seen (+' big 3) :aggregated (+' big 2) :skipped (inc' big)} (:summary result)))
    (is (= result (edn/read-string (pr-str result))))
    (is (= big (get-in initial [:flows fk :packets])))))

(deftest ipv6-indexed-words-retain-validation-and-order
  (let [p (assoc packet :ip-version 6 :src-ip [0N -1N] :dst-ip [0N 0N])]
    (is (= [0N 0N] (:src-ip (flow/key p {:direction :bidir}))))
    (is (= (flow/key p {:direction :bidir})
           (flow/key (reverse-packet p) {:direction :bidir})))
    (doseq [address [[] [0] [0 0 0] '(0 0) [nil 0] [0 1.0]
                     [0 (dec' Long/MIN_VALUE)] [(inc' Long/MAX_VALUE) 0]]]
      (is (nil? (flow/key (assoc p :src-ip address))))))
  (let [p (assoc packet :ip-version 6
                 :src-ip [Long/MIN_VALUE Long/MIN_VALUE]
                 :dst-ip [Long/MIN_VALUE Long/MAX_VALUE])]
    (is (= (:dst-ip p) (:src-ip (flow/key p {:direction :bidir}))))))

(deftest flow-map-boundaries-and-caller-maps
  (doseq [direction [:unidir :bidir]
          size [0 1 7 8 9 10]
          empty-map [{} clojure.lang.PersistentHashMap/EMPTY (sorted-map-by #(compare (:src-port %1) (:src-port %2)))]]
    (let [rf (flow/aggregate-rf {:max-flows 11 :direction direction})
          packets (mapv #(assoc packet :src-port %) (range 1 (inc size)))
          initial (with-meta (assoc (rf) :owner :caller
                                    :flows (with-meta empty-map {:owner :flows})
                                    :summary (with-meta (assoc (:summary (rf)) :owner :summary)
                                               {:owner :summary}))
                    {:owner :state})
          prefix (reduce rf initial packets)
          saved (pr-str prefix)
          p (assoc packet :src-port (if (zero? size) 1 size))
          equal-key (flow/key p {:direction direction})
          stored (find (:flows prefix) equal-key)
          updated (rf prefix p)
          added (rf prefix (assoc p :src-port 11))]
      (when stored
        (is (= equal-key (key stored)))
        (is (not (identical? equal-key (key stored))) "equal packet keys are freshly constructed"))
      (is (= (if (zero? size) 1 2) (get-in updated [:flows equal-key :packets])))
      (is (= (inc size) (count (:flows added))))
      (is (= saved (pr-str prefix)) "updates and additions preserve the shared snapshot")
      (is (= updated (rf (edn/read-string saved) p)))
      (doseq [state [updated added]]
        (is (= :caller (:owner state)))
        (is (= :summary (get-in state [:summary :owner])))
        (is (= (meta initial) (meta state)))
        (is (= (meta (:flows initial)) (meta (:flows state))))
        (is (= (meta (:summary initial)) (meta (:summary state))))
        (is (identical? state (rf state))))
      (when (instance? clojure.lang.PersistentTreeMap empty-map)
        (is (instance? clojure.lang.PersistentTreeMap (:flows updated)))
        (is (= (.comparator ^clojure.lang.PersistentTreeMap empty-map)
               (.comparator ^clojure.lang.PersistentTreeMap (:flows added)))))))
  (let [rf (flow/aggregate-rf {:max-flows 10})
        states (reductions rf (rf) (map #(assoc packet :src-port %) (range 10)))]
    (doseq [n [7 8]]
      (is (instance? clojure.lang.PersistentArrayMap (:flows (nth states n)))))
    (is (instance? clojure.lang.PersistentHashMap (:flows (nth states 9))))))

(deftest hash-map-errors-and-exact-counters
  (doseq [direction [:unidir :bidir]]
    (let [rf (flow/aggregate-rf {:max-flows 9 :direction direction})
          packets (mapv #(assoc packet :src-port %) (range 9))
          state (reduce rf (rf) packets)
          p (first packets)
          fk (flow/key p {:direction direction})
          big (bigint (.shiftLeft java.math.BigInteger/ONE 100))]
      (doseq [start [Long/MAX_VALUE big]]
        (let [seed (-> state
                       (assoc-in [:flows fk] {:packets start :captured-bytes start :wire-bytes start})
                       (assoc :summary {:seen start :aggregated start :skipped start}))
              result (reduce rf seed [p {}])]
          (is (= {:packets (inc' start) :captured-bytes (+' start 40) :wire-bytes (+' start 50)}
                 (get-in result [:flows fk])))
          (is (= {:seen (+' start 2) :aggregated (inc' start) :skipped (inc' start)}
                 (:summary result)))))
      (doseq [[seed input message data]
              [[state (assoc p :src-port 10) "flow cardinality limit exceeded"
                {:reason :max-flows :max-flows 9 :flow (flow/key (assoc p :src-port 10) {:direction direction})}]
               [state (assoc p :len 39) "flow aggregation requires valid :caplen and :len"
                {:reason :invalid-lengths :caplen 40 :len 39}]
               ;; Preserve the existing nil-value convention, even for a present key.
               [(assoc-in state [:flows fk] nil) p "flow cardinality limit exceeded"
                {:reason :max-flows :max-flows 9 :flow fk}]]]
        (try
          (rf seed input)
          (is false "expected the unchanged error contract")
          (catch clojure.lang.ExceptionInfo error
            (is (= message (ex-message error)))
            (is (= data (ex-data error))))))
      (is (= (reduce rf (rf) (take 4 packets))
             (transduce (take 4) rf packets)))
      (is (= state (transduce identity (flow/aggregate-rf {:max-flows 9 :direction direction}) packets))))))

(defspec map-boundary-snapshots-fork-and-resume 100
  (prop/for-all [size (gen/choose 7 10)
                 suffix (gen/vector (gen/choose 0 11) 1 25)
                 direction (gen/elements [:unidir :bidir])]
                (let [rf (flow/aggregate-rf {:max-flows 12 :direction direction})
                      prefix (mapv #(assoc packet :src-port %) (range size))
                      tail (mapv #(assoc packet :src-port %) suffix)
                      snapshot (reduce rf (rf) prefix)
                      saved (pr-str snapshot)
                      left (reduce rf snapshot tail)
                      right (reduce rf snapshot (reverse tail))]
                  (and (= saved (pr-str snapshot))
                       (= left right (reduce rf (edn/read-string saved) tail)
                          (reduce rf (rf) (into prefix tail)))
                       (identical? left (rf left))))))

(deftest hash-map-seeded-pcap-fanout
  (let [opts {:path "test/resources/cooked/sll2.pcap" :decode-mode :flow :max Long/MAX_VALUE}
        rf (flow/aggregate-rf {:max-flows 100 :direction :bidir})
        seed (reduce rf (rf) (map #(assoc packet :src-port %) (range 1024 1033)))
        saved (pr-str seed)
        packets (core/reduce-packets opts conj [])
        expected (transduce identity rf seed packets)]
    (is (instance? clojure.lang.PersistentHashMap (:flows seed)))
    (is (= expected (core/reduce-packets opts rf seed)))
    (is (= expected (:result (core/reduce-packets-report opts rf seed))))
    (is (= (reduce rf seed (take 3 packets))
           (core/reduce-packets (assoc opts :xform (take 3)) rf seed)))
    (with-open [^Closeable capture (core/start-capture opts)
                ^Closeable fanout (stream/fan-out (core/capture-packets capture)
                                                  {:a {:buffer-mode :blocking :buffer-cap 1}
                                                   :b {:buffer-mode :blocking :buffer-cap 1}}
                                                  {:cancel! #(core/stop-capture! capture)})
                ^Closeable a (stream/branch fanout :a) ^Closeable b (stream/branch fanout :b)]
      (let [left (future (reduce rf seed a))
            right (future (transduce identity rf (edn/read-string saved) b))]
        (is (= expected (deref left 10000 :timeout)))
        (is (= expected (deref right 10000 :timeout)))))
    (is (= saved (pr-str seed)))))
