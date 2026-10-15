(ns paclo.pcapng-test
  (:require
   [clojure.java.io :as io]
   [clojure.java.shell :as shell]
   [clojure.test :refer [deftest is testing]]
   [clojure.test.check :as tc]
   [clojure.test.check.generators :as gen]
   [clojure.test.check.properties :as prop]
   [paclo.core :as core]
   [paclo.pcapng :as pcapng]
   [paclo.pcapng.cursor :as cursor])
  (:import
   [java.io ByteArrayOutputStream Closeable File]
   [java.nio ByteBuffer ByteOrder]
   [java.nio.channels AsynchronousCloseException]
   [java.util Arrays]))

(defn- join [& parts]
  (let [out (ByteArrayOutputStream.)]
    (doseq [^bytes part parts] (.write out part))
    (.toByteArray out)))

(defn- words [order sizes values]
  (let [b (.order (ByteBuffer/allocate (reduce + sizes)) order)]
    (doseq [[size value] (map vector sizes values)]
      (case size
        1 (.put b (unchecked-byte value))
        2 (.putShort b (unchecked-short value))
        4 (.putInt b (unchecked-int value))
        8 (.putLong b (unchecked-long value))))
    (.array b)))

(def le ByteOrder/LITTLE_ENDIAN)
(def be ByteOrder/BIG_ENDIAN)
(defn- pad [^bytes bytes] (Arrays/copyOf bytes (* 4 (quot (+ 3 (alength bytes)) 4))))
(defn- block [order type ^bytes body]
  (let [body (pad body) n (+ 12 (alength body))]
    (join (words order [4 4] [type n]) body (words order [4] [n]))))
(defn- opts [order entries]
  (apply join (concat (map (fn [[code ^bytes bytes]]
                             (join (words order [2 2] [code (alength bytes)]) (pad bytes))) entries)
                      [(words order [2 2] [0 0])])))
(defn- shb
  ([] (shb le -1 []))
  ([order length options]
   (block order 0x0a0d0d0a
          (join (words order [4 2 2 8] [0x1a2b3c4d 1 0 length]) (opts order options)))))
(defn- idb
  ([] (idb le 1 64 []))
  ([order link snaplen options]
   (block order 1 (join (words order [2 2 4] [link 0 snaplen]) (opts order options)))))
(defn- epb
  ([] (epb le 0 0N (byte-array [1 2 3]) 3 []))
  ([order id ticks ^bytes bytes len options]
   (block order 6 (join (words order [4 4 4 4 4]
                               [id (quot ticks 4294967296N) (rem ticks 4294967296N) (alength bytes) len])
                        (pad bytes) (opts order options)))))

(defn- temp-call [bytes f]
  (let [file (File/createTempFile "paclo-pcapng-" ".pcapng")]
    (try
      (with-open [out (io/output-stream file)] (.write out ^bytes bytes))
      (f file)
      (finally (.delete file)))))
(defn- events [path]
  (with-open [s (pcapng/open-source {:path path})] (into [] s)))
(defn- read-bytes [bytes]
  (temp-call bytes events))
(defn- failure [f]
  (try (f) nil (catch Throwable e e)))
(defn- reason [f] (:reason (ex-data (failure f))))
(defn- fixture [name] (str "test/resources/pcapng-contracts/" name ".pcapng"))

(deftest e1-semantic-corpus
  (let [values (events (fixture "rich"))
        packets (mapv :packet (filter #(= :packet (:type %)) values))
        interfaces (mapv :interface (filter #(= :interface (:type %)) values))]
    (is (= [:section :interface :packet :interface :packet :opaque-block :packet] (mapv :type values)))
    (is (= (vec (range 7)) (mapv :block-index values)))
    (is (= [0 56 160 320 412 560 584] (mapv :file-offset values)))
    (is (= [[1699999993N 123456N] [1700000000N 125976N] [nil nil]]
           (mapv (juxt :ts-sec :ts-usec) packets)))
    (is (= [{:base 10 :exponent 9} {:base 2 :exponent 10}]
           (mapv :timestamp-resolution interfaces)))
    (is (= [-7 0] (mapv :timestamp-offset-sec interfaces)))
    (is (= [1 1 2 0x8001] (mapv :code (get-in (first packets) [:pcapng :options]))))
    (is (= [1 0 0 0] (vec (:value (nth (get-in (first packets) [:pcapng :options]) 2)))))
    (is (nil? (get-in (last packets) [:pcapng :timestamp])))
    (is (not (contains? (last packets) :ts-sec)))
    (is (= 1700000000123456789N (get-in (first packets) [:pcapng :timestamp :ticks]))))
  (let [values (events (fixture "mixed-sections"))]
    (is (= [0 0 0 1 1 1] (mapv :section-id values)))
    (is (= [:little-endian :big-endian] (mapv #(get-in % [:section :byte-order]) (filter :section values))))
    (is (= [1 12] (mapv #(get-in % [:packet :linktype]) (filter :packet values))))
    (is (= [64 50] (mapv #(get-in % [:interface :snaplen]) (filter :interface values)))))
  (let [packets (mapv :packet (filter :packet (events (fixture "timestamp-extremes"))))]
    (is (every? #(= 18446744073709551615N (get-in % [:pcapng :timestamp :ticks])) packets))
    (is (= [[27670116110564327422N 0] [-9223372036854775808N 0] [0 0]]
           (mapv (juxt :ts-sec :ts-usec) packets))))
  (let [packet (:packet (last (events (fixture "spb-truncated"))))]
    (is (= [15 1500 15] [(:caplen packet) (:len packet) (alength ^bytes (:bytes packet))])))
  (doseq [[name expected] [["forward-interface" :undefined-interface]
                           ["unaligned-length" :invalid-block-length]
                           ["oversized-length" :limit-exceeded]
                           ["option-overrun" :invalid-option-length]
                           ["bad-offset-length" :invalid-option-length]
                           ["duplicate-resolution" :duplicate-option]]]
    (is (= expected (reason #(events (fixture name)))) (str name))))

(deftest existing-pcapng-fixtures
  (let [bad #{"bad-interface" "bad-caplen" "short-block" "bad-trailer" "cut-block"
              "bad-idb-option" "invalid-original-length"}]
    (doseq [file (filter #(.endsWith (.getName ^File %) ".pcapng")
                         (file-seq (io/file "test/resources/capture-formats")))]
      (let [name (.replace (.getName ^File file) ".pcapng" "")]
        (if (bad name)
          (is (some? (failure #(events file))) name)
          (is (seq (events file)) name))))
    (doseq [directory ["cooked" "raw-ip" "null-loop"]
            file (filter #(.endsWith (.getName ^File %) ".pcapng")
                         (file-seq (io/file (str "test/resources/" directory))))]
      (is (seq (events file)) (str file)))))

(deftest timestamp-projection-properties
  (let [result
        (tc/quick-check
         500
         (prop/for-all [hi (gen/choose 0 4294967295) lo (gen/choose 0 4294967295)
                        base (gen/elements [2 10]) exponent (gen/choose 0 127)
                        offset (gen/elements [Long/MIN_VALUE -1 0 1 Long/MAX_VALUE])]
                       (let [ticks (+' (*' hi 4294967296N) lo)
                             d (.pow (biginteger base) exponent)
                             exact (+' offset (/ ticks d))
                             {:keys [ts-sec ts-usec]} (cursor/projection ticks {:base base :exponent exponent} offset)
                             projected (+' ts-sec (/ ts-usec 1000000))]
                         (and (<= 0 ts-usec 999999) (<= projected exact) (< (- exact projected) 1/1000000))))
         :seed 80802)]
    (is (:pass? result) (pr-str result)))
  (is (= {:ts-sec -1N :ts-usec 0N} (cursor/projection 1 {:base 10 :exponent 9} -1)))
  ;; Exercise all 256 wire resolution bytes through the production parser.
  (doseq [v (range 256)]
    (let [packet (:packet (last (read-bytes
                                 (join (shb) (idb le 1 64 [[9 (byte-array [(unchecked-byte v)])]]) (epb)))))]
      (is (= [0 0] [(:ts-sec packet) (:ts-usec packet)]))
      (is (= {:ticks 0N} (get-in packet [:pcapng :timestamp]))))))

(deftest descriptor-order-property
  (let [result
        (tc/quick-check
         50
         (prop/for-all [counts (gen/vector (gen/choose 1 5) 1 8)]
                       (let [wire (apply join
                                         (map-indexed
                                          (fn [section n]
                                            (let [order (if (even? section) le be)]
                                              (apply join (shb order -1 [])
                                                     (mapcat (fn [id] [(idb order (if (even? id) 1 101) 64 [])
                                                                       (epb order id 0N (byte-array [0]) 1 [])]) (range n))))) counts))]
                         (temp-call wire
                                    (fn [file]
                                      (with-open [s (pcapng/open-source {:path file})]
                                        (:ok? (reduce (fn [{:keys [section interfaces ok?]} event]
                                                        (case (:type event)
                                                          :section {:section (:section-id event) :interfaces #{} :ok? ok?}
                                                          :interface {:section section :interfaces (conj interfaces (get-in event [:interface :id])) :ok? ok?}
                                                          :packet {:section section :interfaces interfaces
                                                                   :ok? (and ok? (= section (:section-id event))
                                                                             (contains? interfaces (get-in event [:packet :pcapng :interface-id])))}))
                                                      {:ok? true} s)))))))
         :seed 80803)]
    (is (:pass? result) (pr-str result))))

(deftest decoding-is-explicitly-packet-only
  (let [xf (comp (filter :packet) (map :packet) (core/packet-xf {:decode? true :extensions []}))]
    (with-open [s (pcapng/open-source {:path (fixture "mixed-sections")})]
      (is (= [:ethernet :raw-ip] (mapv #(get-in % [:decoded :type]) (transduce xf conj [] s)))))
    (let [wire (join (shb) (idb le 65535 0 []) (epb))
          packet (:packet (last (read-bytes wire)))
          decoded (first (into [] (core/packet-xf {:decode? true :extensions []}) [packet]))]
      (is (contains? packet :linktype))
      (is (nil? (:linktype packet)))
      (is (= "unsupported linktype" (:decode-error decoded)))
      (is (identical? (:bytes packet) (:bytes decoded))))))

(deftest truncation-and-section-boundaries
  (let [wire (join (shb) (idb) (epb))
        boundaries #{32 56 (alength ^bytes wire)}]
    (doseq [n (range (inc (alength ^bytes wire)))]
      (let [error (failure #(read-bytes (Arrays/copyOf ^bytes wire n)))]
        (is (= (not (boundaries n)) (some? error)) (str "prefix " n)))))
  (doseq [order [le be]]
    (is (= 2 (count (read-bytes (join (shb order 24 []) (idb order 1 64 []))))))
    (is (= 3 (count (read-bytes (join (shb order 24 []) (idb order 1 64 []) (shb))))))
    (doseq [length [-2 1 20 28 100]]
      (is (= :invalid-section-length
             (reason #(read-bytes (join (shb order length []) (idb order 1 64 []))))))))
  (is (= :unsupported-section-version
         (reason #(read-bytes (block le 0x0a0d0d0a (words le [4 2 2 8] [0x1a2b3c4d 2 0 -1]))))))
  (is (= :invalid-section-magic (reason #(read-bytes (block le 0x0a0d0d0a (byte-array 16)))))))

(deftest options-and-opaque-policies
  (doseq [[kind make codes] [[:section #(shb le -1 %) [2 3 4]]
                             [:interface #(join (shb) (idb le 1 64 %)) [2 3 6 7 8 9 10 11 12 13 14 15 16 17 18]]
                             [:packet #(join (shb) (idb) (epb le 0 0N (byte-array 0) 0 %)) [2 4 5 6]]]
          code codes]
    (let [size (get-in @#'cursor/fixed-lengths [kind code] (if (= code 11) 1 0))]
      (is (= :duplicate-option (reason #(read-bytes (make [[code (byte-array size)] [code (byte-array size)]])))))))
  (doseq [[kind make lengths] [[:interface #(join (shb) (idb le 1 64 %)) {4 8, 5 17, 6 6, 7 8, 8 8, 9 1, 10 4, 13 1, 14 8, 16 8, 17 8}]
                               [:packet #(join (shb) (idb) (epb le 0 0N (byte-array 0) 0 %)) {2 4, 4 8, 5 8, 6 4, 8 8}]]
          [code size] lengths]
    (testing (str kind code)
      (is (= :invalid-option-length (reason #(read-bytes (make [[code (byte-array (dec size))]])))))))
  (doseq [code [2988 2989 19372 19373]]
    (is (= :invalid-option-length (reason #(read-bytes (shb le -1 [[code (byte-array 3)]])))))
    (is (= (if (< code 10000) :copyable :never)
           (get-in (first (read-bytes (shb le -1 [[code (byte-array 4)]]))) [:section :options 0 :copy-policy]))))
  (let [values (read-bytes (shb le -1 [[1 (byte-array 0)] [1 (byte-array [(unchecked-byte 255)])]
                                       [0x8001 (byte-array 0)] [0x8001 (byte-array [1])]]))]
    (is (= [1 1 0x8001 0x8001] (mapv :code (get-in values [0 :section :options]))))
    (is (= [-1] (vec (get-in values [0 :section :options 1 :value])))))
  ;; No terminator and nonzero padding are legal; validate extents, not padding content.
  (is (seq (read-bytes (block le 0x0a0d0d0a
                              (join (words le [4 2 2 8] [0x1a2b3c4d 1 0 -1])
                                    (words le [2 2 1 1 1 1] [1 1 65 99 99 99]))))))
  (is (= :invalid-option-length (reason #(read-bytes (shb le -1 [[0 (byte-array [1])]])))))
  (doseq [[type policy] [[4 :copyable] [5 :copyable] [0xbad :copyable] [0x40000bad :never] [0x80000042 :unknown]]]
    (let [body (if (= type 5) (byte-array 12) (byte-array [1 2 3 4]))
          event (last (read-bytes (join (shb) (block le type body))))]
      (is (= :opaque-block (:type event)))
      (is (= policy (get-in event [:block :copy-policy])))
      (is (= (vec body) (vec (get-in event [:block :body]))))))
  (is (= :invalid-block-length (reason #(read-bytes (join (shb) (block le 0xbad (byte-array 0)))))))
  (doseq [[type expected] [[2 :unsupported-packet-block] [10 :unsupported-sensitive-block]]]
    (is (= expected (reason #(read-bytes (join (shb) (block le type (byte-array 4)))))))))

(deftest repeated-interface-address-options
  ;; Draft 06 table 3: address octets keep their order under either section order.
  (doseq [order [le be]]
    (let [ipv4 (byte-array (map unchecked-byte [192 0 2 1 255 255 255 0]))
          ipv6 (byte-array (concat [32 1 13 (unchecked-byte 184)] (repeat 11 0) [1 64]))
          entries [[4 ipv4] [5 ipv6] [4 (aclone ipv4)] [1 (byte-array [65])]
                   [5 (aclone ipv6)] [4 (byte-array (map unchecked-byte [198 51 100 2 255 255 255 128]))]]
          wire (join (shb order -1 []) (idb order 1 64 entries))]
      (doseq [[code value] [[4 ipv4] [5 ipv6]]]
        (is (= :invalid-option-length
               (reason #(read-bytes (join (shb order -1 [])
                                          (idb order 1 64 [[code value]
                                                           [code (Arrays/copyOf ^bytes value (dec (alength ^bytes value)))]])))))))
      (temp-call wire
                 (fn [file]
                   (let [values (events file)
                         options (get-in values [1 :interface :options])]
                     (is (= [4 5 4 1 5 4] (mapv :code options)))
                     (is (= (mapv (comp vec second) entries) (mapv (comp vec :value) options)))
                     (doseq [[[_ input] option] (map vector entries options)]
                       (is (not (identical? input (:value option)))))
                     (is (not (identical? (:value (first options)) (:value (nth options 2)))))
                     (is (not (identical? (:value (nth options 1)) (:value (nth options 4)))))
                     (is (= :eof (with-open [s (pcapng/open-source {:path file})]
                                   (reduce (fn [n _] (inc n)) 0 s)
                                   (:terminal (pcapng/source-info s))))))))
      (doseq [[field limit] [[:max-options-per-block 6] [:max-options-bytes 96]
                             [:max-section-metadata-bytes 804]]]
        (temp-call wire
                   (fn [file]
                     (with-open [s (pcapng/open-source {:path file field limit})]
                       (is (= 2 (reduce (fn [n _] (inc n)) 0 s))))
                     (is (= :limit-exceeded
                            (reason #(with-open [s (pcapng/open-source {:path file field (dec limit)})]
                                       (reduce (fn [n _] (inc n)) 0 s)))))))))))

(defn- traced-packet-failure [wire opts]
  (temp-call wire
             (fn [file]
               (with-open [s (pcapng/open-source (merge {:path file} opts))]
                 (let [allocations (atom []) reads (atom [])
                       allocate @#'cursor/allocate-buffer read! cursor/read-buffer!
                       error (with-redefs-fn
                               {#'cursor/allocate-buffer
                                (fn [n]
                                  (swap! allocations conj n)
                                  (when (> n 128)
                                    (throw (ex-info "Unexpected packet body allocation" {:reason :unexpected-allocation})))
                                  (allocate n))
                                #'cursor/read-buffer!
                                (fn [^java.nio.channels.FileChannel channel ^ByteBuffer buffer & args]
                                  (swap! reads conj {:offset (.position channel) :bytes (.remaining buffer)})
                                  (apply read! channel buffer args))}
                               #(failure (fn []
                                           (reduce (fn [n event]
                                                     (when (= :interface (:type event))
                                                       (reset! allocations [])
                                                       (reset! reads []))
                                                     (inc n)) 0 s))))]
                   {:error (ex-data error) :allocations @allocations :reads @reads
                    :info (pcapng/source-info s)})))))

(deftest packet-ceiling-before-payload-allocation-or-read
  (doseq [order [le be] type [6 3] caplen [64 65536] snaplen [0 caplen]
          suffix [(byte-array 0) (byte-array [1 2 3])]]
    (let [prefix (if (= type 6) (words order [4 4 4 4 4] [0 0 0 caplen caplen]) (words order [4] [caplen]))
          prefix-size (alength ^bytes prefix)
          wire (join (shb order -1 []) (idb order 1 snaplen [])
                     (words order [4 4] [type (+ 12 prefix-size caplen)]) prefix suffix)
          {:keys [error allocations reads info]}
          (traced-packet-failure wire {:max-block-bytes 1048576 :max-packet-bytes 8})]
      (is (= :limit-exceeded (:reason error)))
      (is (= [:max-packet-bytes caplen 8] ((juxt :field :actual :limit) error)))
      (is (= [56 2 0 type] ((juxt :file-offset :block-index :section-id :block-type) error)))
      (is (= [8 prefix-size] allocations))
      (is (= [{:offset 56 :bytes 8} {:offset 64 :bytes prefix-size}] reads))
      (is (= [:failed :error 2 0 0] ((juxt :state :terminal :events :packets :active-metadata-bytes) info)))))
  (doseq [order [le be] type [6 3]
          :let [prefix (if (= type 6) (words order [4 4 4 4 4] [0 0 0 64 64]) (words order [4] [64]))]
          n (range (alength ^bytes prefix))]
    (let [wire (join (shb order -1 []) (idb order 1 0 [])
                     (words order [4 4] [type (+ 12 (alength ^bytes prefix) 64)])
                     (Arrays/copyOf ^bytes prefix (int n)))
          {:keys [error allocations reads]} (traced-packet-failure wire {:max-packet-bytes 8})]
      (is (= :truncated-block (:reason error)))
      (is (= [8 (alength ^bytes prefix)] allocations))
      (is (= [8 (alength ^bytes prefix)] (mapv :bytes reads))))))

(deftest packet-lengths-validated-from-prefix
  (doseq [order [le be]
          [type snaplen body-bytes prefix]
          [[6 0 32 (words order [4 4 4 4 4] [0 0 0 9 8])]
           [6 8 32 (words order [4 4 4 4 4] [0 0 0 9 9])]
           [6 0 28 (words order [4 4 4 4 4] [0 0 0 9 9])]
           [3 0 8 (words order [4] [9])]
           [3 0 20 (words order [4] [9])]]]
    (let [{:keys [error allocations reads]}
          (traced-packet-failure (join (shb order -1 []) (idb order 1 snaplen [])
                                       (words order [4 4] [type (+ 12 body-bytes)]) prefix)
                                 {:max-packet-bytes 16})]
      (is (= :invalid-packet-length (:reason error)))
      (is (= [8 (alength ^bytes prefix)] allocations))
      (is (= [8 (alength ^bytes prefix)] (mapv :bytes reads)))))
  (doseq [order [le be] [type body-size] [[6 16] [3 0]]]
    (let [{:keys [error allocations reads]}
          (traced-packet-failure (join (shb order -1 []) (idb order 1 0 [])
                                       (words order [4 4] [type (+ 12 body-size)])) {})]
      (is (= :invalid-block-length (:reason error)))
      (is (= [8] allocations))
      (is (= [8] (mapv :bytes reads)))))
  (doseq [order [le be]]
    (let [packet (:packet (last (read-bytes (join (shb order -1 []) (idb order 1 0 [])
                                                  (block order 3 (join (words order [4] [3]) (byte-array [1 2 3])))))))]
      (is (= [3 3 [1 2 3]] [(:caplen packet) (:len packet) (vec (:bytes packet))]))
      (is (not (contains? packet :ts-sec))))))

(deftest exact-resource-limits
  (doseq [[field limit wire]
          [[:max-block-bytes 40 (shb le -1 [[1 (byte-array 1)]])]
           [:max-packet-bytes 3 (join (shb) (idb) (epb))]
           [:max-options-bytes 12 (shb le -1 [[1 (byte-array 1)]])]
           [:max-options-per-block 2 (shb le -1 [[1 (byte-array 0)] [1 (byte-array 0)]])]
           [:max-interfaces-per-section 2 (join (shb) (idb) (idb) (epb))]
           [:max-section-metadata-bytes 300 (shb le -1 [[1 (byte-array 1)]])]
           [:max-section-metadata-bytes 596 (join (shb) (idb le 1 64 [[1 (byte-array 0)] [1 (byte-array 1)]]))]
           [:max-opaque-block-bytes 4 (join (shb) (block le 0x80000042 (byte-array 4)))]]]
    (testing (str field)
      (temp-call wire
                 (fn [file]
                   (with-open [s (pcapng/open-source {:path file field limit})]
                     (is (pos? (reduce (fn [n _] (inc n)) 0 s))))
                   (let [error (failure #(with-open [s (pcapng/open-source {:path file field (dec limit)})]
                                           (reduce (fn [n _] (inc n)) 0 s)))]
                     (is (= :limit-exceeded (:reason (ex-data error))))
                     (is (= field (:field (ex-data error)))))))))
  ;; Default interface boundary, consumed with constant-size accumulator.
  (temp-call (apply join (shb) (repeat 4097 (idb)))
             (fn [file]
               (with-open [s (pcapng/open-source {:path file})]
                 (is (= :limit-exceeded
                        (reason #(reduce (fn [n _] (inc n)) 0 s))))
                 (is (= 4097 (:events (pcapng/source-info s))))))))

(deftest hostile-lengths-stop-before-body-read
  (doseq [[header opts expected-position field]
          [[(words le [4 4] [6 0xfffffffc]) {} 8 :max-block-bytes]
           [(words le [4 4] [0x80000042 1028]) {:max-opaque-block-bytes 100} 8 :max-opaque-block-bytes]]]
    (temp-call (join (shb) header)
               (fn [file]
                 (with-open [s (pcapng/open-source (merge {:path file} opts))]
                   (let [positions (atom []) read! cursor/read-buffer!
                         error (with-redefs [cursor/read-buffer!
                                             (fn [^java.nio.channels.FileChannel channel & args]
                                               (let [result (apply read! channel args)]
                                                 (swap! positions conj (.position channel)) result))]
                                 (failure #(reduce (fn [n _] (inc n)) 0 s)))]
                     (is (= :limit-exceeded (:reason (ex-data error))))
                     (is (= field (:field (ex-data error))))
                     (is (= [(+ 32 expected-position)] @positions)))))))
  (is (= :limit-exceeded
         (reason #(read-bytes (join (shb) (idb le 1 0 [])
                                    (block le 6 (words le [4 4 4 4 4] [0 0 0 0xffffffff 0xffffffff])))))))
  (doseq [type [1 3 6 4 5]]
    (is (= :invalid-block-length (reason #(read-bytes (join (shb) (block le type (byte-array 0)))))))))

(deftest option-amplification-and-owned-arrays
  (temp-call (shb le -1 (repeat 4096 [1 (byte-array 0)]))
             (fn [file]
               (with-open [s (pcapng/open-source {:path file})]
                 (is (= 4096 (count (get-in (first (into [] s)) [:section :options])))))))
  (is (= :limit-exceeded (reason #(read-bytes (shb le -1 (repeat 4097 [1 (byte-array 0)]))))))
  (let [wire (join (shb) (idb le 1 0 [[2 (byte-array [65])]])
                   (epb le 0 0N (byte-array [1]) 0xffffffff [[8 (byte-array 8)] [8 (byte-array 8)]])
                   (shb be -1 []) (idb be 1 64 [[2 (byte-array [66])]]))
        values (read-bytes wire)
        packet (:packet (nth values 2))
        again (:packet (nth (read-bytes wire) 2))]
    (is (= 4294967295 (:len packet)))
    (is (= [8 8] (mapv :code (get-in packet [:pcapng :options]))))
    (is (= [65] (vec (get-in values [1 :interface :options 0 :value]))))
    (is (= [66] (vec (get-in values [4 :interface :options 0 :value]))))
    (is (not (identical? (:bytes packet) (:bytes again))))
    (is (= (vec (:bytes packet)) (vec (:bytes again)))))
  (is (= :invalid-packet-length (reason #(read-bytes (join (shb) (idb le 1 2 []) (epb)))))))

(deftest options-validated-before-open
  (doseq [value [nil 0 -1 1.0 2147483640N]
          field (keys cursor/defaults)]
    (is (= :invalid-source-options (reason #(pcapng/open-source {:path "/no/such/file" field value})))))
  (doseq [opts [nil {} {:path nil} {:path "/no/such/file" :unknown 1}
                {:path "/no/such/file" :max-options-per-block 65537}]]
    (is (= :invalid-source-options (reason #(pcapng/open-source opts)))))
  (is (instance? java.nio.file.NoSuchFileException (failure #(pcapng/open-source {:path "/no/such/file"})))))

(deftest lifecycle-and-no-post-stop-reads
  (doseq [stop-type [:section :interface :packet :opaque-block]]
    (let [calls (atom 0) read! cursor/read-buffer!]
      (with-redefs [cursor/read-buffer! (fn [& args] (swap! calls inc) (apply read! args))]
        (with-open [s (pcapng/open-source {:path (fixture "rich")})]
          (let [at-stop (atom nil)
                count (reduce (fn [n event]
                                (if (= stop-type (:type event))
                                  (do (reset! at-stop @calls) (reduced (inc n))) (inc n))) 0 s)]
            (is (= @at-stop @calls))
            (is (= count (:events (pcapng/source-info s))))
            (is (= :reduced (:terminal (pcapng/source-info s))))
            (is (= :source-consumed (reason #(reduce conj [] s)))))))))
  (with-open [s (pcapng/open-source {:path (fixture "rich")})]
    (let [completion (atom 0)
          rf (fn ([] 0) ([n] (swap! completion inc) (is (= :closed (:state (pcapng/source-info s)))) n)
               ([n _] (inc n)))]
      (is (= 1 (transduce (take 1) rf 0 s)))
      (is (= 1 @completion))
      (is (= 1 (:blocks-read (pcapng/source-info s))))))
  (with-open [s (pcapng/open-source {:path (fixture "rich")})]
    (let [error (Exception. "consumer")]
      (is (identical? error (failure #(reduce (fn [_ _] (throw error)) 0 s))))
      (is (= :failed (:state (pcapng/source-info s))))
      (is (= :error (:terminal (pcapng/source-info s))))))
  (with-open [s (pcapng/open-source {:path (fixture "rich")})]
    (let [error (Exception. "completion")]
      (is (identical? error (failure #(transduce (take 1) (fn ([_] (throw error)) ([n _] (inc n))) 0 s))))
      (is (= :reduced (:terminal (pcapng/source-info s))))))
  (let [s (pcapng/open-source {:path (fixture "rich")})]
    (is (not (instance? clojure.lang.Seqable s)))
    (.close ^Closeable s)
    (.close ^Closeable s)
    (is (= :closed (:terminal (pcapng/source-info s))))
    (is (= :source-closed (reason #(reduce conj [] s))))
    (is (= 0 (:active-metadata-bytes (pcapng/source-info s)))))
  (with-open [s (pcapng/open-source {:path (fixture "option-overrun")})]
    (let [error (failure #(reduce (fn [n _] (inc n)) 0 s))]
      (is (= :invalid-option-length (:reason (ex-data error))))
      (is (= 1 (:events (pcapng/source-info s))))
      (is (= :failed (:state (pcapng/source-info s))))
      (is (= (:reason (ex-data error)) (get-in (pcapng/source-info s) [:error :reason]))))))

(deftest simultaneous-consumption-and-cancellation
  (with-open [s (pcapng/open-source {:path (fixture "rich")})]
    (let [entered (promise) proceed (promise)
          reader (future (reduce (fn [n _] (deliver entered true) @proceed (inc n)) 0 s))]
      (try
        (is (= true (deref entered 5000 :timeout)))
        (is (= :source-consumed (reason #(reduce conj [] s))))
        (.close ^Closeable s)
        (is (= :closed (:terminal (pcapng/source-info s))))
        (is (not (realized? reader)))
        (deliver proceed true)
        (is (= 1 (deref reader 5000 :timeout)))
        (is (= 1 (:blocks-read (pcapng/source-info s))))
        (finally (deliver proceed true) @reader))))
  ;; Cancel after a read begins, before the next event is claimed for delivery.
  (with-open [s (pcapng/open-source {:path (fixture "rich")})]
    (let [entered (promise) proceed (promise) read! cursor/read-buffer!
          reader (with-redefs [cursor/read-buffer!
                               (fn [& args] (deliver entered true) @proceed (apply read! args))]
                   (let [worker (future (reduce (fn [n _] (inc n)) 0 s))]
                     (try
                       (is (= true (deref entered 5000 :timeout)))
                       (.close ^Closeable s)
                       (deliver proceed true)
                       (deref worker 5000 :timeout)
                       (finally (deliver proceed true) @worker))))]
      (is (= 1 reader))
      (is (= :closed (:terminal (pcapng/source-info s))))
      (is (= 1 (:events (pcapng/source-info s)))))))

(deftest injected-io-and-close-failures
  (let [closed (atom 0) close! @#'pcapng/close-channel!]
    (with-redefs-fn {#'pcapng/close-channel! (fn [channel] (swap! closed inc) (close! channel))}
      #(is (= :invalid-section-magic (reason (fn [] (read-bytes (block le 0x0a0d0d0a (byte-array 16))))))))
    (is (= 1 @closed)))
  (doseq [primary [(Exception. "consumer") (java.io.IOException. "read")]]
    (with-open [s (pcapng/open-source {:path (fixture "rich")})]
      (let [close-error (java.io.IOException. "close") close! @#'pcapng/close-channel!
            error (with-redefs-fn {#'pcapng/close-channel! (fn [channel] (close! channel) (throw close-error))}
                    #(failure (fn []
                                (if (instance? java.io.IOException primary)
                                  (with-redefs [cursor/read-buffer! (fn [& _] (throw primary))]
                                    (reduce (fn [n _] (inc n)) 0 s))
                                  (reduce (fn [_ _] (throw primary)) 0 s)))))]
        (is (identical? primary error))
        (is (= [close-error] (vec (.getSuppressed ^Throwable error)))))))
  (with-open [s (pcapng/open-source {:path (fixture "rich")})]
    (let [error (java.io.IOException. "sole close") close! @#'pcapng/close-channel!]
      (is (identical? error
                      (with-redefs-fn {#'pcapng/close-channel! (fn [channel] (close! channel) (throw error))}
                        #(failure (fn [] (transduce (take 1) conj [] s))))))
      (is (= :failed (:state (pcapng/source-info s))))))
  (let [s (pcapng/open-source {:path (fixture "rich")})
        error (java.io.IOException. "unused close") close! @#'pcapng/close-channel!]
    (is (identical? error (with-redefs-fn {#'pcapng/close-channel! (fn [channel] (close! channel) (throw error))}
                            #(failure (fn [] (.close ^Closeable s))))))
    (is (= :failed (:state (pcapng/source-info s))))
    (is (zero? (:active-metadata-bytes (pcapng/source-info s))))
    (.close ^Closeable s))
  (with-open [s (pcapng/open-source {:path (fixture "rich")})]
    (with-redefs [cursor/read-buffer! (fn [& _] (.close ^Closeable s) (throw (AsynchronousCloseException.)))]
      (is (= 1 (reduce (fn [n _] (inc n)) 0 s))))
    (is (= :closed (:terminal (pcapng/source-info s)))))
  ;; The same exception from a consumer is still an error, even after cancellation.
  (with-open [s (pcapng/open-source {:path (fixture "rich")})]
    (let [error (AsynchronousCloseException.)]
      (is (identical? error (failure #(reduce (fn [_ _] (.close ^Closeable s) (throw error)) 0 s))))
      (is (= :error (:terminal (pcapng/source-info s)))))))

(deftest streaming-constrained-heap
  ;; 200+ MiB of metadata/opaque wire data, consumed in a separate 48 MiB JVM.
  ;; The parent writes one reusable section buffer; neither consumer collects events.
  (let [section (join (shb) (idb le 1 64 [[1 (byte-array 32768)]])
                      (idb) (block le 0x80000042 (byte-array 8192)))
        file (File/createTempFile "paclo-pcapng-heap-" ".pcapng")]
    (try
      (with-open [out (io/output-stream file)] (dotimes [_ 6000] (.write out ^bytes section)))
      (let [{:keys [exit out err]}
            (shell/sh (str (System/getProperty "java.home") "/bin/java") "-Xmx48m"
                      "-cp" (System/getProperty "java.class.path")
                      "clojure.main" "-m" "paclo.pcapng-heap-probe" (.getPath file))]
        (is (= 0 exit) (str out err))
        (is (.contains ^String out "PCAPNG bounded heap OK")))
      (finally (.delete file)))))
