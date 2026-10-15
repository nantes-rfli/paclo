(ns paclo.pcapng-writer-test
  (:require
   [clojure.java.io :as io]
   [clojure.java.shell :as shell]
   [clojure.test :refer [deftest is]]
   [clojure.test.check :as tc]
   [clojure.test.check.generators :as gen]
   [clojure.test.check.properties :as prop]
   [clojure.walk :as walk]
   [paclo.pcapng :as pcapng]
   [paclo.pcapng.writer])
  (:import
   [clojure.lang IReduceInit]
   [java.io Closeable File IOException]
   [java.nio ByteBuffer ByteOrder]
   [java.nio.file Files Path]
   [java.nio.file.attribute FileAttribute]))

(defn- fixture [name] (str "test/resources/pcapng-contracts/" name ".pcapng"))
(defn- events [path] (with-open [s (pcapng/open-source {:path path})] (into [] s)))
(defn- failure [f] (try (f) nil (catch Throwable e e)))
(defn- reason [f] (:reason (ex-data (failure f))))
(defn- temp-call [f]
  (let [dir (Files/createTempDirectory "paclo-writer-" (make-array FileAttribute 0))
        path (.resolve dir "output.pcapng")]
    (try (f path)
         (finally
           (doseq [^File file (reverse (file-seq (.toFile dir)))] (.delete file))))))
(defn- exists? [^Path path] (.exists (.toFile path)))
(defn- temps [^Path path] (filter #(.startsWith (.getName ^File %) ".paclo-pcapng-")
                                  (file-seq (.toFile (.getParent path)))))
(defn- semantic [value]
  (walk/postwalk (fn [v] (cond (bytes? v) (vec v)
                               (and (map? v) (:type v)) (dissoc v :file-offset :block-index)
                               (and (map? v) (contains? v :section-length)) (assoc v :section-length nil)
                               :else v)) value))
(defn- base-events []
  (-> (vec (take 3 (events "test/resources/capture-formats/single.pcapng")))
      (assoc-in [0 :section :options] [])
      (assoc-in [1 :interface :options] [])
      (assoc-in [2 :packet :pcapng :options] [])))
(defn- write-reason [value opts]
  (temp-call
   (fn [path]
     (let [error (failure #(pcapng/write-pcapng! value path opts))]
       (is (not (exists? path)))
       (is (empty? (temps path)))
       (:reason (ex-data error))))))
(defn- private-var [symbol] (ns-resolve 'paclo.pcapng.writer symbol))

(deftest all-supported-real-fixtures-roundtrip
  (let [bad #{"bad-interface.pcapng" "bad-caplen.pcapng" "short-block.pcapng" "bad-trailer.pcapng"
              "cut-block.pcapng" "bad-idb-option.pcapng" "invalid-original-length.pcapng"}
        files (concat (map #(io/file (fixture %)) ["rich" "mixed-sections" "timestamp-extremes" "spb-truncated"])
                      (for [directory ["capture-formats" "cooked" "raw-ip" "null-loop"]
                            ^File file (file-seq (io/file (str "test/resources/" directory)))
                            :when (and (.endsWith (.getName file) ".pcapng") (not (bad (.getName file))))] file))]
    (doseq [file files]
      (temp-call
       (fn [path]
         (with-open [source (pcapng/open-source {:path file})]
           (let [report (pcapng/write-pcapng! source path)]
             (is (= :known-semantics (:fidelity report)) (str file))
             (is (= {} (:loss-counts report)))
             (is (= :eof (:terminal (pcapng/source-info source))))))
         (is (= (semantic (events file)) (semantic (events path))) (str file))
         (let [{:keys [exit out err]} (shell/sh "python3" "test/resources/verify_pcapng_writer.py" (str file) (str path))]
           (is (= 0 exit) (str file out err)))
         (is (empty? (temps path))))))))

(deftest authored-exact-time-properties
  (let [result (tc/quick-check
                120
                (prop/for-all [hi (gen/choose 0 4294967295) lo (gen/choose 0 4294967295)
                               base (gen/elements [2 10]) exponent (gen/choose 0 127)
                               offset (gen/elements [Long/MIN_VALUE -7 0 1 Long/MAX_VALUE])
                               endian (gen/elements [:little-endian :big-endian])]
                              (temp-call
                               (fn [path]
                                 (let [ticks (+' (*' hi 4294967296N) lo)
                                       raw-offset (.array (.putLong (.order (ByteBuffer/allocate 8)
                                                                            (if (= endian :little-endian)
                                                                              ByteOrder/LITTLE_ENDIAN ByteOrder/BIG_ENDIAN)) offset))
                                       values (-> (base-events)
                                                  (assoc-in [0 :section :byte-order] endian)
                                                  (assoc-in [1 :interface :timestamp-resolution] {:base base :exponent exponent})
                                                  (assoc-in [1 :interface :timestamp-offset-sec] offset)
                                                  (assoc-in [1 :interface :options]
                                                            [{:code 9 :value (byte-array [(unchecked-byte (+ exponent (if (= base 2) 128 0)))])}
                                                             {:code 14 :value raw-offset}])
                                                  (update-in [2 :packet] dissoc :ts-sec :ts-usec)
                                                  (assoc-in [2 :packet :pcapng :timestamp] {:ticks ticks}))]
                                   (pcapng/write-pcapng! values path {:mode :author})
                                   (= (semantic values)
                                      (semantic (update-in (events path) [2 :packet] dissoc :ts-sec :ts-usec)))))))
                :seed 80803)]
    (is (:pass? result) (pr-str result))))

(deftest author-microseconds-and-explicit-absence
  (let [values (-> (base-events)
                   (update-in [2 :packet :pcapng] dissoc :timestamp)
                   (assoc-in [2 :packet :ts-sec] 0) (assoc-in [2 :packet :ts-usec] 123456))]
    (temp-call (fn [path]
                 (is (= :authored (:fidelity (pcapng/write-pcapng! values path {:mode :author}))))
                 (is (= 123456N (get-in (last (events path)) [:packet :pcapng :timestamp :ticks])))))
    (is (= :invalid-field (write-reason values {})))
    (is (= :invalid-field (write-reason (assoc-in values [2 :packet :pcapng :timestamp] nil) {:mode :author})))
    (is (= :invalid-timestamp (write-reason (update-in values [2 :packet] dissoc :ts-usec) {:mode :author}))))
  (let [values (-> (base-events)
                   (assoc-in [1 :interface :timestamp-resolution] {:base 2 :exponent 0})
                   (assoc-in [1 :interface :options] [{:code 9 :value (byte-array [(unchecked-byte 128)])}])
                   (update-in [2 :packet :pcapng] dissoc :timestamp)
                   (assoc-in [2 :packet :ts-sec] 0) (assoc-in [2 :packet :ts-usec] 1))]
    (is (= :invalid-field (write-reason values {:mode :author}))))
  (temp-call (fn [path]
               (let [values (events (fixture "spb-truncated"))]
                 (pcapng/write-pcapng! values path {:mode :author})
                 (is (= (semantic values) (semantic (events path))))))))

(deftest invalid-metadata-is-never-repaired
  (let [values (base-events)]
    (doseq [[expected bad]
            [[:missing-section []]
             [:invalid-section-id (assoc-in values [0 :section :id] 1)]
             [:invalid-interface-id (assoc-in values [1 :interface :id] 1)]
             [:undefined-interface (assoc-in values [2 :packet :pcapng :interface-id] 1)]
             [:descriptor-conflict (assoc-in values [1 :interface :timestamp-offset-sec] 1)]
             [:descriptor-conflict (assoc-in values [1 :interface :timestamp-resolution] {:base 2 :exponent 8})]
             [:timestamp-conflict (update-in values [2 :packet :ts-usec] inc)]
             [:invalid-field (assoc-in values [2 :packet :pcapng :timestamp :ticks] 18446744073709551616N)]
             [:invalid-field (assoc-in values [2 :packet :pcapng :timestamp :ticks] -1)]
             [:invalid-packet-length (assoc-in values [2 :packet :caplen] 0)]
             [:invalid-packet-length (assoc-in values [2 :packet :len] 0)]
             [:invalid-packet-length (assoc-in values [1 :interface :snaplen] 1)]
             [:missing-metadata (update-in values [2 :packet] dissoc :bytes)]
             [:missing-metadata (update-in values [2] dissoc :packet)]
             [:missing-metadata (update-in values [1 :interface] dissoc :options)]
             [:duplicate-option (assoc-in values [1 :interface :options]
                                          [{:code 9 :value (byte-array [6])} {:code 9 :value (byte-array [6])}])]
             [:invalid-option-length (assoc-in values [2 :packet :pcapng :options] [{:code 2 :value (byte-array 3)}])]
             [:invalid-option-length (assoc-in values [0 :section :options] [{:code 0 :value (byte-array 0)}])]]]
      (doseq [opts [{} {:mode :lossy :drop #{:unknown-options :comments}} {:mode :author}]]
        (is (= expected (write-reason bad opts)) (str expected opts))))
    (doseq [packet [(:packet (last values)) {:bytes (byte-array 0) :ts-sec 0 :ts-usec 0}
                    {:flow {} :ts-sec 0 :ts-usec 0}]]
      (is (some? (write-reason [packet] {}))))))

(deftest explicit-loss-counts-and-context
  (let [values (events (fixture "rich"))]
    (is (= :invalid-writer-options (write-reason values {:drop #{:comments}})))
    (is (= :invalid-writer-options (write-reason values {:context-changed? true})))
    (is (= :opaque-context-changed (write-reason values {:mode :lossy :context-changed? true})))
    (temp-call
     (fn [path]
       (let [report (pcapng/write-pcapng! values path {:mode :lossy :drop #{:comments :unknown-options :opaque-blocks}
                                                       :context-changed? true})
             after (events path)]
         (is (= :explicit-loss (:fidelity report)))
         (is (= {:comments 6 :unknown-options 4 :opaque-blocks 1 :context-changed 1} (:loss-counts report)))
         (is (= [:section :interface :packet :interface :packet :packet] (mapv :type after)))
         (is (= (mapv #(get-in % [:packet :pcapng :timestamp]) (filter :packet values))
                (mapv #(get-in % [:packet :pcapng :timestamp]) (filter :packet after)))))))
    ;; Lossy alone retains everything and reports no invented loss.
    (temp-call #(is (= {} (:loss-counts (pcapng/write-pcapng! values % {:mode :lossy}))))))
  (let [values (base-events)
        custom {:type :opaque-block :section-id 0
                :block {:block-type 0x40000bad :body (byte-array 4) :byte-order :little-endian :copy-policy :never}}
        input (conj values custom)]
    (doseq [opts [{} {:mode :lossy}]] (is (= :noncopyable-data (write-reason input opts))))
    (temp-call #(is (= {:opaque-blocks 1} (:loss-counts (pcapng/write-pcapng! input % {:mode :lossy :drop #{:opaque-blocks}})))))
    (is (= :opaque-context-changed
           (write-reason (conj values (assoc-in custom [:block :byte-order] :big-endian)) {:mode :lossy :drop #{:opaque-blocks}})))
    (doseq [code [19372 19373]]
      (let [values (assoc-in values [0 :section :options] [{:code code :value (byte-array 4) :copy-policy :copyable}])]
        (is (= :noncopyable-data (write-reason values {})))
        (temp-call #(is (= {:noncopyable-options 1}
                           (:loss-counts (pcapng/write-pcapng! values % {:mode :lossy :drop #{:noncopyable-options}})))))))
    (doseq [code [2988 2989]]
      (let [values (assoc-in values [0 :section :options] [{:code code :value (byte-array 4)}])]
        (is (= :opaque-context-changed (write-reason values {:mode :lossy :context-changed? true})))
        (temp-call #(is (= {:custom-options 1 :context-changed 1}
                           (:loss-counts (pcapng/write-pcapng! values % {:mode :lossy :context-changed? true :drop #{:custom-options}})))))))))

(deftest opaque-policies-and-minima
  (doseq [[type size] [[4 4] [5 12] [0x00000bad 4] [0x80000042 4]]]
    (let [values (conj (base-events) {:type :opaque-block :section-id 0
                                      :block {:block-type type :body (byte-array size)
                                              :byte-order :little-endian :copy-policy (if (= type 0x80000042) :unknown :copyable)}})]
      (temp-call (fn [path]
                   (pcapng/write-pcapng! values path)
                   (is (= (vec (byte-array size)) (vec (get-in (last (events path)) [:block :body]))))))))
  (doseq [type [1 2 3 6 10 0x0a0d0d0a]]
    (is (= :unsupported-opaque-block
           (write-reason (conj (base-events) {:type :opaque-block :section-id 0
                                              :block {:block-type type :body (byte-array 4) :byte-order :little-endian :copy-policy :unknown}}) {}))))
  (doseq [[type size] [[4 0] [5 8] [0x00000bad 0]]]
    (is (= :invalid-block-length
           (write-reason (conj (base-events) {:type :opaque-block :section-id 0
                                              :block {:block-type type :body (byte-array size) :byte-order :little-endian :copy-policy :unknown}}) {})))))

(deftest destination-protection-and-creation-race
  (temp-call
   (fn [path]
     (spit (.toFile path) "existing")
     (is (= :destination-exists (reason #(pcapng/write-pcapng! (base-events) path))))
     (is (= "existing" (slurp (.toFile path))))
     (is (empty? (temps path)))))
  (temp-call
   (fn [path]
     (let [publish @(private-var 'publish!)]
       (with-redefs-fn {(private-var 'publish!) (fn [temp destination]
                                                  (spit (.toFile ^Path destination) "raced")
                                                  (publish temp destination))}
         #(is (= :atomic-publication-failed (reason (fn [] (pcapng/write-pcapng! (base-events) path))))))
       (is (= "raced" (slurp (.toFile path))))
       (is (empty? (temps path)))))))

(deftest output-failure-paths-and-primary-identity
  (doseq [stage ['write-block! 'flush-output! 'close-output! 'publish!]]
    (temp-call
     (fn [path]
       (let [primary (IOException. (str stage))
             original @(private-var stage)]
         (with-open [source (pcapng/open-source {:path (fixture "rich")})]
           (with-redefs-fn {(private-var stage) (fn [& args]
                                                  (when (= stage 'close-output!) (apply original args))
                                                  (throw primary))}
             #(is (identical? primary (failure (fn [] (pcapng/write-pcapng! source path))))))
           (is (= (if (= stage (quote write-block!)) :failed :closed) (:state (pcapng/source-info source)))))
         (is (not (exists? path)))
         (is (empty? (temps path)))))))
  (temp-call
   (fn [path]
     (let [primary (IOException. "write") close-error (IOException. "close") cleanup-error (IOException. "cleanup")
           close @(private-var 'close-output!)]
       (with-redefs-fn {(private-var 'write-block!) (fn [& _] (throw primary))
                        (private-var 'close-output!) (fn [out] (close out) (throw close-error))
                        (private-var 'cleanup!) (fn [_] (throw cleanup-error))}
         #(is (identical? primary (failure (fn [] (pcapng/write-pcapng! (base-events) path))))))
       (is (some #(identical? close-error %) (.getSuppressed primary)))
       (let [cleanup (last (.getSuppressed primary))]
         (is (identical? cleanup-error (.getCause cleanup)))
         (is (= (str (.toPath ^File (first (temps path)))) (:temp-path (ex-data cleanup)))))
       (is (not (exists? path)))
       (is (= 1 (count (temps path)))))))
  (temp-call
   (fn [path]
     (let [primary (IOException. "open")]
       (with-redefs-fn {(private-var 'open-output!) (fn [_] (throw primary))}
         #(is (identical? primary (failure (fn [] (pcapng/write-pcapng! (base-events) path))))))
       (is (empty? (temps path)))))))

(deftest unsupported-atomic-publication-does-not-fallback
  (temp-call
   (fn [path]
     (with-redefs-fn {(private-var 'publish!) (fn [& _] (throw (java.nio.file.AtomicMoveNotSupportedException. "tmp" "dest" "injected")))}
       #(is (instance? java.nio.file.AtomicMoveNotSupportedException
                       (failure (fn [] (pcapng/write-pcapng! (base-events) path))))))
     (is (not (exists? path)))
     (is (empty? (temps path))))))

(deftest source-consumption-ownership-and-incomplete-input
  (temp-call
   (fn [path]
     (with-open [s (pcapng/open-source {:path (fixture "rich")})]
       (pcapng/write-pcapng! s path)
       (is (= :source-consumed (reason #(pcapng/write-pcapng! s (.resolveSibling ^Path path "second.pcapng")))))
       (is (empty? (temps path))))))
  (temp-call
   (fn [path]
     (with-open [s (pcapng/open-source {:path (fixture "rich")})]
       (reduce (fn [_ _] (reduced nil)) nil s)
       (is (= :source-consumed (reason #(pcapng/write-pcapng! s path))))
       (is (not (exists? path))))))
  (temp-call
   (fn [path]
     (with-open [s (pcapng/open-source {:path (fixture "rich")})]
       (let [write @(private-var 'write-block!)]
         (with-redefs-fn {(private-var 'write-block!) (fn [out bytes] (write out bytes) (.close ^Closeable s))}
           #(is (= :incomplete-source (reason (fn [] (pcapng/write-pcapng! s path)))))))
       (is (= :closed (:terminal (pcapng/source-info s))))
       (is (not (exists? path)))
       (is (empty? (temps path))))))
  (temp-call
   (fn [path]
     (with-open [s (pcapng/open-source {:path (fixture "option-overrun")})]
       (is (= :invalid-option-length (reason #(pcapng/write-pcapng! s path))))
       (is (= :error (:terminal (pcapng/source-info s))))
       (is (not (exists? path)))
       (is (empty? (temps path))))))
  (temp-call
   (fn [path]
     (let [primary (IOException. "upstream") calls (atom 0)
           source (reify IReduceInit
                    (reduce [_ rf init]
                      (let [acc (reduce (fn [acc e] (swap! calls inc) (rf acc e)) init (base-events))]
                        (throw primary) acc)))]
       (is (identical? primary (failure #(pcapng/write-pcapng! source path))))
       (is (= 3 @calls))
       (is (not (exists? path)))
       (is (empty? (temps path)))))))

(deftest limits-exact-and-one-over
  (let [values (base-events)
        packet-size (alength ^bytes (get-in values [2 :packet :bytes]))]
    (doseq [[opts bad]
            [[{:max-packet-bytes packet-size} {:max-packet-bytes (dec packet-size)}]
             [{:max-block-bytes (+ 32 (* 4 (quot (+ packet-size 3) 4)))}
              {:max-block-bytes (dec (+ 32 (* 4 (quot (+ packet-size 3) 4))))}]
             [{:max-interfaces-per-section 1} nil]
             [{:max-section-metadata-bytes 512} {:max-section-metadata-bytes 511}]]]
      (temp-call #(is (= :complete (:status (pcapng/write-pcapng! values % opts)))))
      (when bad (is (= :limit-exceeded (write-reason values bad)))))
    (is (= :limit-exceeded (write-reason (conj (subvec values 0 2)
                                               (assoc-in (nth values 1) [:interface :id] 1))
                                         {:max-interfaces-per-section 1})))
    (doseq [opts [{:unknown true} {:path "ignored"} {:max-block-bytes nil} {:max-options-per-block 65537} {:max-opaque-block-bytes 0}
                  {:mode :something} {:drop [:comments]} {:mode :lossy :drop #{:typo}}]]
      (is (= :invalid-writer-options (write-reason values opts)))))
  (let [values (assoc-in (base-events) [0 :section :options] [{:code 1 :value (byte-array [1])} {:code 1 :value (byte-array 0)}])]
    (temp-call #(is (= :complete (:status (pcapng/write-pcapng! values % {:max-options-bytes 12 :max-options-per-block 2})))))
    (is (= :limit-exceeded (write-reason values {:max-options-bytes 11})))
    (is (= :limit-exceeded (write-reason values {:max-options-per-block 1})))))

(deftest eduction-early-stop-and-plain-reducible-ownership
  (temp-call
   (fn [path]
     (with-open [source (pcapng/open-source {:path (fixture "rich")})]
       (is (= :incomplete-source
              (reason #(pcapng/write-pcapng! (eduction (take 2) source) path))))
       (is (= :reduced (:terminal (pcapng/source-info source))))
       (is (= 2 (:blocks-read (pcapng/source-info source))))
       (is (not (exists? path)))
       (is (empty? (temps path))))))
  (temp-call
   (fn [path]
     (with-open [source (pcapng/open-source {:path (fixture "rich")})]
       (is (= :complete
              (:status (pcapng/write-pcapng! (eduction (take 2) source) path
                                             {:mode :lossy :context-changed? true :drop #{:unknown-options}}))))
       (is (= :reduced (:terminal (pcapng/source-info source))))
       (is (= 2 (count (events path)))))))
  (temp-call
   (fn [path]
     (let [closed (atom 0)
           reducible (reify Closeable (close [_] (swap! closed inc))
                       IReduceInit (reduce [_ rf init] (reduce rf init (base-events))))]
       (pcapng/write-pcapng! reducible path)
       (is (zero? @closed))
       (.close ^Closeable reducible)
       (is (= 1 @closed))))))

(deftest source-close-failure-remains-primary
  (temp-call
   (fn [path]
     (let [close-var (ns-resolve 'paclo.pcapng 'close-channel!)
           close @close-var primary (IOException. "reader close")]
       (with-open [source (pcapng/open-source {:path (fixture "rich")})]
         (with-redefs-fn {close-var (fn [channel] (close channel) (throw primary))}
           #(is (identical? primary (failure (fn [] (pcapng/write-pcapng! source path)))))))
       (is (not (exists? path)))
       (is (empty? (temps path)))))))

(deftest concurrent-consumption-refused-without-stealing-source
  (temp-call
   (fn [path]
     (with-open [source (pcapng/open-source {:path (fixture "rich")})]
       (let [write @(private-var 'write-block!) attempted (atom false)]
         (with-redefs-fn {(private-var 'write-block!)
                          (fn [out bytes]
                            (when (compare-and-set! attempted false true)
                              (is (= :source-consumed (reason #(reduce conj [] source)))))
                            (write out bytes))}
           #(is (= :complete (:status (pcapng/write-pcapng! source path))))))
       (is (= :eof (:terminal (pcapng/source-info source))))))))

(deftest opaque-and-metadata-limits
  (let [values (conj (base-events) {:type :opaque-block :section-id 0
                                    :block {:block-type 0x80000042 :body (byte-array 8)
                                            :byte-order :little-endian :copy-policy :unknown}})]
    (temp-call #(is (= :complete (:status (pcapng/write-pcapng! values % {:max-opaque-block-bytes 8})))))
    (is (= :limit-exceeded (write-reason values {:max-opaque-block-bytes 7}))))
  ;; No terminators are emitted. Section = 256 + 8 TLV + 32 record; IDB = 256.
  (let [values (assoc-in (base-events) [0 :section :options] [{:code 1 :value (byte-array 1)}])]
    (temp-call #(is (= :complete (:status (pcapng/write-pcapng! values % {:max-section-metadata-bytes 552})))))
    (is (= :limit-exceeded (write-reason values {:max-section-metadata-bytes 551})))))

(deftest writer-streaming-constrained-heap
  ;; Reuse one small wire section, never retain input/output events. Over 230 MiB
  ;; passes through both reader and writer within the child JVM's 48 MiB heap.
  (temp-call
   (fn [path]
     (let [input (.resolveSibling ^Path path "input.pcapng")
           ;; Explicit authoring makes a small reusable SHB/2 IDBs/opaque section.
           values (-> (subvec (base-events) 0 2)
                      (assoc-in [1 :interface :options] [{:code 1 :value (byte-array 32768)}])
                      (conj (-> (nth (base-events) 1) (assoc-in [:interface :id] 1)))
                      (conj {:type :opaque-block :section-id 0
                             :block {:block-type 0x80000042 :body (byte-array 8192)
                                     :byte-order :little-endian :copy-policy :unknown}}))
           section-path (.resolveSibling ^Path path "section.pcapng")]
       (pcapng/write-pcapng! values section-path {:mode :author})
       (let [section (Files/readAllBytes section-path)]
         (with-open [out (io/output-stream (.toFile input))]
           (dotimes [_ 6000] (.write out ^bytes section))))
       (let [{:keys [exit out err]}
             (shell/sh (str (System/getProperty "java.home") "/bin/java") "-Xmx48m"
                       "-cp" (System/getProperty "java.class.path")
                       "clojure.main" "-m" "paclo.pcapng-writer-heap-probe" (str input) (str path))]
         (is (= 0 exit) (str out err))
         (is (.contains ^String out "PCAPNG writer bounded heap OK")))
       (is (empty? (temps path)))))))

(deftest exclusive-publication-symlinks-and-concurrent-writers
  (temp-call
   (fn [path]
     (Files/createSymbolicLink path (.resolveSibling ^Path path "missing") (make-array FileAttribute 0))
     (is (= :destination-exists (reason #(pcapng/write-pcapng! (base-events) path))))
     (is (Files/isSymbolicLink path))
     (is (empty? (temps path)))))
  (temp-call
   (fn [path]
     (let [publish @(private-var 'publish!)
           ready (java.util.concurrent.CountDownLatch. 2)]
       (with-redefs-fn {(private-var 'publish!)
                        (fn [temp destination]
                          (.countDown ready)
                          (when-not (.await ready 10 java.util.concurrent.TimeUnit/SECONDS)
                            (throw (IOException. "writer barrier timeout")))
                          (publish temp destination))}
         (fn []
           (let [a (future (try (pcapng/write-pcapng! (base-events) path)
                                (catch Throwable e e)))
                 b (future (try (pcapng/write-pcapng! (base-events) path)
                                (catch Throwable e e)))
                 results [(deref a 15000 :timeout) (deref b 15000 :timeout)]]
             (is (= 1 (count (filter #(= :complete (:status %)) results))))
             (is (= [:atomic-publication-failed]
                    (mapv #(-> % ex-data :reason) (filter #(instance? Throwable %) results))))
             (is (= (semantic (base-events)) (semantic (events path)))))))
       (is (empty? (temps path)))))))

(deftest unsupported-real-filesystem-provider
  (temp-call
   (fn [path]
     (let [zip (.resolveSibling ^Path path "archive.zip")]
       (with-open [fs (java.nio.file.FileSystems/newFileSystem ^Path zip {"create" "true"})]
         (let [output (.getPath fs "/output.pcapng" (make-array String 0))]
           (is (= :atomic-publication-unsupported (reason #(pcapng/write-pcapng! (base-events) output))))
           (is (not (Files/exists output (make-array java.nio.file.LinkOption 0))))
           (with-open [entries (Files/list (.getPath fs "/" (make-array String 0)))]
             (is (zero? (.count entries))))))))))

(deftest default-active-interface-boundary
  (doseq [n [4096 4097]]
    (temp-call
     (fn [path]
       (let [values (base-events)
             input (concat [(first values)]
                           (map #(assoc-in (nth values 1) [:interface :id] %) (range n)))]
         (if (= 4096 n)
           (is (= 4097 (:blocks-written (pcapng/write-pcapng! input path))))
           (do (is (= :limit-exceeded (reason #(pcapng/write-pcapng! input path))))
               (is (not (exists? path)))))
         (is (empty? (temps path))))))))
