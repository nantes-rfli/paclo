(ns paclo.capture-format-test
  "P08-A characterization: native acceptance is distinct from public preservation."
  (:require
   [clojure.data.json :as json]
   [clojure.edn :as edn]
   [clojure.java.shell :as shell]
   [clojure.test :refer [deftest is testing]]
   [paclo.core :as core]
   [paclo.pcap :as pcap])
  (:import
   [java.io Closeable File]
   [java.nio.file Files]
   [jnr.ffi.byref PointerByReference]
   [paclo.jnr PcapLibrary]))

(def ^:private directory "test/resources/capture-formats/")
(def ^:private cases (json/read-str (slurp (str directory "manifest.json")) :key-fn keyword))
(def ^:private ^PcapLibrary native PcapLibrary/INSTANCE)

(defn- hex [^bytes data]
  (.formatHex (java.util.HexFormat/of) data))

(defn- record-data [packet]
  (assoc (select-keys packet [:ts-sec :ts-usec :caplen :len]) :hex (hex (:bytes packet))))

(defn- options [path]
  {:path path :max 100 :max-time-ms 10000})

(defn- native-inventory [path]
  (try
    (let [handle (pcap/open-offline path)
          header (PointerByReference.)
          data (PointerByReference.)]
      (try
        (let [dlt (pcap/datalink handle)]
          (loop [packets []]
            ;; Bound even a broken reader; all fixtures have at most two records.
            (if (= 10 (count packets))
              {:terminal "limit" :packets packets :linktype dlt}
              (let [rc (.pcap_next_ex native handle header data)]
                (if (= 1 rc)
                  (recur (conj packets (#'pcap/read-packet (.getValue header) (.getValue data) dlt)))
                  {:terminal (if (= -2 rc) "eof" "error") :rc rc
                   :err (.pcap_geterr native handle) :packets packets :linktype dlt})))))
        (finally (pcap/close! handle))))
    (catch clojure.lang.ExceptionInfo error
      {:terminal "open-error" :err (:err (ex-data error)) :packets []})))

(deftest native-format-inventory
  (println "P08-A environment"
           (pr-str {:os (System/getProperty "os.name") :os-version (System/getProperty "os.version")
                    :arch (System/getProperty "os.arch") :jdk (System/getProperty "java.version")
                    :libpcap (.pcap_lib_version native)}))
  (doseq [{:keys [file linktype records terminal error-pattern]} cases]
    (testing file
      (let [result (native-inventory (str directory file))
            ;; LINKTYPE_RAW 101 maps to DLT_RAW 12 on the supported Linux/macOS matrix.
            expected-dlt (if (= "raw" linktype)
                           12
                           linktype)]
        (println "P08-A native" file (pr-str (select-keys result [:terminal :rc :err :linktype])))
        (is (= terminal (:terminal result)))
        (is (= records (mapv record-data (:packets result))))
        (when-not (= "open-error" terminal)
          (is (= expected-dlt (:linktype result))))
        (when error-pattern
          (is (string? (:err result)))
          (is (re-find (re-pattern error-pattern) (or (:err result) ""))))))))

(deftest public-raw-and-decode-capabilities
  (doseq [{:keys [file records terminal linktype]} cases
          :when (= "eof" terminal)]
    (testing file
      (let [packets (core/reduce-packets (options (str directory file)) conj [])
            snapshots (mapv record-data packets)]
        (is (= records snapshots))
        (doseq [packet packets]
          (is (= #{:bytes :ts-sec :ts-usec :caplen :len :linktype} (set (keys packet))))
          (is (identical? packet (first (into [] (core/packet-xf {}) [packet]))))
          (doseq [config [{:decode? true :extensions []} {:decode-mode :flow}]]
            (let [result (first (into [] (core/packet-xf config) [packet]))]
              (if (contains? #{1 113 276 "raw"} linktype)
                (if (= "truncated.pcapng" file)
                  (is (:decode-error result))
                  (is (nil? (:decode-error result))))
                (do
                  (is (= "unsupported linktype" (:decode-error result)))
                  (is (= :unsupported-linktype (-> result :diagnostics first :reason)))))
              (when (:decode? config)
                (is (identical? (:bytes packet) (:bytes result))))))
          (is (= snapshots (mapv record-data packets))))))))

(defn- caught [f]
  (try (f) nil (catch clojure.lang.ExceptionInfo error error)))

(defn- assert-read-error [data]
  (is (= {:reason :pcap-read-failed :phase :pcap-next-ex :rc -1}
         (select-keys data [:reason :phase :rc])))
  (is (string? (:native-error data))))

(defn- assert-terminal-stats [stats failed?]
  (is (= 1 (:schema-version stats)))
  (is (= (if failed? :failed :closed) (:state stats)))
  (is (= (if failed? :error :eof) (:stop-reason stats)))
  (is (= stats (edn/read-string (pr-str stats))))
  (if failed?
    (assert-read-error (:error stats))
    (is (nil? (:error stats)))))

(defn- assert-public-pass [opts records failed?]
  (let [errors (atom [])
        config (assoc opts :error-mode :pass :on-error #(swap! errors conj %))
        report (core/reduce-packets-report config conj [])]
    (is (= records (mapv record-data (:result report))))
    (is (= records (mapv record-data (core/reduce-packets config conj []))))
    (is (= records (mapv record-data (core/packets config))))
    (assert-terminal-stats (:stats report) failed?)
    (with-open [^Closeable capture (core/start-capture config)]
      (is (= records (mapv record-data (core/capture-packets capture))))
      (assert-terminal-stats (core/capture-stats capture) failed?))
    (is (= (if failed? 4 0) (count @errors)))
    (doseq [error @errors] (assert-read-error (ex-data error)))))

(defn- assert-public-throw [opts]
  (let [errors (atom [])
        config (assoc opts :on-error #(swap! errors conj %))]
    (doseq [run [#(core/reduce-packets % conj [])
                 #(core/reduce-packets-report % conj [])
                 #(dorun (core/packets %))]]
      (assert-read-error (ex-data (caught #(run config)))))
    (with-open [^Closeable capture (core/start-capture config)]
      (assert-read-error (ex-data (caught #(dorun (core/capture-packets capture)))))
      (assert-terminal-stats (core/capture-stats capture) true))
    (is (= 4 (count @errors)))
    (doseq [error @errors] (assert-read-error (ex-data error)))))

(deftest public-terminal-contract-for-all-fixtures
  (is (= 28 (count cases)))
  (doseq [{:keys [file records terminal]} cases]
    (testing file
      (let [opts (assoc (options (str directory file)) :queue-cap 1)]
        (case terminal
          "open-error"
          ;; Open failures stay synchronous even under :pass.
          (doseq [mode [:throw :pass]
                  run [#(core/reduce-packets % conj [])
                       #(core/reduce-packets-report % conj [])
                       core/packets core/start-capture]]
            (is (= :pcap-open-failed
                   (:reason (ex-data (caught #(run (assoc opts :error-mode mode))))))))
          "error"
          (do (assert-public-pass opts records true)
              (assert-public-throw opts))
          "eof"
          (do (assert-public-pass opts records false)
              (let [report (core/reduce-packets-report opts conj [])]
                (is (= records (mapv record-data (:result report))))
                (assert-terminal-stats (:stats report) false))
              (is (= records (mapv record-data (core/packets opts))))
              (with-open [^Closeable capture (core/start-capture opts)]
                (is (= records (mapv record-data (core/capture-packets capture))))
                (assert-terminal-stats (core/capture-stats capture) false))))))))

(deftest prefix-stops-before-unread-native-error
  (let [opts (options (str directory "multi-linktype.pcapng"))]
    (doseq [[config rf expected] [[opts (fn [result packet] (reduced (conj result packet))) :reduced]
                                  [(assoc opts :stop? (constantly true)) conj :predicate]
                                  [(assoc opts :max 1) conj :max-packets]]]
      (let [report (core/reduce-packets-report config rf [])]
        (is (= 1 (count (:result report))))
        (is (= expected (get-in report [:stats :stop-reason])))
        (is (nil? (get-in report [:stats :error])))))
    (is (= 1 (count (core/packets (assoc opts :stop? (constantly true) :queue-cap 1)))))
    (with-open [^Closeable capture (core/start-capture (assoc opts :stop? (constantly true) :queue-cap 1))]
      (is (= 1 (count (core/capture-packets capture))))
      (is (= :predicate (:stop-reason (core/capture-stats capture)))))))

(deftest public-writer-conversion-contract-for-all-fixtures
  (is (= 28 (count cases)))
  (doseq [{:keys [file records terminal]} cases]
    (testing file
      (let [path (str directory file)
            dlt (or (:linktype (native-inventory path)) 1)
            ^File output (File/createTempFile "paclo-p08-" ".pcapng")]
        (try
          ;; Delay source acquisition until the writer owns its resources.
          (let [packets (lazy-seq (core/packets (options path)))
                run #(core/write-pcap! packets (.getPath output) {:linktype dlt})]
            (if (and (= "eof" terminal) (not= "invalid-original-length.pcapng" file))
              (is (nil? (run)))
              (is (instance? clojure.lang.ExceptionInfo (caught run)))))
          (let [encoded (Files/readAllBytes (.toPath output))
                restored (core/reduce-packets (options (.getPath output)) conj [])]
            (is (contains? #{"d4c3b2a1" "a1b2c3d4"} (hex (byte-array (take 4 encoded)))))
            (is (= (if (= "invalid-original-length.pcapng" file) [] records)
                   (mapv record-data restored)))
            ;; Native DLT, not the savefile's numeric LINKTYPE_RAW.
            (is (= dlt (:linktype (native-inventory (.getPath output)))))
            (is (every? #(= dlt (:linktype %)) restored)))
          (finally (.delete output)))))))

(deftest public-single-native-dlt-roundtrips
  (doseq [source ["ethernet.pcap" "sll2.pcap" "raw.pcap" "loop.pcap"
                  "../linktype-sll.pcap" "../linktype-null.pcap"]]
    (testing source
      (let [packets (core/reduce-packets (options (str directory source)) conj [])
            ^File output (File/createTempFile "paclo-p08-dlt-" ".pcap")
            dlt (:linktype (first packets))]
        (try
          (core/write-pcap! (map identity packets) (.getPath output)
                            {:linktype dlt :snaplen (apply max (map :caplen packets))})
          (let [restored (core/reduce-packets (options (.getPath output)) conj [])]
            (is (= (mapv record-data packets) (mapv record-data restored)))
            (is (= (mapv :linktype packets) (mapv :linktype restored))))
          (when-not (= 1 dlt)
            (is (= :linktype-mismatch
                   (:reason (ex-data (caught #(core/write-pcap! packets (.getPath output)))))))
            (is (empty? (core/reduce-packets (options (.getPath output)) conj []))))
          (finally (.delete output)))))))

(deftest fixtures-and-native-precision-are-reproducible
  (doseq [command [["python3" "test/resources/make_capture_format_fixtures.py" "--check"]
                   ["python3" "test/resources/probe_capture_precision.py"]]]
    (let [{:keys [exit out err]} (apply shell/sh command)]
      (println out)
      (is (= 0 exit) (str command "\n" err)))))

(deftest accepted-invalid-original-length-is-rejected-by-writer
  (let [packets (core/reduce-packets (options (str directory "invalid-original-length.pcapng")) conj [])
        ^File output (File/createTempFile "paclo-p08-invalid-len-" ".pcap")]
    (try
      (is (= [[64 1]] (mapv (juxt :caplen :len) packets)))
      (is (thrown-with-msg? clojure.lang.ExceptionInfo #":len must be >= :caplen"
                            (core/write-pcap! packets (.getPath output))))
      (finally (.delete output)))))
