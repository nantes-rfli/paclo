(ns paclo.capture-format-test
  "P08-A characterization: native acceptance is distinct from public preservation."
  (:require
   [clojure.data.json :as json]
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
              (if (= 1 linktype)
                (if (= "truncated.pcapng" file)
                  (is (:decode-error result))
                  (is (nil? (:decode-error result))))
                (do
                  (is (= "unsupported linktype" (:decode-error result)))
                  (is (= :unsupported-linktype (-> result :diagnostics first :reason)))))
              (when (:decode? config)
                (is (identical? (:bytes packet) (:bytes result))))))
          (is (= snapshots (mapv record-data packets))))))))

(deftest native-read-failures-currently-look-like-public-eof
  ;; Characterizes a known limitation, not the desired P08-B contract.
  (doseq [{:keys [file records terminal]} cases :when (= "error" terminal)]
    (testing file
      (let [path (str directory file)
            report (core/reduce-packets-report (options path) conj [])]
        (is (= records (mapv record-data (:result report))))
        (is (= :eof (get-in report [:stats :stop-reason])))
        (is (nil? (get-in report [:stats :error])))
        (is (= records (mapv record-data (core/packets (options path)))))
        (with-open [^Closeable capture (core/start-capture (options path))]
          (is (= records (mapv record-data (core/capture-packets capture)))))))))

(deftest malformed-open-is-an-exception
  (let [path (str directory "bad-idb-option.pcapng")]
    (is (thrown-with-msg? clojure.lang.ExceptionInfo #"if_tsresol"
                          (core/reduce-packets (options path) conj [])))))

(deftest public-writer-is-classic-ethernet-regardless-of-suffix-or-source
  (doseq [source ["single.pcapng" "multi-interface.pcapng" "nano.pcapng" "truncated.pcapng" "sll2.pcap" "raw.pcap"]]
    (testing source
      (let [packets (core/reduce-packets (options (str directory source)) conj [])
            ^File output (File/createTempFile "paclo-p08-" ".pcapng")]
        (try
          (core/write-pcap! packets (.getPath output))
          (let [encoded (Files/readAllBytes (.toPath output))
                restored (core/reduce-packets (options (.getPath output)) conj [])]
            (is (contains? #{"d4c3b2a1" "a1b2c3d4"} (hex (byte-array (take 4 encoded)))))
            (is (= (mapv record-data packets) (mapv record-data restored)))
            (is (every? #(= 1 (:linktype %)) restored)))
          (finally (.delete output)))))))

(deftest internal-writer-can-use-a-single-native-dlt
  (doseq [source ["sll2.pcap" "raw.pcap" "loop.pcap" "../linktype-sll.pcap" "../linktype-null.pcap"]]
    (let [packets (core/reduce-packets (options (str directory source)) conj [])
          ^File output (File/createTempFile "paclo-p08-dlt-" ".pcap")]
      (try
        (pcap/bytes-seq->pcap! packets {:out (.getPath output) :linktype (:linktype (first packets))})
        (let [restored (core/reduce-packets (options (.getPath output)) conj [])]
          (is (= (mapv record-data packets) (mapv record-data restored)))
          (is (= (mapv :linktype packets) (mapv :linktype restored))))
        (finally (.delete output))))))

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
