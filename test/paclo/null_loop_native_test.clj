(ns paclo.null-loop-native-test
  "Pre-decoder installed-libpcap evidence; compare physical bytes with native and public reads."
  (:require
   [clojure.data.json :as json]
   [clojure.java.shell :as shell]
   [clojure.test :refer [deftest is testing]]
   [paclo.core :as core]
   [paclo.pcap :as pcap])
  (:import
   [java.nio ByteBuffer ByteOrder]
   [java.nio.file Files Paths]
   [jnr.ffi Pointer]
   [jnr.ffi.byref PointerByReference]
   [paclo.jnr PcapHeader PcapLibrary]))

(def directory "test/resources/null-loop/")
(def cases (json/read-str (slurp (str directory "manifest.json")) :key-fn keyword))
(def ^:private ^PcapLibrary native PcapLibrary/INSTANCE)

(defn hex [^bytes data] (.formatHex (java.util.HexFormat/of) data))

(defn stored-hex [{:keys [file container-order]}]
  (let [bytes (Files/readAllBytes (Paths/get (str directory file) (make-array String 0)))
        buffer (doto (ByteBuffer/wrap bytes)
                 (.order (if (= "<" container-order) ByteOrder/LITTLE_ENDIAN ByteOrder/BIG_ENDIAN)))
        ng? (.endsWith ^String file "pcapng")]
    (loop [offset (if ng? 0 24) packets []]
      (if (= offset (alength bytes)) packets
          (let [kind (when ng? (.getInt buffer offset))
                size (if ng? (.getInt buffer (+ offset 4)) (+ 16 (.getInt buffer (+ offset 8))))
                start (+ offset (if ng? 28 16))
                caplen (if ng? (when (= kind 6) (.getInt buffer (+ offset 20))) (- size 16))]
            (recur (+ offset size)
                   (if caplen
                     (conj packets (hex (java.util.Arrays/copyOfRange bytes start (+ start caplen))))
                     packets)))))))

(defn native-hex [path]
  (let [handle (pcap/open-offline path)
        header (PointerByReference.) data (PointerByReference.)]
    (try
      (loop [packets []]
        (when (> (count packets) 100) (throw (ex-info "probe limit exceeded" {})))
        (let [rc (.pcap_next_ex native handle header data)]
          (if (= 1 rc)
            (let [bytes (byte-array (PcapHeader/caplen (.getValue header)))]
              (.get ^Pointer (.getValue data) 0 bytes 0 (alength bytes))
              (recur (conj packets (hex bytes))))
            {:rc rc :linktype (pcap/datalink handle) :hex packets})))
      (finally (pcap/close! handle)))))

(deftest installed-libpcap-cross-endian-bytes
  (println "P08-D2 environment"
           (pr-str {:os (System/getProperty "os.name") :os-version (System/getProperty "os.version")
                    :arch (System/getProperty "os.arch") :jdk (System/getProperty "java.version")
                    :host-order (str (ByteOrder/nativeOrder)) :libpcap (.pcap_lib_version native)}))
  (doseq [{:keys [file linktype records] :as fixture} cases]
    (testing file
      (let [stored (stored-hex fixture)
            direct (native-hex (str directory file))
            raw (core/reduce-packets {:path (str directory file)} conj [])
            expected (mapv :hex records)]
        (is (= expected stored (:hex direct) (mapv #(hex (:bytes %)) raw)))
        (is (= -2 (:rc direct)))
        (is (= linktype (:linktype direct)))
        (is (every? #(= linktype (:linktype %)) raw))
        (println "P08-D2 native" file
                 (pr-str {:records (count stored) :native-dlt (:linktype direct)
                          :stored=native=raw (= expected stored (:hex direct) (mapv #(hex (:bytes %)) raw))
                          :pseudoheaders (vec (distinct (map #(subs % 0 (min 8 (count %))) stored)))}))))))

(deftest deterministic-null-loop-fixtures
  (let [{:keys [exit out err]} (shell/sh "python3" "test/resources/make_null_loop_fixtures.py" "--check")]
    (is (zero? exit) (str out err))))
