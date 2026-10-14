(ns paclo.pcap-roundtrip-test
  (:require
   [clojure.java.io :as io]
   [clojure.test :refer [deftest is testing]]
   [paclo.core :as core]
   [paclo.pcap :as p])
  (:import
   [java.io File]
   [java.nio ByteBuffer ByteOrder]
   [java.nio.file Files]))

(def ^:private fixture "test/resources/metadata-roundtrip.pcap")

(defn- comparable [packet]
  (update (select-keys packet [:ts-sec :ts-usec :caplen :len :bytes]) :bytes vec))

(defn- expected-record [sec usec caplen len ethertype marker]
  {:ts-sec sec :ts-usec usec :caplen caplen :len len
   :bytes (vec (concat (range 12) [(quot (long ethertype) 256) (mod (long ethertype) 256)]
                       (repeat (- (long caplen) 14) marker)))})

(def ^:private expected
  [(expected-record 0 0 60 60 0x0800 1)
   (expected-record 1700000000 123456 60 60 0x0806 2)
   (expected-record 1700000001 654321 42 1500 0x0800 3)
   (expected-record 2147483647 999999 60 4294967295 0x0800 4)])

(defn- read-records [path & [opts]]
  (mapv comparable (core/packets (merge {:path path :max Long/MAX_VALUE} opts))))

(defn- binary-records
  "Parse serialized PCAP headers without using Paclo's reader or libpcap."
  [^File file]
  (let [buffer (ByteBuffer/wrap (Files/readAllBytes (.toPath file)))
        _ (.order buffer ByteOrder/LITTLE_ENDIAN)
        magic (.getInt buffer)
        _ (.order buffer (if (= (unchecked-int 0xa1b2c3d4) magic)
                           ByteOrder/LITTLE_ENDIAN ByteOrder/BIG_ENDIAN))
        uint32 (fn [] (Integer/toUnsignedLong (.getInt buffer)))]
    (is (contains? #{(unchecked-int 0xa1b2c3d4) (unchecked-int 0xd4c3b2a1)} magic))
    (is (= 2 (.getShort buffer)))
    (is (= 4 (.getShort buffer)))
    (.position buffer 16)
    (is (= 65536 (uint32)))
    (is (= 1 (uint32)))
    (loop [records []]
      (if (.hasRemaining buffer)
        (let [sec (uint32) usec (uint32) caplen (uint32) len (uint32)
              bytes (byte-array caplen)]
          (.get buffer bytes)
          (recur (conj records {:ts-sec sec :ts-usec usec :caplen caplen :len len
                                :bytes (vec bytes)})))
        records))))

(deftest independent-fixture-read-filter-write-read
  (let [out (File/createTempFile "paclo-metadata-" ".pcap")
        retained (mapv expected [0 2 3])]
    (try
      (testing "known binary fixture independently agrees with libpcap reader"
        (is (= expected (binary-records (io/file fixture))))
        (is (= expected (read-records fixture))))
      (testing "BPF filtering keeps ordered original packet maps, including truncation"
        (let [packets (core/packets {:path fixture :filter "ip" :max Long/MAX_VALUE})]
          (core/write-pcap! packets (.getAbsolutePath out)))
        (is (= retained (binary-records out)))
        (is (= retained (read-records (.getAbsolutePath out)))))
      (testing "Clojure filtering also writes read packet maps directly"
        (core/write-pcap!
         (core/packets {:path fixture :xform (filter #(< (long (:caplen %)) (long (:len %))))})
         (.getAbsolutePath out))
        (is (= (subvec expected 2) (binary-records out)))
        (is (= (subvec expected 2) (read-records (.getAbsolutePath out)))))
      (finally (.delete out)))))

(deftest public-writer-legacy-and-fallback
  (let [out (File/createTempFile "paclo-legacy-" ".pcap")
        bytes (byte-array (range 60))]
    (try
      (with-redefs [p/now-sec-usec (fn [] [123 456])]
        (core/write-pcap! [bytes {:bytes bytes} {:bytes bytes :sec 99}
                           {:bytes bytes :sec 0 :usec 999999}
                           {:bytes bytes :ts-sec 10 :ts-usec 20 :sec 30 :usec 40}]
                          (.getAbsolutePath out)))
      (let [records (binary-records out)]
        (is (= [[123 456] [123 456] [123 456] [0 999999] [10 20]]
               (mapv (juxt :ts-sec :ts-usec) records)))
        (is (every? #(= [60 60] ((juxt :caplen :len) %)) records))
        (is (every? #(= (vec bytes) (:bytes %)) records))
        (is (= records (read-records (.getAbsolutePath out)))))
      (finally (.delete out)))))

(deftest serialized-seconds-do-not-overflow
  (let [out (File/createTempFile "paclo-seconds-" ".pcap")]
    (try
      (core/write-pcap! [{:bytes (byte-array 0) :ts-sec 4294967295 :ts-usec 999999}]
                        (.getAbsolutePath out))
      ;; Check file bits independently: older native readers sign-extend seconds.
      (is (= [{:ts-sec 4294967295 :ts-usec 999999 :caplen 0 :len 0 :bytes []}]
             (binary-records out)))
      (finally (.delete out)))))

(deftest invalid-input-leaves-readable-empty-file
  (let [out (File/createTempFile "paclo-invalid-" ".pcap")]
    (try
      (doseq [packet [{:bytes [1 2]} {:bytes (byte-array 2) :caplen 1}
                      {:bytes (byte-array 2) :len 1}
                      {:bytes (byte-array 2) :ts-sec 1}]]
        (is (thrown? clojure.lang.ExceptionInfo
                     (core/write-pcap! [packet] (.getAbsolutePath out))))
        ;; A failed write still closes/flushed the dumper and leaves a valid empty PCAP.
        (is (= [] (binary-records out)))
        (is (= [] (read-records (.getAbsolutePath out)))))
      (finally (.delete out)))))

(defn- serialized-snaplen [^File file]
  (let [buffer (ByteBuffer/wrap (Files/readAllBytes (.toPath file)))
        _ (.order buffer ByteOrder/LITTLE_ENDIAN)
        magic (.getInt buffer)]
    (.order buffer (if (= (unchecked-int 0xa1b2c3d4) magic)
                     ByteOrder/LITTLE_ENDIAN ByteOrder/BIG_ENDIAN))
    (Integer/toUnsignedLong (.getInt buffer 16))))

(deftest single-dlt-framing-and-snaplen-validation
  (let [out (File/createTempFile "paclo-framing-" ".pcap")
        good {:bytes (byte-array [1 2]) :linktype 1 :ts-sec 0 :ts-usec 0}]
    (try
      (doseq [invalid [(assoc good :linktype 113) (assoc good :linktype nil)
                       (assoc good :linktype -1) (assoc good :linktype 1.0)
                       (assoc good :linktype "1") (assoc good :linktype 2147483648N)
                       (assoc good :bytes (byte-array 3))]]
        (is (thrown? clojure.lang.ExceptionInfo
                     (core/write-pcap! (map identity [good invalid good])
                                       (.getPath out) {:snaplen 2})))
        (is (= [(comparable (assoc good :caplen 2 :len 2))]
               (read-records (.getPath out)))))
      (testing "missing metadata trusts the explicit DLT; bytes stay unchanged"
        (with-redefs [p/now-sec-usec (fn [] [0 0])]
          (core/write-pcap! [(byte-array [1 2]) (dissoc good :linktype)]
                            (.getPath out) {:linktype 113 :snaplen 2}))
        (is (= 2 (serialized-snaplen out)))
        (let [saved (core/reduce-packets {:path (.getPath out)} conj [])]
          (is (= [113 113] (mapv :linktype saved)))
          (is (= [[1 2] [1 2]] (mapv (comp vec :bytes) saved)))))
      (testing "zero input still writes a readable header with the selected native DLT"
        (core/write-pcap! [] (.getPath out) {:linktype 113 :snaplen 1})
        (is (= 1 (serialized-snaplen out)))
        (is (empty? (read-records (.getPath out))))
        (p/with-pcap [handle (p/open-offline (.getPath out))]
          (is (= 113 (p/datalink handle)))))
      (testing "unsupported native DLT fails to open a dumper"
        (is (thrown-with-msg? clojure.lang.ExceptionInfo #"pcap_dump_open failed"
                              (core/write-pcap! [] (.getPath out) {:linktype 999999}))))
      (finally (.delete out)))))

(deftest lazy-source-exception-keeps-written-prefix
  (let [out (File/createTempFile "paclo-source-failure-" ".pcap")
        packet {:bytes (byte-array 2) :ts-sec 123 :ts-usec 456}
        error (Exception. "source failed")
        packets (cons packet (lazy-seq (throw error)))]
    (try
      (is (identical? error (try (core/write-pcap! packets (.getPath out))
                                 (catch Throwable failure failure))))
      (is (= [(comparable (assoc packet :caplen 2 :len 2))]
             (read-records (.getPath out))))
      (finally (.delete out)))))

(deftest native-output-errors-are-observable
  (let [directory (.toFile (Files/createTempDirectory "paclo-output-error-"
                                                      (make-array java.nio.file.attribute.FileAttribute 0)))]
    (try
      (is (thrown-with-msg? clojure.lang.ExceptionInfo #"pcap_dump_open failed"
                            (core/write-pcap! [] (.getPath directory))))
      (finally (.delete directory))))
  ;; Linux offers a deterministic real flush failure, without filling a disk.
  (when (.exists (File. "/dev/full"))
    (doseq [size [64 8192 65536]]
      (testing (str "native output failure with " size " captured bytes")
        (let [error (try (core/write-pcap! [(byte-array size)] "/dev/full")
                         (catch clojure.lang.ExceptionInfo error error))
              data (ex-data error)]
          (is (= {:reason :pcap-write-failed :phase :pcap-dump-flush}
                 (select-keys data [:reason :phase])))
          (is (or (= -1 (:rc data)) (pos? (long (or (:stdio-error data) 0))))))))))
