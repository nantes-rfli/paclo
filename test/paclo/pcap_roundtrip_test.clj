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
