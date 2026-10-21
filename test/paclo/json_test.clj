(ns paclo.json-test
  (:require
   [clojure.data.json :as json]
   [clojure.edn :as edn]
   [clojure.java.io :as io]
   [clojure.string :as str]
   [clojure.test :refer [deftest is testing]]
   [examples.common :as common]
   [paclo.dev.perf-merge :as perf-merge])
  (:import
   [java.io
    EOFException
    PushbackReader
    StringReader
    StringWriter]))

(deftest json-number-types-and-round-trips
  (doseq [[text expected expected-class]
          [["0" 0 Long] ["-0" 0 Long]
           ["9223372036854775807" Long/MAX_VALUE Long]
           ["-9223372036854775808" Long/MIN_VALUE Long]
           ["9223372036854775808" 9223372036854775808N clojure.lang.BigInt]
           ["1.25" 1.25 Double] ["1e3" 1000.0 Double]
           ["1.25e-3" 0.00125 Double]]]
    (testing text
      (let [value (json/read-str text)]
        (is (= expected value))
        (is (= expected-class (class value)))
        (is (= value (json/read-str (json/write-str value)))))))
  (is (= 1.234567890123456789M
         (json/read-str "1.234567890123456789" :bigdec true)))
  (is (instance? BigDecimal (json/read-str "1.25" :bigdec true)))
  (is (= {"missing" nil "enabled" false "rows" [true 1 "dns"]}
         (json/read-str (json/write-str {:missing nil :enabled false :rows [true 1 "dns"]})))))

(deftest json-unicode-escaping-and-reader-writer-parity
  (doseq [text ["" "plain" "日本語 café 😀" "é" "quote\" slash/ backslash\\"
                (apply str (map char (range 32)))]]
    (let [encoded (json/write-str text)
          writer (StringWriter.)]
      (json/write text writer)
      (is (= encoded (str writer)))
      (is (not-any? #(< (int %) 32) encoded))
      (is (= text (json/read-str encoded)))
      (with-open [reader (StringReader. encoded)]
        (is (= text (json/read reader))))))
  (is (= "日本語 😀\b\f\n\r\t\"\\/"
         (json/read-str "\"\\u65e5\\u672c\\u8a9e \\ud83d\\ude00\\b\\f\\n\\r\\t\\\"\\\\\\/\""))))

(deftest repeated-numeric-reads-preserve-eof
  ;; Upstream 2.5.0 unread -1 into the caller's reader after a number at EOF.
  (doseq [text ["0" "-1" "9223372036854775808" "1.25" "1e3"]]
    (with-open [reader (PushbackReader. (StringReader. text) 64)]
      (is (= (json/read-str text) (json/read reader)))
      (dotimes [_ 2]
        (is (= ::eof (json/read reader :eof-error? false :eof-value ::eof))))))
  (with-open [reader (PushbackReader. (StringReader. "1 null false 2.5") 64)]
    (is (= [1 nil false 2.5 ::eof]
           (vec (repeatedly 5 #(json/read reader :eof-error? false :eof-value ::eof)))))))

(deftest empty-truncated-and-malformed-json-diagnostics
  (doseq [[text message] [["" "JSON error (end-of-file)"]
                          [" \n\t" "JSON error (end-of-file)"]
                          ["[" "JSON error (EOF in array)"]
                          ["{" "JSON error (EOF in object)"]
                          ["\"" "JSON error (end-of-file inside string)"]]]
    (let [error (try (json/read-str text) (catch EOFException e e))]
      (is (instance? EOFException error))
      (is (= message (ex-message error)))))
  (doseq [text ["" " \n\t"]]
    (is (= ::eof (json/read-str text :eof-error? false :eof-value ::eof))))
  (doseq [text ["01" "-" "1." "[1,]" "{\"x\":}"]]
    (is (thrown-with-msg? Exception #"JSON error" (json/read-str text))))
  (doseq [[text message] [["\"\\q\"" "No matching clause: 113"]
                          ["1e" "No matching clause: -1"]]]
    (let [error (try (json/read-str text) (catch IllegalArgumentException e e))]
      (is (instance? IllegalArgumentException error))
      (is (= message (ex-message error)))))
  ;; Keep the existing default single-value reader policy; Paclo adds no parser.
  (is (= true (json/read-str "true false"))))

(deftest control-characters-report-the-offending-character
  ;; Whitespace remains valid; other raw controls outside strings are not EOF.
  (doseq [code (remove #{9 10 13} (range 32))
          [prefix suffix] [["" ""] ["[" "]"] ["{\"x\":" "}"]]]
    (let [text (str prefix (char code) suffix)
          error (try (json/read-str text) (catch Exception e e))]
      (is (= Exception (class error)))
      (is (= (str "JSON error (unexpected character): " (char code))
             (ex-message error))))))

(deftest cli-jsonl-retains-line-framing-null-and-escaping
  (let [row (array-map :qname "日本語\n\"\\😀" :count 4 :rtt-ms 0.125 :missing nil)
        expected "{\"qname\":\"\\u65e5\\u672c\\u8a9e\\n\\\"\\\\\\ud83d\\ude00\",\"count\":4,\"rtt-ms\":0.125,\"missing\":null}\n"
        output (with-out-str (common/emit :jsonl [row row]))]
    (is (= (str expected expected) output))
    (is (= [row row] (mapv #(json/read-str % :key-fn keyword) (str/split-lines output)))))
  (is (= "{\"value\":false}\n" (with-out-str (common/emit :jsonl false))))
  (is (= "{\"value\":null}\n" (with-out-str (common/emit :jsonl nil)))))

(deftest performance-report-json-and-edn-retain-values
  (let [dir (.toFile (java.nio.file.Files/createTempDirectory
                      "paclo-json-report" (make-array java.nio.file.attribute.FileAttribute 0)))
        report (array-map :schema-version 2 :profile :quick :live nil
                          :offline [{:scenario :full-reduce :path "日本語\n.pcap"
                                     :runs [{:packets 50000 :bytes 3200000 :decode-errors 0
                                             :elapsed-ns 9223372036854775808N
                                             :queue-drop-rate 0.0}]}])]
    (try
      (let [{:keys [edn json]} (perf-merge/write-results! (str dir) report)
            text (slurp json)
            decoded (json/read-str text :key-fn keyword)]
        (is (= report (edn/read-string (slurp edn))))
        (is (str/ends-with? text "\n"))
        (is (= 1 (count (str/split-lines text))))
        (is (= (-> report (assoc :profile "quick")
                   (assoc-in [:offline 0 :scenario] "full-reduce")) decoded))
        (is (instance? clojure.lang.BigInt (get-in decoded [:offline 0 :runs 0 :elapsed-ns]))))
      (finally
        (doseq [^java.io.File file (reverse (file-seq (io/file dir)))] (.delete file))))))
