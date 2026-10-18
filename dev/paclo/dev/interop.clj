(ns paclo.dev.interop
  "P16 integration assertions against freshly generated external-tool captures."
  (:require
   [clojure.data.json :as json]
   [clojure.java.io :as io]
   [clojure.test :refer [deftest is run-tests testing]]
   [clojure.walk :as walk]
   [distribution-consumer.consumer :as consumer]
   [paclo.core :as core]
   [paclo.pcapng :as pcapng])
  (:import
   [java.io File]
   [java.nio.file Files]
   [java.nio.file.attribute FileAttribute]))

(def ^:dynamic *directory* nil)
(def ^:dynamic *manifest* nil)
(def ^:dynamic *outputs* nil)

(defn- path [file] (str (io/file *directory* file)))
(defn- hex [^bytes data] (.formatHex (java.util.HexFormat/of) data))
(defn- snapshot [packet]
  (assoc (select-keys packet [:ts-sec :ts-usec :caplen :len :linktype])
         :hex (hex (:bytes packet))))
(defn- packet-records [records]
  (mapv #(dissoc % :section-id :interface-id :ticks) records))
(defn- source-events [file]
  (with-open [source (pcapng/open-source {:path (path file)})]
    (let [result (into [] source)]
      (is (= {:state :closed :terminal :eof}
             (select-keys (pcapng/source-info source) [:state :terminal])))
      result)))
(defn- semantic [value]
  (walk/postwalk
   (fn [v]
     (cond
       (bytes? v) (vec v)
       (and (map? v) (:type v)) (dissoc v :file-offset :block-index)
       (and (map? v) (contains? v :section-length)) (assoc v :section-length nil)
       :else v)) value))
(defn- failure [f] (try (f) nil (catch clojure.lang.ExceptionInfo e e)))
(defn- report-output! [source file records & [preserve]]
  (swap! *outputs* conj {:source source :file file :records (packet-records records)
                         :preserve (boolean preserve)}))

(deftest external-native-path
  (doseq [{:keys [file records native prefix]} (:cases *manifest*)]
    (testing file
      (let [config {:path (path file) :error-mode :pass}
            report (core/reduce-packets-report config conj [])
            expected (packet-records (if (= "error" native) (take prefix records) records))]
        (println "P16 native" file (pr-str (select-keys (:stats report) [:stop-reason :error])))
        (is (= expected (mapv snapshot (:result report))))
        (is (= (keyword native) (get-in report [:stats :stop-reason])))
        (if (= "error" native)
          (do
            (is (= :pcap-read-failed (get-in report [:stats :error :reason])))
            (is (= :pcap-read-failed
                   (:reason (ex-data (failure #(core/reduce-packets
                                                {:path (path file)} conj [])))))))
          (do
            (is (nil? (get-in report [:stats :error])))
            ;; Exercise actual BPF evaluation through Paclo's loaded libpcap.
            (doseq [[filter-expr expected-records] [["udp dst port 53" expected]
                                                    ["udp dst port 54" []]]]
              (let [filtered (core/reduce-packets-report
                              (assoc config :filter filter-expr) conj [])]
                (is (= expected-records (mapv snapshot (:result filtered))))
                (is (= :eof (get-in filtered [:stats :stop-reason])))))
            (let [output (str "native-" file ".pcap")
                  packets (:result report)
                  dlt (:linktype (first packets))
                  snaplen (apply max (map :caplen packets))]
              (core/write-pcap! packets (path output) {:linktype dlt :snaplen snaplen})
              (is (= expected (mapv snapshot (core/reduce-packets {:path (path output)} conj []))))
              (report-output! file output records))))))))

(deftest external-metadata-path-and-preserving-writer
  (doseq [{:keys [file records pcapng]} (:cases *manifest*) :when pcapng]
    (testing file
      (let [events (source-events file)
            packets (mapv :packet (filter :packet events))
            output (str "preserve-" file)]
        (is (= (packet-records records) (mapv snapshot packets)))
        (is (= (mapv #(select-keys % [:section-id :interface-id]) records)
               (mapv #(select-keys (:pcapng %) [:section-id :interface-id]) packets)))
        (is (= (mapv #(bigint (:ticks %)) records)
               (mapv #(get-in % [:pcapng :timestamp :ticks]) packets)))
        (with-open [source (pcapng/open-source {:path (path file)})]
          (let [report (pcapng/write-pcapng! source (path output))]
            (is (= {:status :complete :fidelity :known-semantics :loss-counts {}}
                   (select-keys report [:status :fidelity :loss-counts])))))
        (is (= (semantic events) (semantic (source-events output))))
        (report-output! file output records true)))))

(deftest explicit-loss-and-authoring
  (let [file "comments.pcapng"
        original (source-events file)
        comments (filter #(= 1 (:code %))
                         (mapcat #(or (get-in % [:section :options])
                                      (get-in % [:interface :options])
                                      (get-in % [:packet :pcapng :options])) original))
        packet-comments (mapv #(String. ^bytes (:value %) java.nio.charset.StandardCharsets/UTF_8)
                              (filter #(= 1 (:code %))
                                      (get-in (first (filter :packet original)) [:packet :pcapng :options])))
        output "lossy-comments.pcapng"]
    (is (= ["first comment" "second comment"] packet-comments))
    (with-open [source (pcapng/open-source {:path (path file)})]
      (let [report (pcapng/write-pcapng! source (path output) {:mode :lossy :drop #{:comments}})]
        (is (= :explicit-loss (:fidelity report)))
        (is (= {:comments (count comments)} (:loss-counts report)))))
    (let [copied (source-events output)
          drop-comments (fn [v] (if (and (map? v) (vector? (:options v)))
                                  (update v :options #(filterv (fn [o] (not= 1 (:code o))) %)) v))]
      (is (= (walk/postwalk drop-comments (semantic original)) (semantic copied))))
    (report-output! file output (:records (first (filter #(= file (:file %)) (:cases *manifest*))))))
  (let [file "rich.pcapng"
        output "lossy-rich.pcapng"
        events (source-events file)
        records (:records (first (filter #(= file (:file %)) (:cases *manifest*))))
        opaque (count (filter #(= :opaque-block (:type %)) events))]
    (is (= 2 opaque))
    (with-open [source (pcapng/open-source {:path (path file)})]
      (let [report (pcapng/write-pcapng! source (path output)
                                         {:mode :lossy :drop #{:opaque-blocks :unknown-options}})]
        (is (= {:opaque-blocks 2 :unknown-options 3} (:loss-counts report)))))
    (let [expected (walk/postwalk
                    (fn [v] (if (and (map? v) (vector? (:options v)))
                              (update v :options #(filterv (fn [o] (not= 0xf123 (:code o))) %)) v))
                    (filterv #(not= :opaque-block (:type %)) events))]
      (is (= (semantic expected) (semantic (source-events output)))))
    (report-output! file output records)
    (let [authored (str "author-" file)
          values (filterv #(not= :opaque-block (:type %)) events)]
      (is (= :authored (:fidelity (pcapng/write-pcapng! values (path authored) {:mode :author}))))
      (is (= (semantic values) (semantic (source-events authored))))
      (report-output! file authored records))))

(deftest externally-derived-malformed-input-and-publication
  (doseq [{:keys [file reason]} (:malformed *manifest*)]
    (testing file
      (let [report (core/reduce-packets-report {:path (path file) :error-mode :pass} conj [])]
        (is (= 1 (count (:result report))))
        (is (= :error (get-in report [:stats :stop-reason])))
        (is (= :pcap-read-failed (get-in report [:stats :error :reason]))))
      (when reason
        (let [dir (Files/createTempDirectory "paclo-interop-failure-" (make-array FileAttribute 0))
              output (.resolve dir "output.pcapng")]
          (try
            (with-open [source (pcapng/open-source {:path (path file)})]
              (let [error (failure #(pcapng/write-pcapng! source output))]
                (is (= (keyword reason) (:reason (ex-data error))))
                (is (= :error (:terminal (pcapng/source-info source))))))
            (is (empty? (seq (.listFiles (.toFile dir)))))
            (finally (Files/delete dir))))))))

(deftest publication-is-exclusive-and-delayed
  (let [dir (Files/createTempDirectory "paclo-interop-atomic-" (make-array FileAttribute 0))
        output (.resolve dir "output.pcapng")]
    (try
      (with-open [source (pcapng/open-source {:path (path "comments.pcapng")})]
        (pcapng/write-pcapng!
         (eduction (map (fn [event]
                          (is (not (.exists (.toFile output))))
                          event)) source) output))
      (is (= ["output.pcapng"] (mapv #(.getName ^File %) (.listFiles (.toFile dir)))))
      (let [before (vec (Files/readAllBytes output))]
        (with-open [source (pcapng/open-source {:path (path "comments.pcapng")})]
          (is (= :destination-exists
                 (:reason (ex-data (failure #(pcapng/write-pcapng! source output)))))))
        (is (= before (vec (Files/readAllBytes output)))))
      (finally
        (Files/deleteIfExists output)
        (Files/delete dir)))))

(defn -main [directory]
  (try
    (binding [*directory* directory
              *manifest* (json/read-str (slurp (io/file directory "manifest.json")) :key-fn keyword)
              *outputs* (atom [])]
      (let [result (run-tests 'paclo.dev.interop)]
        (spit (path "paclo.json") (json/write-str {:tests result :outputs @*outputs*
                                                   :runtime (consumer/runtime-info)}))
        (when (pos? (+ (:fail result) (:error result)))
          (throw (ex-info "P16 interoperability assertions failed" result)))))
    (finally (shutdown-agents))))
