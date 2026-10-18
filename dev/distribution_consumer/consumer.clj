(ns distribution-consumer.consumer
  (:require
   [clojure.data.json :as json]
   [clojure.java.io :as io]
   [clojure.string :as str]
   [clojure.walk :as walk]
   [paclo.core :as core]
   [paclo.decode-ext :as decode-ext]
   [paclo.dns :as dns]
   [paclo.flow :as flow]
   [paclo.pcap :as pcap]
   [paclo.pcapng :as pcapng]
   [paclo.proto.dns-ext :as dns-ext]
   [paclo.proto.tls-ext :as tls-ext]
   [paclo.stream :as stream]
   [paclo.window :as window])
  (:import
   [java.io Closeable]
   [java.lang.management ManagementFactory]
   [java.util Properties]
   [paclo.jnr PcapHandle PcapLibrary]))

(defn check! [value context]
  (when-not value (throw (ex-info "Distribution consumer failed" {:check context}))))

(defn read-packets [path opts]
  (core/reduce-packets (merge {:path path :max Long/MAX_VALUE} opts) conj []))

(defn packet-values [packets]
  (mapv #(update % :bytes vec) packets))

(defn semantic [value]
  (walk/postwalk (fn [v]
                   (cond
                     (bytes? v) (vec v)
                     (and (map? v) (:type v)) (dissoc v :file-offset :block-index)
                     (and (map? v) (contains? v :section-length)) (assoc v :section-length nil)
                     :else v)) value))

(defn read-events [path]
  (with-open [source (pcapng/open-source {:path path})]
    (let [events (into [] source)]
      (check! (= :eof (:terminal (pcapng/source-info source))) :pcapng-eof)
      (check! (= :closed (:state (pcapng/source-info source))) :pcapng-closed)
      events)))

;; Diagnostic-only dladdr binding; never part of the published Paclo JAR.
(definterface NativeImageLocator
  (^int dladdr [^jnr.ffi.Pointer address ^jnr.ffi.Pointer info]))

(defn libpcap-image []
  (let [runtime (jnr.ffi.Runtime/getSystemRuntime)
        loaded (first (filter #(some #{"pcap"} (.getLibraryNames %))
                              (jnr.ffi.Runtime/getLoadedLibraries)))
        library (com.kenai.jffi.Library/getCachedInstance
                 (first (.getSuccessfulPaths loaded)) com.kenai.jffi.Library/LAZY)
        address (.getSymbolAddress library "pcap_lib_version")
        locator (-> (jnr.ffi.LibraryLoader/create NativeImageLocator) (.load "c"))
        info (jnr.ffi.Memory/allocateDirect runtime (* 4 (.addressSize runtime)))
        rc (.dladdr ^NativeImageLocator locator (jnr.ffi.Pointer/wrap runtime address) info)]
    (check! (not= 0 rc) :libpcap-image)
    (.getString (.getPointer info 0) 0)))

(defn dependency-version [artifact]
  (with-open [input (io/input-stream (io/resource (str "META-INF/maven/com.github.jnr/"
                                                       artifact "/pom.properties")))]
    (let [properties (doto (Properties.) (.load input))]
      (.getProperty properties "version"))))

(defn runtime-info []
  {:java (into {} (map (fn [key] [key (System/getProperty key)])
                       ["java.version" "java.runtime.version" "java.vendor" "java.vm.name"
                        "java.specification.version" "os.name" "os.version" "os.arch"]))
   :jvm-arguments (vec (.getInputArguments (ManagementFactory/getRuntimeMXBean)))
   :clojure (clojure-version)
   :libpcap-image (libpcap-image)
   :jnr-ffi-version (dependency-version "jnr-ffi")
   :jffi-version (dependency-version "jffi")
   :libpcap-version (.pcap_lib_version PcapLibrary/INSTANCE)
   :native-libraries (mapv (fn [library]
                             {:names (vec (.getLibraryNames library))
                              :paths (vec (.getSuccessfulPaths library))})
                           (jnr.ffi.Runtime/getLoadedLibraries))
   :native-address-bytes (.addressSize (jnr.ffi.Runtime/getSystemRuntime))
   :native-long-bytes (.longSize (jnr.ffi.Runtime/getSystemRuntime))})

(defn write-runtime! [path]
  (spit path (str (json/write-str (runtime-info)) "\n")))

(defn native-check! [path]
  (check! (= 4 (count (read-packets path {:filter "udp port 53"}))) :bpf-match)
  (check! (empty? (read-packets path {:filter "tcp"})) :bpf-no-match)
  (let [failure (try (read-packets path {:filter "udp and ("}) nil
                     (catch IllegalStateException e e))]
    (check! (and failure (str/includes? (ex-message failure) "pcap_compile failed"))
            :bpf-invalid))
  (let [failure (try (PcapHandle/openOffline (str path ".missing")) nil
                     (catch IllegalStateException e e))]
    (check! (and failure (str/includes? (ex-message failure) "pcap_open_offline failed"))
            :failed-open))
  ;; No capture privileges needed; list-devices owns/frees the native linked list.
  (check! (vector? (pcap/list-devices)) :interface-enumeration)
  (prn :native-compatibility-ok (runtime-info)))

(defn verify! []
  ;; Every library resource and binding must come from this exact local JAR.
  (let [expected (.getCanonicalFile (io/file "paclo.jar"))
        ^Class binding-class PcapHandle]
    (doseq [path ["paclo/core.clj" "paclo/stream.clj" "paclo/decode_ext.clj"
                  "paclo/flow.clj" "paclo/window.clj" "paclo/dns.clj"
                  "paclo/pcapng.clj" "paclo/proto/dns_ext.clj" "paclo/proto/tls_ext.clj"]]
      (let [url (io/resource path)]
        (check! (= "jar" (some-> url .getProtocol)) [:jar-resource path])
        (check! (= expected (.getCanonicalFile (io/file (.toURI (.getJarFileURL (.openConnection url))))))
                [:same-jar path])))
    (check! (= expected (io/file (.toURI (.. binding-class getProtectionDomain getCodeSource getLocation))))
            :binding-origin)
    (doseq [entry (str/split (System/getProperty "java.class.path")
                             (re-pattern (System/getProperty "path.separator")))]
      (let [file (.getCanonicalFile (io/file entry))]
        (check! (or (= file (.getCanonicalFile (io/file ".")))
                    (and (.isFile file) (str/ends-with? entry ".jar")))
                [:isolated-classpath entry]))))
  (check! (sequential? (decode-ext/installed)) :decode-registry)
  (check! (some? PcapLibrary/INSTANCE) :jnr-library)
  (native-check! "fixtures/dns-sample.pcap")
  (with-open [handle (PcapHandle/openOffline "fixtures/dns-sample.pcap")]
    (check! (some? (.pointer handle)) :java-native-handle)
    (.close handle)) ; close is idempotent
  (doseq [[file dlt link-kind] [["dns-sample.pcap" 1 :ethernet]
                                ["cooked/sll.pcap" 113 :linux-sll]
                                ["cooked/sll2.pcap" 276 :linux-sll2]
                                ["raw-ip/raw.pcap" 12 :raw-ip]
                                ["null-loop/null-header-le-file-le.pcap" 0 :null]
                                ["null-loop/loop-header-be-file-le.pcap" 108 :loop]]]
    (let [path (str "fixtures/" file)
          raw (read-packets path {})
          decoded (read-packets path {:decode? true :extensions []})
          projected (read-packets path {:decode-mode :flow})
          output (str "roundtrip-" dlt ".pcap")]
      (check! (seq raw) [:offline-read dlt])
      (check! (every? #(= dlt (:linktype %)) raw) [:native-dlt dlt])
      (check! (= link-kind (get-in (first decoded) [:decoded :type])) [:decode dlt])
      (check! (some flow/key projected) [:flow-decode dlt])
      (core/write-pcap! raw output {:linktype dlt})
      (check! (= (packet-values raw) (packet-values (read-packets output {}))) [:classic-roundtrip dlt])))
  (let [packets (read-packets "fixtures/dns-sample.pcap"
                              {:decode? true :extensions [dns-ext/annotate-dns]})
        events (keep dns/packet->event packets)
        result (reduce (fn [{:keys [state matches]} event]
                         (let [step (dns/step state event)]
                           {:state (:state step)
                            :matches (+ matches (count (filter #(= :match (:kind %)) (:events step))))}))
                       {:state (dns/init {:timeout-us 5000000 :max-pending 20 :max-retired 20}) :matches 0}
                       events)
        flows (read-packets "fixtures/dns-sample.pcap" {:decode-mode :flow})
        aggregate (transduce identity (flow/aggregate-rf {:max-flows 20}) flows)
        state (window/init {:width-us 1000000 :max-windows 20 :max-groups 20})
        stepped (window/step state {:time-us 0 :group :dns :captured-bytes 42})]
    (check! (= 4 (count packets)) :ethernet-count)
    (check! (every? :qname events) :dns-annotation)
    (check! (= 2 (:matches result)) :dns-matches)
    (check! (empty? (:events (dns/finish (:state result)))) :dns-finish)
    (check! (= 4 (get-in aggregate [:summary :aggregated])) :flow-aggregate)
    (check! (= 1 (count (flow/top-n aggregate {:n 1}))) :flow-top-n)
    (check! (= 1 (get-in (window/advance (:state stepped) 1000000)
                         [:events 0 :groups :dns :packets])) :window-advance)
    (check! (= false (get-in (window/finish (:state stepped)) [:events 0 :complete?])) :window-finish))
  (let [packets (read-packets "fixtures/tls-sni-alpn-sample.pcap"
                              {:decode? true :extensions [tls-ext/annotate-tls-sni]})]
    (check! (some #(= "example.com" (get-in % [:decoded :l3 :l4 :app :sni])) packets) :tls-annotation))
  (let [events (read-events "fixtures/pcapng-contracts/rich.pcapng")
        report (pcapng/write-pcapng! events "roundtrip.pcapng")]
    (check! (= :complete (:status report)) :pcapng-write)
    (check! (= :known-semantics (:fidelity report)) :pcapng-preserve)
    (check! (= (semantic events) (semantic (read-events "roundtrip.pcapng"))) :pcapng-exact-roundtrip))
  (let [source (pcapng/open-source {:path "fixtures/pcapng-contracts/rich.pcapng"})]
    (with-open [s source] (reduce (fn [_ event] (reduced event)) nil s))
    (check! (= :reduced (:terminal (pcapng/source-info source))) :pcapng-early-close))
  (let [capture (core/start-capture {:path "fixtures/dns-sample.pcap" :buffer-cap 1})]
    (with-open [^Closeable c capture
                ^Closeable fanout (stream/fan-out (core/capture-packets c)
                                                  {:left {:buffer-mode :blocking :buffer-cap 1}
                                                   :right {:buffer-mode :blocking :buffer-cap 1}}
                                                  {:cancel! #(core/stop-capture! c)})
                ^Closeable left (stream/branch fanout :left)
                ^Closeable right (stream/branch fanout :right)]
      (let [count-packets #(reduce (fn [n _] (inc n)) 0 %)
            a (future (count-packets left))
            b (future (count-packets right))]
        (check! (= 4 (deref a 10000 :timeout) (deref b 10000 :timeout)) :managed-stream)))
    (check! (= :closed (:state (core/capture-stats capture))) :managed-close))
  (println :distribution-consumer-ok :jdk (System/getProperty "java.version")
           :public-namespaces :native :all-dlts :classic :pcapng :flow :dns :window :annotations :closed))

(defn -main [& [report]]
  (try
    (verify!)
    (when report (write-runtime! report))
    (finally (shutdown-agents))))
