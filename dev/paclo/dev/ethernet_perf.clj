(ns paclo.dev.ethernet-perf
  "Issue #44 opt-in paired decode measurements. Pass one EDN options map.
   Historical implementation sources are renamed, never patched. See the report."
  (:require
   [clojure.edn :as edn]
   [clojure.java.io :as io]
   [clojure.java.shell :as shell]
   [clojure.string :as str]
   [clojure.walk :as walk]
   [paclo.core :as core]
   [paclo.dev.perf-data :as data]
   [paclo.dev.perf-metrics :as metrics]
   [paclo.flow.project :as project]
   [paclo.linktype :as linktype]
   [paclo.parse :as parse])
  (:import
   [com.sun.management ThreadMXBean]
   [java.lang.management ManagementFactory]
   [java.nio ByteBuffer]
   [java.nio.file Files Paths]
   [java.nio.file.attribute FileAttribute]
   [java.security MessageDigest]
   [java.time Duration]
   [java.util Arrays]
   [jdk.jfr Recording]))

(def source-paths
  ["src/paclo/linktype.clj" "src/paclo/parse.clj"
   "src/paclo/flow/project.clj" "src/paclo/core.clj"])

(defn- sha256 [s]
  (apply str (map #(format "%02x" (bit-and % 255))
                  (.digest (MessageDigest/getInstance "SHA-256") (.getBytes ^String s "UTF-8")))))

(defn implementation
  "Load unchanged Git sources under distinct namespaces; record original hashes.
   Dependencies outside these four namespaces deliberately use the same checkout."
  [ref index]
  (let [names (into {} (map (fn [n] [n (str "paclo.dev.ethernet-ref" index "." n)])
                            ["paclo.linktype" "paclo.parse" "paclo.flow.project" "paclo.core"]))
        hashes (into {}
                     (for [path source-paths]
                       (let [{:keys [exit out err]} (if (.isDirectory (io/file ref))
                                                      {:exit 0 :out (slurp (io/file ref path))}
                                                      (shell/sh "git" "show" (str ref ":" path)))]
                         (when-not (zero? exit)
                           (throw (ex-info "cannot read reference" {:ref ref :path path :error err})))
                         (load-string (reduce-kv str/replace out names))
                         (let [original (-> path (str/replace "src/" "") (str/replace ".clj" "")
                                            (str/replace "/" "."))]
                           (dosync (alter @#'clojure.core/*loaded-libs* conj (symbol (get names original)))))
                         [path (sha256 out)])))]
    {:id ref :hashes hashes
     :xf (ns-resolve (symbol (names "paclo.core")) 'packet-xf)}))

(defn- current []
  {:id "working-tree" :xf core/packet-xf
   :hashes (into {} (map (fn [path] [path (sha256 (slurp path))]) source-paths))})

(defn- put16! [^bytes b offset value]
  (aset-byte b offset (unchecked-byte (bit-shift-right value 8)))
  (aset-byte b (inc offset) (unchecked-byte value)))

(defn frame
  "Deterministic IPv4/IPv6 TCP/UDP; size includes the untagged Ethernet header.
   Payload is inert (ports 12000/5300 or 443); VLAN tags add four bytes each."
  [version traffic size vlans]
  (let [^bytes ipv4 (data/ethernet-ipv4-frame size traffic)
        ^bytes ethernet
        (if (= version 4)
          ipv4
          (let [b (byte-array size) proto (if (= traffic :tcp) 6 17)]
            (System/arraycopy ipv4 0 b 0 12)
            (put16! b 12 0x86dd)
            (aset-byte b 14 (byte 0x60))
            (put16! b 18 (- size 54))
            (aset-byte b 20 (byte proto))
            (aset-byte b 21 (byte 64))
            (doseq [o [22 38]]
              (aset-byte b o (byte 0x20)) (aset-byte b (inc o) (byte 1))
              (aset-byte b (+ o 15) (byte (if (= o 22) 1 2))))
            (System/arraycopy ipv4 34 b 54 (if (= traffic :tcp) 20 8))
            (when (= traffic :udp) (put16! b 58 (- size 54)))
            b))]
    (if (zero? vlans)
      ethernet
      (let [b (byte-array (+ size (* 4 vlans)))]
        (System/arraycopy ethernet 0 b 0 12)
        (dotimes [i vlans]
          (put16! b (+ 12 (* i 4)) (if (zero? i) 0x88a8 0x8100))
          (put16! b (+ 14 (* i 4)) (+ 0xb000 i)))
        (System/arraycopy ethernet 12 b (+ 12 (* 4 vlans)) (- size 12))
        b))))

(defn packet [^bytes ethernet dlt version]
  (let [header (case dlt 1 14 113 16 276 20 12 0 0 4 108 4)
        b (if (= dlt 1) ethernet
              (let [b (byte-array (+ header (- (alength ethernet) 14)))]
                (case dlt
                  113 (do (put16! b 2 1) (put16! b 4 6)
                          (System/arraycopy ethernet 0 b 6 6)
                          (System/arraycopy ethernet 12 b 14 2))
                  276 (do (put16! b 8 1) (aset-byte b 11 (byte 6))
                          (System/arraycopy ethernet 0 b 12 6)
                          (System/arraycopy ethernet 12 b 0 2))
                  0 (aset-byte b 0 (byte (if (= version 4) 2 24)))
                  108 (aset-byte b 3 (byte (if (= version 4) 2 24)))
                  12 nil)
                (System/arraycopy ethernet 14 b header (- (alength ethernet) 14)) b))]
    {:bytes b :linktype dlt :ts-sec 1700000000 :ts-usec 123456
     :caplen (alength ^bytes b) :len (alength ^bytes b)}))

(defn scenarios [suite]
  (case suite
    :legacy (for [[traffic size] [[:udp 64] [:tcp 512]] mode [:full :flow]]
              {:version 4 :traffic traffic :size size :vlans 0 :dlt 1 :mode mode})
    :matrix (for [version [4 6] traffic [:udp :tcp] size [96 1514]
                  dlt [1 113 276 12 0 108] vlans (if (= dlt 1) [0 1 2] [0]) mode [:full :flow]]
              {:version version :traffic traffic :size size :vlans vlans :dlt dlt :mode mode})
    :native (for [version [4 6] traffic [:udp :tcp] dlt [1 113 276 12 0 108]
                  container [:pcap :pcapng] mode [:full :flow]]
              {:version version :traffic traffic :size (if (= traffic :udp) 96 1514)
               :vlans 0 :dlt dlt :container container :mode mode})
    :fixtures (for [path ["test/resources/dns-sample.pcap" "test/resources/tls-sni-alpn-sample.pcap"
                          "test/resources/cooked/sll.pcap" "test/resources/cooked/sll2.pcap"
                          "test/resources/raw-ip/raw.pcap"
                          "test/resources/null-loop/null-header-le-file-le.pcap"
                          "test/resources/null-loop/loop-header-be-file-le.pcap"]
                    container [:pcap :pcapng] mode [:full :flow]]
                {:path path :input-limit 8 :container container :mode mode})
    :trace [{:path "test/resources/dns-sample.pcap" :mode :full}
            {:path "test/resources/dns-sample.pcap" :mode :flow}]
    (throw (ex-info "unknown benchmark suite" {:suite suite}))))

(defn- config [mode]
  (if (= mode :full) {:decode? true :extensions []} {:decode-mode :flow}))

(defn- as-data [v]
  (walk/postwalk #(if (bytes? %) (vec %) %) v))

(defn- check-packets! [mode raw decoded]
  (when-not (= (count raw) (count decoded))
    (throw (ex-info "benchmark packet loss" {})))
  (doseq [[input output] (map vector raw decoded)]
    (when (:decode-error output) (throw (ex-info "benchmark decode failed" output)))
    (when-not (if (= mode :full)
                (identical? (:bytes input) (:bytes output))
                (not-any? #(contains? output %) [:bytes :decoded]))
      (throw (ex-info "benchmark ownership failure" {:mode mode}))))
  decoded)

(defn- sum-packet [acc p]
  ;; Consume decoded protocol; check complete values and counts separately.
  (unchecked-add (long acc) (long (or (:protocol p) (get-in p [:decoded :l3 :protocol])
                                      (get-in p [:decoded :l3 :next-header]) 0))))

(defn- gc-state []
  (reduce (fn [s b] (-> s (update :count + (.getCollectionCount b))
                        (update :ms + (.getCollectionTime b))))
          {:count 0 :ms 0} (ManagementFactory/getGarbageCollectorMXBeans)))

(defn- sample [f]
  (let [^ThreadMXBean bean (ManagementFactory/getThreadMXBean)
        gc (gc-state) allocated (.getCurrentThreadAllocatedBytes bean)
        cpu (.getCurrentThreadCpuTime bean) start (System/nanoTime)
        checksum (f) elapsed (- (System/nanoTime) start)
        cpu (- (.getCurrentThreadCpuTime bean) cpu)
        allocated (- (.getCurrentThreadAllocatedBytes bean) allocated) gc-after (gc-state)]
    {:ns elapsed :cpu-ns cpu :allocated allocated :checksum checksum
     :gc-count (- (:count gc-after) (:count gc)) :gc-ms (- (:ms gc-after) (:ms gc))}))

(defn- report [samples n]
  {:packets-per-second (/ (* 1e9 n) (double (metrics/median (map :ns samples))))
   :cpu-ns-per-packet (/ (double (metrics/median (map :cpu-ns samples))) n)
   :allocation-bytes-per-packet (/ (double (metrics/median (map :allocated samples))) n)
   :gc-count (reduce + (map :gc-count samples)) :gc-ms (reduce + (map :gc-ms samples))
   :samples samples})

(defn- write-capture! [path packets container dlt]
  (if (= container :pcap)
    (core/write-pcap! packets (str path) {:linktype dlt})
    ;; Write a simple little-endian SHB/IDB and EPBs. No implementation under
    ;; test generates these bytes; the native reader validates every record.
    (with-open [out (io/output-stream (str path))]
      (letfn [(u16 [v] (.write out (bit-and v 255)) (.write out (bit-and (bit-shift-right v 8) 255)))
              (u32 [v] (dotimes [i 4] (.write out (bit-and (bit-shift-right v (* 8 i)) 255))))]
        (u32 0x0a0d0d0a) (u32 28) (u32 0x1a2b3c4d) (u16 1) (u16 0)
        (u32 0xffffffff) (u32 0xffffffff) (u32 28)
        (u32 1) (u32 20) (u16 (if (= dlt 12) 101 dlt)) (u16 0) (u32 65536) (u32 20)
        (doseq [{:keys [bytes caplen len ts-sec ts-usec]} packets]
          (let [padding (mod (- caplen) 4) length (+ 32 caplen padding)]
            (u32 6) (u32 length) (u32 0)
            (let [ticks (+ (* ts-sec 1000000) ts-usec)]
              (u32 (unsigned-bit-shift-right ticks 32)) (u32 ticks))
            (u32 caplen) (u32 len) (.write out ^bytes bytes)
            (dotimes [_ padding] (.write out 0)) (u32 length)))))))

(defn compare-case!
  [implementations {:keys [version traffic size vlans dlt mode container path input-limit] :as scenario}
   {:keys [packets warmups runs reverse?] :or {packets 10000 warmups 5 runs 9}}]
  (let [raw (if path (core/reduce-packets {:path path :max (or input-limit Long/MAX_VALUE)} conj [])
                [(packet (frame version traffic size vlans) dlt version)])
        dlt (or dlt (:linktype (first raw)))
        snapshots (mapv #(aclone ^bytes (:bytes %)) raw)
        inputs (vec (take packets (cycle raw)))
        temp (when container (Files/createTempFile "paclo-ethernet-perf-" (str "." (name container))
                                                   (make-array FileAttribute 0)))
        native-path (or (some-> temp str) path)]
    (try
      (when temp
        (write-capture! temp inputs container dlt)
        (let [replayed (core/reduce-packets {:path (str temp) :max Long/MAX_VALUE} conj [])]
          (when-not (= (as-data inputs) (as-data replayed))
            (throw (ex-info "generated capture differs from input" {:scenario scenario})))))
      (let [variants
            (vec (keep (fn [{:keys [id xf]}]
                         (let [xf (xf (config mode)) probe (first (into [] xf [(first raw)]))]
                           (if (= :unsupported-linktype (-> probe :diagnostics first :reason))
                             (do (println (pr-str {:type :unsupported :id id :scenario scenario})) nil)
                             (let [decoded (check-packets! mode raw (into [] xf raw))]
                               {:id id :decoded (as-data decoded)
                                :run (if native-path
                                       #(core/reduce-packets {:path native-path :max Long/MAX_VALUE :xform xf}
                                                             sum-packet 0)
                                       #(transduce xf (completing sum-packet) 0 inputs))})))) implementations))
            variants (if reverse? (vec (reverse variants)) variants)
            expected (:decoded (first variants))
            n (if (and path (not container)) (count raw) packets)
            samples (atom {}) warm (atom {})]
        (when (empty? variants) (throw (ex-info "no supported variants" {:scenario scenario})))
        (doseq [{:keys [id decoded]} variants]
          (when-not (= expected decoded)
            (throw (ex-info "complete decoded outputs differ" {:scenario scenario :id id}))))
        (dotimes [_ warmups]
          (doseq [{:keys [id run]} variants] (swap! warm update id (fnil conj []) (sample run))))
        (dotimes [round runs]
          (doseq [[order {:keys [id run]}] (map-indexed vector (if (even? round) variants (reverse variants)))]
            (swap! samples update id (fnil conj []) (assoc (sample run) :round round :order order))))
        (when-not (apply = (map :checksum (mapcat val @samples)))
          (throw (ex-info "sample checksum mismatch" {:scenario scenario})))
        (doseq [[p snapshot] (map vector raw snapshots)]
          (when-not (Arrays/equals ^bytes (:bytes p) ^bytes snapshot)
            (throw (ex-info "input mutation" {:scenario scenario}))))
        (doseq [{:keys [id]} variants]
          (println (pr-str (merge {:type :measurement :id id :scenario scenario :packets n
                                   :scope (if native-path :native-read-packet-xf :packet-xf-only)
                                   :outputs-equal? true :bytes-unchanged? true :ownership-checked? true
                                   :drops 0 :errors 0 :warmup-samples (get @warm id)}
                                  (report (get @samples id) n)))) (flush)))
      (finally (when temp (Files/delete temp))))))

(defn- profile! [mode constructor jfr]
  ;; Stack collection perturbs execution, kept separate from paired timings.
  (let [p (packet (frame 4 :udp 64 0) 1 4)
        inputs (vec (repeat 50000 p)) xf (constructor (config mode))
        thread (Thread/currentThread) running (atom true) stacks (atom [])]
    (dotimes [_ 10] (transduce xf (completing sum-packet) 0 inputs))
    (with-open [recording (Recording.)]
      (when jfr
        (.withPeriod (.enable recording "jdk.ExecutionSample") (Duration/ofMillis 5))
        (.withStackTrace (.enable recording "jdk.ObjectAllocationSample"))
        (.enable recording "jdk.GarbageCollection")
        (.start recording))
      (let [sampler (future (while @running
                              (swap! stacks conj (mapv str (.getStackTrace thread)))
                              (Thread/sleep 2)))]
        (try (dotimes [_ (if (= mode :flow) 400 80)] (transduce xf (completing sum-packet) 0 inputs))
             (finally (reset! running false) @sampler)))
      (when jfr
        (.stop recording)
        (.dump recording (Paths/get (str jfr "-" (name mode) ".jfr") (make-array String 0)))))
    (println (pr-str {:type :profile :mode mode :samples (count @stacks)
                      :top-frames (take 30 (sort-by val > (frequencies (map first @stacks))))
                      :inclusive (take 60 (sort-by val > (frequencies (mapcat #(distinct (filter (fn [s] (str/includes? s "paclo.")) %)) @stacks))))}))))

(defn- stages! [{:keys [packets warmups runs] :or {packets 10000 warmups 5 runs 9} :as options}]
  (let [p (packet (frame 4 :udp 64 0) 1 4) b (:bytes p)
        framing (linktype/payload b 1) buffer (ByteBuffer/wrap b)
        l3 (:l3 (parse/packet->clj b))
        operations {:dlt #(linktype/packet-dlt p) :framing #(linktype/payload b 1)
                    :link-map-and-macs #(linktype/header buffer 1 framing l3)
                    :parse #(parse/packet->clj b) :projection #(project/project-packet p)}]
    (doseq [[stage f] (sort-by key operations)]
      (let [run #(loop [i (long packets) result nil] (if (zero? i) (hash result) (recur (dec i) (f))))]
        (dotimes [_ warmups] (run))
        (println (pr-str (merge {:type :stage :stage stage :options options}
                                (report (vec (repeatedly runs #(sample run))) packets))))))))

(defn- used-heap []
  (dotimes [_ 2] (System/gc) (Thread/sleep 50))
  (let [r (Runtime/getRuntime)] (- (.totalMemory r) (.freeMemory r))))

(defn- retained! [implementations]
  ;; Approximate forced-GC delta, input and result remain strongly reachable.
  ;; No claim about native RSS or long-running streaming retention.
  (doseq [mode [:full :flow] implementation implementations]
    (let [inputs (vec (repeat 20000 (packet (frame 4 :udp 64 0) 1 4)))
          xf ((:xf implementation) (config mode))]
      (dotimes [_ 3] (into [] xf inputs))
      (let [owner (atom inputs) before (used-heap) result (into [] xf @owner) after (used-heap)]
        (check-packets! mode @owner result)
        (println (pr-str {:type :retained :id (:id implementation) :mode mode :packets (count result)
                          :estimated-bytes-per-packet (/ (double (- after before)) (count result))
                          :inputs-reachable? (identical? inputs @owner) :outputs-retained? (vector? result)}))))))

(defn- prewarm! [implementations only-mode]
  ;; Warm every protocol/framing call site before per-case warmups. A short
  ;; first Flow row otherwise overlaps C2 compilation after the first Full row.
  (let [cases (vec (for [version [4 6] traffic [:udp :tcp] dlt [1 113 276 12 0 108]
                         tags (if (= dlt 1) [0 1 2] [0])]
                     (packet (frame version traffic 96 tags) dlt version)))]
    (dotimes [_ 5]
      (doseq [{:keys [xf]} implementations mode (if only-mode [only-mode] [:full :flow])]
        (let [xf (xf (config mode))]
          (doseq [p cases]
            (when-not (= :unsupported-linktype (-> (first (into [] xf [p])) :diagnostics first :reason))
              (transduce xf (completing sum-packet) 0 (vec (repeat 10000 p)))))))))
  (println (pr-str {:type :prewarm :rounds 5 :packets-per-shape 10000
                    :shapes 32 :modes (if only-mode [only-mode] [:full :flow])})) (flush))

(defn -main [& [options]]
  (try
    (let [{:keys [refs suite trace replay? only-mode profile-id] :or {refs ["e444b10"] suite :legacy} :as opts}
          (if options (edn/read-string options) {})
          ^ThreadMXBean bean (ManagementFactory/getThreadMXBean)]
      (when-not (and (.isThreadAllocatedMemorySupported bean) (.isCurrentThreadCpuTimeSupported bean))
        (throw (ex-info "allocation/CPU measurement unavailable" {})))
      (.setThreadAllocatedMemoryEnabled bean true) (.setThreadCpuTimeEnabled bean true)
      (let [implementations (conj (mapv implementation refs (range)) (current))]
        (println (pr-str {:type :environment :environment (metrics/environment) :options opts
                          :implementations (mapv #(dissoc % :xf) implementations)
                          :shared-dependencies :checkout :retained-memory :not-measured}))
        (cond
          (= suite :profile) (let [chosen (if profile-id
                                            (or (first (filter #(= profile-id (:id %)) implementations))
                                                (throw (ex-info "unknown profile implementation" {:id profile-id})))
                                            (last implementations))]
                               (doseq [mode [:full :flow]] (profile! mode (:xf chosen) (:jfr opts))))
          (= suite :stages) (stages! opts)
          (= suite :retained) (retained! implementations)
          :else (do (prewarm! implementations only-mode)
                    (doseq [scenario (if trace (map #(cond-> (assoc % :path trace) replay? (assoc :container :pcap)) (scenarios :trace)) (scenarios suite))
                            :when (or (nil? only-mode) (= only-mode (:mode scenario)))]
                      (compare-case! implementations scenario opts))))))
    (finally (shutdown-agents))))
