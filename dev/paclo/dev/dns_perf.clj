(ns paclo.dev.dns-perf
  "Opt-in Issue #37 paired core/pipeline measurements; no performance gate.
   clojure -J-Xms512m -J-Xmx512m -M:dev:dns-ext -m paclo.dev.dns-perf SUITE [label-or-trace-path] [reverse]"
  (:require
   [clojure.edn :as edn]
   [clojure.java.shell :as shell]
   [clojure.string :as str]
   [examples.dns-cli :as cli]
   [examples.dns-qps :as qps]
   [examples.dns-rtt :as rtt]
   [paclo.core :as core]
   [paclo.dev.dns-cli-perf]
   [paclo.dns :as dns]
   [paclo.window :as window])
  (:import
   [com.sun.management OperatingSystemMXBean ThreadMXBean]
   [java.io File Writer]
   [java.lang.management ManagementFactory]))

(def warmups 5)
(def runs 7)

(defn- source [path]
  (let [{:keys [exit out err]} (shell/sh "git" "show" (str "452de98:" path))]
    (when-not (zero? exit) (throw (ex-info "baseline unavailable" {:path path :error err})))
    out))

(defn- resolve-in [space names]
  (into {} (map (fn [n] [(keyword n) (ns-resolve space (symbol n))]) names)))

(defn- source-id [path]
  (let [{:keys [exit out]} (shell/sh "git" "hash-object" path)]
    (assert (zero? exit) (str "cannot identify " path))
    (str/trim out)))

(defn- load-baseline []
  (doseq [[path from to] [["src/paclo/dns.clj" "paclo.dns" "paclo.dev.issue37-baseline-dns"]
                          ["src/paclo/window.clj" "paclo.window" "paclo.dev.issue37-baseline-window"]
                          ["dev/examples/dns_rtt.clj" "examples.dns-rtt" "paclo.dev.issue37-baseline-rtt"]
                          ["dev/examples/dns_qps.clj" "examples.dns-qps" "paclo.dev.issue37-baseline-qps"]]]
    (load-string (-> (source path)
                     (str/replace-first (str "(ns " from) (str "(ns " to))
                     (str/replace "[paclo.dns :as dns]" "[paclo.dev.issue37-baseline-dns :as dns]")
                     (str/replace "[paclo.window :as window]" "[paclo.dev.issue37-baseline-window :as window]"))))
  {:dns (resolve-in 'paclo.dev.issue37-baseline-dns ["init" "step" "advance" "finish"])
   :window (resolve-in 'paclo.dev.issue37-baseline-window ["init" "step" "advance" "finish"])
   :rtt (resolve-in 'paclo.dev.issue37-baseline-rtt ["init" "step" "finish" "report" "consume"])
   :qps (resolve-in 'paclo.dev.issue37-baseline-qps ["init" "step" "finish" "report"])})

(def current
  {:dns {:init dns/init :step dns/step :advance dns/advance :finish dns/finish}
   :window {:init window/init :step window/step :advance window/advance :finish window/finish}
   :rtt {:init rtt/init :step rtt/step :finish rtt/finish :report rtt/report
         :consume (ns-resolve 'examples.dns-rtt 'consume)}
   :qps {:init qps/init :step qps/step :finish qps/finish :report qps/report}})

(defn- observable [x]
  ;; Only the optional internal scalar hint differs; all public data/events,
  ;; every pending/retired entry and all reports must agree.
  (if (map? x)
    (cond-> (dissoc x :paclo.dns/next-expiry-us)
      (:state x) (update :state observable)
      (:analysis x) (update :analysis observable))
    x))

(defn- gc-totals []
  (reduce (fn [[n ms] b] [(+ n (max 0 (.getCollectionCount ^java.lang.management.GarbageCollectorMXBean b)))
                          (+ ms (max 0 (.getCollectionTime ^java.lang.management.GarbageCollectorMXBean b)))])
          [0 0] (ManagementFactory/getGarbageCollectorMXBeans)))

(defn- counters []
  (let [^ThreadMXBean bean (ManagementFactory/getThreadMXBean)
        ids (.getAllThreadIds bean)]
    {:allocated (when (.isThreadAllocatedMemorySupported bean)
                  (zipmap ids (.getThreadAllocatedBytes bean ids)))
     :gc (gc-totals)}))

(defn- measure [f]
  (let [^ThreadMXBean bean (ManagementFactory/getThreadMXBean)
        ^OperatingSystemMXBean os (ManagementFactory/getOperatingSystemMXBean)
        before (counters) cpu (.getCurrentThreadCpuTime bean) process-cpu (.getProcessCpuTime os)
        start (System/nanoTime) result (f) elapsed (- (System/nanoTime) start)
        cpu (- (.getCurrentThreadCpuTime bean) cpu)
        process-cpu (- (.getProcessCpuTime os) process-cpu) after (counters)]
    {:result result
     :sample {:ns elapsed :thread-cpu-ns cpu :process-cpu-ns process-cpu
              :live-thread-allocated-bytes
              (when (:allocated before)
                (reduce-kv (fn [n id value]
                             (+ n (max 0 (- value (max 0 (get (:allocated before) id 0))))))
                           0 (:allocated after)))
              :gc-count (- (first (:gc after)) (first (:gc before)))
              :gc-ms (- (second (:gc after)) (second (:gc before)))}}))

(defn- paired [label units fs reverse?]
  (let [expected (observable ((:baseline fs)))]
    (dotimes [_ warmups]
      (doseq [impl [:baseline :current]]
        (assert (= expected (observable ((impl fs)))) (str label " warmup mismatch"))))
    (dotimes [i runs]
      (doseq [impl (if (= reverse? (even? i)) [:current :baseline] [:baseline :current])]
        (let [{:keys [result sample]} (measure (impl fs))]
          (assert (= expected (observable result)) (str label " result mismatch"))
          (prn (merge {:scenario label :implementation impl :run i :units units :equal? true}
                      sample)))))))

(def options {:timeout-us 1000000 :reuse-delay-us 1000000 :max-pending 100000 :max-retired 100000})
(def query {:time-us 0 :kind :query :id 0 :protocol :udp :ip-version 4
            :src {:ip "192.0.2.1" :port 50000} :dst {:ip "192.0.2.53" :port 53}
            :qname "q.example" :qtype 1 :qclass 1})

(defn- response [q t]
  (assoc q :kind :response :src (:dst q) :dst (:src q) :time-us t :rcode 0))

(defn- expiry-state [api n retired? dense?]
  (reduce (fn [s i]
            (let [q (assoc query :id (mod i 65536) :qname (str "q" i ".example")
                           :time-us (if dense? 0 i))
                  r ((:step api) s q)]
              (if retired? (:state ((:step api) (:state r) (response q (:time-us q)))) (:state r))))
          ((:init api) options) (range n)))

(defn- advances [api initial watermarks]
  (reduce (fn [{:keys [state events]} w]
            (let [r ((:advance api) state w)]
              {:state (:state r) :events (into events (:events r))}))
          {:state initial :events []} watermarks))

(defn- expiry-suite [base reverse?]
  (doseq [n [10 1000 10000] retired? [false true] dense? [false true]
          mode [:none :few :all]]
    (let [deadline (if retired? 2000000 1000000)
          watermarks (case mode :none (range 20) :few [deadline] :all [(+ deadline n)])
          states {:baseline (expiry-state (:dns base) n retired? dense?)
                  :current (expiry-state (:dns current) n retired? dense?)}]
      (paired [:expiry n (if retired? :retired :pending) (if dense? :dense :sparse) mode]
              (count watermarks)
              (into {} (for [[impl api] [[:baseline (:dns base)] [:current (:dns current)]]]
                         [impl #(advances api (impl states) watermarks)])) reverse?)))
  (doseq [retired? [false true]]
    (let [n 1000 deadline (if retired? 2000000 1000000)
          states {:baseline (expiry-state (:dns base) n retired? false)
                  :current (expiry-state (:dns current) n retired? false)}]
      (paired [:expiry-sequential n retired?] n
              (into {} (for [[impl api] [[:baseline (:dns base)] [:current (:dns current)]]]
                         [impl #(advances api (impl states) (range deadline (+ deadline n)))])) reverse?))))

(defn- generated-packets [n qnames spacing]
  (let [frame (ns-resolve 'paclo.dev.dns-cli-perf 'frame)
        put-u16! (ns-resolve 'paclo.dev.dns-cli-perf 'put-u16!)]
    (vec (mapcat (fn [i]
                   (for [response? [false true]]
                     (let [bytes (frame (mod i qnames) response?)
                           t (+ 1000000000 (* i spacing) (if response? 100 0))]
                       (put-u16! bytes 42 (mod i 65536))
                       {:bytes bytes :caplen (alength ^bytes bytes) :len (alength ^bytes bytes) :linktype 1
                        :ts-sec (quot t 1000000) :ts-usec (mod t 1000000)})))
                 (range n)))))

(defn- report-run [api packets opts]
  (let [state (reduce (:step api) ((:init api) opts) packets)
        finished ((:finish api) state)]
    {:state finished :report ((:report api) finished)}))

(defn- fixture-suite [base reverse? path]
  (let [opts (cli/capture-options path "udp and port 53")
        packets (core/reduce-packets opts conj [])
        units (count packets)]
    (prn {:fixture path :packets units :qnames (count (set (keep #(get-in % [:decoded :l3 :l4 :app :qname]) packets)))
          :first-time-us (dns/packet-time-us (first packets))
          :last-time-us (dns/packet-time-us (peek packets))})
    (doseq [async? [false true] mode [:pairs :stats :qstats]]
      (paired [:fixture-rtt mode async?] units
              (into {} (for [[impl api] [[:baseline (:rtt base)] [:current (:rtt current)]]]
                         [impl #(let [r (cli/run opts (:step api) ((:init api) {:mode mode})
                                                 (assoc cli/execution-defaults :async? async? :async-buffer 1))]
                                  {:execution (:execution r)
                                   :report ((:report api) ((:finish api) (:state r)))})])) reverse?))
    (doseq [group [:rcode :rrtype :qname :qname-suffix :client :server]]
      (paired [:fixture-qps group] units
              {:baseline #(report-run (:qps base) packets {:group group})
               :current #(report-run (:qps current) packets {:group group})} reverse?))
    (prn {:fixture-result (report-run (:rtt current) packets {:mode :stats})})))

(defn- core-run [api events advance?]
  (reduce (fn [{:keys [state events] :as acc} e]
            (let [a (if advance? ((:advance api) state (:time-us e)) acc)
                  r ((:step api) (:state a) e)]
              {:state (:state r) :events (into (into events (if advance? (:events a) [])) (:events r))}))
          {:state ((:init api) options) :events []} events))

(defn- pipeline-suite [base reverse?]
  (let [file (File/createTempFile "paclo-issue37-" ".pcap") path (.getAbsolutePath file)]
    (try
      (doseq [[n qnames spacing] [[500 10 1000] [2000 2000 1000] [20000 2000 1000000]]]
        (let [raw (generated-packets n qnames spacing)
              _ (core/write-pcap! raw path)
              opts (cli/capture-options path "udp and port 53")
              decoded (into [] (core/packet-xf opts) raw)
              events (mapv dns/packet->event decoded)
              count-packet (fn [[n bytes] p] [(inc n) (+ bytes (:caplen p))])
              units (* 2 n)]
          (prn {:input :generated-pcap :pairs n :qnames qnames :spacing-us spacing
                :duration-us (* n spacing) :file-bytes (.length file)})
          (doseq [[label f] [[:native #(core/reduce-packets (dissoc opts :decode? :extensions :extension-error-mode) count-packet [0 0])]
                             [:native-full #(core/reduce-packets opts count-packet [0 0])]
                             [:packet-event #(mapv dns/packet->event decoded)]]]
            (paired [label n qnames] units {:baseline f :current f} reverse?))
          ;; A long trace is measured end-to-end, rather than retaining all
          ;; correlation events for every core-only decomposition as well.
          (when (< n 20000)
            (doseq [advance? [false true]]
              (paired [:correlation n qnames advance?] units
                      {:baseline #(core-run (:dns base) events advance?)
                       :current #(core-run (:dns current) events advance?)} reverse?))
            (doseq [mode [:pairs :stats :qstats]]
              (paired [:rtt-replay n qnames mode] units
                      {:baseline #(report-run (:rtt base) decoded {:mode mode})
                       :current #(report-run (:rtt current) decoded {:mode mode})} reverse?))
            (let [matches (:events (core-run (:dns base) events false))]
              (doseq [mode [:pairs :stats :qstats]]
                (paired [:rtt-report-update n qnames mode] n
                        (into {} (for [[impl api] [[:baseline (:rtt base)] [:current (:rtt current)]]]
                                   [impl #(reduce (:consume api) ((:init api) {:mode mode}) matches)])) reverse?)))
            (doseq [group [:rcode :rrtype :qname :qname-suffix :client :server]]
              (paired [:qps-replay n qnames group] units
                      {:baseline #(report-run (:qps base) decoded {:group group})
                       :current #(report-run (:qps current) decoded {:group group})} reverse?)))
          (doseq [async? [false true] mode [:pairs :stats :qstats]]
            (paired [:native-rtt n qnames mode async?] units
                    (into {} (for [[impl api] [[:baseline (:rtt base)] [:current (:rtt current)]]]
                               [impl #(let [r (cli/run opts (:step api) ((:init api) {:mode mode})
                                                       (assoc cli/execution-defaults :async? async? :async-buffer 1))
                                            finished ((:finish api) (:state r))]
                                        {:state finished :execution (:execution r) :report ((:report api) finished)})])) reverse?))
          (when (< n 20000)
            (doseq [async? [false true]]
              (let [f #(with-redefs [core/reduce-packets (fn [_ step initial] (reduce step initial decoded))]
                         (cli/run {} (fn [n _] (inc n)) 0
                                  (assoc cli/execution-defaults :async? async? :async-buffer 1)))]
                (paired [:delivery-only n async?] units {:baseline f :current f} reverse?)))
            (doseq [async? [false true] group [:rcode :qname :client :server]]
              (paired [:native-qps n qnames group async?] units
                      (into {} (for [[impl api] [[:baseline (:qps base)] [:current (:qps current)]]]
                                 [impl #(let [r (cli/run opts (:step api) ((:init api) {:group group})
                                                         (assoc cli/execution-defaults :async? async? :async-buffer 1))]
                                          {:execution (:execution r)
                                           :report ((:report api) ((:finish api) (:state r)))})])) reverse?))
            (let [rows (:report (report-run (:qps current) decoded {:group :qname}))
                  emit (ns-resolve 'examples.dns-qps 'emit)]
              (doseq [fmt [:edn :jsonl :csv]]
                (let [f #(let [sink (Writer/nullWriter)]
                           (binding [*out* sink] (dotimes [_ 20] (emit fmt rows)))
                           (count rows))]
                  (paired [:output n qnames fmt] (* 20 (count rows)) {:baseline f :current f} reverse?)))))))
      ;; Existing real native fixture; provenance/size does not establish a
      ;; representative production capture. Preserve its original timestamps.
      (fixture-suite base reverse? "test/resources/dns-sample.pcap")
      (finally (.delete file)))))

(defn- anomalies-suite [base reverse?]
  (let [raw (generated-packets 500 100 4000)
        packets (vec (mapcat (fn [i]
                               (let [q (nth raw (* 2 i)) r (nth raw (inc (* 2 i)))
                                     t (+ 1000000000 (* i 4000))
                                     at (fn [p dt] (let [v (+ t dt)]
                                                     (assoc p :ts-sec (quot v 1000000) :ts-usec (mod v 1000000))))]
                                 (case (mod i 4)
                                   0 [(at q 0) (at q 10) (at q -10) (at r 100) (at q 200) (at r 210)]
                                   1 [(at q 0) (at r 2000)]
                                   2 [(at r 0) (at q 10) (at r 20)]
                                   3 [(at q 100) (at r 50)]))) (range 500)))
        decoded (into [] (core/packet-xf (cli/capture-options "unused" "udp and port 53")) packets)]
    (doseq [reorder [0 300] mode [:pairs :stats :qstats]]
      (let [opts {:mode mode :reorder-us reorder :timeout-us 1000 :reuse-delay-us 1000}]
        (paired [:anomalies mode reorder] (count packets)
                {:baseline #(report-run (:rtt base) decoded opts)
                 :current #(report-run (:rtt current) decoded opts)} reverse?)
        (prn {:diagnostics [:anomalies mode reorder]
              :result (select-keys (:state (report-run (:rtt current) decoded opts)) [:pairs :diagnostics])})))))

(defn- steady-suite [base reverse?]
  (let [file (File/createTempFile "paclo-issue37-steady-" ".pcap") path (.getAbsolutePath file)
        raw (generated-packets 20000 2000 1000)
        opts (cli/capture-options path "udp and port 53")]
    (try
      (core/write-pcap! raw path)
      (prn {:input :steady-generated-pcap :pairs 20000 :qnames 2000 :spacing-us 1000
            :duration-us 20000000 :timeout-us 5000000 :reuse-delay-us 5000000})
      (doseq [async? [false true]]
        (paired [:steady-native-stats async?] 40000
                (into {} (for [[impl api] [[:baseline (:rtt base)] [:current (:rtt current)]]]
                           [impl #(let [r (cli/run opts (:step api) ((:init api) {:mode :stats})
                                                   (assoc cli/execution-defaults :async? async? :async-buffer 1))
                                        state (:state r)
                                        retained {:pending (count (get-in state [:analysis :pending]))
                                                  :retired (count (get-in state [:analysis :retired]))
                                                  :samples (count (:samples state))}
                                        finished ((:finish api) state)]
                                    (assert (= 20000 (:pairs state)))
                                    (assert (= {:pending 0 :retired 10000 :samples 20000} retained))
                                    {:state finished :execution (:execution r) :retained-before-finish retained
                                     :report ((:report api) finished)})])) reverse?))
      (finally (.delete file)))))

(defn- dispatch-suite [base reverse?]
  ;; Baseline APIs are namespace Vars, candidate APIs are function values.
  ;; Measure that calling-convention difference with identical main code.
  (let [direct (update-vals base #(update-vals % deref))
        raw (generated-packets 2000 2000 1000)
        file (File/createTempFile "paclo-issue37-dispatch-" ".pcap") path (.getAbsolutePath file)
        opts (cli/capture-options path "udp and port 53")
        events (into [] (comp (core/packet-xf opts) (map dns/packet->event)) raw)]
    (try
      (core/write-pcap! raw path)
      (paired [:dispatch-correlation] 4000
              {:baseline #(core-run (:dns base) events false)
               :current #(core-run (:dns direct) events false)} reverse?)
      (doseq [async? [false true]]
        (paired [:dispatch-native-stats async?] 4000
                (into {} (for [[impl api] [[:baseline (:rtt base)] [:current (:rtt direct)]]]
                           [impl #(let [r (cli/run opts (:step api) ((:init api) {:mode :stats})
                                                   (assoc cli/execution-defaults :async? async? :async-buffer 1))]
                                    {:state ((:finish api) (:state r)) :execution (:execution r)})])) reverse?))
      (finally (.delete file)))))

(defn- window-suite [base reverse?]
  (doseq [n [10 1000 10000] restored? [false true] mode [:none :few :all]]
    (let [make-state (fn [api]
                       (let [s (reduce (fn [s i] (:state ((:step api) s {:time-us (* i 10) :group :dns :captured-bytes 64})))
                                       ((:init api) {:width-us 10 :max-windows n :max-groups n}) (range n))]
                         (if restored? (edn/read-string (pr-str s)) s)))
          states {:baseline (make-state (:window base)) :current (make-state (:window current))}
          watermarks (case mode :none [0] :few [10] :all [(* n 10)])]
      (paired [:window-advance n restored? mode] 1
              (into {} (for [[impl api] [[:baseline (:window base)] [:current (:window current)]]]
                         [impl #(advances api (impl states) watermarks)])) reverse?))))

(defn- used-heap []
  (System/gc)
  (Thread/sleep 100)
  (let [r (Runtime/getRuntime)] (- (.totalMemory r) (.freeMemory r))))

(defn- retention-suite [base]
  (doseq [n [1000 10000 100000] retired? [false true] impl [:baseline :current]]
    (let [api (get-in (if (= impl :baseline) base current) [:dns])
          ;; Hold independent complete roots, separate from timed measurements.
          before (used-heap) roots (mapv (fn [_] (expiry-state api n retired? false)) (range (if (= n 100000) 1 10)))
          after (used-heap)]
      (prn {:retention [n retired? impl] :roots (count roots)
            :entries (reduce + (map #(count ((if retired? :retired :pending) %)) roots))
            :estimated-heap-bytes (- after before)
            :edn-characters (count (pr-str (first roots)))
            :roundtrip? (= (first roots) (edn/read-string (pr-str (first roots))))}))))

(defn- large-suite [base reverse?]
  (doseq [retired? [false true]]
    (let [states {:baseline (expiry-state (:dns base) 100000 retired? false)
                  :current (expiry-state (:dns current) 100000 retired? false)}]
      (paired [:large-expiry 100000 retired?] 1
              (into {} (for [[impl api] [[:baseline (:dns base)] [:current (:dns current)]]]
                         [impl #(advances api (impl states) [0])])) reverse?))))

(defn- stress-suite [base reverse?]
  (doseq [n [10000 100000]]
    (let [states {:baseline (expiry-state (:dns base) n true false)
                  :current (expiry-state (:dns current) n true false)}]
      (paired [:retired-sequential n 1000] 1000
              (into {} (for [[impl api] [[:baseline (:dns base)] [:current (:dns current)]]]
                         [impl #(advances api (impl states) (range 2000000 2001000))])) reverse?)))
  (let [make-state (fn [api]
                     (reduce (fn [s i] (:state ((:step api) s (assoc query :id i :qname (str "pending" i ".example") :time-us i))))
                             (expiry-state api 10000 true false) (range 1000)))
        states {:baseline (make-state (:dns base)) :current (make-state (:dns current))}]
    (paired [:mixed-expiry 1000 10000 100] 100
            (into {} (for [[impl api] [[:baseline (:dns base)] [:current (:dns current)]]]
                       [impl #(advances api (impl states) (range 1000000 1000100))])) reverse?)))

(defn- retired-scan [retired watermark short-circuit?]
  (let [minimum (volatile! nil)
        earlier (ns-resolve 'paclo.dns 'earlier)
        retained (reduce-kv
                  (if short-circuit?
                    (fn [retained k until]
                      (let [next @minimum]
                        (cond
                          (and next (<= next until)) retained
                          (<= until watermark) (dissoc retained k)
                          :else (do (vreset! minimum until) retained))))
                    (fn [retained k until]
                      (if (<= until watermark)
                        (dissoc retained k)
                        (do (vreset! minimum (earlier @minimum until)) retained))))
                  retired retired)]
    [retained @minimum]))

(defn- scan-suite [reverse?]
  (doseq [n [1000 10000 100000] mode [:none :few :all]]
    (let [retired (:retired (expiry-state (:dns current) n true false))
          watermark (case mode :none 0 :few 2000000 :all (+ 2000000 n))]
      (paired [:retired-scan-method n mode] 1
              {:baseline #(retired-scan retired watermark false)
               :current #(retired-scan retired watermark true)} reverse?))))

(defn- retired-scan-accumulator [retired watermark]
  (let [retained (volatile! retired)
        minimum (reduce-kv
                 (fn [minimum k until]
                   (cond
                     (and minimum (<= minimum until)) minimum
                     (<= until watermark) (do (vreset! retained (dissoc @retained k)) minimum)
                     :else until)) nil retired)]
    [@retained minimum]))

(defn- accumulator-suite [reverse?]
  (doseq [n [1000 10000 100000] mode [:none :few :all]]
    (let [retired (:retired (expiry-state (:dns current) n true false))
          watermark (case mode :none 0 :few 2000000 :all (+ 2000000 n))]
      (paired [:retired-scan-accumulator n mode] 1
              {:baseline #(retired-scan retired watermark false)
               :current #(retired-scan-accumulator retired watermark)} reverse?))))

(defn -main [& [suite label reverse-order]]
  (try
    (let [base (load-baseline)
          ^ThreadMXBean bean (ManagementFactory/getThreadMXBean)]
      (when (.isThreadAllocatedMemorySupported bean) (.setThreadAllocatedMemoryEnabled bean true))
      (prn {:baseline (cond (#{"scan" "accumulator"} suite) "scalar-double-comparison"
                            (= suite "dispatch") "same-main-var-vs-function"
                            :else "452de98cf6d1a604e5823e80dc1cf5edadfe4b67") :candidate label :scope suite :reverse? (boolean reverse-order)
            :dns-source-blob (source-id "src/paclo/dns.clj")
            :runner-source-blob (source-id "dev/paclo/dev/dns_perf.clj")
            :jdk (System/getProperty "java.version") :clojure (clojure-version)
            :os (System/getProperty "os.name") :arch (System/getProperty "os.arch")
            :warmups (if (= suite "steady") 2 warmups) :runs (if (= suite "steady") 5 runs)
            :heap-max (.maxMemory (Runtime/getRuntime))})
      (case suite
        "expiry" (expiry-suite base (boolean reverse-order))
        "pipeline" (pipeline-suite base (boolean reverse-order))
        "steady" (with-redefs [warmups 2 runs 5] (steady-suite base (boolean reverse-order)))
        "dispatch" (dispatch-suite base (boolean reverse-order))
        "window" (window-suite base (boolean reverse-order))
        "anomalies" (anomalies-suite base (boolean reverse-order))
        "trace" (fixture-suite base false label)
        "retention" (retention-suite base)
        "large" (large-suite base (boolean reverse-order))
        "stress" (stress-suite base (boolean reverse-order))
        "scan" (scan-suite (boolean reverse-order))
        "accumulator" (accumulator-suite (boolean reverse-order))
        (throw (ex-info "expected expiry, pipeline, steady, window, anomalies, large, stress, scan, accumulator, trace or retention" {:suite suite}))))
    (finally (shutdown-agents))))
