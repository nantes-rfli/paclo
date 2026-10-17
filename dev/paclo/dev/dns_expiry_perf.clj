(ns paclo.dev.dns-expiry-perf
  "Post-#57 experiments; reuse the existing paired counter/equality machinery."
  (:require
   [clojure.edn :as edn]
   [clojure.java.shell :as shell]
   [clojure.string :as str]
   [examples.dns-cli :as cli]
   [paclo.core :as core]
   [paclo.dev.dns-perf :as perf]
   [paclo.dns :as dns])
  (:import
   [com.sun.management ThreadMXBean]
   [java.io File]
   [java.lang.management ManagementFactory]))

(def baseline "17e2088b89c91fc72ad44a482d379c9268b6cea7")

(defn- helper [n] (ns-resolve 'paclo.dev.dns-perf n))

(defn- source [path]
  (let [{:keys [exit out err]} (shell/sh "git" "show" (str baseline ":" path))]
    (assert (zero? exit) err)
    out))

(defn- observable [x]
  (when-let [index (or (:paclo.dns/retired-expiries x)
                       (:paclo.dns/retired-expiries (meta (:retired x))))]
    (assert (= (:retired x)
               (reduce-kv (fn [m until ks]
                            (reduce #(assoc %1 %2 until) m (if (vector? ks) ks [ks])))
                          {} index)) "index membership differs from retired keys"))
  (if (map? x)
    (cond-> (dissoc x :paclo.dns/next-expiry-us :paclo.dns/retired-expiries
                    :paclo.dev.issue37-baseline-dns/next-expiry-us)
      (:state x) (update :state observable)
      (:analysis x) (update :analysis observable))
    x))

(defn- api []
  (into {} (for [n '[init step advance finish]] [(keyword n) (ns-resolve 'paclo.dns n)])))

(defn- restored-stress-suite [base reverse?]
  (doseq [n [10000 100000]]
    (let [states (into {} (for [[impl api] [[:baseline (:dns base)] [:current (api)]]]
                            [impl (edn/read-string (pr-str ((helper 'expiry-state) api n true false)))]))]
      ((helper 'paired) [:restored-retired-sequential n 1000] 1000
                        (into {} (for [[impl api] [[:baseline (:dns base)] [:current (api)]]]
                                   [impl #((helper 'advances) api (impl states) (range 2000000 2001000))])) reverse?))))

(defn- activation-suite [base reverse?]
  (doseq [n [1023 1024 1025 2048]]
    (let [states (into {} (for [[impl api] [[:baseline (:dns base)] [:current (api)]]]
                            [impl ((helper 'expiry-state) api n true false)]))
          q (assoc perf/query :id n :qname (str "q" n ".example") :time-us n)]
      ((helper 'paired) [:retired-index-activation n] 2
                        (into {} (for [[impl api] [[:baseline (:dns base)] [:current (api)]]]
                                   [impl #(let [r ((:step api) (impl states) q)]
                                            ((:step api) (:state r) ((helper 'response) q n)))])) reverse?))))

(defn- update-suite [base reverse? short?]
  (doseq [n (if short? [10 1000] [10 1000 10000 100000]) dense? [false true]]
    ((helper 'paired) [:build-retired n dense?] (* 2 n)
                      {:baseline #((helper 'expiry-state) (:dns base) n true dense?)
                       :current #((helper 'expiry-state) (api) n true dense?)} reverse?)))

(defn- boundary-suite [base reverse?]
  (doseq [n [10 10000 100000] dense? [false true] mode [:none :first :all :restored :legacy]]
    (let [a ((helper 'expiry-state) (:dns base) n true dense?)
          b ((helper 'expiry-state) (api) n true dense?)
          w (case mode :none 0 :all (+ 2000000 n) 2000000)
          b (case mode
              :restored (edn/read-string (pr-str b))
              :legacy (-> b
                          (dissoc :paclo.dns/next-expiry-us :paclo.dns/retired-expiries)
                          (update :retired with-meta nil))
              b)]
      ((helper 'paired) [:retired-boundary n dense? mode] 1
                        {:baseline #((get-in base [:dns :advance]) a w)
                         :current #(dns/advance b w)} reverse?))))

(defn- ordinary-suite [base reverse? long?]
  (let [file (File/createTempFile "paclo-expiry-ordinary-" ".pcap")
        path (.getAbsolutePath file)]
    (try
      (doseq [[n names spacing] (if long? [[20000 2000 1000000]] [[500 10 1000] [2000 2000 1000]])]
        (core/write-pcap! ((helper 'generated-packets) n names spacing) path)
        (doseq [async? [false true]]
          ((helper 'paired) [(if long? :low-density-native-stats :ordinary-native-stats) n names async?] (* 2 n)
                            (into {} (for [[impl api] [[:baseline (:rtt base)] [:current (:rtt perf/current)]]]
                                       [impl #(let [r (cli/run (cli/capture-options path "udp and port 53")
                                                               (:step api) ((:init api) {:mode :stats})
                                                               (assoc cli/execution-defaults :async? async? :async-buffer 1))]
                                                {:state ((:finish api) (:state r)) :execution (:execution r)
                                                 :report ((:report api) ((:finish api) (:state r)))})])) reverse?)))
      (finally (.delete file)))))

(defn- retained-suite [base]
  (doseq [n [1000 10000 100000] impl [:baseline :current]]
    (let [api (if (= impl :baseline) (:dns base) (api))
          before ((helper 'used-heap))
          roots (mapv (fn [_] ((helper 'expiry-state) api n true false))
                      (range (if (= n 100000) 1 10)))
          after ((helper 'used-heap))
          state (first roots)
          serialized-state (if (= impl :baseline)
                             (-> state
                                 (assoc :paclo.dns/next-expiry-us
                                        (:paclo.dev.issue37-baseline-dns/next-expiry-us state))
                                 (dissoc :paclo.dev.issue37-baseline-dns/next-expiry-us))
                             state)]
      (observable state)
      (prn {:retention [n true impl] :roots (count roots)
            :entries (reduce + (map #(count (:retired %)) roots))
            :estimated-heap-bytes (- after before)
            :edn-characters (count (pr-str serialized-state))
            :roundtrip? (= state (edn/read-string (pr-str state)))}))))

(defn- restored-retention-suite [base active?]
  (doseq [n [1000 10000 100000] impl [:baseline :current]]
    (let [api (if (= impl :baseline) (:dns base) (api))
          before ((helper 'used-heap))
          roots (mapv (fn [_] (let [s (edn/read-string (pr-str ((helper 'expiry-state) api n true false)))]
                                (if active? (:state ((:advance api) s 2000000)) s)))
                      (range (if (= n 100000) 1 5)))
          after ((helper 'used-heap))]
      (prn {:restored-retention [n impl] :active? active? :roots (count roots)
            :entries (reduce + (map #(count (:retired %)) roots))
            :estimated-heap-bytes (- after before)}))))

(defn- correctness-suite []
  (require 'paclo.dns-test)
  (let [result (with-redefs-fn
                 {(ns-resolve 'paclo.dns-test 'without-expiry-hint)
                  #(-> %
                       (dissoc :paclo.dns/next-expiry-us :paclo.dns/retired-expiries)
                       (update :retired with-meta nil))}
                 #((ns-resolve 'clojure.test 'run-tests) 'paclo.dns-test))]
    (assert (zero? (+ (:fail result) (:error result))) (pr-str result))))

(defn -main [& [suite candidate-path reverse-order]]
  (try
    (let [base (with-redefs-fn {(helper 'source) source} #((helper 'load-baseline)))
          ^ThreadMXBean bean (ManagementFactory/getThreadMXBean)]
      (when candidate-path (load-string (slurp candidate-path)))
      (when (.isThreadAllocatedMemorySupported bean) (.setThreadAllocatedMemoryEnabled bean true))
      (prn {:baseline baseline :candidate-source (when candidate-path candidate-path)
            :candidate-sha256 (when candidate-path
                                (let [{:keys [exit out]} (shell/sh "shasum" "-a" "256" candidate-path)]
                                  (assert (zero? exit)) (first (str/split out #"\s+"))))
            :dns-source-blob ((helper 'source-id) "src/paclo/dns.clj")
            :runner-source-blob ((helper 'source-id) "dev/paclo/dev/dns_expiry_perf.clj")
            :scope suite :reverse? (boolean reverse-order) :warmups (cond (= suite "steady") 2
                                                                          (#{"short" "ordinary-hot"} suite) 20
                                                                          :else perf/warmups)
            :runs (if (= suite "steady") 5 perf/runs)
            :jdk (System/getProperty "java.version") :clojure (clojure-version)
            :os (System/getProperty "os.name") :arch (System/getProperty "os.arch")
            :heap-max (.maxMemory (Runtime/getRuntime))})
      (with-redefs-fn {(helper 'observable) observable
                       #'perf/current (assoc perf/current :dns (api))}
        #(case suite
           "correctness" (correctness-suite)
           "activation" (activation-suite base (boolean reverse-order))
           "restored-stress" (restored-stress-suite base (boolean reverse-order))
           "stress" ((helper 'stress-suite) base (boolean reverse-order))
           "boundary" (boundary-suite base (boolean reverse-order))
           "updates" (update-suite base (boolean reverse-order) false)
           "short" (with-redefs [perf/warmups 20]
                     (update-suite base (boolean reverse-order) true))
           "ordinary-hot" (with-redefs [perf/warmups 20]
                            (ordinary-suite base (boolean reverse-order) false))
           "retention" (retained-suite base)
           "restored-retention" (restored-retention-suite base false)
           "active-restored-retention" (restored-retention-suite base true)
           "steady" (with-redefs [perf/warmups 2 perf/runs 5]
                      ((helper 'steady-suite) base (boolean reverse-order)))
           "ordinary" (ordinary-suite base (boolean reverse-order) false)
           "low-density" (ordinary-suite base (boolean reverse-order) true)
           "pipeline" ((helper 'pipeline-suite) base (boolean reverse-order))
           "anomalies" ((helper 'anomalies-suite) base (boolean reverse-order))
           "trace" ((helper 'fixture-suite) base (boolean reverse-order) "test/resources/dns-sample.pcap")
           (throw (ex-info "unknown suite" {:suite suite})))))
    (finally (shutdown-agents))))
