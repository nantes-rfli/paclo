(ns examples.dns-cli-test
  (:require
   [clojure.core.async :as async]
   [clojure.data.json :as json]
   [clojure.edn :as edn]
   [clojure.java.shell :as shell]
   [clojure.string :as str]
   [clojure.test :refer [deftest is]]
   [clojure.test.check.clojure-test :refer [defspec]]
   [clojure.test.check.generators :as gen]
   [clojure.test.check.properties :as prop]
   [examples.common :as ex]
   [examples.dns-cli :as cli]
   [examples.dns-qps :as qps]
   [examples.dns-rtt :as rtt]
   [paclo.core :as core]
   [paclo.dns :as dns]
   [paclo.pcap :as pcap]))

(declare bounded-top-n-reference exact-statistics-reference packet-window-reference
         exact-sample-capacity-never-truncates)

(defn packet
  ([time response?] (packet time response? 42 "example.com"))
  ([time response? id name]
   {:ts-sec (quot (-' time (mod time 1000000)) 1000000) :ts-usec (mod time 1000000)
    :caplen 80 :len 200 :bytes (byte-array 80) :linktype 1
    :decoded {:l3 {:type :ipv4 :src (if response? "192.0.2.53" "192.0.2.1")
                   :dst (if response? "192.0.2.1" "192.0.2.53")
                   :l4 {:type :udp :src-port (if response? 53 50000) :dst-port (if response? 50000 53)
                        :length 40 :data-len 32
                        :app {:type :dns :id id :qr? response? :flags-raw (if response? 32768 0)
                              :opcode 0 :qdcount 1 :qname name :qtype 1 :qclass 1
                              :qtype-name :A :rcode 0 :rcode-name "noerror"}}}}}))

(defn analyze [init step finish report opts packets]
  (let [s (reduce step (init opts) packets) ended (finish s)]
    {:state ended :report (report ended)}))
(defn rtt-analysis [opts packets] (analyze rtt/init rtt/step rtt/finish rtt/report opts packets))
(defn qps-analysis [opts packets] (analyze qps/init qps/step qps/finish qps/report opts packets))
(defn reason [f] (try (f) nil (catch clojure.lang.ExceptionInfo e (:reason (ex-data e)))))
(defn run-main [f & args]
  (let [out (java.io.StringWriter.) err (java.io.StringWriter.)]
    (binding [*out* out *err* err] (apply f args))
    {:out (str out) :err (str err)}))

(deftest rtt-values-statistics-filter-and-ranking
  (let [packets (mapcat (fn [i us] [(packet (* i 10000) false i "a.example")
                                    (packet (+ (* i 10000) us) true i "a.example")])
                        (range) [100 200 300 400 500])
        {:keys [report]} (rtt-analysis {:mode :stats} packets)]
    (is (= 5 (:pairs report) (:with-rtt report)))
    (is (= {:count 5 :min 0.1 :p50 0.3 :p95 0.5 :p99 0.5 :avg 0.3 :max 0.5} (:rtt report)))
    (is (= {:noerror 5} (get-in report [:rcode :counts])))
    (is (= 0 (:pairs (:report (rtt-analysis {:mode :stats :client "198.51.100"} packets)))))
    (is (= 5 (:pairs (first (:report (rtt-analysis {:mode :qstats :metric :p95} packets))))))
    (is (= [0.1 0.2] (mapv :rtt-ms (:report (rtt-analysis {:topn 2} packets))))))
  (let [ps [(packet 0 false 2 "b.example") (packet 100 true 2 "b.example")
            (packet 200 false 1 "a.example") (packet 300 true 1 "a.example")]]
    (is (= [1 2] (mapv :id (:report (rtt-analysis {} ps)))))
    (is (= ["a.example" "b.example"] (mapv :qname (:report (rtt-analysis {:mode :qstats} ps)))))))

(deftest strict-correlation-and-watermarks
  (let [q (packet 100 false) r (packet 200 true)
        replay [q (packet 120 false) r r (packet 300 false)]
        result (rtt-analysis {} replay)]
    (is (= 1 (count (:report result))))
    (is (= 0.1 (:rtt-ms (first (:report result)))))
    (is (= {:duplicate-or-expired-response 1 :id-reuse 1 :retransmissions 1} (get-in result [:state :diagnostics]))))
  (doseq [[packets opts diagnostic]
          [[[(packet 100 true)] {} :unmatched-response]
           [[(update-in (packet 100 false) [:decoded :l3 :l4 :app] dissoc :qclass)] {} :ambiguous-question]
           [[(assoc (packet 100 false) :diagnostics [{:stage :dns}])] {} :ineligible-packet]
           [[(packet 100 false) (packet 90 true)] {:reorder-us 20} :negative-rtt]
           [[(packet 100 false) (packet 90 true)] {} :late-event]
           [[(packet 100 false) (packet 200 true)] {:timeout-us 50 :reuse-delay-us 50} :timeout]
           [[(packet 100 false)] {} :unfinished]]]
    (let [r (rtt-analysis opts packets)]
      (is (empty? (:report r)))
      (is (= 1 (get-in r [:state :diagnostics diagnostic])))))
  (let [ps [(packet 0 false) (packet 10 true) (packet 21 false) (packet 25 true)]
        result (rtt-analysis {:timeout-us 10 :reuse-delay-us 10} ps)]
    ;; Deadline equality expires first transaction; quarantine has released by 21.
    (is (= [0.004] (mapv :rtt-ms (:report result)))))
  (is (= :invalid-time (reason #(rtt/step (rtt/init {}) (dissoc (packet 0 false) :ts-sec))))))

(deftest rtt-retention-limits
  (let [q (packet 0 false 1 "a") other (packet 0 false 2 "b")]
    (is (= :max-pending (reason #(reduce rtt/step (rtt/init {:max-pending 1}) [q other]))))
    (is (= :max-retired (reason #(reduce rtt/step (rtt/init {:max-retired 1})
                                         [q (packet 1 true 1 "a") (packet 2 false 2 "b") (packet 3 true 2 "b")])))))
  (let [ps [(packet 0 false 1 "a") (packet 1 true 1 "a")
            (packet 2 false 2 "b") (packet 3 true 2 "b")]]
    (is (= :max-samples (reason #(rtt-analysis {:mode :stats :max-samples 1 :topn 1} ps))))
    (is (= :max-qnames (reason #(rtt-analysis {:mode :qstats :max-qnames 1} ps))))
    (let [s (reduce rtt/step (rtt/init {:mode :pairs :topn 1 :max-samples 1}) ps)]
      (is (= 2 (:pairs s))) (is (= 1 (count (:candidates s))))
      (is (empty? (:samples s))) (is (empty? (:qstats s))))))

(deftest qps-packet-counts-time-bytes-and-groups
  (let [ps [(packet 0 false) (packet 10 true) (packet 999999 false 43 "other")
            (packet 1000000 false)]
        r (:report (qps-analysis {} ps))]
    (is (= [{:t 0 :key :noerror :count 3 :bytes 240}
            {:t 1000 :key :noerror :count 1 :bytes 80}] r))
    (is (= 3 (count (:report (qps-analysis {:group :qname} ps)))))
    (is (= 3 (count (:report (qps-analysis {:bucket-ms 200} ps)))))
    (doseq [group [:rrtype :qname-suffix :client :server]]
      (is (seq (:report (qps-analysis {:group group} ps))))))
  (let [incomplete (update-in (packet 0 false) [:decoded :l3 :l4 :app] dissoc :qclass)]
    (is (nil? (:qclass (dns/packet->event incomplete))))
    (is (= 1 (:count (first (:report (qps-analysis {} [incomplete]))))))
    (is (empty? (:report (rtt-analysis {} [incomplete])))))
  (is (= -1000 (:t (first (:report (qps-analysis {} [(packet -1 false)]))))))
  (is (= 1000000000000000000000N
         (:t (first (:report (qps-analysis {} [(packet 1000000000000000000000000N false)])))))))

(deftest qps-out-of-order-watermark-and-late
  (let [ps [(packet 1000000 false) (packet 0 false)]
        late (qps-analysis {} ps) allowed (qps-analysis {:reorder-us 1000000} ps)]
    (is (= 1 (count (:report late))))
    (is (= 1 (get-in late [:state :diagnostics :late-event])))
    (is (= 2 (count (:report allowed))))
    (is (= 0 (get-in allowed [:state :analysis :watermark-us]))))
  (let [s (reduce qps/step (qps/init {}) [(packet 0 false) (packet 1000000 false)])]
    (is (= 1 (count (:rows s))))
    (is (= 1 (count (get-in s [:analysis :windows]))))
    (is (= 1 (:open-tail-windows (qps/finish s))))))

(deftest empty-buckets-preserve-all-groups-and-preflight
  (let [ps [(packet 0 false 1 "a") (packet 0 false 2 "b") (packet 2000000 false 3 "a")]
        opts {:group :qname :emit-empty? true}
        rows (:report (qps-analysis opts ps))]
    (is (= 4 (count rows)))
    (is (= 2 (count (filter #(zero? (:t %)) rows))))
    (is (= [{:t 1000 :key :_all :count 0 :bytes 0}] (filterv #(= 1000 (:t %)) rows)))
    (is (= 6 (count (:report (qps-analysis (assoc opts :emit-empty-per-key? true) ps)))))
    (is (= :max-buckets (reason #(qps-analysis (assoc opts :max-buckets 3) ps))))
    (is (= :max-buckets (reason #(qps-analysis (assoc opts :emit-empty-per-key? true :max-buckets 5) ps)))))
  (is (= :max-buckets (reason #(qps-analysis {:emit-empty? true :max-buckets 10}
                                             [(packet 0 false) (packet 10000000000000000000000N false)]))))
  (is (= [] (:report (qps-analysis {:emit-empty-per-key? true} [])))))

(deftest independent-qps-limits
  (is (= :max-windows (reason #(qps-analysis {:max-windows 1 :reorder-us 3000000}
                                             [(packet 0 false) (packet 1000000 false)]))))
  (is (= :max-groups (reason #(qps-analysis {:max-groups 1 :group :qname}
                                            [(packet 0 false 1 "a") (packet 0 false 2 "b")]))))
  (is (= :max-buckets (reason #(qps-analysis {:max-buckets 1}
                                             [(packet 0 false) (packet 1000000 false)])))))

(deftest real-fixture-sync-async-formats-and-alert
  (doseq [[f positional] [[rtt/-main ["_" "_" "stats" "_" "edn"]]
                          [rtt/-main ["_" "_" "qstats" "p95" "edn"]]
                          [qps/-main ["_" "1000" "rcode" "edn"]]]]
    (let [sync (apply run-main f "test/resources/dns-sample.pcap" positional)
          async (apply run-main f "test/resources/dns-sample.pcap" (concat positional ["--async" "--async-buffer" "1"]))]
      (is (= (edn/read-string (:out sync)) (edn/read-string (:out async))))
      (is (str/includes? (:err async) ":complete? true"))))
  (let [p "test/resources/dns-sample.pcap"
        edn (edn/read-string (:out (run-main qps/-main p)))
        js (:out (run-main qps/-main p "_" "_" "_" "jsonl"))
        csv (:out (run-main qps/-main p "_" "_" "_" "csv"))]
    (is (= (mapv :count edn) (mapv #(get (json/read-str %) "count") (str/split-lines js))))
    (is (= "t_ms,key,count,bytes" (first (str/split-lines csv))))
    (is (= (inc (count edn)) (count (str/split-lines csv)))))
  (let [s (rtt/finish (reduce rtt/step (rtt/init {})
                              [(packet 0 false) (-> (packet 100 true)
                                                    (assoc-in [:decoded :l3 :l4 :app :rcode] 3))]))
        err (java.io.StringWriter.)]
    (binding [*err* err] (#'rtt/alert! s 50))
    (is (str/includes? (str err) "100.00%")))
  (is (= "www.例え.テスト" (#'qps/normalize-qname "www.xn--r8jz45g.xn--zckzah." true false))))

(deftest execution-zero-timeout-errors-and-join
  (let [closed (atom 0) packet (packet 0 false)
        source (fn [_ step init] (try (reduce step init (repeat 100 packet)) (finally (swap! closed inc))))]
    (with-redefs [core/reduce-packets source]
      (is (= :consumer-error
             (reason #(cli/run {} (fn [& _] (throw (ex-info "consumer" {:reason :consumer-error})))
                               nil (assoc cli/execution-defaults :async? true :async-buffer 1)))))
      (is (= 1 @closed))))
  (let [error (ex-info "source failure" {:reason :source-error})]
    (with-redefs [core/reduce-packets (fn [& _] (throw error))]
      (doseq [async? [false true]]
        (is (= :source-error (reason #(cli/run {} conj [] (assoc cli/execution-defaults :async? async?))))))))
  (with-redefs [core/reduce-packets (fn [& _] (throw (Exception. "must not open")))
                async/timeout (fn [_] (throw (Exception. "must not schedule")))]
    (let [r (cli/run {} conj [] (assoc cli/execution-defaults :async? true :async-timeout-ms 0))]
      (is (= [] (:state r))) (is (true? (get-in r [:execution :cancelled?])))
      (is (false? (get-in r [:execution :complete?]))))))

(deftest deterministic-drops-and-midway-cancel
  (let [started (promise) release (promise) closed (promise)
        source (fn [_ step init]
                 (try
                   (step init :first) (deliver started true) @release
                   (reduce step init (repeat 5 :next))
                   (finally (deliver closed true))))
        slow-step (fn [s p] (deliver release true) (is (= true (deref closed 5000 :timeout))) (conj s p))]
    (with-redefs [core/reduce-packets source]
      (let [r (cli/run {} slow-step [] (assoc cli/execution-defaults :async? true :async-buffer 1 :async-mode :dropping))]
        (is (= true @started))
        (is (= 6 (get-in r [:execution :read])))
        (is (= 4 (get-in r [:execution :dropped])))
        (is (= 2 (get-in r [:execution :delivered])))
        (is (false? (get-in r [:execution :complete?]))))))
  (let [cancel (async/chan) closed (promise)
        source (fn [_ step init] (try (reduce step init (range 100)) (finally (deliver closed true))))]
    (with-redefs [core/reduce-packets source async/timeout (fn [^long _] cancel)]
      (let [r (cli/run {} (fn [s p] (async/close! cancel) (conj s p)) []
                       (assoc cli/execution-defaults :async? true :async-buffer 1 :async-timeout-ms 100))]
        (is (= [0] (:state r)))
        (is (= true (deref closed 5000 :timeout)))
        (is (true? (get-in r [:execution :cancelled?])))))))

(deftest real-owner-closes-on-consumer-and-source-errors
  (doseq [async? [false true] source-error? [false true]]
    (let [closed (atom 0)]
      (with-redefs [pcap/open-offline (constantly :handle) pcap/datalink (constantly 1)
                    pcap/close! (fn [_] (swap! closed inc))
                    pcap/loop-n-or-ms! (fn [_ _ handler]
                                         (if source-error? (throw (ex-info "read" {:reason :read}))
                                             (handler (packet 0 false))))]
        (is (= (if source-error? :read :reducer)
               (reason #(cli/run {:path "stub"} (fn [& _] (throw (ex-info "reduce" {:reason :reducer})))
                                 nil (assoc cli/execution-defaults :async? async? :async-buffer 1)))))
        (is (= 1 @closed))))))

(deftest cli-failure-contract-and-no-partial-output
  ;; Substitute exit only for in-process validation; subprocess below checks the real status.
  (with-redefs [ex/error-exit! (fn [message code] (throw (ex-info message {:exit code})))]
    (doseq [[f args] [[qps/-main ["test/resources/dns-sample.pcap" "--max-buckets" "1"]]
                      [rtt/-main ["test/resources/dns-sample.pcap" "_" "1" "stats" "--max-samples" "1"]]]]
      (let [out (java.io.StringWriter.)]
        (binding [*out* out]
          (try (apply f args) (is false) (catch clojure.lang.ExceptionInfo e (is (= 5 (:exit (ex-data e)))))))
        (is (= "" (str out)))))
    (doseq [flags [["--async-buffer" "0"] ["--async-timeout-ms" "-1"] ["--reorder-us" "-1"] ["--max-buckets" "0"] ["--bogus"]]]
      (try (cli/parse-flags flags {} {"--max-buckets" [:max-buckets 1]})
           (is false) (catch clojure.lang.ExceptionInfo e (is (= 4 (:exit (ex-data e))))))))
  (let [{:keys [exit out err]} (shell/sh "clojure" "-M:dev:dns-ext" "-m" "examples.dns-qps"
                                         "test/resources/dns-sample.pcap" "--max-buckets" "1")]
    (is (= 5 exit)) (is (str/blank? out)) (is (str/includes? err "max-buckets"))))

(defspec bounded-top-n-reference 100
  (prop/for-all [rtts (gen/vector (gen/choose 0 999) 1 30) top (gen/choose 1 10)]
                (let [ps (mapcat (fn [i us] [(packet (* i 10000) false i "q") (packet (+ (* i 10000) us) true i "q")]) (range) rtts)
                      states (reductions rtt/step (rtt/init {:topn top}) ps)
                      result (rtt/report (rtt/finish (last states)))]
                  (and (= (mapv #(/ % 1000.0) (take top (sort rtts))) (mapv :rtt-ms result))
                       (every? #(<= (count (:candidates %)) top) states)
                       (every? #(empty? (:samples %)) states)
                       (= result (:report (rtt-analysis {:topn top} ps)))))))

(defspec exact-statistics-reference 100
  (prop/for-all [values (gen/vector (gen/choose 0 999) 1 30)]
                (let [ps (mapcat (fn [i us] [(packet (* i 10000) false i "q") (packet (+ (* i 10000) us) true i "q")]) (range) values)
                      stats (:rtt (:report (rtt-analysis {:mode :stats :max-samples 50 :topn 1} ps)))
                      ordered (sort values) n (count values)
                      percentile (fn [p] (/ (nth (vec ordered) (dec (long (Math/ceil (* n p))))) 1000.0))]
                  (and (= (percentile 0.5) (:p50 stats)) (= (percentile 0.95) (:p95 stats))
                       (= (percentile 0.99) (:p99 stats))
                       (= (/ (double (/ (reduce + values) n)) 1000.0) (:avg stats))))))

(defspec packet-window-reference 100
  (prop/for-all [times (gen/vector (gen/choose -1000000 3000000) 0 40) width (gen/choose 1 1000)]
                (let [ps (map #(packet % false) times) opts {:bucket-ms width :reorder-us 5000000}
                      states (reductions qps/step (qps/init opts) ps)
                      rows (qps/report (qps/finish (last states)))
                      expected (->> times (group-by #(-' % (mod % (* width 1000))))
                                    (map (fn [[t xs]] {:t (quot t 1000) :key :noerror :count (count xs) :bytes (* 80 (count xs))}))
                                    (sort-by :t) vec)]
                  (and (= expected rows) (= rows (:report (qps-analysis opts ps)))
                       (every? #(<= (get-in % [:analysis :group-count]) 200000) states)))))

(deftest independent-analysis-runs-and-no-global-extension-change
  (let [source (cli/capture-options "test/resources/dns-sample.pcap" "udp and port 53")
        execution (assoc cli/execution-defaults :async? true :async-buffer 1)
        a (future (cli/run source rtt/step (rtt/init {:mode :stats}) execution))
        b (future (cli/run source qps/step (qps/init {:group :qname}) execution))
        ra (deref a 10000 :timeout) rb (deref b 10000 :timeout)]
    (is (map? ra)) (is (map? rb))
    (when (and (map? ra) (map? rb))
      (is (= 2 (:pairs (rtt/report (rtt/finish (:state ra))))))
      (is (= 4 (reduce + (map :count (qps/report (qps/finish (:state rb)))))))
      (is (true? (get-in ra [:execution :complete?])))
      (is (true? (get-in rb [:execution :complete?]))))))

(deftest offline-cli-reads-beyond-capture-defaults
  (let [frame (first (core/reduce-packets {:path "test/resources/dns-sample.pcap" :max 1} conj []))
        file (java.io.File/createTempFile "paclo-qps-long" ".pcap")]
    (try
      (core/write-pcap! (map #(assoc frame :ts-sec % :ts-usec 0) (range 120)) (.getAbsolutePath file))
      (doseq [flags [[] ["--async" "--async-buffer" "1"]]]
        (let [rows (edn/read-string (:out (apply run-main qps/-main (.getAbsolutePath file) flags)))]
          (is (= 120 (reduce + (map :count rows))))))
      (is (> (:max-time-ms (cli/capture-options "unused" "udp")) 10000))
      (finally (.delete file)))))

(deftest jsonl-pairs-and-qstats-use-only-matched-rows
  (doseq [mode ["pairs" "qstats"]]
    (let [result (run-main rtt/-main "test/resources/dns-sample.pcap" "_" "_" mode "_" "jsonl")
          rows (mapv json/read-str (str/split-lines (:out result)))]
      (is (= 2 (count rows)))
      (is (every? #(contains? % "qname") rows))
      (is (not-any? #(contains? % "async?") rows)))))

(defspec exact-sample-capacity-never-truncates 100
  (prop/for-all [n (gen/choose 1 15) maximum (gen/choose 1 15)]
                (let [ps (mapcat (fn [i] [(packet (* i 1000) false i "q")
                                          (packet (+ (* i 1000) 1) true i "q")]) (range n))
                      result (try (rtt-analysis {:mode :stats :topn 1 :max-samples maximum} ps)
                                  (catch clojure.lang.ExceptionInfo e (:reason (ex-data e))))]
                  (if (> n maximum)
                    (= :max-samples result)
                    (and (= n (get-in result [:report :pairs]))
                         (= n (count (get-in result [:state :samples]))))))))

(deftest qps-client-server-groups-follow-dns-message-roles
  (let [ps [(packet 0 false 1 "a") (packet 100 true 1 "a")
            (packet 200 false 2 "b") (packet 300 true 2 "b")]]
    (doseq [[group ip] [[:client "192.0.2.1"] [:server "192.0.2.53"]]]
      (is (= [{:t 0 :key ip :count 4 :bytes 320}]
             (:report (qps-analysis {:group group} ps)))))))
