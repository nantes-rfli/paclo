(ns paclo.dns-test
  (:require
   [clojure.edn :as edn]
   [clojure.test :refer [deftest is testing]]
   [clojure.test.check.clojure-test :refer [defspec]]
   [clojure.test.check.generators :as gen]
   [clojure.test.check.properties :as prop]
   [paclo.core :as core]
   [paclo.dns :as dns]
   [paclo.proto.dns-ext :as dns-ext]
   [paclo.stream :as stream]
   [paclo.window :as window])
  (:import
   [java.io Closeable]))

(declare exact-single-use-rtt deterministic-bounded-edn)

(def opts {:timeout-us 100 :reuse-delay-us 50 :max-pending 10 :max-retired 10})
(def query {:time-us 10 :kind :query :id 42 :protocol :udp :ip-version 4
            :src {:ip "192.0.2.1" :port 50000} :dst {:ip "192.0.2.53" :port 53}
            :qname "example.com" :qtype 1 :qclass 1})
(defn response [q t] (assoc q :kind :response :time-us t :src (:dst q) :dst (:src q) :rcode 0))
(defn add [s e] (:state (dns/step s e)))
(defn kinds [result] (mapv :kind (:events result)))
(defn reason [f] (try (f) nil (catch clojure.lang.ExceptionInfo e (:reason (ex-data e)))))

(deftest matching-retries-and-snapshots
  (let [initial (dns/init opts) state (add initial query)
        retried (add state (assoc query :time-us 15))
        earlier (add retried (assoc query :time-us 5))
        result (dns/step earlier (response query 20))]
    (is (= [:match] (kinds result)))
    (is (= 15 (get-in result [:events 0 :rtt-us])))
    (is (= 2 (get-in result [:events 0 :retransmissions])))
    (is (= 105 (get-in result [:events 0 :deadline-us])))
    (is (= 1 (count (:pending state))))
    (is (= 0 (:retransmissions (first (vals (:pending state))))))
    (is (= initial (dns/init opts)))
    (is (empty? (get-in result [:state :pending])))
    (is (= [:duplicate-or-expired-response] (kinds (dns/step (:state result) (response query 20)))))
    (is (= [:id-reuse] (kinds (dns/step (:state result) (assoc query :time-us 30)))))
    (is (= result (edn/read-string (pr-str result)))))
  (testing "RTT/deadline arithmetic promotes"
    (let [q (assoc query :time-us Long/MIN_VALUE)
          state (add (dns/init (assoc opts :timeout-us 30000000000000000000N)) q)
          result (dns/step state (response q Long/MAX_VALUE))]
      (is (= (-' Long/MAX_VALUE Long/MIN_VALUE) (get-in result [:events 0 :rtt-us]))))))

(deftest endpoints-version-and-question-disambiguate
  (doseq [other [(assoc query :id 43) (assoc-in query [:src :port] 50001)
                 (assoc-in query [:src :ip] "192.0.2.2") (assoc-in query [:dst :ip] "192.0.2.54")
                 (assoc query :qname "other.example") (assoc query :qtype 28) (assoc query :qclass 3)
                 (assoc query :ip-version 6 :src {:ip "2001:db8:0:0:0:0:0:1" :port 50000}
                        :dst {:ip "2001:db8:0:0:0:0:0:53" :port 53})]]
    (let [state (reduce add (dns/init opts) [query other])
          result (dns/step state (response other 20))]
      (is (= 2 (count (:pending state))))
      (is (= [:match] (kinds result)))
      (is (= 1 (count (get-in result [:state :pending]))))
      (is (= [:match] (kinds (dns/step (:state result) (response query 20)))))))
  (let [state (add (dns/init opts) (assoc query :qname "EXAMPLE.COM"))]
    (is (= [:match] (kinds (dns/step state (response query 20)))))))

(deftest expiry-and-id-reuse-boundaries
  (let [state (add (dns/init opts) query)
        before (dns/advance state 109)
        at (dns/advance (:state before) 110)
        released (dns/advance (:state at) 160)
        reused (add (:state released) (assoc query :time-us 160))]
    (is (= [] (:events before)))
    (is (= [:timeout] (kinds at)))
    (is (empty? (get-in at [:state :pending])))
    (is (= 1 (count (get-in at [:state :retired]))))
    (is (= [:duplicate-or-expired-response] (kinds (dns/step (:state at) (response query 120)))))
    (is (= [:late-event] (kinds (dns/step (:state at) (response query 109)))))
    (is (= [:id-reuse] (kinds (dns/step (:state at) (assoc query :time-us 120)))))
    (is (empty? (get-in released [:state :retired])))
    (is (= 1 (count (:pending reused))))
    (is (= [:match] (kinds (dns/step reused (response query 170)))))
    (is (= [] (:events (dns/advance (:state released) 160))))
    (is (= :watermark-regression (reason #(dns/advance (:state released) 159)))))
  (let [state (add (dns/init opts) query)]
    (is (= [:match] (kinds (dns/step state (response query 109)))))
    (doseq [t [110 111 1000]]
      (let [result (dns/step state (response query t))]
        (is (= [:timeout :unmatched-response] (kinds result)))
        (is (= :outside-timeout (get-in result [:events 1 :reason])))
        (is (empty? (get-in result [:state :pending])))))
    (is (= [:expiry-required] (kinds (dns/step state (assoc query :time-us 110)))))
    (let [all (dns/advance state 1000)]
      (is (empty? (get-in all [:state :pending])))
      (is (empty? (get-in all [:state :retired]))))))

(deftest ambiguity-unmatched-and-negative-rtt
  (let [initial (dns/init opts)
        unmatched (dns/step initial (response query 20))]
    (is (= [:unmatched-response] (kinds unmatched)))
    (is (= initial (:state unmatched)))
    (is (= [:unfinished] (kinds (dns/finish (add (:state unmatched) query))))))
  (doseq [k [:qname :qtype :qclass] e [query (response query 20)]]
    (let [state (add (dns/init opts) query) r (dns/step state (dissoc e k))]
      (is (= [:ambiguous-question] (kinds r)))
      (is (= state (:state r)))))
  (let [state (add (dns/init opts) query) result (dns/step state (response query 9))]
    (is (= [:negative-rtt] (kinds result)))
    (is (= -1 (get-in result [:events 0 :rtt-us])))
    (is (empty? (get-in result [:state :pending])))))

(deftest input-bounds-and-terminal-state
  (doseq [k [:timeout-us :reuse-delay-us :max-pending :max-retired] v [nil 0 -1 1.5]]
    (is (= :invalid-options (reason #(dns/init (assoc opts k v))))))
  (doseq [v [nil 1.5 "10"]]
    (is (= :invalid-time (reason #(dns/step (dns/init opts) (assoc query :time-us v)))))
    (is (= :invalid-time (reason #(dns/advance (dns/init opts) v)))))
  (doseq [e [(assoc query :id -1) (assoc query :protocol :tcp) (assoc query :qname identity)
             (assoc query :qtype 65536) (assoc query :qclass -1) (assoc query :rcode 16)
             (assoc-in query [:src :port] nil) (assoc-in query [:dst :port] 54)
             (assoc-in query [:src :ip] "host.example") (assoc query :ip-version 5)]]
    (is (= :invalid-event (reason #(dns/step (dns/init opts) e)))))
  (let [state (add (dns/init (assoc opts :max-pending 1 :max-retired 1)) query)
        matched (dns/step state (response query 20))
        other (assoc query :id 43) full (add (:state matched) other)]
    (is (= :max-pending (reason #(add state other))))
    (is (= 1 (:retransmissions (first (vals (:pending (add state query)))))))
    (is (= :max-retired (reason #(dns/step full (response other 20)))))
    (is (= :max-retired (reason #(dns/advance full 110))))
    (is (= 1 (count (:pending full))))
    (let [finished (dns/finish full)]
      (is (= [:unfinished] (kinds finished)))
      (is (empty? (get-in finished [:state :pending])))
      (is (empty? (get-in finished [:state :retired])))
      (is (= [] (:events (dns/finish (:state finished)))))
      (is (= :finished (reason #(dns/step (:state finished) query))))
      (is (= :finished (reason #(dns/advance (:state finished) 200))))))
  (is (= opts (:options (dns/init opts)))))

(deftest native-time-contract
  (is (= -1 (dns/packet-time-us {:ts-sec -1 :ts-usec 999999})))
  (is (= (+' (*' Long/MAX_VALUE 1000000) 999999)
         (dns/packet-time-us {:ts-sec Long/MAX_VALUE :ts-usec 999999})))
  (doseq [p [{} {:ts-sec 1} {:ts-sec 1 :ts-usec 1000000} {:ts-sec 1 :ts-usec -1}
             {:ts-sec 1.0 :ts-usec 0} {:sec 1 :usec 0} {:ts-sec 1 :ts-usec 0.1}]]
    (is (= :invalid-time (reason #(dns/packet-time-us p))))))

(def capture-opts {:path "test/resources/dns-sample.pcap" :max Long/MAX_VALUE
                   :decode? true :extensions [dns-ext/annotate-dns]})

(deftest packet-projection-contract
  (let [packet (first (core/packets capture-opts)) event (dns/packet->event packet)]
    (is (= :query (:kind event)))
    (is (= "example.com" (:qname event)))
    (is (= event (edn/read-string (pr-str event))))
    (is (not (contains? event :bytes)))
    (doseq [p [(assoc packet :diagnostics [{:stage :extension :reason :extension-exception}])
               (assoc packet :diagnostics [{:stage :decode :reason :unsupported-linktype}])
               (assoc packet :decode-error nil) (assoc packet :linktype 9999)
               (assoc-in packet [:decoded :l3 :frag?] true)
               (assoc-in packet [:decoded :l3 :l4 :app] nil)
               (assoc-in packet [:decoded :l3 :l4 :app :opcode] 1)
               (assoc-in packet [:decoded :l3 :l4 :app :qdcount] 2)
               (assoc-in packet [:decoded :l3 :l4 :data-len] 1)]]
      (is (nil? (dns/packet->event p))))
    (is (= :invalid-time (reason #(dns/packet->event (dissoc packet :ts-sec)))))
    (is (= [:ambiguous-question]
           (kinds (dns/step (dns/init opts)
                            (dns/packet->event (update-in packet [:decoded :l3 :l4 :app] dissoc :qname)))))))
  (let [raw (first (core/packets (select-keys capture-opts [:path :max])))
        unannotated (first (sequence (core/packet-xf {:decode? true :extensions []}) [raw]))]
    (is (nil? (:qname (dns/packet->event unannotated))))
    (is (= [:ambiguous-question] (kinds (dns/step (dns/init opts) (dns/packet->event unannotated)))))
    (is (nil? (dns/packet->event raw))))
  (let [packet (first (core/packets capture-opts))
        v6 (-> packet (assoc-in [:decoded :l3 :type] :ipv6)
               (assoc-in [:decoded :l3 :src] "2001:0DB8:0:0:0:0:0:1")
               (assoc-in [:decoded :l3 :dst] "2001:db8:0:0:0:0:0:53"))]
    (is (= 6 (:ip-version (dns/packet->event v6))))
    (is (= "2001:db8:0:0:0:0:0:1" (get-in (dns/packet->event v6) [:src :ip])))))

(defn replay-step [{:keys [state events]} event]
  (let [r (dns/step state event)] {:state (:state r) :events (into events (:events r))}))
(defn replay [events]
  (let [r (reduce replay-step {:state (dns/init (assoc opts :timeout-us 10000000)) :events []} events)
        final (dns/advance (:state r) (+' (reduce max 0 (map :time-us events)) 20000000))]
    {:state (:state final) :events (into (:events r) (:events final))}))

(deftest actual-pcap-analysis-paths
  (let [packets (vec (core/packets capture-opts)) events (mapv dns/packet->event packets)
        initial {:state (dns/init (assoc opts :timeout-us 10000000)) :events []}
        packet-rf (fn [s p] (replay-step s (dns/packet->event p)))
        accumulated (reduce replay-step initial events)
        expected (replay events)
        complete (fn [r] (let [last (dns/advance (:state r) (+' (reduce max 0 (map :time-us events)) 20000000))]
                           {:state (:state last) :events (into (:events r) (:events last))}))]
    (is (= [:query :response :query :response] (mapv :kind events)))
    (is (= [:match :match] (kinds expected)))
    (is (= accumulated (transduce (map dns/packet->event) (completing replay-step) initial packets)))
    (is (= expected (complete (core/reduce-packets capture-opts packet-rf initial))))
    (with-open [^Closeable capture (core/start-capture capture-opts)]
      (is (= expected (complete (reduce packet-rf initial (core/capture-packets capture))))))
    (with-open [^Closeable capture (core/start-capture capture-opts)
                ^Closeable fanout (stream/fan-out (core/capture-packets capture)
                                                  {:a {:buffer-mode :blocking :buffer-cap 1}
                                                   :b {:buffer-mode :blocking :buffer-cap 1}}
                                                  {:cancel! #(core/stop-capture! capture)})
                ^Closeable a (stream/branch fanout :a) ^Closeable b (stream/branch fanout :b)]
      (let [left (future (complete (reduce packet-rf initial a)))
            right (future (complete (transduce (map dns/packet->event) (completing replay-step)
                                               {:state (dns/init (assoc opts :timeout-us 10000000)) :events []} b)))]
        (is (= expected (deref left 10000 :timeout)))
        (is (= expected (deref right 10000 :timeout)))))
    (is (= initial {:state (dns/init (assoc opts :timeout-us 10000000)) :events []}))
    (let [wopts {:width-us 1000000 :max-windows 10 :max-groups 10}
          rf (fn [s p] (:state (window/step s {:time-us (dns/packet-time-us p)
                                               :group :dns :captured-bytes (:caplen p)})))
          expected (reduce rf (window/init wopts) packets)]
      (is (= expected (core/reduce-packets capture-opts rf (window/init wopts))))
      (with-open [^Closeable capture (core/start-capture capture-opts)]
        (is (= expected (reduce rf (window/init wopts) (core/capture-packets capture))))))))

(defspec exact-single-use-rtt 200
  (prop/for-all [t gen/large-integer rtt (gen/choose 0 99) retries (gen/choose 0 5)]
                (let [q (assoc query :time-us t)
                      state (reduce add (dns/init opts) (repeat (inc retries) q))
                      r (dns/step state (response q (+' t rtt)))
                      duplicate (dns/step (:state r) (response q (+' t rtt)))]
                  (and (= [:match] (kinds r)) (= rtt (get-in r [:events 0 :rtt-us]))
                       (= retries (get-in r [:events 0 :retransmissions]))
                       (not-any? #(= :match (:kind %)) (:events duplicate))
                       (empty? (get-in r [:state :pending]))))))

(defspec deterministic-bounded-edn 200
  (prop/for-all [ids (gen/vector (gen/choose 0 9) 0 50)]
                (let [events (mapv #(assoc query :id %) ids)
                      initial (dns/init opts) states (reductions add initial events)
                      result (dns/advance (last states) 160)]
                  (and (= (last states) (reduce add initial events))
                       (= result (edn/read-string (pr-str result)))
                       (every? #(<= (count (:pending %)) 10) states)
                       (empty? (get-in result [:state :pending]))
                       (empty? (get-in result [:state :retired])) (= initial (dns/init opts))))))

(deftest real-decoder-ipv6-and-incomplete-header
  (let [packet (first (core/packets capture-opts))
        raw (vec (:bytes packet))
        udp (subvec raw 34)
        address (fn [last-word] [0x20 0x01 0x0d 0xb8 0 0 0 0 0 0 0 0 0 0 0 last-word])
        bytes (byte-array (map unchecked-byte
                               (concat (subvec raw 0 12) [0x86 0xdd]
                                       [0x60 0 0 0 0 (count udp) 17 64]
                                       (address 1) (address 53) udp)))
        decode (core/packet-xf {:decode? true :extensions [dns-ext/annotate-dns]})
        v6 (first (sequence decode [(assoc packet :bytes bytes :caplen (alength bytes) :len (alength bytes))]))
        short (byte-array (take (+ 34 8 11) raw))]
    (is (= 6 (:ip-version (dns/packet->event v6))))
    (is (= "2001:db8:0:0:0:0:0:1" (get-in (dns/packet->event v6) [:src :ip])))
    ;; Keep network/transport lengths internally consistent; DNS alone is short.
    (aset-byte short 17 (byte 39))
    (aset-byte short 39 (byte 19))
    (is (nil? (dns/packet->event (first (sequence decode [(assoc packet :bytes short)])))))
    (let [file (java.io.File/createTempFile "paclo-dns-v6" ".pcap")]
      (try
        (core/write-pcap! [(assoc packet :bytes bytes :caplen (alength bytes) :len (alength bytes))]
                          (.getAbsolutePath file))
        (is (= (dns/packet->event v6)
               (dns/packet->event (first (core/packets (assoc capture-opts :path (.getAbsolutePath file)))))))
        (finally (.delete file))))
    (is (= raw (vec (:bytes packet))))))

(deftest normalization-drops-non-data-and-canonicalizes-addresses
  (let [input (assoc query :bytes (byte-array 10) :extra (Throwable.) :delayed (delay query))
        state (add (dns/init opts) (assoc-in input [:src :ip] "192.000.002.001"))
        q (:query (first (vals (:pending state))))]
    (is (= query q))
    (is (= state (edn/read-string (pr-str state)))))
  (is (= 100 (get-in (dns/init (dissoc opts :reuse-delay-us)) [:options :reuse-delay-us]))))

(declare bounded-mixed-transitions)

(defspec bounded-mixed-transitions 200
  (prop/for-all [actions (gen/vector (gen/tuple (gen/elements [:query :response :advance])
                                                (gen/choose 0 9) (gen/choose -50 300)) 0 60)]
                (let [run (fn []
                            (reduce (fn [rs [kind id t]]
                                      (let [s (:state (peek rs))
                                            r (if (= :advance kind)
                                                (dns/advance s (max (or (:watermark-us s) t) t))
                                                (dns/step s (if (= :query kind)
                                                              (assoc query :id id :time-us t)
                                                              (response (assoc query :id id) t))))]
                                        (conj rs r)))
                                    [{:state (dns/init opts) :events []}] actions))
                      results (run)]
                  (and (= results (run)) (= results (edn/read-string (pr-str results)))
                       (every? #(and (<= (count (get-in % [:state :pending])) 10)
                                     (<= (count (get-in % [:state :retired])) 10)) results)
                       (every? (fn [r]
                                 (every? #(or (not= :match (:kind %))
                                              (= (:rtt-us %) (-' (get-in % [:response :time-us])
                                                                 (get-in % [:query :time-us])))) (:events r))) results)
                       (= (dns/init opts) (:state (first results)))))))

(deftest windows-with-identical-explicit-watermark-across-capture-paths
  (let [packets (vec (core/packets capture-opts))
        times (mapv dns/packet-time-us packets)
        watermark (+' (reduce max times) 1000000)
        options {:width-us 1000000 :max-windows 10 :max-groups 10}
        event (fn [p group] {:time-us (dns/packet-time-us p) :group group :captured-bytes (:caplen p)})
        rf (fn [s p] (:state (window/step s (event p :dns))))
        finalize #(window/advance % watermark)
        expected (finalize (reduce rf (window/init options) packets))]
    (is (= expected (finalize (transduce (map #(event % :dns))
                                         (completing (fn [s e] (:state (window/step s e))))
                                         (window/init options) packets))))
    (is (= expected (finalize (core/reduce-packets capture-opts rf (window/init options)))))
    (with-open [^Closeable capture (core/start-capture capture-opts)]
      (is (= expected (finalize (reduce rf (window/init options) (core/capture-packets capture))))))
    (with-open [^Closeable capture (core/start-capture capture-opts)
                ^Closeable fanout (stream/fan-out (core/capture-packets capture)
                                                  {:a {:buffer-mode :blocking :buffer-cap 1}
                                                   :b {:buffer-mode :blocking :buffer-cap 1}}
                                                  {:cancel! #(core/stop-capture! capture)})
                ^Closeable a (stream/branch fanout :a) ^Closeable b (stream/branch fanout :b)]
      (let [left (future (finalize (reduce rf (window/init options) a)))
            right (future (finalize (reduce (fn [s p] (:state (window/step s (event p :other))))
                                            (window/init options) b)))
            left (deref left 10000 :timeout) right (deref right 10000 :timeout)]
        (is (= expected left))
        (is (= (mapv #(get-in % [:groups :dns]) (:events left))
               (mapv #(get-in % [:groups :other]) (:events right))))
        (is (every? #(= #{:other} (set (keys (:groups %)))) (:events right)))))))

(deftest addresses-and-restored-state
  (doseq [address ["192.0.2.1." "192.0.2.256" "192.0.2" "2001:db8::1" "1:2:3:4:5:6:7:8:"]]
    (is (= :invalid-event (reason #(dns/step (dns/init opts) (assoc-in query [:src :ip] address))))))
  (let [state (add (dns/init opts) query)
        restored (edn/read-string (pr-str state))]
    (is (= (dns/step state (response query 20)) (dns/step restored (response query 20))))
    (is (= (dns/advance state 110) (dns/advance restored 110)))
    (is (= (dns/finish state) (dns/finish restored)))))

(deftest mixed-quarantine-expiry-preserves-live-keys-and-snapshots
  (let [other (assoc query :id 43 :time-us 20)
        first-state (:state (dns/step (add (dns/init opts) query) (response query 11)))
        state (:state (dns/step (add first-state other) (response other 21)))
        before (dns/advance state 159)
        at (dns/advance state 160)
        after (dns/advance (:state at) 170)]
    (is (= 2 (count (:retired state))))
    (is (= (:retired state) (get-in before [:state :retired])))
    (is (= 1 (count (get-in at [:state :retired]))))
    (is (= [:id-reuse] (kinds (dns/step (:state at) (assoc other :time-us 160)))))
    (is (= [] (kinds (dns/step (:state at) (assoc query :time-us 160)))))
    (is (empty? (get-in after [:state :retired])))
    (is (= 2 (count (:retired state))))))
