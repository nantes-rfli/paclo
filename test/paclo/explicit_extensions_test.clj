(ns paclo.explicit-extensions-test
  (:require
   [clojure.test :refer [deftest is testing]]
   [clojure.test.check.clojure-test :refer [defspec]]
   [clojure.test.check.generators :as gen]
   [clojure.test.check.properties :as prop]
   [paclo.core :as core]
   [paclo.decode-ext :as dx]
   [paclo.parse :as parse]
   [paclo.pcap :as pcap]
   [paclo.proto.dns-ext :as dns]
   [paclo.proto.tls-ext :as tls]
   [paclo.stream :as stream]))

(declare explicit-composition-preserves-order-and-isolates-failure)

(defn- mark [value]
  (fn [m] (update m :order (fnil conj []) value)))

(defn- transform [xf]
  (first (into [] xf [{:bytes (byte-array 14)}])))

(deftest ordered-selection-including-empty-and-duplicates
  (with-redefs [parse/packet->clj (constantly {})]
    (let [a (mark :a)
          b (mark :b)]
      (doseq [[extensions expected] [[[] nil] [[a] [:a]] [[b a a] [:b :a :a]]]]
        (is (= expected (:order (transform (core/packet-xf
                                            {:decode? true :extensions extensions})))))))))

(deftest explicit-selection-is-independent-of-dynamic-registration
  (with-redefs [parse/packet->clj (constantly {})]
    (let [legacy (core/packet-xf {:decode? true})
          empty-xf (core/packet-xf {:decode? true :extensions []})
          a (core/packet-xf {:decode? true :extensions [(mark :a)]})
          b (core/packet-xf {:decode? true :extensions [(mark :b)]})]
      (try
        (dx/register! ::global (mark :global))
        (is (= [:global] (:order (transform legacy))))
        (is (nil? (:order (transform empty-xf))))
        (is (= [:a] (:order (transform a))))
        (is (= [:b] (:order (transform b))))
        (dx/register! ::global (mark :changed))
        (is (= [:changed] (:order (transform legacy))))
        (is (= [:a] (:order (transform a))))
        (is (= [:b] (:order (transform b))))
        (dx/unregister! ::global)
        (is (nil? (:order (transform legacy))))
        (is (= [:a] (:order (transform a))))
        (finally (dx/unregister! ::global))))))

(deftest invalid-options-fail-before-opening-any-source
  (let [opened (atom 0)
        invalid (concat
                 (map #(hash-map :decode? true :extensions %)
                      [nil {} :hook "hook" '(identity) [nil] [{}] [:hook]
                       ["hook"] [identity 1]])
                 [{:extensions []} {:decode? false :extensions []}
                  {:decode? :truthy :extensions []}
                  {:decode-mode :flow :extensions []}
                  {:decode? true :decode-mode :flow :extensions []}])]
    (with-redefs [pcap/capture->seq (fn [_] (swap! opened inc) [])
                  pcap/reduce-capture (fn [& _] (swap! opened inc))
                  pcap/reduce-capture-report (fn [& _] (swap! opened inc))]
      (doseq [opts invalid]
        (testing (pr-str opts)
          (is (thrown? clojure.lang.ExceptionInfo (core/packet-xf opts)))
          (is (thrown? clojure.lang.ExceptionInfo (core/packets opts)))
          (is (thrown? clojure.lang.ExceptionInfo (core/reduce-packets opts conj [])))
          (is (thrown? clojure.lang.ExceptionInfo (core/reduce-packets-report opts conj [])))
          ;; Without a source, native open would fail differently if validation were late.
          (is (thrown-with-msg? clojure.lang.ExceptionInfo #"extensions|cannot be combined"
                                (core/start-capture opts)))))
      (is (zero? @opened)))))

(deftest failures-preserve-the-last-map-and-continue
  (with-redefs [parse/packet->clj (constantly {:l2 {:type :ethernet}})]
    (let [calls (atom [])
          extension (fn [tag result]
                      (fn [m]
                        (swap! calls conj tag)
                        (result m)))
          extensions [(extension :first (mark :first))
                      (extension :boom (fn [_] (throw (ex-info "boom" {}))))
                      (extension :nil (constantly nil))
                      (extension :nonmap (constantly [:invalid]))
                      (extension :last (mark :last))]
          out (transform (core/packet-xf {:decode? true :extensions extensions}))]
      (is (= [:first :boom :nil :nonmap :last] @calls))
      (is (= [:first :last] (:order out)))
      (is (= {:l2 {:type :ethernet}} (:decoded out))))))

(deftest extensions-skip-decode-failures-and-preexisting-errors
  (let [calls (atom 0)
        xf (core/packet-xf {:decode? true
                            :extensions [(fn [m] (swap! calls inc) m)]})]
    (with-redefs [parse/packet->clj (fn [_ _dlt] (throw (ex-info "invalid packet" {})))]
      (is (= "invalid packet" (:decode-error (transform xf)))))
    (with-redefs [parse/packet->clj (constantly {})]
      (let [out (into [] xf [{:bytes (byte-array 3)}
                             {}
                             {:bytes (byte-array 14) :decode-error nil}])]
        (is (every? #(contains? % :decode-error) out))))
    (is (zero? @calls))))

(defspec explicit-composition-preserves-order-and-isolates-failure 100
  (prop/for-all [steps (gen/vector (gen/tuple (gen/elements [:ok :nil :throw])
                                              gen/small-integer))]
                (let [extensions (mapv (fn [[kind value]]
                                         (case kind
                                           :ok (mark value)
                                           :nil (constantly nil)
                                           :throw (fn [_] (throw (ex-info "boom" {})))))
                                       steps)
                      xf (core/packet-xf {:decode? true :extensions extensions})
                      packet {:bytes (byte-array 14)}
                      expected (mapv second (filter #(= :ok (first %)) steps))]
                  (with-redefs [parse/packet->clj (constantly {})]
                    (let [a (first (into [] xf [packet]))
                          b (first (into [] xf [packet]))]
                      (and (= expected (vec (:order a))) (= a b)))))))

(defn- ordinary-data [value]
  ;; Native reads and parsing create fresh arrays; compare their contents throughout.
  (cond
    (bytes? value) (vec value)
    (map? value) (update-vals value ordinary-data)
    (vector? value) (mapv ordinary-data value)
    :else value))

(defn- source-opts [path]
  {:path path :max Long/MAX_VALUE :max-time-ms 60000})

(deftest real-dns-and-tls-match-all-five-execution-models
  (doseq [[path annotate app-key expected]
          [["test/resources/dns-sample.pcap" dns/annotate-dns :summary "DNS message"]
           ["test/resources/tls-sni-alpn-sample.pcap" tls/annotate-tls-sni :sni "example.com"]]]
    (let [source (source-opts path)
          raw (vec (core/packets source))
          base (into [] (core/packet-xf {:decode? true :extensions []}) raw)
          opts (assoc source :decode? true
                      :extensions [(mark :before) annotate (mark :after)]
                      :xform (map (mark :user)))
          direct (into [] (comp (core/packet-xf opts) (:xform opts)) raw)
          report (core/reduce-packets-report opts conj [])
          managed (with-open [capture (core/start-capture opts)]
                    (let [packets (vec (core/capture-packets capture))]
                      (is (zero? (get-in (core/capture-stats capture) [:packets :decode-errors])))
                      packets))
          outputs [direct (vec (core/packets opts))
                   (core/reduce-packets opts conj []) (:result report) managed]]
      (is (seq raw))
      (is (apply = (map ordinary-data outputs)))
      (is (some #(= expected (get-in % [:decoded :l3 :l4 :app app-key])) direct))
      (is (every? #(= [:before :after :user] (:order %)) direct))
      (is (= :eof (get-in report [:stats :stop-reason])))
      (is (zero? (get-in report [:stats :packets :decode-errors])))
      (is (= (mapv #(select-keys % [:bytes :ts-sec :ts-usec :caplen :len]) raw)
             (mapv #(select-keys % [:bytes :ts-sec :ts-usec :caplen :len]) direct)))
      (is (= (mapv ordinary-data (map #(dissoc % :order) direct))
             (mapv ordinary-data (map annotate base)))))))

(deftest concurrent-fanout-branches-select-different-annotations
  (let [raw (vec (concat (core/packets (source-opts "test/resources/dns-sample.pcap"))
                         (core/packets (source-opts "test/resources/tls-sni-alpn-sample.pcap"))))
        before (mapv ordinary-data raw)
        dns-xf (core/packet-xf {:decode? true :extensions [dns/annotate-dns]})
        tls-xf (core/packet-xf {:decode? true :extensions [tls/annotate-tls-sni]})
        release (promise)
        global-calls (atom 0)]
    (with-open [fanout (stream/fan-out raw {:dns {:buffer-mode :blocking :buffer-cap 1}
                                            :tls {:buffer-mode :blocking :buffer-cap 1}})
                dns-branch (stream/branch fanout :dns)
                tls-branch (stream/branch fanout :tls)]
      (let [a (future @release (into [] dns-xf dns-branch))
            b (future @release (into [] tls-xf tls-branch))]
        (try
          (dx/register! ::global (fn [m] (swap! global-calls inc) m))
          (deliver release true)
          (let [dns-result (deref a 10000 ::timeout)
                tls-result (deref b 10000 ::timeout)]
            (is (vector? dns-result))
            (is (vector? tls-result))
            (when (and (vector? dns-result) (vector? tls-result))
              (is (= (count raw) (count dns-result) (count tls-result)))
              (is (= (ordinary-data (into [] dns-xf raw)) (ordinary-data dns-result)))
              (is (= (ordinary-data (into [] tls-xf raw)) (ordinary-data tls-result)))
              (is (some #(= "DNS message" (get-in % [:decoded :l3 :l4 :app :summary])) dns-result))
              (is (not-any? #(get-in % [:decoded :l3 :l4 :app :sni]) dns-result))
              (is (some #(= "example.com" (get-in % [:decoded :l3 :l4 :app :sni])) tls-result))
              (is (not-any? #(= "DNS message" (get-in % [:decoded :l3 :l4 :app :summary])) tls-result))
              (is (= before (mapv ordinary-data raw)))
              (is (zero? @global-calls))))
          (finally
            (dx/unregister! ::global)
            (future-cancel a)
            (future-cancel b)))))))

(deftest protocol-registration-uses-the-public-functions
  (let [registered (atom [])]
    (with-redefs [dx/register! (fn [k f] (swap! registered conj [k f]) k)]
      (is (= :paclo.proto.dns-ext/dns-summary (dns/register!)))
      (is (= :paclo.proto.tls-ext/tls-sni (tls/register!))))
    (is (= [[:paclo.proto.dns-ext/dns-summary dns/annotate-dns]
            [:paclo.proto.tls-ext/tls-sni tls/annotate-tls-sni]]
           @registered))
    (is (contains? (ns-publics 'paclo.proto.dns-ext) 'annotate-dns))
    (is (contains? (ns-publics 'paclo.proto.tls-ext) 'annotate-tls-sni))))

(deftest report-keeps-existing-counts-and-reduced-stop-contract
  (let [report (core/reduce-packets-report
                {:path "test/resources/dns-sample.pcap"
                 :decode? true
                 :extensions [(fn [_] (throw (ex-info "isolated" {})))
                              dns/annotate-dns]}
                (fn [acc packet] (reduced (conj acc packet))) [])]
    (is (= 1 (count (:result report))))
    (is (= "DNS message" (get-in report [:result 0 :decoded :l3 :l4 :app :summary])))
    (is (= :reduced (get-in report [:stats :stop-reason])))
    (is (= 1 (get-in report [:stats :packets :captured])))
    (is (zero? (get-in report [:stats :packets :decode-errors])))))
