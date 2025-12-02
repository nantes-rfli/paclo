(ns paclo.pcap-unit-test
  (:require
   [clojure.test :refer [deftest is testing]]
   [paclo.pcap :as p]))

(deftest blank-str?-basics
  (let [f (deref #'p/blank-str?)]
    (testing "nil is blank"
      (is (true? (f nil))))
    (testing "whitespace string is blank"
      (is (f "   \t")))
    (testing "non-blank string is falsey"
      (is (false? (boolean (f "abc")))))))

(deftest normalize-desc-trims-and-filters
  (let [f (deref #'p/normalize-desc)]
    (testing "trims surrounding whitespace"
      (is (= "eth0" (f "  eth0  "))))
    (testing "blank becomes nil"
      (is (nil? (f "   "))))
    (testing "nil stays nil"
      (is (nil? (f nil))))))

(deftest idle-next-accumulates-and-breaks
  (let [f (deref #'p/idle-next)]
    (is (= {:idle 5 :break? false} (f 3 2 10)))
    (is (= {:idle 12 :break? true} (f 5 7 10)))))

(deftest valid-filter-string?-accepts-non-blank
  (let [f (deref #'p/valid-filter-string?)]
    (is (false? (f nil)))
    (is (false? (f "")))
    (is (false? (f "   ")))
    (is (true? (f "tcp")))))

(deftest ensure-bytes-timestamp-requires-bytes
  (let [f (deref #'p/ensure-bytes-timestamp)]
    (is (thrown-with-msg? clojure.lang.ExceptionInfo #"missing :bytes"
                          (f {:sec 1})))
    (let [[ba sec usec] (f {:bytes (byte-array [1]) :sec 10 :usec 20})]
      (is (= [1] (vec ba)))
      (is (= 10 sec))
      (is (= 20 usec)))))

(deftest apply-filter!-skips-when-no-filter
  (let [calls (atom 0)
        f (deref #'p/apply-filter!)]
    (is (= :pcap (f :pcap {:filter nil})))
    (is (= 0 @calls))))

(deftest set-bpf-on-device-uses-lookupnet
  (let [mask (atom nil)
        called (atom false)]
    (with-redefs [p/lookupnet (fn [_] {:mask 123})
                  p/set-bpf-with-netmask! (fn [_ _ m] (reset! mask m) (reset! called true))]
      (p/set-bpf-on-device! :pcap "en0" "tcp")
      (is @called)
      (is (= 123 @mask)))))

(deftest set-bpf-on-device-fallbacks-to-zero-on-error
  (let [mask (atom nil)]
    (with-redefs [p/lookupnet (fn [_] (throw (RuntimeException. "boom")))
                  p/set-bpf-with-netmask! (fn [_ _ m] (reset! mask m))]
      (p/set-bpf-on-device! :pcap "en0" "udp")
      (is (= 0 @mask)))))

(deftest set-bpf!-uses-zero-netmask
  (let [opts (atom nil)]
    (with-redefs [p/apply-filter! (fn [_ o] (reset! opts o))]
      (p/set-bpf! :pcap "udp")
      (is (= {:filter "udp" :optimize? true :netmask 0} @opts)))))

(deftest set-bpf-with-netmask!-passes-int
  (let [opts (atom nil)]
    (with-redefs [p/apply-filter! (fn [_ o] (reset! opts o))]
      (p/set-bpf-with-netmask! :pcap "tcp" 255)
      (is (= {:filter "tcp" :optimize? true :netmask 255} @opts)))))

(deftest pkt-handler-normalizes-arities
  (let [h0-called (atom 0)
        h1-called (atom nil)
        f (deref #'p/->pkt-handler)]
    ((f nil) {:x 1}) ;; noop
    ((f (fn [] (swap! h0-called inc))) {:x 1})
    ((f (fn [m] (reset! h1-called m))) {:x 2})
    (is (= 1 @h0-called))
    (is (= {:x 2} @h1-called))))

(deftest bytes-seq->pcap!-writes-and-closes
  (let [calls (atom [])]
    (with-redefs [p/open-dead (fn [& _] :dead)
                  p/open-dumper (fn [_ out] (swap! calls conj [:open out]) :dumper)
                  p/ensure-bytes-timestamp (fn [p] (if (map? p) [(:bytes p) 1 2] [p 1 2]))
                  p/mk-hdr (fn ^Object [^long sec ^long usec ^long len] {:hdr [sec usec len]})
                  p/bytes->ptr (fn [ba] {:ptr (vec ba)})
                  p/dump! (fn [_ hdr dat] (swap! calls conj [:dump hdr dat]))
                  p/flush-dumper! (fn [_] (swap! calls conj [:flush]))
                  p/close-dumper! (fn [_] (swap! calls conj [:close-d]))
                  p/close! (fn [_] (swap! calls conj [:close-pcap]))]
      (p/bytes-seq->pcap! [(byte-array [1 2]) {:bytes (byte-array [3])}] {:out "x"})
      (is (= [[:open "x"]
              [:dump {:hdr [1 2 2]} {:ptr [1 2]}]
              [:dump {:hdr [1 2 1]} {:ptr [3]}]
              [:flush]
              [:close-d]
              [:close-pcap]]
             @calls)))))
