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

;; end of file
