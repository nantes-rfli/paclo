(ns paclo.pcap-unit-test
  (:require
   [clojure.test :refer [deftest is testing]]
   [paclo.pcap :as p])
  (:import
   [jnr.ffi Memory Pointer]
   [jnr.ffi.byref AbstractReference IntByReference PointerByReference]
   [paclo.jnr PcapLibrary]))

;; テスト用の軽量スタブ群 -------------------------------------------------

(defn- set-ref! ^PointerByReference [^PointerByReference ref ^Pointer p]
  (let [f (.getDeclaredField AbstractReference "value")]
    (.setAccessible f true)
    (.set f ref p))
  ref)

(defn- stub-lib
  "PcapLibrary の簡易スタブ。必要な挙動のみ fns で上書きする。"
  [{:keys [lookupnet-fn dump-open-fn open-dead-fn next-ex-fn]}]
  (reify PcapLibrary
    (pcap_lookupnet [_ dev netp maskp err]
      (if lookupnet-fn (lookupnet-fn dev netp maskp err) 0))
    (pcap_dump_open [_ _pcap path]
      (if dump-open-fn (dump-open-fn path) nil))
    (pcap_open_dead [_ link snap]
      (if open-dead-fn (open-dead-fn link snap) nil))
    (pcap_next_ex [_ _ hdr-ref dat-ref]
      (if next-ex-fn (next-ex-fn hdr-ref dat-ref) 0))
    (pcap_breakloop [_ _] nil)
    (pcap_close [_ _] nil)
    (pcap_open_offline [_ _ _] nil)
    (pcap_open_live [_ _ _ _ _ _] nil)
    (pcap_compile [_ _ _ _ _ _] 0)
    (pcap_setfilter [_ _ _] 0)
    (pcap_freecode [_ _] nil)
    (pcap_lib_version [_] "fake")
    (pcap_dump [_ _ _ _] nil)
    (pcap_dump_flush [_ _] nil)
    (pcap_dump_close [_ _] nil)
    (pcap_geterr [_ _] "")
    (pcap_findalldevs [_ _ _] 0)
    (pcap_freealldevs [_ _] nil)))

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

(deftest open-offline-empty-errbuf-message
  (let [f (doto (java.io.File/createTempFile "pcap" ".pcap")
            (spit "ab"))]
    (try
      (with-redefs [p/lib (reify PcapLibrary
                            (pcap_open_offline [_ _ _] nil))]
        (is (thrown-with-msg? clojure.lang.ExceptionInfo #"pcap_open_offline failed"
                              (p/open-offline (.getAbsolutePath f)))))
      (finally (.delete f)))))

(deftest capture->seq-on-error-hook-called
  (let [err-called (atom 0)]
    (with-redefs [p/lib (reify PcapLibrary
                          (pcap_next_ex [_ _ _ _] (throw (RuntimeException. "boom")))
                          (pcap_close [_ _] nil)
                          (pcap_open_offline [_ _ _] :h)
                          (pcap_open_live [_ _ _ _ _ _] nil)
                          (pcap_open_dead [_ _ _] nil)
                          (pcap_breakloop [_ _] nil)
                          (pcap_compile [_ _ _ _ _ _] 0)
                          (pcap_setfilter [_ _ _] 0)
                          (pcap_freecode [_ _] nil)
                          (pcap_lib_version [_] "fake")
                          (pcap_dump_open [_ _ _] nil)
                          (pcap_dump [_ _ _ _] nil)
                          (pcap_dump_flush [_ _] nil)
                          (pcap_dump_close [_ _] nil)
                          (pcap_geterr [_ _] "")
                          (pcap_findalldevs [_ _ _] 0)
                          (pcap_freealldevs [_ _] nil)
                          (pcap_lookupnet [_ _ _ _ _] 0))
                  p/open-offline (fn [& _] :h)
                  p/close! (fn [_] nil)]
      (let [out (doall (p/capture->seq {:path "dummy"
                                        :error-mode :pass
                                        :on-error (fn [_] (swap! err-called inc))
                                        :max 1 :max-time-ms 5 :idle-max-ms 5}))]
        (is (= [] out))
        (is (= 1 @err-called))))))

(deftest list-devices-error-throws
  (with-redefs [p/lib (reify PcapLibrary
                        (pcap_findalldevs [_ _ _] -1))]
    (is (thrown-with-msg? clojure.lang.ExceptionInfo #"pcap_findalldevs failed"
                          (p/list-devices)))))

;; ここから新規追加テスト --------------------------------------------------

(deftest lookup-netmask-success-and-error
  (let [lib-ok  (stub-lib {:lookupnet-fn (fn [_dev _net mask _err]
                                           (let [rt  (jnr.ffi.Runtime/getSystemRuntime)
                                                 mem (Memory/allocate rt 4)]
                                             (.putInt mem 0 (int 0x1234))
                                             (.fromNative ^IntByReference mask rt mem 0))
                                           0)})
        lib-ng  (stub-lib {:lookupnet-fn (fn [& _] -1)})
        f       (deref #'p/lookup-netmask)]
    (with-redefs [p/lib lib-ok]
      (is (= 0x1234 (f "en0"))))
    (with-redefs [p/lib lib-ng]
      (is (= 0 (f "lo0"))))))

(deftest open-dead-defaults-to-ethernet-65536
  (let [called (atom nil)
        ptr    (Memory/allocate (jnr.ffi.Runtime/getSystemRuntime) 1)
        lib    (stub-lib {:open-dead-fn (fn [link snap]
                                          (reset! called [link snap])
                                          ptr)})]
    (with-redefs [p/lib lib]
      (is (= ptr (p/open-dead))))
    (is (= [p/DLT_EN10MB 65536] @called))))

(deftest bytes-seq->pcap!-requires-out
  (is (thrown-with-msg? clojure.lang.ExceptionInfo #":out is required"
                        (p/bytes-seq->pcap! [(byte-array 0)] {:out "   "})))
  (is (thrown-with-msg? clojure.lang.ExceptionInfo #":out is required"
                        (p/bytes-seq->pcap! [(byte-array 0)] {:out nil}))))

(deftest open-dumper-throws-when-lib-returns-nil
  (let [pcap (Memory/allocate (jnr.ffi.Runtime/getSystemRuntime) 1)
        lib (stub-lib {:dump-open-fn (fn [_] nil)})]
    (with-redefs [p/lib lib]
      (is (thrown-with-msg? clojure.lang.ExceptionInfo #"pcap_dump_open failed"
                            (p/open-dumper pcap "out.pcap"))))))

(deftest loop!-processes-packet-and-stops-on-eof
  (let [rt   (jnr.ffi.Runtime/getSystemRuntime)
        hdr  (Memory/allocate rt 24)
        dat  (Memory/allocate rt 2)
        _    (.putLong hdr (long 0) (long 1))
        _    (.putLong hdr (long 8) (long 2))
        _    (.putInt  hdr (long 16) (int 2))
        _    (.putInt  hdr (long 20) (int 2))
        _    (.put dat (long 0) (byte-array [9 8]) (int 0) (int 2))
        rcs  (atom [1 0 -2])
        lib  (stub-lib {:next-ex-fn (fn [hdr-ref dat-ref]
                                      (let [rc (first @rcs)]
                                        (swap! rcs rest)
                                        (when (= 1 rc)
                                          (set-ref! hdr-ref hdr)
                                          (set-ref! dat-ref dat))
                                        rc))})
        handled (atom [])]
    (with-redefs [p/lib lib]
      (is (= -2 (p/loop! dat #(swap! handled conj %)))))
    (is (= 1 (count @handled)))
    (is (= 2 (:caplen (first @handled))))
    (is (= [9 8] (vec (:bytes (first @handled)))))))

(deftest with-pcap-closes-on-throw
  (let [closed (atom nil)
        ptr    (Memory/allocate (jnr.ffi.Runtime/getSystemRuntime) 1)]
    (with-redefs [p/close! (fn [h] (reset! closed h))]
      (is (thrown? Exception
                   (p/with-pcap [_ ptr]
                     (throw (Exception. "boom"))))))
    (is (= ptr @closed))))

(deftest with-dumper-flushes-and-closes-on-throw
  (let [flushed (atom 0)
        closed  (atom 0)]
    (with-redefs [p/open-dumper (fn [& _] :d)
                  p/flush-dumper! (fn [_] (swap! flushed inc))
                  p/close-dumper! (fn [_] (swap! closed inc))]
      (is (thrown? Exception
                   (p/with-dumper [_ (p/open-dumper :pcap "out")]
                     (throw (Exception. "fail"))))))
    (is (= 1 @flushed))
    (is (= 1 @closed))))

(deftest open-offline-applies-filter-when-provided
  (let [tmp (java.io.File/createTempFile "pcap" ".pcap")
        ptr (Memory/allocate (jnr.ffi.Runtime/getSystemRuntime) 1)
        seen (atom nil)]
    (spit tmp "data")
    (try
      (with-redefs [p/lib (reify PcapLibrary
                            (pcap_open_offline [_ _ _] ptr)
                            (pcap_close [_ _] nil))
                    p/apply-filter! (fn [h opts] (reset! seen [h opts]) h)]
        (is (= ptr (p/open-offline (.getAbsolutePath tmp) {:filter "udp" :optimize? false})))
        (is (= [ptr {:filter "udp" :optimize? false}] @seen)))
      (finally (.delete tmp)))))

(deftest list-devices-empty-when-no-ifaces
  (with-redefs [p/lib (reify PcapLibrary
                        (pcap_findalldevs [_ _ _] 0)
                        (pcap_freealldevs [_ _] nil))
                p/macos-device->desc (fn [] {})]
    (is (= [] (p/list-devices)))))

(deftest loop-n!-arity1-stops-after-n
  (let [calls (atom 0)
        breaks (atom 0)]
    (with-redefs [p/loop! (fn [_ h] (dotimes [_ 2] (h {})))
                  p/breakloop! (fn [_] (swap! breaks inc))]
      (p/loop-n! :pcap 2 (fn [_] (swap! calls inc))))
    (is (= 2 @calls))
    (is (= 1 @breaks))))

(deftest loop-for-ms!-arity1-breaks-on-duration
  (let [calls (atom 0)
        breaks (atom 0)]
    (with-redefs [p/loop! (fn [_ h]
                            (h {})
                            (Thread/sleep 2)
                            (h {}))
                  p/breakloop! (fn [_] (swap! breaks inc))]
      (p/loop-for-ms! :pcap 1 (fn [_] (swap! calls inc))))
    (is (= 2 @calls))
    (is (= 1 @breaks))))
