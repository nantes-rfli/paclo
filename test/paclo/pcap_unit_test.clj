(ns paclo.pcap-unit-test
  (:require
   [clojure.test :refer [deftest is testing]]
   [paclo.pcap :as p])
  (:import
   [jnr.ffi Memory Pointer]
   [jnr.ffi.byref AbstractReference IntByReference PointerByReference]
   [paclo.jnr PcapLibrary]))

;; -------------------------------------------------------------

(defn- set-ref! ^PointerByReference [^PointerByReference ref ^Pointer p]
  (let [f (.getDeclaredField AbstractReference "value")]
    (.setAccessible f true)
    (.set f ref p))
  ref)

(defn- stub-lib
  "Create a PcapLibrary test double with overridable function slots."
  [{:keys [lookupnet-fn dump-open-fn open-dead-fn next-ex-fn findalldevs-fn]}]
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
    (pcap_findalldevs [_ pp err]
      (if findalldevs-fn (findalldevs-fn pp err) 0))
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

(deftest open-live-rejects-missing-device
  (is (thrown-with-msg? clojure.lang.ExceptionInfo #"non-blank"
                        (p/open-live {})))
  (is (thrown-with-msg? clojure.lang.ExceptionInfo #"non-blank"
                        (p/open-live {:device "   "}))))

(deftest capture->seq-requires-source
  (is (thrown-with-msg? clojure.lang.ExceptionInfo #"requires either :device or :path"
                        (p/capture->seq {})))
  (is (thrown-with-msg? clojure.lang.ExceptionInfo #"either :device or :path, not both"
                        (p/capture->seq {:device "en0" :path "trace.pcap"}))))

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

(deftest open-offline-nonempty-errbuf-message
  (let [f (doto (java.io.File/createTempFile "pcap" ".pcap")
            (spit "ab"))]
    (try
      (with-redefs [p/lib (reify PcapLibrary
                            (pcap_open_offline [_ _ err]
                              (let [^Pointer err* err
                                    ^bytes msg (.getBytes "oops")
                                    len (alength msg)]
                                (dotimes [i len]
                                  (.putByte err* (long i) (aget msg i)))
                                (.putByte err* (long len) (byte 0)))
                              nil))]
        (is (thrown-with-msg? clojure.lang.ExceptionInfo #"pcap_open_offline failed: oops"
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

;; -------------------------------------------------------------

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
                   (p/with-pcap ^{:clj-kondo/ignore [:unresolved-symbol]} [h ptr]
                     (is (= ptr h))
                     (throw (Exception. "boom"))))))
    (is (= ptr @closed))))

(deftest with-dumper-flushes-and-closes-on-throw
  (let [flushed (atom 0)
        closed  (atom 0)]
    (with-redefs [p/open-dumper (fn [& _] :d)
                  p/flush-dumper! (fn [_] (swap! flushed inc))
                  p/close-dumper! (fn [_] (swap! closed inc))]
      (is (thrown? Exception
                   (p/with-dumper ^{:clj-kondo/ignore [:unresolved-symbol]} [d (p/open-dumper :pcap "out")]
                     (is (= :d d))
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

(deftest list-devices-falls-back-to-macos-desc-when-missing
  (let [rt         (jnr.ffi.Runtime/getSystemRuntime)
        ptr-size   (.addressSize rt)
        name-bytes (.getBytes "en0")
        name-buf   (doto (java.nio.ByteBuffer/allocateDirect (inc (alength name-bytes)))
                     (.put name-bytes)
                     (.put (byte 0))
                     (.flip))
        name-ptr   (jnr.ffi.Pointer/wrap rt name-buf)
        struct-buf (java.nio.ByteBuffer/allocateDirect (* 3 ptr-size))
        struct     (jnr.ffi.Pointer/wrap rt struct-buf)]
    ;; next=NULL, name=name-ptr, desc=NULL (fallback should be used)
    (.putAddress struct (long 0) (long 0))
    (.putAddress struct (long ptr-size) (.address name-ptr))
    (.putAddress struct (long (* 2 ptr-size)) (long 0))
    (with-redefs [p/lib (stub-lib {:findalldevs-fn (fn [pp _err]
                                                     (set-ref! pp struct)
                                                     0)})
                  p/macos-device->desc (fn [] {"en0" "AirPort"})]
      (is (= [{:name "en0" :desc "AirPort"}]
             (p/list-devices))))))

(deftest loop!-returns-error-on-timeout-and-error
  (let [calls (atom 0)
        ptr  (Memory/allocate (jnr.ffi.Runtime/getSystemRuntime) 1)
        lib (reify PcapLibrary
              (pcap_next_ex [_ _ _ _]
                (let [^long n (swap! calls inc)]
                  (case (int n)
                    1 0    ; timeout
                    2 -1)))
              (pcap_breakloop [_ _] nil)
              (pcap_close [_ _] nil)
              (pcap_open_offline [_ _ _] nil)
              (pcap_open_live [_ _ _ _ _ _] nil)
              (pcap_open_dead [_ _ _] nil)
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
              (pcap_lookupnet [_ _ _ _ _] 0))]
    (with-redefs [p/lib lib]
      (is (= -1 (p/loop! ptr (fn [_] (throw (RuntimeException. "should not happen")))))))
    (is (= 2 @calls))))

(deftest capture->seq-live-stop-and-filter
  (let [filter-seen (atom nil)
        handled (atom [])]
    (with-redefs [p/open-live (fn [_] :h)
                  p/set-bpf-on-device! (fn [_ dev expr] (reset! filter-seen [dev expr]))
                  p/set-bpf! (fn [& _] nil)
                  p/loop-n-or-ms! (fn [_ _ handler]
                                    (handler {:bytes (byte-array [1])})
                                    nil)]
      (let [pkts (doall (p/capture->seq {:device "en0" :filter "tcp" :max 1 :max-time-ms 5}))]
        (reset! handled pkts)))
    (is (= ["en0" "tcp"] @filter-seen))
    (is (= 1 (count @handled)))
    (is (= 1 (aget ^bytes (:bytes (first @handled)) 0)))))

(deftest open-dead-custom-params
  (let [seen (atom nil)
        ptr  (Memory/allocate (jnr.ffi.Runtime/getSystemRuntime) 1)]
    (with-redefs [p/lib (reify PcapLibrary
                          (pcap_open_dead [_ link snap]
                            (reset! seen [link snap])
                            ptr)
                          (pcap_close [_ _] nil)
                          (pcap_open_offline [_ _ _] nil)
                          (pcap_open_live [_ _ _ _ _ _] nil)
                          (pcap_next_ex [_ _ _ _] -2)
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
                          (pcap_lookupnet [_ _ _ _ _] 0))]
      (is (= ptr (p/open-dead 100 9000))))
    (is (= [100 9000] @seen))))

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
                            (Thread/sleep 2)
                            (h {}))
                  p/breakloop! (fn [_] (swap! breaks inc))]
      (p/loop-for-ms! :pcap 1 (fn [_] (swap! calls inc))))
    (is (= 1 @calls))
    (is (= 1 @breaks))))

(deftest loop-n!-idle-branch-handles-packet-and-timeout
  (let [rt (jnr.ffi.Runtime/getSystemRuntime)
        hdr (Memory/allocate rt 24)
        dat (Memory/allocate rt 2)
        _ (.putLong hdr (long 0) (long 1))
        _ (.putLong hdr (long 8) (long 2))
        _ (.putInt  hdr (long 16) (int 2))
        _ (.putInt  hdr (long 20) (int 2))
        _ (.put dat (long 0) (byte-array [9 8]) (int 0) (int 2))
        rcs (atom [1 0 -1])
        lib (stub-lib {:next-ex-fn (fn [hdr-ref dat-ref]
                                     (let [rc (first @rcs)]
                                       (swap! rcs rest)
                                       (when (= 1 rc)
                                         (set-ref! hdr-ref hdr)
                                         (set-ref! dat-ref dat))
                                       rc))})
        handled (atom [])]
    (with-redefs [p/lib lib
                  p/breakloop! (fn [_] (swap! handled conj :break))]
      (p/loop-n! (Memory/allocate rt 1) 2 #(swap! handled conj (:caplen %))
                 {:idle-max-ms 2 :timeout-ms 1}))
    (is (some #{2} @handled))
    (is (some #{:break} @handled))))

(deftest loop-for-ms!-idle-branch-processes-packet
  (let [rt (jnr.ffi.Runtime/getSystemRuntime)
        hdr (Memory/allocate rt 24)
        dat (Memory/allocate rt 1)
        _ (.putLong hdr (long 0) (long 1))
        _ (.putLong hdr (long 8) (long 2))
        _ (.putInt  hdr (long 16) (int 1))
        _ (.putInt  hdr (long 20) (int 1))
        _ (.put dat (long 0) (byte-array [7]) (int 0) (int 1))
        rcs (atom [1 -2])
        lib (stub-lib {:next-ex-fn (fn [hdr-ref dat-ref]
                                     (let [rc (first @rcs)]
                                       (swap! rcs rest)
                                       (when (= 1 rc)
                                         (set-ref! hdr-ref hdr)
                                         (set-ref! dat-ref dat))
                                       rc))})
        handled (atom [])]
    (with-redefs [p/lib lib
                  p/breakloop! (fn [_] (swap! handled conj :break))]
      (p/loop-for-ms! (Memory/allocate rt 1) 5 #(swap! handled conj (:caplen %))
                      {:idle-max-ms 2 :timeout-ms 1}))
    (is (some #{1} @handled))
    (is (some #{:break} @handled))))

(deftest loop-n!-idle-branch-breaks-on-error
  (let [rt     (jnr.ffi.Runtime/getSystemRuntime)
        breaks (atom 0)
        lib    (stub-lib {:next-ex-fn (fn [& _] -1)})]
    (with-redefs [p/lib lib
                  p/breakloop! (fn [_] (swap! breaks inc))]
      (p/loop-n! (Memory/allocate rt 1) 1 (fn [_]) {:idle-max-ms 1 :timeout-ms 1}))
    (is (= 1 @breaks))))

(deftest loop-for-ms!-idle-branch-breaks-on-error
  (let [rt     (jnr.ffi.Runtime/getSystemRuntime)
        breaks (atom 0)
        lib    (stub-lib {:next-ex-fn (fn [& _] -1)})]
    (with-redefs [p/lib lib
                  p/breakloop! (fn [_] (swap! breaks inc))]
      (p/loop-for-ms! (Memory/allocate rt 1) 2 (fn [_]) {:idle-max-ms 1 :timeout-ms 1}))
    (is (= 1 @breaks))))

(deftest loop-n-or-ms!-idle-branch-breaks-on-error
  (let [rt     (jnr.ffi.Runtime/getSystemRuntime)
        breaks (atom 0)
        lib    (stub-lib {:next-ex-fn (fn [& _] -1)})]
    (with-redefs [p/lib lib
                  p/breakloop! (fn [_] (swap! breaks inc))]
      (p/loop-n-or-ms! (Memory/allocate rt 1)
                       {:n 2 :ms 10 :idle-max-ms 1 :timeout-ms 1}
                       (fn [_])))
    (is (= 1 @breaks))))

(deftest loop-n-or-ms!-no-idle-breaks-on-count
  (let [breaks (atom 0)]
    (with-redefs [p/loop! (fn [_ handler] (handler {:bytes (byte-array 1)}))
                  p/breakloop! (fn [_] (swap! breaks inc))]
      (p/loop-n-or-ms! :pcap {:n 1 :ms 100} (fn [_])))
    (is (= 1 @breaks))))

(deftest loop-n-or-ms!-idle-branch-breaks-on-timeout
  (let [rt (jnr.ffi.Runtime/getSystemRuntime)
        rcs (atom [0 -1])
        lib (stub-lib {:next-ex-fn (fn [& _]
                                     (let [rc (first @rcs)]
                                       (swap! rcs rest)
                                       rc))})
        breaks (atom 0)]
    (with-redefs [p/lib lib
                  p/breakloop! (fn [_] (swap! breaks inc))]
      (p/loop-n-or-ms! (Memory/allocate rt 1)
                       {:n 2 :ms 50 :idle-max-ms 5 :timeout-ms 5}
                       (fn [_])))
    (is (pos? (long @breaks)))))

(deftest with-live-and-offline-wrap-close
  (let [opened-live (atom nil)
        opened-offline (atom nil)
        closed (atom [])]
    (with-redefs [p/open-live (fn [opts] (reset! opened-live opts) :live)
                  p/open-offline (fn [path] (reset! opened-offline path) :off)
                  p/close! (fn [h] (swap! closed conj h))]
      (p/with-live [h {:device "en0"}]
        (is (= :live h)))
      (p/with-offline [h (p/open-offline "/tmp/dummy.pcap")]
        (is (= :off h))))
    (is (= {:device "en0"} @opened-live))
    (is (= "/tmp/dummy.pcap" @opened-offline))
    (is (= [:live :off] @closed))))

(deftest lookupnet-success-and-error
  (let [rt (jnr.ffi.Runtime/getSystemRuntime)
        lib-ok (stub-lib {:lookupnet-fn (fn [_ net mask _]
                                          (let [mem (Memory/allocate rt 4)]
                                            (.putInt mem 0 (int 0x01020304))
                                            (.fromNative ^IntByReference net rt mem 0))
                                          (let [mem (Memory/allocate rt 4)]
                                            (.putInt mem 0 (int 0x0000ff00))
                                            (.fromNative ^IntByReference mask rt mem 0))
                                          0)})
        lib-ng (stub-lib {:lookupnet-fn (fn [_ _ _ err]
                                          (let [^Pointer err* err
                                                ^bytes msg (.getBytes "oops")
                                                len (alength msg)]
                                            (dotimes [i len]
                                              (.putByte err* (long i) (aget msg i)))
                                            (.putByte err* (long len) (byte 0)))
                                          -1)})]
    (with-redefs [p/lib lib-ok]
      (is (= {:net 0x01020304 :mask 0x0000ff00} (p/lookupnet "en0"))))
    (with-redefs [p/lib lib-ng]
      (is (thrown-with-msg? clojure.lang.ExceptionInfo #"pcap_lookupnet failed"
                            (p/lookupnet "en0"))))))

(deftest capture->pcap-applies-filter-and-stops-at-max
  (let [calls (atom [])
        rt (jnr.ffi.Runtime/getSystemRuntime)
        hdr (Memory/allocate rt 24)
        dat (Memory/allocate rt 1)
        lib (stub-lib {:next-ex-fn (let [first? (atom true)]
                                     (fn [hdr-ref dat-ref]
                                       (if @first?
                                         (do (reset! first? false)
                                             (set-ref! hdr-ref hdr)
                                             (set-ref! dat-ref dat)
                                             1)
                                         -2)))})]
    (with-redefs [p/lib lib
                  p/open-live (fn [opts] (swap! calls conj [:open opts]) (Memory/allocate rt 1))
                  p/open-dumper (fn [_ out] (swap! calls conj [:open-dumper out]) :d)
                  p/dump! (fn [& _] (swap! calls conj [:dump]))
                  p/flush-dumper! (fn [_] (swap! calls conj [:flush]))
                  p/close-dumper! (fn [_] (swap! calls conj [:close-d]))
                  p/close! (fn [_] (swap! calls conj [:close-pcap]))
                  p/set-bpf-on-device! (fn [& args] (swap! calls conj (into [:set-bpf-device] args)))
                  p/set-bpf! (fn [& args] (swap! calls conj (into [:set-bpf] args)))]
      (is (= 1 (p/capture->pcap {:device "en0" :filter "tcp" :max 1} "out.pcap"))))
    (let [tags (map first @calls)]
      (is (= [:open :open-dumper :set-bpf-device :dump :flush :close-d :close-pcap]
             tags)))))

(deftest capture->pcap-handles-timeout-and-error
  (let [calls (atom [])
        rt (jnr.ffi.Runtime/getSystemRuntime)
        hdr (Memory/allocate rt 24)
        dat (Memory/allocate rt 1)
        rc-seq (atom [0 -1])
        lib (stub-lib {:next-ex-fn (fn [hdr-ref dat-ref]
                                     (let [rc (first @rc-seq)]
                                       (swap! rc-seq rest)
                                       (set-ref! hdr-ref hdr)
                                       (set-ref! dat-ref dat)
                                       rc))})]
    (with-redefs [p/lib lib
                  p/open-live (fn [opts] (swap! calls conj [:open opts]) (Memory/allocate rt 1))
                  p/open-dumper (fn [_ out] (swap! calls conj [:open-dumper out]) :d)
                  p/dump! (fn [& _] (swap! calls conj [:dump]))
                  p/flush-dumper! (fn [_] (swap! calls conj [:flush]))
                  p/close-dumper! (fn [_] (swap! calls conj [:close-d]))
                  p/close! (fn [_] (swap! calls conj [:close-pcap]))
                  p/set-bpf! (fn [& args] (swap! calls conj (into [:set-bpf] args)))]
      (is (= 0 (p/capture->pcap {:filter "udp" :max 1 :timeout-ms 10} "out2.pcap"))))
    (is (some #{:set-bpf} (map first @calls)))
    (is (some #{:flush} (map first @calls)))))

(deftest run-live-for-ms!-covers-arities-and-branches
  (let [calls (atom [])
        rt (jnr.ffi.Runtime/getSystemRuntime)
        hdr (Memory/allocate rt 24)
        dat (Memory/allocate rt 1)
        lib (stub-lib {:next-ex-fn (fn [hdr-ref dat-ref]
                                     (set-ref! hdr-ref hdr)
                                     (set-ref! dat-ref dat)
                                     -2)})]
    (with-redefs [p/lib lib
                  p/open-live (fn [opts] (swap! calls conj [:open opts]) (Memory/allocate rt 1))
                  p/breakloop! (fn [_] (swap! calls conj [:break]))
                  p/set-bpf-on-device! (fn [& args] (swap! calls conj (into [:set-bpf-device] args)))
                  p/set-bpf! (fn [& args] (swap! calls conj (into [:set-bpf] args)))
                  p/close! (fn [h] (swap! calls conj [:close h]))]
      ;; arity with loop opts (idle branch + device filter path)
      (p/run-live-for-ms! {:device "en0" :filter "tcp"} 5 (fn [_]) {:idle-max-ms 10})
      ;; 3-arity delegate (no device, filter -> set-bpf path)
      (p/run-live-for-ms! {:filter "udp"} 3 (fn [_])))
    (let [tags (map first @calls)]
      (is (some #{:set-bpf-device} tags))
      (is (some #{:set-bpf} tags))
      (is (<= 2 (count (filter #(= :close %) tags)))))))

(deftest run-live-n!-covers-arities-and-idle-branch
  (let [calls (atom [])
        rt (jnr.ffi.Runtime/getSystemRuntime)
        lib (stub-lib {:next-ex-fn (fn [& _] -2)})]
    (with-redefs [p/lib lib
                  p/open-live (fn [opts] (swap! calls conj [:open opts]) (Memory/allocate rt 1))
                  p/set-bpf! (fn [& args] (swap! calls conj (into [:set-bpf] args)))
                  p/set-bpf-on-device! (fn [& args] (swap! calls conj (into [:set-bpf-device] args)))
                  p/close! (fn [_] (swap! calls conj [:close]))]
      (p/run-live-n! {:filter "udp"} 1 (fn [_]))
      (p/run-live-n! {:device "en0" :filter "tcp"} 2 (fn [_]) {:idle-max-ms 5 :timeout-ms 1}))
    (let [tags (map first @calls)]
      (is (some #{:set-bpf} tags))
      (is (some #{:set-bpf-device} tags))
      (is (= 2 (count (filter #(= :close %) tags)))))))

(deftest run-live-summaries-cover-shortcuts
  (let [stub-n  (reify clojure.lang.IFn$OLOOO
                  (invokePrim [_ _opts _n handler _loop-opts]
                    (handler :pkt)
                    nil)
                  clojure.lang.IFn
                  (invoke [_ _opts _n handler _loop-opts]
                    (handler :pkt)
                    nil))
        stub-ms (reify clojure.lang.IFn$OLOOO
                  (invokePrim [_ _opts _ms handler _loop-opts]
                    (handler :pkt)
                    nil)
                  clojure.lang.IFn
                  (invoke [_ _opts _ms handler _loop-opts]
                    (handler :pkt)
                    nil))]
    (with-redefs [p/run-live-n! stub-n
                  p/run-live-for-ms! stub-ms]
      (let [res-n  (p/run-live-n-summary! {:device "d"} 1 (fn [_] nil))
            res-ms (p/run-live-for-ms-summary! {:device "d"} 5 (fn [_] nil))]
        (is (= 1 (:count res-n)))
        (is (= :n (:stopped res-n)))
        (is (>= (:duration-ms res-n) 0))
        (is (= 1 (:count res-ms)))
        (is (= :idle-or-eof (:stopped res-ms)))))))

(deftest macos-device->desc-non-mac-returns-empty-map
  (let [orig (System/getProperty "os.name")
        f (deref #'p/macos-device->desc)]
    (try
      (System/setProperty "os.name" "Linux")
      (is (= {} (f)))
      (finally
        (when orig (System/setProperty "os.name" orig))))))
