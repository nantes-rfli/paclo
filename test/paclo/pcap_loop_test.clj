(ns paclo.pcap-loop-test
  (:require
   [clojure.test :refer [deftest is]]
   [paclo.pcap :as pcap])
  (:import
   [jnr.ffi Memory Pointer]
   [jnr.ffi.byref AbstractReference PointerByReference]
   [paclo.jnr PcapLibrary]))

(defn- make-hdr+dat
  "固定の pcap_pkthdr とデータ領域を作る。"
  [^bytes ba]
  (let [rt (jnr.ffi.Runtime/getSystemRuntime)
        hdr (Memory/allocate rt 24)
        dat (Memory/allocate rt (long (alength ba)))
        len (alength ba)]
    (.putLong hdr (long 0) (long 123))   ;; tv_sec
    (.putLong hdr (long 8) (long 456))   ;; tv_usec
    (.putInt  hdr (long 16) (int len))   ;; caplen
    (.putInt  hdr (long 20) (int len))   ;; len
    (.put dat (long 0) ba (int 0) (int len))
    {:hdr hdr :dat dat}))

(def ^:private fake-pcap
  ;; breakloop で Pointer 型が要求されるので 1バイトのダミーメモリを使う
  (Memory/allocate (jnr.ffi.Runtime/getSystemRuntime) 1))

(defn- set-ref! ^PointerByReference [^PointerByReference ref ^Pointer p]
  (let [f (.getDeclaredField AbstractReference "value")]
    (.setAccessible f true)
    (.set f ref p))
  ref)

(defn- stub-run-live-n! [call-count]
  (reify clojure.lang.IFn$OLOOO
    (invokePrim [_ _opts _n handler _loop-opts]
      (dotimes [_ call-count] (handler {}))
      nil)
    clojure.lang.IFn
    (invoke [_ _opts _n handler _loop-opts]
      (dotimes [_ call-count] (handler {}))
      nil)))

(defn- stub-run-live-for-ms! [call-count sleep-ms]
  (reify clojure.lang.IFn$OLOOO
    (invokePrim [_ _opts _dur handler _loop-opts]
      (dotimes [_ call-count] (handler {}))
      (when (pos? sleep-ms) (Thread/sleep sleep-ms))
      nil)
    clojure.lang.IFn
    (invoke [_ _opts _dur handler _loop-opts]
      (dotimes [_ call-count] (handler {}))
      (when (pos? sleep-ms) (Thread/sleep sleep-ms))
      nil)))

(defn- fake-lib-open-live
  "pcap_open_live が指定の pcap を返すフェイク lib。nil を返させたい場合は :pcap nil を渡す。"
  [{:keys [pcap] :as opts}]
  (let [p (if (contains? opts :pcap) pcap fake-pcap)]
    {:lib
     (reify PcapLibrary
       (pcap_open_live [_ _device _snaplen _promisc _to_ms _errbuf] p)
       (pcap_close [_ _] nil)
       (pcap_open_offline [_ _ _] nil)
       (pcap_open_dead [_ _ _] nil)
       (pcap_next_ex [_ _ _ _] 0)
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
     :pcap p}))

(defn- fake-lib
  "rcs を順に返す pcap lib のフェイク。
   rc=1 のときは hdr/dat をセットする。"
  [{:keys [rcs hdr dat break-calls]}]
  (let [rcs* (atom rcs)
        breaks (or break-calls (atom 0))
        hdr' (or hdr (Memory/allocate (jnr.ffi.Runtime/getSystemRuntime) 24))
        dat' (or dat (Memory/allocate (jnr.ffi.Runtime/getSystemRuntime) 0))]
    {:lib
     (reify PcapLibrary
       (pcap_next_ex [_ _ hdr-ref dat-ref]
         (let [rc (if-let [v (first @rcs*)]
                    (do (swap! rcs* rest) v)
                    -2)]
           (when (= 1 rc)
             (set-ref! hdr-ref hdr')
             (set-ref! dat-ref dat'))
           rc))
       (pcap_breakloop [_ _] (swap! breaks inc))
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
       (pcap_lookupnet [_ _ _ _ _] 0))
     :rcs rcs*
     :breaks breaks}))

(deftest loop-n!-breaks-on-idle-timeout
  (let [{:keys [lib breaks]} (fake-lib {:rcs [0 0 0 0]})]
    (with-redefs [pcap/lib lib]
      (pcap/loop-n! fake-pcap 5 (fn [_]) {:idle-max-ms 5 :timeout-ms 2}))
    (is (= 1 @breaks))))

(deftest loop-n-or-ms!-stop?-triggers-break
  (let [{:keys [hdr dat]} (make-hdr+dat (byte-array [1 2 3]))
        {:keys [lib breaks]} (fake-lib {:rcs [1 1 -2] :hdr hdr :dat dat})
        handled (atom 0)]
    (with-redefs [pcap/lib lib]
      (pcap/loop-n-or-ms! fake-pcap {:n 10 :ms 1000 :idle-max-ms 100 :timeout-ms 10
                                     :stop? (fn [_] true)}
                          (fn [_] (swap! handled inc))))
    (is (= 1 @handled))
    (is (= 1 @breaks))))

(deftest loop-for-ms!-idle-breaks
  (let [{:keys [lib breaks]} (fake-lib {:rcs [0 0 0]})]
    (with-redefs [pcap/lib lib]
      (pcap/loop-for-ms! fake-pcap 100 (fn [_]) {:idle-max-ms 5 :timeout-ms 2}))
    (is (= 1 @breaks))))

(deftest capture->seq-collects-packets-and-stops
  (let [{:keys [hdr dat]} (make-hdr+dat (byte-array [9 9]))
        {:keys [lib breaks]} (fake-lib {:rcs [1 1 -2] :hdr hdr :dat dat})]
    (with-redefs [pcap/lib lib
                  pcap/open-offline (fn [& _] fake-pcap)
                  pcap/open-live (fn [& _] fake-pcap)]
      (let [pkts (doall (pcap/capture->seq {:path "dummy"
                                            :max 5
                                            :max-time-ms 50
                                            :timeout-ms 10
                                            :idle-max-ms 20}))]
        (is (= 2 (count pkts)))
        (is (= [9 9] (map #(aget ^bytes % 0) (map :bytes pkts))))
        (is (= 1 @breaks))))))

(deftest capture->seq-passes-errors-when-requested
  (let [{:keys [lib]} (fake-lib {:rcs [-1]})]
    (with-redefs [pcap/lib lib
                  pcap/open-offline (fn [& _] fake-pcap)]
      (let [out (doall (pcap/capture->seq {:path "dummy" :error-mode :pass
                                           :max 1 :max-time-ms 10 :idle-max-ms 5}))]
        (is (= [] out))))))

(deftest capture->seq-stop?-preempts-error-while-pass
  (let [{:keys [hdr dat]} (make-hdr+dat (byte-array [1]))
        {:keys [lib breaks]} (fake-lib {:rcs [1 -1] :hdr hdr :dat dat})
        stop-called (atom 0)]
    (with-redefs [pcap/lib lib
                  pcap/open-offline (fn [& _] fake-pcap)]
      (let [out (doall (pcap/capture->seq {:path "dummy"
                                           :stop? (fn [_] (swap! stop-called inc) true)
                                           :error-mode :pass
                                           :max 5 :max-time-ms 50 :idle-max-ms 10}))]
        (is (= 1 (count out)))
        (is (>= @stop-called 1))
        (is (<= 1 @breaks))))))

(deftest run-live-n-summary-reports-n-or-idle
  (with-redefs [pcap/run-live-n! (stub-run-live-n! 2)]
    (let [summary (pcap/run-live-n-summary! {} 2 (fn [_]) {})]
      (is (= 2 (:count summary)))
      (is (= :n (:stopped summary)))))
  (with-redefs [pcap/run-live-n! (stub-run-live-n! 1)] ; 未達
    (let [summary (pcap/run-live-n-summary! {} 2 (fn [_]) {})]
      (is (= 1 (:count summary)))
      (is (= :idle-or-eof (:stopped summary))))))

(deftest run-live-for-ms-summary-distinguishes-timeout
  (with-redefs [pcap/run-live-for-ms! (stub-run-live-for-ms! 1 2)]
    (let [summary (pcap/run-live-for-ms-summary! {} 1 (fn [_]) {})]
      (is (= 1 (:count summary)))
      (is (= :time (:stopped summary)))))
  (with-redefs [pcap/run-live-for-ms! (stub-run-live-for-ms! 1 0)]
    (let [summary (pcap/run-live-for-ms-summary! {} 1000 (fn [_]) {})]
      (is (= 1 (:count summary)))
      (is (= :idle-or-eof (:stopped summary))))))

(deftest open-live-uses-lookup-netmask-and-filter
  (let [{:keys [lib pcap]} (fake-lib-open-live {})
        seen (atom nil)]
    (with-redefs [pcap/lib lib
                  pcap/lookup-netmask (fn [_] 0x1234)
                  pcap/apply-filter! (fn [h opts] (reset! seen opts) h)]
      (is (= pcap (pcap/open-live {:device "en0" :filter "tcp"})))
      (is (= 0x1234 (:netmask @seen)))
      (is (= "tcp" (:filter @seen))))))

(deftest open-live-skips-filter-when-nil
  (let [{:keys [lib pcap]} (fake-lib-open-live {})
        seen (atom nil)]
    (with-redefs [pcap/lib lib
                  pcap/lookup-netmask (fn [_] 0x1)
                  pcap/apply-filter! (fn [h opts] (reset! seen opts) h)]
      (is (= pcap (pcap/open-live {:device "en0"})))
      (is (= 0x1 (:netmask @seen)))
      (is (nil? (:filter @seen))))))

(deftest open-live-throws-when-lib-returns-nil
  (let [{:keys [lib]} (fake-lib-open-live {:pcap nil})]
    (with-redefs [pcap/lib lib]
      (is (thrown-with-msg? clojure.lang.ExceptionInfo #"pcap_open_live failed"
                            (pcap/open-live {:device "en0"}))))))
