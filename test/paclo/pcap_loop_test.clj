(ns paclo.pcap-loop-test
  (:require
   [clojure.test :refer [deftest is]]
   [paclo.pcap :as pcap])
  (:import
   [jnr.ffi Memory Pointer]
   [jnr.ffi.byref PointerByReference]
   [paclo.jnr PcapConfigLibrary PcapLibrary]))

(defn- alloc-direct ^Pointer [^long n]
  (Memory/allocateDirect (jnr.ffi.Runtime/getSystemRuntime) n))

(defn- make-hdr+dat
  "Create fixed pcap_pkthdr and payload pointers."
  [^bytes ba]
  (let [hdr (alloc-direct 24)
        dat (alloc-direct (long (max 1 (alength ba))))
        len (alength ba)]
    (.putLong hdr (long 0) (long 123))   ;; tv_sec
    (.putLong hdr (long 8) (long 456))   ;; tv_usec
    (.putInt  hdr (long 16) len)   ;; caplen
    (.putInt  hdr (long 20) len)   ;; len
    (.put dat (long 0) ba 0 len)
    {:hdr hdr :dat dat}))

(def ^:private fake-pcap
  ;; breakloop expects a Pointer, so use 1-byte dummy memory.
  (alloc-direct 1))

(defn- set-ref! ^PointerByReference [^PointerByReference ref ^Pointer p]
  (let [rt (jnr.ffi.Runtime/getSystemRuntime)
        slot (alloc-direct (long (.nativeSize ref rt)))]
    (.putPointer slot (long 0) p)
    (.fromNative ref rt slot (long 0)))
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

(defn- stub-run-live-for-ms! [call-count ^long sleep-ms]
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
  "Fake PcapLibrary where pcap_open_live returns configured pcap (or nil)."
  [{:keys [pcap] :as opts}]
  (let [p (if (contains? opts :pcap) pcap fake-pcap)]
    {:lib
     (reify PcapLibrary
       (pcap_datalink [_ _] 1)
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
       (pcap_dump_flush [_ _] 0)
       (pcap_dump_close [_ _] nil)
       (pcap_geterr [_ _] "")
       (pcap_findalldevs [_ _ _] 0)
       (pcap_freealldevs [_ _] nil)
       (pcap_lookupnet [_ _ _ _ _] 0))
     :pcap p}))

(defn- fake-lib
  "Fake PcapLibrary returning `rcs` in sequence.
   For rc=1, header/data refs are populated."
  [{:keys [rcs hdr dat break-calls native-error]}]
  (let [rcs* (atom rcs)
        breaks (or break-calls (atom 0))
        hdr' (or hdr (alloc-direct 24))
        dat' (or dat (alloc-direct 1))]
    {:lib
     (reify PcapLibrary
       (pcap_datalink [_ _] 1)
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
       (pcap_dump_flush [_ _] 0)
       (pcap_dump_close [_ _] nil)
       (pcap_geterr [_ _] (or native-error ""))
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
        {:keys [lib breaks]} (fake-lib {:rcs [1 1 -2] :hdr hdr :dat dat})
        ready (atom 0)]
    (with-redefs [pcap/datalink (constantly 1)
                  pcap/lib lib
                  pcap/open-offline (fn [& _] fake-pcap)
                  pcap/open-live (fn [& _] fake-pcap)]
      (let [pkts (doall (pcap/capture->seq {:path "dummy"
                                            :on-ready #(swap! ready inc)
                                            :max 5
                                            :max-time-ms 50
                                            :timeout-ms 10
                                            :idle-max-ms 20}))]
        (is (= 2 (count pkts)))
        (is (= [9 9] (map #(aget ^bytes % 0) (map :bytes pkts))))
        (is (= 1 @ready))
        (is (= 1 @breaks))))))

(deftest capture->seq-passes-errors-when-requested
  (let [{:keys [lib]} (fake-lib {:rcs [-1]})]
    (with-redefs [pcap/datalink (constantly 1)
                  pcap/lib lib
                  pcap/open-offline (fn [& _] fake-pcap)]
      (let [out (doall (pcap/capture->seq {:path "dummy" :error-mode :pass
                                           :max 1 :max-time-ms 10 :idle-max-ms 5}))]
        (is (= [] out))))))

(deftest capture->seq-stop?-preempts-error-while-pass
  (let [{:keys [hdr dat]} (make-hdr+dat (byte-array [1]))
        {:keys [lib breaks]} (fake-lib {:rcs [1 -1] :hdr hdr :dat dat})
        stop-called (atom 0)]
    (with-redefs [pcap/datalink (constantly 1)
                  pcap/lib lib
                  pcap/open-offline (fn [& _] fake-pcap)]
      (let [out (doall (pcap/capture->seq {:path "dummy"
                                           :stop? (fn [_] (swap! stop-called inc) true)
                                           :error-mode :pass
                                           :max 5 :max-time-ms 50 :idle-max-ms 10}))]
        (is (= 1 (count out)))
        (is (>= @stop-called 1))
        (is (<= 1 @breaks))))))

(deftest capture->seq-throws-when-error-mode-throw
  (let [lib (reify PcapLibrary
              (pcap_datalink [_ _] 1)
              (pcap_next_ex [_ _ _ _] (throw (RuntimeException. "boom")))
              (pcap_close [_ _] nil)
              (pcap_open_offline [_ _ _] nil)
              (pcap_open_live [_ _ _ _ _ _] nil)
              (pcap_open_dead [_ _ _] nil)
              (pcap_breakloop [_ _] nil)
              (pcap_compile [_ _ _ _ _ _] 0)
              (pcap_setfilter [_ _ _] 0)
              (pcap_freecode [_ _] nil)
              (pcap_lib_version [_] "fake")
              (pcap_dump_open [_ _ _] nil)
              (pcap_dump [_ _ _ _] nil)
              (pcap_dump_flush [_ _] 0)
              (pcap_dump_close [_ _] nil)
              (pcap_geterr [_ _] "")
              (pcap_findalldevs [_ _ _] 0)
              (pcap_freealldevs [_ _] nil)
              (pcap_lookupnet [_ _ _ _ _] 0))
        closed? (atom false)]
    (with-redefs [pcap/datalink (constantly 1)
                  pcap/lib lib
                  pcap/open-offline (fn [& _] fake-pcap)
                  pcap/close! (fn [_]
                                (Thread/sleep 20)
                                (reset! closed? true))]
      (is (thrown-with-msg? clojure.lang.ExceptionInfo #"capture->seq background error"
                            (dorun (pcap/capture->seq {:path "dummy"
                                                       :error-mode :throw
                                                       :max 1 :max-time-ms 10 :idle-max-ms 5}))))
      (is (true? @closed?)))))

(deftest capture->seq-respects-queue-cap
  (let [{:keys [hdr dat]} (make-hdr+dat (byte-array [42]))
        {:keys [lib breaks]} (fake-lib {:rcs [1 1 1 -2] :hdr hdr :dat dat})]
    (with-redefs [pcap/datalink (constantly 1)
                  pcap/lib lib
                  pcap/open-offline (fn [& _] fake-pcap)]
      (let [pkts (doall (pcap/capture->seq {:path "dummy"
                                            :queue-cap 2
                                            :max 10 :max-time-ms 50 :idle-max-ms 20}))]
        (is (= 3 (count pkts)))
        (is (= [42 42 42] (map #(aget ^bytes % 0) (map :bytes pkts))))
        (is (= 1 @breaks))))))

(deftest capture->seq-reports-blocking-queue-stats
  (let [{:keys [hdr dat]} (make-hdr+dat (byte-array [42]))
        {:keys [lib]} (fake-lib {:rcs [1 1 1 -2] :hdr hdr :dat dat})
        stats (promise)]
    (with-redefs [pcap/datalink (constantly 1)
                  pcap/lib lib
                  pcap/open-offline (fn [& _] fake-pcap)]
      (is (= 3
             (count
              (pcap/capture->seq
               {:path "dummy"
                :queue-cap 2
                :queue-mode :blocking
                :on-queue-stats #(deliver stats %)
                :max 10 :max-time-ms 50 :idle-max-ms 20}))))
      (is (= {:mode :blocking
              :capacity 2
              :enqueued 3
              :dropped 0}
             (select-keys @stats
                          [:mode :capacity :enqueued :dropped])))
      (is (<= 1 (:max-depth @stats) 2))
      (is (<= 0 (:blocked-events @stats)))
      (is (<= 0 (:blocked-ns @stats))))))

(deftest capture->seq-dropping-mode-reports-paclo-drops
  (let [{:keys [hdr dat]} (make-hdr+dat (byte-array [7]))
        {:keys [lib]} (fake-lib {:rcs [1 1 1 -2] :hdr hdr :dat dat})
        stats (promise)]
    (with-redefs [pcap/datalink (constantly 1)
                  pcap/lib lib
                  pcap/open-offline (fn [& _] fake-pcap)]
      (let [packets (pcap/capture->seq
                     {:path "dummy"
                      :queue-cap 2
                      :queue-mode :dropping
                      :on-queue-stats #(deliver stats %)
                      :max 10 :max-time-ms 50 :idle-max-ms 20})]
        ;; Wait until the producer fills the queue and drops the remaining
        ;; packets before allowing the lazy consumer to drain it.
        (is (map? (deref stats 1000 nil)))
        (is (= 2 (count packets)))
        (is (= {:mode :dropping
                :capacity 2
                :enqueued 2
                :dropped 1
                :blocked-events 0
                :blocked-ns 0
                :max-depth 2}
               @stats))))))

(deftest capture->seq-validates-queue-options
  (is (thrown-with-msg? clojure.lang.ExceptionInfo
                        #"queue-mode"
                        (pcap/capture->seq
                         {:path "dummy" :queue-mode :unknown})))
  (is (thrown-with-msg? clojure.lang.ExceptionInfo
                        #"queue-cap"
                        (pcap/capture->seq
                         {:path "dummy" :queue-cap 0}))))

(deftest capture->seq-stop?-with-queue-cap
  (let [{:keys [hdr dat]} (make-hdr+dat (byte-array [7]))
        {:keys [lib]} (fake-lib {:rcs [1 1 1] :hdr hdr :dat dat})
        stopped (atom 0)]
    (with-redefs [pcap/datalink (constantly 1)
                  pcap/lib lib
                  pcap/open-offline (fn [& _] fake-pcap)]
      (let [pkts (doall (pcap/capture->seq {:path "dummy"
                                            :queue-cap 2
                                            :stop? (fn [_] (swap! stopped inc) (>= (long @stopped) 1))
                                            :max 10 :max-time-ms 100 :idle-max-ms 30}))]
        (is (= 1 (count pkts)))
        (is (>= @stopped 1))))))

(deftest run-live-n-summary-reports-n-or-idle
  (with-redefs [pcap/run-live-n! (stub-run-live-n! 2)]
    (let [summary (pcap/run-live-n-summary! {} 2 (fn [_]) {})]
      (is (= 2 (:count summary)))
      (is (= :n (:stopped summary)))))
  (with-redefs [pcap/run-live-n! (stub-run-live-n! 1)] ; not reached target n
    (let [summary (pcap/run-live-n-summary! {} 2 (fn [_]) {})]
      (is (= 1 (:count summary)))
      (is (= :idle-or-eof (:stopped summary))))))

(deftest run-live-for-ms-summary-distinguishes-timeout
  (with-redefs [pcap/run-live-for-ms! (stub-run-live-for-ms! 1 20)]
    (let [summary (pcap/run-live-for-ms-summary! {} 1 (fn [_]) {})]
      (is (= 1 (:count summary)))
      (is (= :time (:stopped summary)))))
  (with-redefs [pcap/run-live-for-ms! (stub-run-live-for-ms! 1 0)]
    (let [summary (pcap/run-live-for-ms-summary! {} 60000 (fn [_]) {})]
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

(deftest open-live-configured-applies-options-before-activation
  (let [calls (atom [])
        handle (alloc-direct 1)
        configured-lib
        (reify PcapConfigLibrary
          (pcap_create [_ device _]
            (swap! calls conj [:create device])
            handle)
          (pcap_set_snaplen [_ _ value]
            (swap! calls conj [:snaplen value])
            0)
          (pcap_set_promisc [_ _ value]
            (swap! calls conj [:promisc value])
            0)
          (pcap_set_timeout [_ _ value]
            (swap! calls conj [:timeout value])
            0)
          (pcap_set_buffer_size [_ _ value]
            (swap! calls conj [:buffer-size value])
            0)
          (pcap_set_immediate_mode [_ _ value]
            (swap! calls conj [:immediate value])
            0)
          (pcap_activate [_ _]
            (swap! calls conj [:activate])
            0))]
    (with-redefs [pcap/config-lib configured-lib
                  pcap/lookup-netmask (constantly 0)
                  pcap/apply-filter! (fn [h _] h)]
      (is (= handle
             (pcap/open-live {:device "en0"
                              :snaplen 2048
                              :promiscuous? false
                              :timeout-ms 25
                              :buffer-size 16777216
                              :immediate? true}))))
    (is (= [[:create "en0"]
            [:snaplen 2048]
            [:promisc 0]
            [:timeout 25]
            [:buffer-size 16777216]
            [:immediate 1]
            [:activate]]
           @calls))))

(deftest open-live-configured-closes-handle-on-configuration-error
  (let [handle (alloc-direct 1)
        closed (atom [])
        configured-lib
        (reify PcapConfigLibrary
          (pcap_create [_ _ _] handle)
          (pcap_set_snaplen [_ _ _] -1)
          (pcap_set_promisc [_ _ _] 0)
          (pcap_set_timeout [_ _ _] 0)
          (pcap_set_buffer_size [_ _ _] 0)
          (pcap_set_immediate_mode [_ _ _] 0)
          (pcap_activate [_ _] 0))]
    (with-redefs [pcap/config-lib configured-lib
                  pcap/close! #(swap! closed conj %)]
      (is (thrown-with-msg? clojure.lang.ExceptionInfo
                            #"pcap-set-snaplen failed"
                            (pcap/open-live {:device "en0"
                                             :buffer-size 4096}))))
    (is (= [handle] @closed))))

(deftest open-live-configured-reports-missing-libpcap-capability
  (let [handle (alloc-direct 1)
        closed (atom [])
        configured-lib
        (reify PcapConfigLibrary
          (pcap_create [_ _ _] handle)
          (pcap_set_snaplen [_ _ _]
            (throw (UnsatisfiedLinkError. "missing symbol")))
          (pcap_set_promisc [_ _ _] 0)
          (pcap_set_timeout [_ _ _] 0)
          (pcap_set_buffer_size [_ _ _] 0)
          (pcap_set_immediate_mode [_ _ _] 0)
          (pcap_activate [_ _] 0))]
    (with-redefs [pcap/config-lib configured-lib
                  pcap/close! #(swap! closed conj %)]
      (try
        (pcap/open-live {:device "en0" :buffer-size 4096})
        (is false "expected unsupported capability error")
        (catch clojure.lang.ExceptionInfo error
          (is (= :unsupported-live-configuration
                 (:reason (ex-data error)))))))
    (is (= [handle] @closed))))

(deftest open-live-rejects-invalid-buffer-size
  (is (thrown-with-msg? clojure.lang.ExceptionInfo
                        #":buffer-size must be an integer"
                        (pcap/open-live {:device "en0"
                                         :buffer-size 0})))
  (is (thrown-with-msg? clojure.lang.ExceptionInfo
                        #":buffer-size must be an integer"
                        (pcap/open-live {:device "en0"
                                         :buffer-size (inc Integer/MAX_VALUE)})))
  (is (thrown-with-msg? clojure.lang.ExceptionInfo
                        #":immediate[?] must be boolean"
                        (pcap/open-live {:device "en0"
                                         :immediate? :yes}))))

(defn- caught-error [f]
  (try (f) nil (catch Throwable error error)))

(deftest native-status-errors-propagate-through-every-loop
  (doseq [rc [-1 -3 2 99]
          run [#(pcap/loop! % (fn [_]))
               #(pcap/loop-n! % 10 (fn [_]))
               #(pcap/loop-n! % 10 (fn [_]) {:idle-max-ms 100})
               #(pcap/loop-for-ms! % 1000 (fn [_]))
               #(pcap/loop-for-ms! % 1000 (fn [_]) {:idle-max-ms 100})
               #(pcap/loop-n-or-ms! % {:n 10 :ms 1000} (fn [_]))
               #(pcap/loop-n-or-ms! % {:n 10 :ms 1000 :idle-max-ms 100} (fn [_]))]]
    (let [{:keys [lib]} (fake-lib {:rcs [rc]})]
      (with-redefs [pcap/lib lib]
        (let [error (caught-error #(run fake-pcap))]
          (is (= {:reason :pcap-read-failed :phase :pcap-next-ex
                  :rc rc :native-error ""}
                 (ex-data error))))))))

(deftest eof-ignores-stale-native-error
  (let [{:keys [lib]} (fake-lib {:rcs [-2] :native-error "stale native failure"})]
    (with-redefs [pcap/lib lib]
      ;; The fake returns an error string even at EOF; classification alone
      ;; determines success. Native message content has no control-flow role.
      (is (= -2 (pcap/loop! fake-pcap (fn [_])))))))

(deftest failed-offline-filter-closes-real-handle-once
  (let [close pcap/close!
        handles (atom [])]
    (with-redefs [pcap/close! (fn [handle] (swap! handles conj handle) (close handle))]
      (is (instance? Throwable
                     (caught-error #(pcap/open-offline
                                     "test/resources/capture-formats/ethernet.pcap"
                                     {:filter "udp and ("}))))
      (is (= 1 (count @handles))))))

(deftest failed-open-setup-retains-cause-and-closes-once
  (doseq [configured? [false true]
          stage [:filter :netmask]
          cleanup-fails? [false true]]
    (let [{:keys [lib]} (fake-lib-open-live {})
          ^Throwable failure (ex-info "setup failed" {:stage stage})
          cleanup (Exception. "close failed")
          closed (atom [])]
      (with-redefs [pcap/lib lib
                    pcap/open-live-configured (fn [_] fake-pcap)
                    pcap/apply-filter! (fn [h _] (if (= stage :filter) (throw failure) h))
                    pcap/lookup-netmask (fn [_] (if (= stage :netmask) (throw failure) 0))
                    pcap/close! (fn [h]
                                  (swap! closed conj h)
                                  (when cleanup-fails? (throw cleanup)))]
        (is (identical? failure
                        (caught-error #(pcap/open-live
                                        (cond-> {:device "en0" :filter "udp"}
                                          configured? (assoc :buffer-size 4096))))))
        (is (= [fake-pcap] @closed))
        (is (= (if cleanup-fails? [cleanup] []) (vec (.getSuppressed failure)))))))
  (doseq [cleanup-fails? [false true]]
    (let [failure (ex-info "setfilter failed" {:phase :pcap-setfilter})
          closed (atom [])]
      (with-redefs [pcap/apply-filter! (fn [_ _] (throw failure))
                    pcap/close! (fn [h]
                                  (swap! closed conj h)
                                  ;; This test owns a real offline handle.
                                  (.pcap_close PcapLibrary/INSTANCE h)
                                  (when cleanup-fails? (throw (Exception. "close failed"))))]
        (is (identical? failure
                        (caught-error #(pcap/open-offline
                                        "test/resources/capture-formats/ethernet.pcap"
                                        {:filter "udp"}))))
        (is (= 1 (count @closed)))))))

(deftest successful-live-open-transfers-ownership
  (let [{:keys [lib]} (fake-lib-open-live {})
        closed (atom [])]
    (with-redefs [pcap/lib lib
                  pcap/open-live-configured (fn [_] fake-pcap)
                  pcap/apply-filter! (fn [h _] h)
                  pcap/lookup-netmask (constantly 0)
                  pcap/close! #(swap! closed conj %)]
      (doseq [opts [{:device "en0"} {:device "en0" :buffer-size 4096}]]
        (is (identical? fake-pcap (pcap/open-live opts))))
      (is (empty? @closed)))))

(deftest configured-open-cleanup-does-not-mask-original-error
  (let [failure (Exception. "configuration failed")
        cleanup (Exception. "close failed")
        closed (atom 0)
        configured-lib
        (reify PcapConfigLibrary
          (pcap_create [_ _ _] fake-pcap)
          (pcap_set_snaplen [_ _ _] (throw failure))
          (pcap_set_promisc [_ _ _] 0)
          (pcap_set_timeout [_ _ _] 0)
          (pcap_set_buffer_size [_ _ _] 0)
          (pcap_set_immediate_mode [_ _ _] 0)
          (pcap_activate [_ _] 0))]
    (with-redefs [pcap/config-lib configured-lib
                  pcap/close! (fn [_] (swap! closed inc) (throw cleanup))]
      (is (identical? failure (caught-error #(pcap/open-live {:device "en0" :buffer-size 4096}))))
      (is (= 1 @closed))
      (is (= [cleanup] (vec (.getSuppressed failure)))))))

(deftest lazy-terminal-error-never-waits-for-full-queue
  (doseq [mode [:throw :pass]
          queue-mode [:blocking :dropping]]
    (let [{:keys [hdr dat]} (make-hdr+dat (byte-array [7]))
          {:keys [lib]} (fake-lib {:rcs [1 -1] :hdr hdr :dat dat})
          closed (atom 0)
          errors (atom [])
          producer (atom nil)
          start-future clojure.core/future-call]
      (with-redefs [pcap/lib lib
                    pcap/open-offline (fn [& _] fake-pcap)
                    pcap/close! (fn [_] (swap! closed inc))
                    clojure.core/future-call (fn [f] (let [running (start-future f)]
                                                       (reset! producer running)
                                                       running))]
        (let [packets (pcap/capture->seq
                       {:path "dummy" :max 10 :queue-cap 1 :queue-mode queue-mode
                        :error-mode mode :on-error #(do (swap! errors conj %) (throw (Exception. "callback failed")))})]
          ;; No consumer drains the capacity-one queue until producer exits.
          (is (not= ::timeout (deref @producer 2000 ::timeout)))
          (is (= 1 @closed))
          (is (= 1 (count @errors)))
          (is (= :pcap-read-failed (:reason (ex-data (first @errors)))))
          (is (= [7] (vec (:bytes (first packets)))))
          (if (= mode :pass)
            (is (nil? (next packets)))
            (is (= :pcap-read-failed (:reason (ex-data (caught-error #(next packets))))))))))))

(deftest configured-open-failures-close-through-one-owner
  (doseq [stage [:snaplen :promisc :timeout :buffer :immediate :activate :filter]]
    (let [closed (atom [])
          fail (fn [step] (if (= stage step) -1 0))
          configured-lib
          (reify PcapConfigLibrary
            (pcap_create [_ _ _] fake-pcap)
            (pcap_set_snaplen [_ _ _] (fail :snaplen))
            (pcap_set_promisc [_ _ _] (fail :promisc))
            (pcap_set_timeout [_ _ _] (fail :timeout))
            (pcap_set_buffer_size [_ _ _] (fail :buffer))
            (pcap_set_immediate_mode [_ _ _] (fail :immediate))
            (pcap_activate [_ _] (fail :activate)))
          {:keys [lib]} (fake-lib-open-live {})]
      (with-redefs [pcap/lib lib
                    pcap/config-lib configured-lib
                    pcap/lookup-netmask (constantly 0)
                    pcap/apply-filter! (fn [h _]
                                         (if (= stage :filter)
                                           (throw (ex-info "setfilter failed" {:phase :pcap-setfilter}))
                                           h))
                    pcap/close! #(swap! closed conj %)]
        (is (instance? clojure.lang.ExceptionInfo
                       (caught-error #(pcap/open-live {:device "en0" :buffer-size 4096
                                                       :immediate? true :filter "udp"}))))
        (is (= [fake-pcap] @closed))))))

(deftest successful-offline-open-keeps-native-handle-until-owner-closes
  (let [close pcap/close!
        closed (atom [])]
    (with-redefs [pcap/close! (fn [h] (swap! closed conj h) (close h))]
      (let [handle (pcap/open-offline "test/resources/capture-formats/ethernet.pcap" {:filter "udp"})]
        (is (empty? @closed))
        (is (= 1 (pcap/datalink handle)))
        (pcap/close! handle)
        (is (= [handle] @closed))))))
