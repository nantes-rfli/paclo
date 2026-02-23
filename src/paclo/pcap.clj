(ns paclo.pcap
  (:require
   [clojure.java.io :as io]
   [clojure.string :as str])
  (:import
   [java.util.concurrent LinkedBlockingQueue]
   [jnr.ffi LibraryLoader Memory Pointer]
   [jnr.ffi.byref IntByReference PointerByReference]
   [paclo.jnr PcapHeader PcapLibrary]))

(def ^:private ^jnr.ffi.Runtime rt (jnr.ffi.Runtime/getSystemRuntime))
(def ^:private ^PcapLibrary lib
  (let [os      (.. System (getProperty "os.name") toLowerCase)
        libname (if (.contains os "win") "wpcap" "pcap")
        loader  (LibraryLoader/create PcapLibrary)]
    (.load loader libname)))

;; --- constants (use before any functions) ---
(def ^:const PCAP_ERRBUF_SIZE 256)

(defn ^:private lookup-netmask
  "Resolve netmask from a device name. Returns 0 on lookup failure."
  [^String device]
  (let [^Pointer err  (Memory/allocate rt (long PCAP_ERRBUF_SIZE))
        ^IntByReference netp  (IntByReference.)
        ^IntByReference maskp (IntByReference.)
        rc    (.pcap_lookupnet lib device netp maskp err)]
    (if (neg? rc)
      0
      (.getValue maskp))))

(defn ^:private valid-filter-string?
  "Return true when filter is a non-blank string."
  [filter]
  (and (string? filter) (not (str/blank? filter))))

(defn ^:private apply-filter!
  "Apply a BPF filter to a pcap handle. Example opts:
   {:filter \"udp and port 53\" :optimize? true :netmask 0}"
  [^Pointer pcap {:keys [filter optimize? netmask]}]
  (when (and pcap (valid-filter-string? filter))
    (let [opt?  (if (nil? optimize?) true optimize?)
          mask  (int (or netmask 0))         ;; Default netmask is 0 (unknown)
          prog  (PcapLibrary/compileFilter pcap filter opt? mask)]
      (try
        (PcapLibrary/setFilterOrThrow pcap prog)
        (finally
          (PcapLibrary/freeFilter prog)))))
  pcap)

(defn- blank-str? [^String s]
  (or (nil? s) (re-find #"^\s*$" s)))

(defn- valid-device? [device]
  (and (string? device) (not (blank-str? device))))

(defn- valid-path? [path]
  (cond
    (instance? java.io.File path) (not (blank-str? (.getPath ^java.io.File path)))
    (string? path) (not (blank-str? path))
    :else false))

(defn vlan-tag->str
  "Render VLAN tag map {:tpid .. :vid .. :pcp .. :dei ..} as a display string."
  [{:keys [tpid vid pcp dei]}]
  (format "[TPID=0x%04X VID=%d PCP=%d DEI=%s]" (long tpid) (long vid) (long pcp) (boolean dei)))

(defn- normalize-desc [^String s]
  (let [t (when s (str/trim s))]
    (when (and t (not (blank-str? t))) t)))

(defn open-offline
  (^Pointer [path]
   (open-offline path {}))
  (^Pointer [path opts]
   (let [f   (io/file path)
         abs (.getAbsolutePath ^java.io.File f)]
     (when-not (.exists ^java.io.File f)
       (throw (ex-info (str "pcap file not found: " abs)
                       {:path abs :reason :not-found})))
     (when (zero? (.length ^java.io.File f))
       (throw (ex-info (str "pcap file is empty: " abs)
                       {:path abs :reason :empty})))
     (let [^Pointer err (Memory/allocate rt (long PCAP_ERRBUF_SIZE))
           pcap (.pcap_open_offline lib abs err)]
       (when (nil? pcap)
         (let [raw (try (.getString ^Pointer err (long 0)) (catch Throwable _ ""))  ; Best-effort errbuf read
               msg (let [t (str/trim (or raw ""))]
                     (if (seq t)
                       (str "pcap_open_offline failed: " t)
                       "pcap_open_offline failed"))]
           (throw (ex-info msg
                           {:path abs :reason :pcap-open-failed :err raw}))))
       (apply-filter! pcap opts)
       pcap))))

(defn open-live
  [{:keys [device snaplen promiscuous? timeout-ms netmask]
    :or   {snaplen 65536 promiscuous? true timeout-ms 10}
    :as   opts}]
  (when-not (valid-device? device)
    (throw (ex-info "open-live requires non-blank :device" {:device device})))
  (let [^Pointer err    (Memory/allocate rt (long PCAP_ERRBUF_SIZE))
        promisc (if promiscuous? 1 0)
        pcap    (.pcap_open_live lib device snaplen promisc timeout-ms err)]
    (when (nil? pcap)
      (throw (ex-info "pcap_open_live failed"
                      {:device device :err (.getString ^Pointer err (long 0))})))
    (let [resolved-mask (or netmask (when device (lookup-netmask device)))
          opts*         (if (some? resolved-mask) (assoc opts :netmask resolved-mask) opts)]
      (apply-filter! pcap opts*))))

(defn close! [^Pointer pcap] (.pcap_close lib pcap))

;; ------------------------------------------------------------
;; with-pcap / with-dumper / with-live / with-offline
;; ------------------------------------------------------------

;; Macros below reference these fns; declare them so macro expansion can resolve.
(declare open-dumper dump! flush-dumper! close-dumper!)

(defmacro with-pcap
  "Example: (with-pcap [h (open-live {:device \"en0\"})]
         (loop-n! h 10 prn))"
  [[sym open-expr] & body]
  `(let [~sym ~open-expr]
     (try
       ~@body
       (finally
         (close! ~sym)))))

(defmacro with-dumper
  "Example: (with-dumper [d (open-dumper h \"out.pcap\")]
         (dump! d hdr data))"
  [[sym open-expr] & body]
  `(let [~sym ~open-expr]
     (try
       ~@body
       (finally
         (flush-dumper! ~sym)
         (close-dumper! ~sym)))))

(defmacro with-live
  "Example: (with-live [h {:device \"en0\" :filter \"tcp\"}]
         (loop-n! h 10 prn))"
  [[sym opts] & body]
  `(with-pcap [~sym (open-live ~opts)]
     ~@body))

(defmacro with-offline
  "Example:
     (with-offline [h (open-offline \"dev/resources/fixtures/sample.pcap\")]
       (loop-for-ms! h 2000 prn))
     (with-offline [h (open-offline \"dev/resources/fixtures/sample.pcap\" {:filter \"udp\"})]
       (loop-n! h 50 prn))"
  [[sym open-expr] & body]
  `(with-pcap [~sym ~open-expr]
     ~@body))

;; ------------------------------------------------------------
;; ------------------------------------------------------------

(def ^:const PCAP_PKTHDR_BYTES 24)
(def ^:const DLT_EN10MB 1) ; Ethernet

(defn ^:private now-sec-usec []
  (let [ms (System/currentTimeMillis)
        sec (long (quot ms 1000))
        usec (long (* 1000 (long (mod ms 1000))))]
    [sec usec]))

(defn ^:private ensure-bytes-timestamp
  "Normalize one packet input into [byte-array sec usec].
   - If map, :bytes required; sec/usec optional (defaults to now).
   - If byte-array, wraps with current timestamp.
   Throws ex-info on missing :bytes."
  [p]
  (if (map? p)
    (let [{:keys [bytes sec usec]} p
          ba' (or bytes (byte-array 0))]
      (when (nil? bytes)
        (throw (ex-info "missing :bytes" {:item p})))
      (let [[s u] (if (and sec usec) [sec usec] (now-sec-usec))]
        [^bytes ba' (long s) (long u)]))
    (let [[s u] (now-sec-usec)]
      [^bytes p (long s) (long u)])))

(defn ^:private idle-next
  "Given current idle ms, tick, and target, return {:idle <new> :break? bool}."
  [^long idle ^long tick ^long idle-target]
  (let [idle' (unchecked-add idle tick)]
    {:idle idle'
     :break? (>= idle' idle-target)}))

(defn rc->status
  "Classify pcap_next_ex return code.
   1 => :packet, 0 => :timeout, -2 => :eof, anything else => :error."
  [^long rc]
  (case (int rc)
    1 :packet
    0 :timeout
    -2 :eof
    :error))

(defn rc->status-detail
  "Return a map {:rc rc :status <kw> :summary <string|nil>} that is convenient for
   logging when pcap_next_ex finishes with EOF (-2) or an error (-1/others)."
  [rc]
  (let [status (rc->status rc)]
    {:rc rc
     :status status
     :summary (case status
                :eof "pcap_next_ex reached EOF (rc=-2)"
                :error (format "pcap_next_ex returned error (rc=%d)" (long rc))
                nil)}))

(defn open-dead
  "Create a dead pcap handle for generation/writing.
   `linktype` uses DLT_* constants. Default snaplen is 65536."
  ([]
   (open-dead DLT_EN10MB 65536))
  ([linktype snaplen]
   (.pcap_open_dead lib (int linktype) (int snaplen))))

(defn ^:private bytes->ptr [^bytes ba]
  (let [^Pointer m (Memory/allocate rt (long (alength ba)))]
    (.put m (long 0) ba (int 0) (int (alength ba)))
    m))

(defn ^:private mk-hdr
  "Build a pcap_pkthdr pointer.
   `sec`/`usec` are epoch second/microsecond values; `len` is int."
  [^long sec ^long usec ^long len]
  (let [^Pointer hdr (Memory/allocate rt (long PCAP_PKTHDR_BYTES))]
    (.putLong hdr (long 0) sec)
    (.putLong hdr (long 8) usec)
    (.putInt  hdr (long 16) (int len))
    (.putInt  hdr (long 20) (int len))
    hdr))

(defn bytes-seq->pcap!
  "Write a sequence of packet bytes to a PCAP file.
   packets: sequence of `byte-array` or
            `{:bytes <ba> :sec <long> :usec <long>}`
   opts: {:out \"out.pcap\" :linktype DLT_* :snaplen 65536}"
  [packets {:keys [out linktype snaplen]
            :or   {linktype DLT_EN10MB snaplen 65536}}]
  (when (str/blank? out)
    (throw (ex-info "bytes-seq->pcap!: :out is required" {})))
  (let [pcap (open-dead linktype snaplen)]
    (try
      (let [d (open-dumper pcap out)]
        (try
          (doseq [p packets]
            (let [[^bytes ba sec usec] (ensure-bytes-timestamp p)
                  hdr (mk-hdr sec usec (alength ba))
                  dat (bytes->ptr ba)]
              (dump! d hdr dat)))
          (finally
            (flush-dumper! d)
            (close-dumper! d))))
      (finally
        (close! pcap)))))

(defn lookupnet
  "Resolve network address/mask for device `dev`.
   Success: {:net int :mask int}
   Failure: throws ex-info with :phase :lookupnet."
  [dev]
  (let [^IntByReference net-ref  (IntByReference.)
        ^IntByReference mask-ref (IntByReference.)
        ^Pointer err     (Memory/allocate rt (long PCAP_ERRBUF_SIZE))
        rc       (.pcap_lookupnet lib dev net-ref mask-ref err)]
    (if (zero? rc)
      {:net  (.getValue net-ref)
       :mask (.getValue mask-ref)}
      (throw (ex-info "pcap_lookupnet failed"
                      {:phase  :lookupnet
                       :device dev
                       :rc     rc
                       :err    (.getString ^Pointer err (long 0))})))))

(defn set-bpf!
  "Apply BPF with optimize=1 and netmask=0 (unknown). Returns true."
  [^Pointer pcap expr]
  (apply-filter! pcap {:filter expr :optimize? true :netmask 0})
  true)

(defn set-bpf-with-netmask!
  "Apply BPF with optimize=1 and explicit netmask. Returns true."
  [^Pointer pcap expr netmask]
  (apply-filter! pcap {:filter expr :optimize? true :netmask (int netmask)})
  true)

(defn set-bpf-on-device!
  "Lookup device netmask for `dev` and apply BPF via set-bpf-with-netmask!.
   Returns true."
  [^Pointer pcap dev expr]
  (let [mask (try
               (:mask (lookupnet dev)) ; Reuse detailed lookupnet path
               (catch Throwable _ 0))] ; Safe fallback
    (set-bpf-with-netmask! pcap expr mask)))

(defn loop!
  "Poll `pcap_next_ex`.
   `handler` receives maps like {:ts-sec :ts-usec :caplen :len :bytes}.
   Terminates when rc<0 (EOF/error)."
  [^Pointer pcap handler]
  (let [^PointerByReference hdr-ref (PointerByReference.)
        ^PointerByReference dat-ref (PointerByReference.)]
    (loop []
      (let [rc (.pcap_next_ex lib pcap hdr-ref dat-ref)
            status (rc->status rc)]
        (cond
          (= status :packet)
          (let [^jnr.ffi.Pointer hdr (.getValue hdr-ref)
                ^jnr.ffi.Pointer dat (.getValue dat-ref)
                ts-sec (PcapHeader/tv_sec hdr)
                ts-usec (PcapHeader/tv_usec hdr)
                caplen (PcapHeader/caplen hdr)
                len    (PcapHeader/len hdr)
                arr    (byte-array (int caplen))]
            (.get dat (long 0) arr (int 0) (int (alength arr)))
            (handler {:ts-sec ts-sec :ts-usec ts-usec
                      :caplen caplen :len len :bytes arr})
            (recur))

          (= status :timeout)  ; timeout (live capture)
          (recur)

          (= status :eof)     ; offline EOF
          rc

          :else     ; -1 error
          rc)))))

(defn breakloop! [^Pointer pcap] (.pcap_breakloop lib pcap))

(defn open-dumper ^Pointer [^Pointer pcap ^String path]
  (let [^Pointer d (.pcap_dump_open lib pcap path)]
    (when (nil? d)
      (throw (ex-info "pcap_dump_open failed" {:path path})))
    d))

(defn dump! [^Pointer dumper ^Pointer hdr ^Pointer data]
  (.pcap_dump lib dumper hdr data))

(defn flush-dumper! [^Pointer dumper]
  (.pcap_dump_flush lib dumper))

(defn close-dumper! [^Pointer dumper]
  (.pcap_dump_close lib dumper))

(defn capture->pcap
  "Capture live packets and save them to out.pcap.
   opts:
   {:device \"en0\"
    :filter \"tcp port 80\"     ; optional
    :max 100                    ; stop when captured count reaches this value
    :snaplen 65536
    :promiscuous? true
    :timeout-ms 10              ; pcap_next_ex timeout
    :max-time-ms 10000          ; wall-clock max duration (ms)
    :idle-max-ms 3000}          ; continuous idle max (ms)"
  [{:keys [device filter max snaplen promiscuous? timeout-ms max-time-ms idle-max-ms]
    :or {max 100 snaplen 65536 promiscuous? true timeout-ms 10
         max-time-ms 10000 idle-max-ms 3000}}
   out]
  (let [pcap   (open-live {:device device :snaplen snaplen :promiscuous? promiscuous? :timeout-ms timeout-ms})
        dumper (open-dumper pcap out)
        ^PointerByReference hdr-ref (PointerByReference.)
        ^PointerByReference dat-ref (PointerByReference.)
        t0 (System/currentTimeMillis)
        max-long (long max)
        max-time-long (long max-time-ms)
        idle-max-long (long idle-max-ms)]
    (try
      (when filter
        (if (some? device)
          (set-bpf-on-device! pcap device filter)
          (set-bpf! pcap filter)))
      (loop [n 0 idle 0]
        (let [now (System/currentTimeMillis)]
          (cond
            (>= n max-long) n
            (>= (- now t0) max-time-long) n
            (>= idle idle-max-long) n
            :else
            (let [rc (.pcap_next_ex lib pcap hdr-ref dat-ref)
                  status (rc->status rc)]
              (cond
                (= status :packet)
                (do
                  (let [^Pointer hdr (.getValue hdr-ref)
                        ^Pointer dat (.getValue dat-ref)]
                    (dump! dumper hdr dat))
                  (recur (inc n) 0))
                (= status :timeout) ; timeout
                (recur n (+ idle (long timeout-ms)))
                :else    ; eof or error
                n)))))
      (finally
        (flush-dumper! dumper)
        (close-dumper! dumper)
        (close! pcap)))))

(defn- macos-device->desc []
  (let [os (.. System (getProperty "os.name") toLowerCase)
        ^java.io.File networksetup-bin (io/file "/usr/sbin/networksetup")]
    (if (or (not (.contains os "mac"))
            (not (and (.exists networksetup-bin)
                      (.canExecute networksetup-bin))))
      {}
      (let [^"[Ljava.lang.String;" cmd (into-array String [(.getAbsolutePath networksetup-bin) "-listallhardwareports"])
            ^java.lang.ProcessBuilder pb (java.lang.ProcessBuilder. cmd)
            _    (.redirectErrorStream pb true)   ;; Do not rely on Redirect enum constants
            proc (.start pb)
            rdr  (java.io.BufferedReader.
                  (java.io.InputStreamReader. (.getInputStream proc)))]
        (try
          (loop [m {}
                 cur-port nil
                 line (.readLine rdr)]
            (if (nil? line)
              m
              (cond
                (.startsWith line "Hardware Port: ")
                (recur m (str/trim (subs line 14)) (.readLine rdr))

                (.startsWith line "Device: ")
                (let [dev (subs line 8)]
                  (recur (assoc m dev cur-port) cur-port (.readLine rdr)))

                :else
                (recur m cur-port (.readLine rdr)))))
          (finally
            (.close rdr)
            (.waitFor proc)))))))

(defn list-devices
  "Return a simple list of available devices.
   On macOS, fills missing descriptions using networksetup.
   - skips entries with blank names
   - applies fallback when description is blank"
  []
  (let [^Pointer err (Memory/allocate rt (long PCAP_ERRBUF_SIZE))
        ^PointerByReference pp  (PointerByReference.)]
    (when (neg? (.pcap_findalldevs lib pp err))
      (throw (ex-info "pcap_findalldevs failed" {:err (.getString ^Pointer err (long 0))})))
    (let [^Pointer head (.getValue pp)
          fallback (macos-device->desc)]
      (try
        (loop [p head, acc (transient [])]
          (if (or (nil? p) (= 0 (.address p)))
            (persistent! acc)
            (let [^paclo.jnr.PcapLibrary$PcapIf ifc (paclo.jnr.PcapLibrary$PcapIf. rt)]
              (.useMemory ifc p)
              (let [^Pointer name-ptr (.get (.-name ifc))
                    ^Pointer desc-ptr (.get (.-desc ifc))
                    ^Pointer next-ptr (.get (.-next ifc))
                    name     (when (and name-ptr (not= 0 (.address name-ptr)))
                               (let [s (.getString name-ptr 0)]
                                 (when-not (blank-str? s) s)))
                    desc0    (when (and desc-ptr (not= 0 (.address desc-ptr)))
                               (normalize-desc (.getString desc-ptr 0)))
                    desc     (or desc0 (when name (normalize-desc (get fallback name))))]
                (if name
                  (recur next-ptr (conj! acc {:name name :desc desc}))
                  (recur next-ptr acc))))))
        (finally
          (.pcap_freealldevs lib head))))))

(defn- ->pkt-handler
  "Normalize `handler` to a 1-arg function.
   - 1-arg function: called directly
   - 0-arg function: called via ArityException fallback
   - nil: no-op handler"
  [handler]
  (cond
    (nil? handler)
    (fn [_] nil)

    :else
    (fn [pkt]
      (try
        (handler pkt)                     ;; Call as 1-arg handler
        (catch clojure.lang.ArityException _
          (handler))))))                  ;; Fallback call as 0-arg handler

;; -----------------------------------------
;; -----------------------------------------
;; NOTE:

(defn loop-n!
  "Process up to n packets via pcap_next_ex, then stop.
   Options: {:idle-max-ms <ms> :timeout-ms <ms>}
   Example: (loop-n! h 10 handler) ; default behavior
       (loop-n! h 10 handler {:idle-max-ms 3000 :timeout-ms 100})"
  ([^Pointer pcap ^long n handler]
   (assert (pos? n) "n must be positive")
   (let [c (atom 0)
         handle (->pkt-handler handler)]
     (loop! pcap (fn [pkt]
                   (handle pkt)
                   (swap! c inc)
                   (when (>= (long @c) n)
                     (breakloop! pcap))))))
  ([^Pointer pcap ^long n handler {:keys [idle-max-ms timeout-ms]}]
   (if (nil? idle-max-ms)
     (loop-n! pcap n handler)
     (do
       (assert (pos? n) "n must be positive")
       (let [hdr-ref (PointerByReference.)
             dat-ref (PointerByReference.)
             idle-ms-target (long idle-max-ms)
             tick (long (or timeout-ms 100))
             handle (->pkt-handler handler)]
         (loop [count 0 idle 0]
           (when (< count n)
             (let [rc (.pcap_next_ex lib pcap hdr-ref dat-ref)
                   status (rc->status rc)]
               (cond
                 (= status :packet)
                 (let [^jnr.ffi.Pointer hdr (.getValue hdr-ref)
                       ^jnr.ffi.Pointer dat (.getValue dat-ref)
                       ts-sec (PcapHeader/tv_sec hdr)
                       ts-usec (PcapHeader/tv_usec hdr)
                       caplen (PcapHeader/caplen hdr)
                       len    (PcapHeader/len hdr)
                       arr    (byte-array (int caplen))]
                   (.get dat (long 0) arr (int 0) (int (alength arr)))
                   (handle {:ts-sec ts-sec :ts-usec ts-usec
                            :caplen caplen :len len :bytes arr})
                   (recur (unchecked-inc (long count)) 0))

                 (= status :timeout)
                 (let [{:keys [idle break?]} (idle-next idle tick idle-ms-target)]
                   (if break?
                     (breakloop! pcap)
                     (recur count (long idle))))

                 :else
                 (breakloop! pcap))))))))))

(defn loop-for-ms!
  "Stop after duration-ms elapsed (wall-clock).
   Options: {:idle-max-ms <ms> :timeout-ms <ms>}
   Example: (loop-for-ms! h 3000 handler)
       (loop-for-ms! h 3000 handler {:idle-max-ms 1000 :timeout-ms 50})"
  ([^Pointer pcap ^long duration-ms handler]
   (assert (pos? duration-ms) "duration-ms must be positive")
   (let [t0 (System/currentTimeMillis)
         handle (->pkt-handler handler)]
     (loop! pcap (fn [pkt]
                   (handle pkt)
                   (when (>= (- (System/currentTimeMillis) t0) duration-ms)
                     (breakloop! pcap))))))
  ([^Pointer pcap ^long duration-ms handler {:keys [idle-max-ms timeout-ms]}]
   (if (nil? idle-max-ms)
     (loop-for-ms! pcap duration-ms handler)
     (do
       (assert (pos? duration-ms) "duration-ms must be positive")
       (let [hdr-ref (PointerByReference.)
             dat-ref (PointerByReference.)
             t0 (System/currentTimeMillis)
             deadline (+ t0 (long duration-ms))
             idle-ms-target (long idle-max-ms)
             tick (long (or timeout-ms 100))
             handle (->pkt-handler handler)]
         (loop [idle 0]
           (when (< (System/currentTimeMillis) deadline)
             (let [rc (.pcap_next_ex lib pcap hdr-ref dat-ref)
                   status (rc->status rc)]
               (cond
                 (= status :packet)
                 (let [^jnr.ffi.Pointer hdr (.getValue hdr-ref)
                       ^jnr.ffi.Pointer dat (.getValue dat-ref)
                       ts-sec (PcapHeader/tv_sec hdr)
                       ts-usec (PcapHeader/tv_usec hdr)
                       caplen (PcapHeader/caplen hdr)
                       len    (PcapHeader/len hdr)
                       arr    (byte-array (int caplen))]
                   (.get dat (long 0) arr (int 0) (int (alength arr)))
                   (handle {:ts-sec ts-sec :ts-usec ts-usec
                            :caplen caplen :len len :bytes arr})
                   (recur 0))

                 (= status :timeout)
                 (let [{:keys [idle break?]} (idle-next idle tick idle-ms-target)]
                   (if break?
                     (breakloop! pcap)
                     (recur (long idle))))

                 :else
                 (breakloop! pcap))))))))))

(defn loop-n-or-ms!
  "Stop when either n packets are processed or duration-ms is reached.
   conf: {:n <long> :ms <long> :idle-max-ms <ms-optional> :timeout-ms <ms-optional> :stop? <fn-optional>}"
  [^Pointer pcap {:keys [n ms idle-max-ms timeout-ms stop?]} handler]
  (when (nil? n) (throw (ex-info "missing :n" {})))
  (when (nil? ms) (throw (ex-info "missing :ms" {})))
  (assert (pos? (long n)) "n must be positive")
  (assert (pos? (long ms)) "ms must be positive")
  (let [handle (->pkt-handler handler)
        n-long (long n)
        ms-long (long ms)]
    (if (nil? idle-max-ms)
      (let [c  (atom 0)
            t0 (System/currentTimeMillis)]
        (loop! pcap (fn [pkt]
                      (handle pkt)
                      (swap! c inc)
                      (let [stop-n? (>= (long @c) n-long)
                            stop-t? (>= (- (System/currentTimeMillis) t0) ms-long)
                            stop-custom? (and stop? (stop? pkt))]
                        (when (or stop-n? stop-t? stop-custom?)
                          (breakloop! pcap))))))
      (let [hdr-ref (PointerByReference.)
            dat-ref (PointerByReference.)
            t0 (System/currentTimeMillis)
            deadline (+ t0 ms-long)
            tick (long (or timeout-ms 100))
            idle-target (long idle-max-ms)]
        (loop [count 0 idle 0]
          (when (and (< count n-long)
                     (< (System/currentTimeMillis) deadline))
            (let [rc (.pcap_next_ex lib pcap hdr-ref dat-ref)
                  status (rc->status rc)]
              (cond
                (= status :packet)
                (let [^jnr.ffi.Pointer hdr (.getValue hdr-ref)
                      ^jnr.ffi.Pointer dat (.getValue dat-ref)
                      ts-sec (PcapHeader/tv_sec hdr)
                      ts-usec (PcapHeader/tv_usec hdr)
                      caplen (PcapHeader/caplen hdr)
                      len    (PcapHeader/len hdr)
                      arr    (byte-array (int caplen))
                      _      (.get dat (long 0) arr (int 0) (int (alength arr)))
                      pkt    {:ts-sec ts-sec :ts-usec ts-usec
                              :caplen caplen :len len :bytes arr}]
                  (handle pkt)
                  (if (and stop? (stop? pkt))
                    (breakloop! pcap)            ;; Immediate stop on match (works for offline too)
                    (recur (unchecked-inc (long count)) 0)))

                (= status :timeout)
                (let [{:keys [idle break?]} (idle-next idle tick idle-target)]
                  (if break?
                    (breakloop! pcap)
                    (recur count (long idle))))

                :else
                (breakloop! pcap)))))))))

;; -----------------------------------------
;; -----------------------------------------

(defn run-live-n!
  "Open live capture, optionally apply BPF, process n packets, then close.
   Additional option: :idle-max-ms (:timeout-ms is shared with open-live)
   Example: (run-live-n! {:device \"en1\" :filter \"tcp\" :timeout-ms 100}
                    50
                    handler
                    {:idle-max-ms 3000})"
  ([opts ^long n handler]
   (run-live-n! opts n handler {}))
  ([{:keys [device filter snaplen promiscuous? timeout-ms]
     :or {snaplen 65536 promiscuous? true timeout-ms 10}}
    ^long n
    handler
    {:keys [idle-max-ms]}]
   (let [h (open-live {:device device :snaplen snaplen :promiscuous? promiscuous? :timeout-ms timeout-ms})]
     (try
       (when filter
         (if device (set-bpf-on-device! h device filter)
             (set-bpf! h filter)))
       (if idle-max-ms
         (loop-n! h n handler {:idle-max-ms idle-max-ms :timeout-ms timeout-ms})
         (loop-n! h n handler))
       (finally (close! h))))))

(defn run-live-for-ms!
  "Open live capture, optionally apply BPF, process for duration-ms, then close.
   Additional option: {:idle-max-ms <ms>}
   Example: (run-live-for-ms! {:device \"en1\" :timeout-ms 50}
                         5000
                         handler
                         {:idle-max-ms 1000})"
  ([opts ^long duration-ms handler]
   (run-live-for-ms! opts duration-ms handler {}))
  ([{:keys [device filter snaplen promiscuous? timeout-ms]
     :or {snaplen 65536 promiscuous? true timeout-ms 10}}
    ^long duration-ms
    handler
    {:keys [idle-max-ms]}]
   (let [h (open-live {:device device :snaplen snaplen :promiscuous? promiscuous? :timeout-ms timeout-ms})]
     (try
       (when filter
         (if device (set-bpf-on-device! h device filter)
             (set-bpf! h filter)))
       (if idle-max-ms
         (loop-for-ms! h duration-ms handler {:idle-max-ms idle-max-ms :timeout-ms timeout-ms})
         (loop-for-ms! h duration-ms handler))
       (finally (close! h))))))

;; -----------------------------------------
;; -----------------------------------------

(defn capture->seq
  "High-level API that returns packets as a lazy sequence.
   opts:
   - live:    {:device \"en1\" :filter \"tcp\" :snaplen 65536 :promiscuous? true :timeout-ms 10}
   - offline: {:path \"sample.pcap\" :filter \"...\"}
   - shared stop conditions (safe defaults when omitted):
       :max <int>               ; max packet count (default 100)
       :max-time-ms <int>       ; max elapsed time (default 10000)
       :idle-max-ms <int>       ; max continuous idle time (default 3000)
   - internal queue:
       :queue-cap <int>         ; producer -> consumer buffer (default 1024)
   - error handling:
       :on-error (fn [throwable])   ; optional callback on background thread errors
       :error-mode :throw|:pass     ; default :throw, :pass skips background errors
   - stop hook:
       :stop? (fn [pkt] boolean)    ; stop immediately when true (breakloop!)

   Returns a lazy seq of packet maps."
  [{:keys [device path filter snaplen promiscuous? timeout-ms
           max max-time-ms idle-max-ms queue-cap on-error error-mode stop?]
    :or   {snaplen 65536 promiscuous? true timeout-ms 10
           error-mode :throw}}]
  (let [default-max 100
        default-max-time-ms 10000
        default-idle-max-ms 3000
        default-queue-cap 1024
        _ (when (and device path)
            (throw (ex-info "capture->seq takes either :device or :path, not both" {:device device :path path})))
        _ (when-not (or (valid-device? device) (valid-path? path))
            (throw (ex-info "capture->seq requires either :device or :path" {:device device :path path})))
        max         (or max default-max)
        max-time-ms (or max-time-ms default-max-time-ms)
        idle-max-ms (or idle-max-ms default-idle-max-ms)
        cap         (int (or queue-cap default-queue-cap))
        q           (LinkedBlockingQueue. cap)
        sentinel    ::end-of-capture
        make-error-item (fn [^Throwable ex] {:type :paclo/capture-error :ex ex})
        ;; open
        h (if device
            (open-live {:device device :snaplen snaplen :promiscuous? promiscuous? :timeout-ms timeout-ms})
            (open-offline path))]
    (future
      (let [captured-error (atom nil)]
        (try
          (when filter
            (if device
              (set-bpf-on-device! h device filter)
              (set-bpf! h filter)))
          (loop-n-or-ms! h {:n max :ms max-time-ms :idle-max-ms idle-max-ms :timeout-ms timeout-ms :stop? stop?}
                         (fn [pkt]
                           (.put q pkt)
                           (when (and stop? (stop? pkt))
                             (breakloop! h))))
          (catch Throwable ex
            (when on-error (try (on-error ex) (catch Throwable _)))
            (reset! captured-error ex))
          (finally
            (try
              (close! h)
              (catch Throwable ex
                (when on-error (try (on-error ex) (catch Throwable _)))))
            (when-let [ex @captured-error]
              (.put q (make-error-item ex)))
            (.put q sentinel)))))
    (letfn [(drain []
              (lazy-seq
               (let [x (.take q)]
                 (cond
                   (identical? x sentinel) '()
                   (and (map? x) (= (:type x) :paclo/capture-error))
                   (if (= error-mode :pass)
                     (drain)
                     (throw (ex-info "capture->seq background error"
                                     {:source :capture->seq}
                                     (:ex x))))
                   :else (cons x (drain))))))]
      (drain))))

;; ------------------------------------------------------------
;; - run-live-n-summary!     => {:count n :duration-ms X :stopped :n | :idle-or-eof}
;; - run-live-for-ms-summary!=> {:count n :duration-ms X :stopped :time | :idle-or-eof}
;; ------------------------------------------------------------

(defn run-live-n-summary!
  "Run run-live-n! and return a summary map.
   Example: (run-live-n-summary! {:device \"en0\" :filter \"udp\" :timeout-ms 50} 100 (fn [_]) {:idle-max-ms 3000})"
  ([opts ^long n handler]
   (run-live-n-summary! opts n handler {}))
  ([opts ^long n handler loop-opts]
   (let [cnt (atom 0)
         t0  (System/currentTimeMillis)
         wrapped (fn [pkt] (swap! cnt inc) (handler pkt))]
     (run-live-n! opts n wrapped loop-opts)
     (let [elapsed (- (System/currentTimeMillis) t0)
           stopped (if (>= ^long @cnt n) :n :idle-or-eof)]
       {:count @cnt :duration-ms elapsed :stopped stopped}))))

(defn run-live-for-ms-summary!
  "Run run-live-for-ms! and return a summary map.
   Example: (run-live-for-ms-summary! {:device \"en0\" :filter \"tcp\" :timeout-ms 50} 3000 (fn [_]) {:idle-max-ms 1000})"
  ([opts ^long duration-ms handler]
   (run-live-for-ms-summary! opts duration-ms handler {}))
  ([opts ^long duration-ms handler loop-opts]
   (let [cnt (atom 0)
         t0  (System/currentTimeMillis)
         wrapped (fn [pkt] (swap! cnt inc) (handler pkt))]
     (run-live-for-ms! opts duration-ms wrapped loop-opts)
     (let [elapsed (- (System/currentTimeMillis) t0)
           stopped (if (>= elapsed (long duration-ms)) :time :idle-or-eof)]
       {:count @cnt :duration-ms elapsed :stopped stopped}))))
