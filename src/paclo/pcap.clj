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
  "デバイス名から netmask を取得。失敗時は 0 を返す。"
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
  "pcap ハンドルに BPF フィルタを適用。opts 例:
   {:filter \"udp and port 53\" :optimize? true :netmask 0}"
  [^Pointer pcap {:keys [filter optimize? netmask]}]
  (when (and pcap (valid-filter-string? filter))
    (let [opt?  (if (nil? optimize?) true optimize?)
          mask  (int (or netmask 0))         ;; ★ 既定は 0（不明）
          prog  (PcapLibrary/compileFilter pcap filter opt? mask)]
      (try
        (PcapLibrary/setFilterOrThrow pcap prog)
        (finally
          (PcapLibrary/freeFilter prog)))))
  pcap)

(defn- blank-str? [^String s]
  (or (nil? s) (re-find #"^\s*$" s)))

(defn- normalize-desc [^String s]
  (let [t (when s (str/trim s))]
    (when (and t (not (blank-str? t))) t)))

(defn open-offline
  (^Pointer [path]
   (open-offline path {}))
  (^Pointer [path opts]
   ;; 1) まずファイルの存在・サイズを明示チェック（原因を特定しやすく）
   (let [f   (io/file path)
         abs (.getAbsolutePath ^java.io.File f)]
     (when-not (.exists ^java.io.File f)
       (throw (ex-info (str "pcap file not found: " abs)
                       {:path abs :reason :not-found})))
     (when (zero? (.length ^java.io.File f))
       (throw (ex-info (str "pcap file is empty: " abs)
                       {:path abs :reason :empty})))
     ;; 2) 実際に pcap_open_offline（errbufも拾う）
     (let [^Pointer err (Memory/allocate rt (long PCAP_ERRBUF_SIZE))
           pcap (.pcap_open_offline lib abs err)]
       (when (nil? pcap)
         (let [raw (try (.getString ^Pointer err (long 0)) (catch Throwable _ ""))  ; errbuf 取得（失敗しても無視）
               msg (let [t (str/trim (or raw ""))]
                     (if (seq t)
                       (str "pcap_open_offline failed: " t)
                       "pcap_open_offline failed"))]
           (throw (ex-info msg
                           {:path abs :reason :pcap-open-failed :err raw}))))
       ;; 3) BPFフィルタが来ていれば適用（core側でDSL→文字列化されていればそのまま渡る）
       (apply-filter! pcap opts)
       ;; 4) ハンドルを返す
       pcap))))

(defn open-live
  [{:keys [device snaplen promiscuous? timeout-ms netmask]
    :or   {snaplen 65536 promiscuous? true timeout-ms 10}
    :as   opts}]
  (let [^Pointer err    (Memory/allocate rt (long PCAP_ERRBUF_SIZE))
        promisc (if promiscuous? 1 0)
        pcap    (.pcap_open_live lib device snaplen promisc timeout-ms err)]
    (when (nil? pcap)
      (throw (ex-info "pcap_open_live failed"
                      {:device device :err (.getString ^Pointer err (long 0))})))
    ;; ★ netmask 未指定ならデバイスから解決（失敗時は 0 が返る）
    (let [resolved-mask (or netmask (when device (lookup-netmask device)))
          opts*         (if (some? resolved-mask) (assoc opts :netmask resolved-mask) opts)]
      (apply-filter! pcap opts*))))

(defn close! [^Pointer pcap] (.pcap_close lib pcap))

;; ------------------------------------------------------------
;; 安全ラッパ（必ず close/flush する）
;; with-pcap / with-dumper / with-live / with-offline
;; ------------------------------------------------------------

;; Macros below reference these fns; declare them so macro expansion can resolve.
(declare open-dumper dump! flush-dumper! close-dumper!)

(defmacro with-pcap
  "例: (with-pcap [h (open-live {:device \"en0\"})]
         (loop-n! h 10 prn))"
  [[sym open-expr] & body]
  `(let [~sym ~open-expr]
     (try
       ~@body
       (finally
         (close! ~sym)))))

(defmacro with-dumper
  "例: (with-dumper [d (open-dumper h \"out.pcap\")]
         (dump! d hdr data))"
  [[sym open-expr] & body]
  `(let [~sym ~open-expr]
     (try
       ~@body
       (finally
         (flush-dumper! ~sym)
         (close-dumper! ~sym)))))

(defmacro with-live
  "例: (with-live [h {:device \"en0\" :filter \"tcp\"}]
         (loop-n! h 10 prn))"
  [[sym opts] & body]
  `(with-pcap [~sym (open-live ~opts)]
     ~@body))

(defmacro with-offline
  "例:
     (with-offline [h (open-offline \"dev/resources/fixtures/sample.pcap\")]
       (loop-for-ms! h 2000 prn))
     (with-offline [h (open-offline \"dev/resources/fixtures/sample.pcap\" {:filter \"udp\"})]
       (loop-n! h 50 prn))"
  [[sym open-expr] & body]
  `(with-pcap [~sym ~open-expr]
     ~@body))

;; ------------------------------------------------------------
;; 生成系ユーティリティ（pcap_open_dead で PCAP を生成）
;; マクロ（with-pcap/with-dumper）より下に置く
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
  [idle tick idle-target]
  (let [idle' (+ idle tick)]
    {:idle idle'
     :break? (>= idle' idle-target)}))

(defn open-dead
  "生成用の pcap ハンドルを作る（linktype は DLT_*、snaplen 既定 65536）"
  ([]
   (open-dead DLT_EN10MB 65536))
  ([linktype snaplen]
   (.pcap_open_dead lib (int linktype) (int snaplen))))

(defn ^:private bytes->ptr [^bytes ba]
  (let [^Pointer m (Memory/allocate rt (long (alength ba)))]
    (.put m (long 0) ba (int 0) (int (alength ba)))
    m))

(defn ^:private mk-hdr
  "pcap_pkthdr を作る。sec/usec は long（エポック秒/マイクロ秒）。len は int。"
  [^long sec ^long usec ^long len]
  (let [^Pointer hdr (Memory/allocate rt (long PCAP_PKTHDR_BYTES))]
    (.putLong hdr (long 0) sec)
    (.putLong hdr (long 8) usec)
    (.putInt  hdr (long 16) (int len))
    (.putInt  hdr (long 20) (int len))
    hdr))

(defn bytes-seq->pcap!
  "バイト列のシーケンスを PCAP に書き出す。
   packets: シーケンス。要素は `byte-array` または
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
  "デバイス名 dev のネットワークアドレス/マスクを取得。
   成功: {:net int :mask int}
   失敗: ex-info（:phase :lookupnet を含む）"
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
  "pcap に BPF を適用。optimize=1、netmask=0（未知時）で apply-filter! に委譲。成功で true。"
  [^Pointer pcap expr]
  (apply-filter! pcap {:filter expr :optimize? true :netmask 0})
  true)

(defn set-bpf-with-netmask!
  "pcap に BPF を適用。optimize=1、netmask 明示で apply-filter! に委譲。成功で true。"
  [^Pointer pcap expr netmask]
  (apply-filter! pcap {:filter expr :optimize? true :netmask (int netmask)})
  true)

(defn set-bpf-on-device!
  "デバイス dev の netmask を lookup して BPF を適用（内部で set-bpf-with-netmask!）。成功で true。"
  [^Pointer pcap dev expr]
  (let [mask (try
               (:mask (lookupnet dev)) ; 既存の詳細版lookupを再利用（失敗時に例外）
               (catch Throwable _ 0))] ; 念のためフォールバック
    (set-bpf-with-netmask! pcap expr mask)))

(defn loop!
  "pcap_next_ex をポーリング。handlerは (fn {:ts-sec :ts-usec :caplen :len :bytes}) を受け取る。
   終端: rc<0（pcap EOF/err）で終了。"
  [^Pointer pcap handler]
  (let [^PointerByReference hdr-ref (PointerByReference.)
        ^PointerByReference dat-ref (PointerByReference.)]
    (loop []
      (let [rc (.pcap_next_ex lib pcap hdr-ref dat-ref)]
        (cond
          (= rc 1)
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

          (= rc 0)  ; timeout (live capture)
          (recur)

          :else     ; -1 error / -2 EOF (offline)
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
  "ライブでキャプチャして out.pcap に保存。
   opts:
   {:device \"en0\"
    :filter \"tcp port 80\"     ; 省略可
    :max 100                    ; 取れたパケット数がこの件数に達したら終了
    :snaplen 65536
    :promiscuous? true
    :timeout-ms 10              ; pcap_next_ex のタイムアウト
    :max-time-ms 10000          ; 壁時計タイム上限（ms）
    :idle-max-ms 3000}          ; 連続アイドル上限（ms）"
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
      ;; ★ 変更点：device+filter が両方ある場合は netmask を自動適用
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
            (let [rc (.pcap_next_ex lib pcap hdr-ref dat-ref)]
              (cond
                (= rc 1)
                (do
                  (let [^Pointer hdr (.getValue hdr-ref)
                        ^Pointer dat (.getValue dat-ref)]
                    (dump! dumper hdr dat))
                  (recur (inc n) 0))
                (= rc 0) ; timeout
                (recur n (+ idle (long timeout-ms)))
                :else    ; -1 err / -2 EOF
                n)))))
      (finally
        (flush-dumper! dumper)
        (close-dumper! dumper)
        (close! pcap)))))

;; macOS だけ networksetup から “人間が読める名称” を補完
(defn- macos-device->desc []
  (let [os (.. System (getProperty "os.name") toLowerCase)]
    (if (not (.contains os "mac"))
      {}
      (let [^"[Ljava.lang.String;" cmd (into-array String ["networksetup" "-listallhardwareports"])
            ^java.lang.ProcessBuilder pb (java.lang.ProcessBuilder. cmd)
            _    (.redirectErrorStream pb true)   ;; ← Redirect 定数は使わない
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
  "利用可能デバイスの簡易一覧。macOSでは networksetup で desc を補完する。
   - name が空/空白のエントリはスキップ
   - desc が空/空白なら fallback を適用"
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
            ;; 完了
            (persistent! acc)
            (let [^paclo.jnr.PcapLibrary$PcapIf ifc (paclo.jnr.PcapLibrary$PcapIf. rt)]
              (.useMemory ifc p)
              (let [^Pointer name-ptr (.get (.-name ifc))
                    ^Pointer desc-ptr (.get (.-desc ifc))
                    ^Pointer next-ptr (.get (.-next ifc))
                    ;; name の空/空白はスキップ
                    name     (when (and name-ptr (not= 0 (.address name-ptr)))
                               (let [s (.getString name-ptr 0)]
                                 (when-not (blank-str? s) s)))
                    ;; desc が空/空白なら fallback に置換
                    desc0    (when (and desc-ptr (not= 0 (.address desc-ptr)))
                               (normalize-desc (.getString desc-ptr 0)))
                    desc     (or desc0 (when name (normalize-desc (get fallback name))))]
                (if name
                  (recur next-ptr (conj! acc {:name name :desc desc}))
                  (recur next-ptr acc))))))
        (finally
          (.pcap_freealldevs lib head))))))

;; --- handler 正規化（0引数でも受け付ける） -------------------------------
(defn- ->pkt-handler
  "渡された handler を『1引数を取る関数』に正規化する。
   - 1引数関数ならそのまま呼ぶ
   - 0引数関数なら ArityException を捕まえて fallback で呼ぶ
   - nil は no-op"
  [handler]
  (cond
    (nil? handler)
    (fn [_] nil)

    :else
    (fn [pkt]
      (try
        (handler pkt)                     ;; 1引数として呼ぶ
        (catch clojure.lang.ArityException _
          (handler))))))                  ;; 0引数で呼ぶ

;; -----------------------------------------
;; REPL用：小回りヘルパ（件数/時間/idleで停止）
;; -----------------------------------------
;; NOTE:
;; - :idle-max-ms を与えた場合のみ idle 監視を有効化。
;; - その場合、:timeout-ms（open-liveに渡した値）も渡すと精度が上がる。
;;   未指定なら 100ms を仮定して idle を積算します。

(defn loop-n!
  "pcap_next_ex を最大 n 件処理して停止。
   オプション: {:idle-max-ms <ms> :timeout-ms <ms>}
   例: (loop-n! h 10 handler) ; 従来どおり
       (loop-n! h 10 handler {:idle-max-ms 3000 :timeout-ms 100})"
  ([^Pointer pcap ^long n handler]
   (assert (pos? n) "n must be positive")
   (let [c (atom 0)
         handle (->pkt-handler handler)]
     (loop! pcap (fn [pkt]
                   (handle pkt)
                   (swap! c inc)
                   (when (>= ^long @c n)
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
             (let [rc (.pcap_next_ex lib pcap hdr-ref dat-ref)]
               (cond
                 (= rc 1)
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
                   (recur (inc count) 0))

                 (= rc 0)
                 (let [{:keys [idle break?]} (idle-next idle tick idle-ms-target)]
                   (if break?
                     (breakloop! pcap)
                     (recur count idle)))

                 :else
                 (breakloop! pcap))))))))))

(defn loop-for-ms!
  "開始から duration-ms 経過したら停止（壁時計基準）。
   オプション: {:idle-max-ms <ms> :timeout-ms <ms>}
   例: (loop-for-ms! h 3000 handler)
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
             (let [rc (.pcap_next_ex lib pcap hdr-ref dat-ref)]
               (cond
                 (= rc 1)
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

                 (= rc 0)
                 (let [{:keys [idle break?]} (idle-next idle tick idle-ms-target)]
                   (if break?
                     (breakloop! pcap)
                     (recur idle)))

                 :else
                 (breakloop! pcap))))))))))

(defn loop-n-or-ms!
  "n件到達 or duration-ms 経過の早い方で停止。
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
      ;; --- idle監視なし: loop! を使うパス（handler内で停止条件を見る）
      (let [c  (atom 0)
            t0 (System/currentTimeMillis)]
        (loop! pcap (fn [pkt]
                      (handle pkt)
                      (swap! c inc)
                      (let [stop-n? (>= ^long @c n-long)
                            stop-t? (>= (- (System/currentTimeMillis) t0) ms-long)
                            stop-custom? (and stop? (stop? pkt))]
                        (when (or stop-n? stop-t? stop-custom?)
                          (breakloop! pcap))))))
      ;; --- idle監視あり: pcap_next_ex を自前で回すパス（pkt毎に stop? を判定）
      (let [hdr-ref (PointerByReference.)
            dat-ref (PointerByReference.)
            t0 (System/currentTimeMillis)
            deadline (+ t0 ms-long)
            tick (long (or timeout-ms 100))
            idle-target (long idle-max-ms)]
        (loop [count 0 idle 0]
          (when (and (< count n-long)
                     (< (System/currentTimeMillis) deadline))
            (let [rc (.pcap_next_ex lib pcap hdr-ref dat-ref)]
              (cond
                (= rc 1)
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
                    (breakloop! pcap)            ;; ★ ヒット即停止（オフラインでも即効）
                    (recur (inc count) 0)))

                (= rc 0)
                (let [{:keys [idle break?]} (idle-next idle tick idle-target)]
                  (if break?
                    (breakloop! pcap)
                    (recur count idle)))

                :else
                (breakloop! pcap)))))))))

;; -----------------------------------------
;; REPL用：ワンショット実験（open→filter→loop→close）
;; -----------------------------------------

(defn run-live-n!
  "デバイスを開いて、必要ならBPFを設定して、n件だけ処理して閉じる。
   追加オプション: :idle-max-ms （:timeout-ms は open-live と共有）
   例: (run-live-n! {:device \"en1\" :filter \"tcp\" :timeout-ms 100}
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
  "デバイスを開いて、必要ならBPFを設定して、duration-msだけ処理して閉じる。
   追加オプション: {:idle-max-ms <ms>}
   例: (run-live-for-ms! {:device \"en1\" :timeout-ms 50}
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
;; 高レベルAPI：capture->seq
;; - ライブ/オフライン両対応
;; - デフォルトで安全に手仕舞い（:max/:max-time-ms/:idle-max-ms）
;; - バックグラウンドでキャプチャし、lazy-seq で取り出し
;; -----------------------------------------

(defn capture->seq
  "パケットを lazy-seq で返す高レベルAPI。
   opts:
   - ライブ:  {:device \"en1\" :filter \"tcp\" :snaplen 65536 :promiscuous? true :timeout-ms 10}
   - オフライン: {:path \"sample.pcap\" :filter \"...\"}
   - 共有停止条件（指定なければ安全な既定値で自動手仕舞い）:
       :max <int>               ; 取得最大件数（default 100）
       :max-time-ms <int>       ; 経過時間上限（default 10000）
       :idle-max-ms <int>       ; 無通信連続上限（default 3000）
   - 内部キュー:
       :queue-cap <int>         ; バックグラウンド→呼び出し側のバッファ（default 1024）
   - エラー処理:
       :on-error (fn [throwable])   ; 背景スレッドで例外発生時に呼ばれる（任意）
       :error-mode :throw|:pass     ; 既定 :throw（lazy側に再スロー）/:pass はスキップ
   - ★停止条件フック（新規）:
       :stop? (fn [pkt] boolean)    ; 受信pktを見て true なら即 stop（breakloop!）

   返り値: lazy-seq of packet-maps （loop! ハンドラで渡している {:ts-sec … :bytes …}）"
  [{:keys [device path filter snaplen promiscuous? timeout-ms
           max max-time-ms idle-max-ms queue-cap on-error error-mode stop?]
    :or   {snaplen 65536 promiscuous? true timeout-ms 10
           error-mode :throw}}]
  (let [default-max 100
        default-max-time-ms 10000
        default-idle-max-ms 3000
        default-queue-cap 1024
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
    ;; バックグラウンドでキャプチャしてキューに流す
    (future
      (try
        (when filter
          (if device
            (set-bpf-on-device! h device filter)
            (set-bpf! h filter)))
        (loop-n-or-ms! h {:n max :ms max-time-ms :idle-max-ms idle-max-ms :timeout-ms timeout-ms :stop? stop?}
                       (fn [pkt]
                         (.put q pkt)
                         ;; ★ 任意条件で即停止
                         (when (and stop? (stop? pkt))
                           (breakloop! h))))
        (catch Throwable ex
          (when on-error (try (on-error ex) (catch Throwable _)))
          (.put q (make-error-item ex)))
        (finally
          (.put q sentinel)
          (close! h))))
    ;; lazy-seq を返す
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
;; ライブ実行のサマリ版（後方互換のため新規追加）
;; - run-live-n-summary!     => {:count n :duration-ms X :stopped :n | :idle-or-eof}
;; - run-live-for-ms-summary!=> {:count n :duration-ms X :stopped :time | :idle-or-eof}
;;   ※ :idle-or-eof は「件数未達で停止（アイドル or EOF/ERR）」の総称
;; ------------------------------------------------------------

(defn run-live-n-summary!
  "run-live-n! と同等の処理を行い、サマリを返す。
   例: (run-live-n-summary! {:device \"en0\" :filter \"udp\" :timeout-ms 50} 100 (fn [_]) {:idle-max-ms 3000})"
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
  "run-live-for-ms! と同等の処理を行い、サマリを返す。
   例: (run-live-for-ms-summary! {:device \"en0\" :filter \"tcp\" :timeout-ms 50} 3000 (fn [_]) {:idle-max-ms 1000})"
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
