(ns paclo.pcap
  (:import
   [jnr.ffi LibraryLoader Memory Pointer]
   [jnr.ffi.byref PointerByReference IntByReference]
   [paclo.jnr PcapLibrary PcapHeader]
   ;; ★ 追加
   [java.util.concurrent LinkedBlockingQueue TimeUnit]))

(def ^:private ^jnr.ffi.Runtime rt (jnr.ffi.Runtime/getSystemRuntime))
(def ^:private ^PcapLibrary lib
  (let [os      (.. System (getProperty "os.name") toLowerCase)
        libname (if (.contains os "win") "wpcap" "pcap")
        loader  (LibraryLoader/create PcapLibrary)]
    (.load loader libname)))

(def PCAP_ERRBUF_SIZE 256)
(def ^:private BPF_PROG_BYTES 16)

(defn open-offline ^Pointer [path]
  (let [err (Memory/allocate rt PCAP_ERRBUF_SIZE)
        pcap (.pcap_open_offline lib path err)]
    (when (nil? pcap)
      (throw (ex-info "pcap_open_offline failed"
                      {:err (.getString err 0)})))
    pcap))

(defn open-live ^Pointer [{:keys [device snaplen promiscuous? timeout-ms]
                           :or {snaplen 65536 promiscuous? true timeout-ms 10}}]
  (let [err (Memory/allocate rt PCAP_ERRBUF_SIZE)
        promisc (if promiscuous? 1 0)
        pcap (.pcap_open_live lib device snaplen promisc timeout-ms err)]
    (when (nil? pcap)
      (throw (ex-info "pcap_open_live failed" {:device device :err (.getString err 0)})))
    pcap))

(defn close! [^Pointer pcap] (.pcap_close lib pcap))

;; -----------------------------------------------------------------------------
;; ★ 追加: pcap_lookupnet のラッパ
;; -----------------------------------------------------------------------------
(defn lookupnet
  "デバイス名 dev のネットワークアドレス/マスクを取得。
   成功: {:net int :mask int}
   失敗: ex-info（:err に libpcap のメッセージ）"
  [dev]
  (let [net-ref  (IntByReference.)
        mask-ref (IntByReference.)
        err      (Memory/allocate rt PCAP_ERRBUF_SIZE)
        rc       (.pcap_lookupnet lib dev net-ref mask-ref err)]
    (if (zero? rc)
      {:net  (.getValue net-ref)
       :mask (.getValue mask-ref)}
      (throw (ex-info "pcap_lookupnet failed"
                      {:device dev
                       :rc     rc
                       :err    (.getString err 0)})))))

(defn set-bpf! [^Pointer pcap expr]
  (let [prog (paclo.jnr.BpfProgram. rt)]
    (try
      ;; optimize=1, netmask=0（未知のときは 0 が無難）
      (let [rc-compile (.pcap_compile lib pcap (.addr prog) expr 1 0)]
        (when (neg? rc-compile)
          (throw (ex-info "pcap_compile failed"
                          {:expr expr
                           :rc rc-compile
                           :err (.pcap_geterr lib pcap)}))))
      (let [rc-set (.pcap_setfilter lib pcap (.addr prog))]
        (when (neg? rc-set)
          (throw (ex-info "pcap_setfilter failed"
                          {:expr expr
                           :rc rc-set
                           :err (.pcap_geterr lib pcap)}))))
      (finally
        ;; 成否に関わらず bf_insn を解放
        (.pcap_freecode lib (.addr prog))))))

;; -----------------------------------------------------------------------------
;; ★ 追加: 明示 netmask を使って BPF を設定する安全版（既存を壊さない）
;; -----------------------------------------------------------------------------
(defn set-bpf-with-netmask!
  "pcap ハンドルに BPF を適用。optimize=1、netmask を明示指定。
   戻り値: true（例外がなければ成功）"
  [^Pointer pcap expr netmask]
  (let [prog (paclo.jnr.BpfProgram. rt)]
    (try
      (let [rc-compile (.pcap_compile lib pcap (.addr prog) expr 1 (int netmask))]
        (when (neg? rc-compile)
          (throw (ex-info "pcap_compile failed"
                          {:expr expr
                           :netmask netmask
                           :rc rc-compile
                           :err (.pcap_geterr lib pcap)}))))
      (let [rc-set (.pcap_setfilter lib pcap (.addr prog))]
        (when (neg? rc-set)
          (throw (ex-info "pcap_setfilter failed"
                          {:expr expr
                           :netmask netmask
                           :rc rc-set
                           :err (.pcap_geterr lib pcap)}))))
      true
      (finally
        (.pcap_freecode lib (.addr prog))))))

(defn set-bpf-on-device!
  "デバイス dev の netmask を lookup して BPF を適用するショートカット。"
  [^Pointer pcap dev expr]
  (let [{:keys [mask]} (lookupnet dev)]
    (set-bpf-with-netmask! pcap expr mask)))

(defn loop!
  "pcap_next_ex をポーリング。handlerは (fn {:ts-sec :ts-usec :caplen :len :bytes}) を受け取る。
   終端: rc<0（pcap EOF/err）で終了。"
  [^Pointer pcap handler]
  (let [hdr-ref (PointerByReference.)
        dat-ref (PointerByReference.)]
    (loop []
      (let [rc (.pcap_next_ex lib pcap hdr-ref dat-ref)]
        (cond
          (= rc 1)
          (let [hdr (.getValue hdr-ref)
                dat (.getValue dat-ref)
                ts-sec (PcapHeader/tv_sec hdr)
                ts-usec (PcapHeader/tv_usec hdr)
                caplen (PcapHeader/caplen hdr)
                len    (PcapHeader/len hdr)
                arr    (byte-array (int caplen))]
            (.get dat 0 arr 0 (alength arr))
            (handler {:ts-sec ts-sec :ts-usec ts-usec
                      :caplen caplen :len len :bytes arr})
            (recur))

          (= rc 0)  ; timeout (live capture)
          (recur)

          :else     ; -1 error / -2 EOF (offline)
          rc)))))

(defn breakloop! [^Pointer pcap] (.pcap_breakloop lib pcap))

(defn open-dumper ^Pointer [^Pointer pcap path]
  (let [d (.pcap_dump_open lib pcap path)]
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
        hdr-ref (PointerByReference.)
        dat-ref (PointerByReference.)
        t0 (System/currentTimeMillis)]
    (try
      ;; ★ 変更点：device+filter が両方ある場合は netmask を自動適用
      (when filter
        (if (some? device)
          (set-bpf-on-device! pcap device filter)
          (set-bpf! pcap filter)))
      (loop [n 0 idle 0]
        (let [now (System/currentTimeMillis)]
          (cond
            (>= n max) n
            (>= (- now t0) max-time-ms) n
            (>= idle idle-max-ms) n
            :else
            (let [rc (.pcap_next_ex lib pcap hdr-ref dat-ref)]
              (cond
                (= rc 1)
                (do
                  (dump! dumper (.getValue hdr-ref) (.getValue dat-ref))
                  (recur (inc n) 0))
                (= rc 0) ; timeout
                (recur n (+ idle timeout-ms))
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
      (let [pb   (java.lang.ProcessBuilder.
                  (into-array String ["networksetup" "-listallhardwareports"]))
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
                (recur m (subs line 14) (.readLine rdr))

                (.startsWith line "Device: ")
                (let [dev (subs line 8)]
                  (recur (assoc m dev cur-port) cur-port (.readLine rdr)))

                :else
                (recur m cur-port (.readLine rdr)))))
          (finally
            (.close rdr)
            (.waitFor proc)))))))

(defn list-devices
  "利用可能デバイスの簡易一覧。macOSでは networksetup で desc を補完する。"
  []
  (let [err (Memory/allocate rt PCAP_ERRBUF_SIZE)
        pp  (PointerByReference.)]
    (when (neg? (.pcap_findalldevs lib pp err))
      (throw (ex-info "pcap_findalldevs failed" {:err (.getString err 0)})))
    (let [head (.getValue pp)
          fallback (macos-device->desc)]
      (try
        (loop [p head, acc (transient [])]
          (if (or (nil? p) (= 0 (.address p)))
            (persistent! acc)
            (let [ifc (paclo.jnr.PcapLibrary$PcapIf. rt)]
              (.useMemory ifc p)
              (let [name-ptr (.get (.-name ifc))
                    desc-ptr (.get (.-desc ifc))
                    next-ptr (.get (.-next ifc))
                    name     (when (and name-ptr (not= 0 (.address name-ptr)))
                               (.getString name-ptr 0))
                    desc     (or (when (and desc-ptr (not= 0 (.address desc-ptr)))
                                   (.getString desc-ptr 0))
                                 (get fallback name))]
                (recur next-ptr (conj! acc {:name name :desc desc}))))))
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
                    (when (>= (swap! c inc) n)
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
                  (let [hdr (.getValue hdr-ref)
                        dat (.getValue dat-ref)
                        ts-sec (PcapHeader/tv_sec hdr)
                        ts-usec (PcapHeader/tv_usec hdr)
                        caplen (PcapHeader/caplen hdr)
                        len    (PcapHeader/len hdr)
                        arr    (byte-array (int caplen))]
                    (.get dat 0 arr 0 (alength arr))
                    (handle {:ts-sec ts-sec :ts-usec ts-usec
                             :caplen caplen :len len :bytes arr})
                    (recur (inc count) 0))
  
                  (= rc 0)
                  (let [idle' (+ idle tick)]
                    (if (>= idle' idle-ms-target)
                      (breakloop! pcap)
                      (recur count idle')))
  
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
                  (let [hdr (.getValue hdr-ref)
                        dat (.getValue dat-ref)
                        ts-sec (PcapHeader/tv_sec hdr)
                        ts-usec (PcapHeader/tv_usec hdr)
                        caplen (PcapHeader/caplen hdr)
                        len    (PcapHeader/len hdr)
                        arr    (byte-array (int caplen))]
                    (.get dat 0 arr 0 (alength arr))
                    (handle {:ts-sec ts-sec :ts-usec ts-usec
                             :caplen caplen :len len :bytes arr})
                    (recur 0))
  
                  (= rc 0)
                  (let [idle' (+ idle tick)]
                    (if (>= idle' idle-ms-target)
                      (breakloop! pcap)
                      (recur idle')))
  
                  :else
                  (breakloop! pcap))))))))))


(defn loop-n-or-ms!
  "n件到達 or duration-ms 経過の早い方で停止。
   conf: {:n <long> :ms <long> :idle-max-ms <ms-optional> :timeout-ms <ms-optional>}"
  [^Pointer pcap {:keys [n ms idle-max-ms timeout-ms] :as conf} handler]
  (when (nil? n) (throw (ex-info "missing :n" {})))
  (when (nil? ms) (throw (ex-info "missing :ms" {})))
  (assert (pos? n) "n must be positive")
  (assert (pos? ms) "ms must be positive")
  (let [handle (->pkt-handler handler)]
    (if (nil? idle-max-ms)
      (let [c  (atom 0)
            t0 (System/currentTimeMillis)]
        (loop! pcap (fn [pkt]
                      (handle pkt)
                      (let [stop-n? (>= (swap! c inc) n)
                            stop-t? (>= (- (System/currentTimeMillis) t0) ms)]
                        (when (or stop-n? stop-t?)
                          (breakloop! pcap))))))
      (let [hdr-ref (PointerByReference.)
            dat-ref (PointerByReference.)
            t0 (System/currentTimeMillis)
            deadline (+ t0 (long ms))
            tick (long (or timeout-ms 100))
            idle-target (long idle-max-ms)]
        (loop [count 0 idle 0]
          (when (and (< count n)
                     (< (System/currentTimeMillis) deadline))
            (let [rc (.pcap_next_ex lib pcap hdr-ref dat-ref)]
              (cond
                (= rc 1)
                (let [hdr (.getValue hdr-ref)
                      dat (.getValue dat-ref)
                      ts-sec (PcapHeader/tv_sec hdr)
                      ts-usec (PcapHeader/tv_usec hdr)
                      caplen (PcapHeader/caplen hdr)
                      len    (PcapHeader/len hdr)
                      arr    (byte-array (int caplen))]
                  (.get dat 0 arr 0 (alength arr))
                  (handle {:ts-sec ts-sec :ts-usec ts-usec
                           :caplen caplen :len len :bytes arr})
                  (recur (inc count) 0))

                (= rc 0)
                (let [idle' (+ idle tick)]
                  (if (>= idle' idle-target)
                    (breakloop! pcap)
                    (recur count idle')))

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
    {:keys [idle-max-ms] :as loop-opts}]
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
    {:keys [idle-max-ms] :as loop-opts}]
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

(def ^:private ^:const default-max 100)
(def ^:private ^:const default-max-time-ms 10000)
(def ^:private ^:const default-idle-max-ms 3000)
(def ^:private ^:const default-queue-cap 1024)

(defn capture->seq
  "パケットを lazy-seq で返す高レベルAPI。
   opts:
   - ライブ:  {:device \"en1\" :filter \"tcp\" :snaplen 65536 :promiscuous? true :timeout-ms 10}
   - オフライン: {:path \"sample.pcap\" :filter \"...\"}  ; filterはオフラインでも使用可
   - 共有停止条件（指定なければ安全な既定値で自動手仕舞い）:
       :max <int>               ; 取得最大件数（default 100）
       :max-time-ms <int>       ; 経過時間上限（default 10000）
       :idle-max-ms <int>       ; 無通信連続上限（default 3000）
   - 内部キュー:
       :queue-cap <int>         ; バックグラウンド→呼び出し側のバッファ（default 1024）

   返り値: lazy-seq of packet-maps （loop! ハンドラで渡している {:ts-sec … :bytes …}）"
  [{:keys [device path filter snaplen promiscuous? timeout-ms
           max max-time-ms idle-max-ms queue-cap]
    :or   {snaplen 65536 promiscuous? true timeout-ms 10}}]
  (let [max         (or max default-max)
        max-time-ms (or max-time-ms default-max-time-ms)
        idle-max-ms (or idle-max-ms default-idle-max-ms)
        cap         (int (or queue-cap default-queue-cap))
        q           (LinkedBlockingQueue. cap)
        sentinel    ::end-of-capture
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
        ;; 取得条件の組合せ：:max と :max-time-ms を併用し、無通信でも終わる
        (loop-n-or-ms! h {:n max :ms max-time-ms :idle-max-ms idle-max-ms :timeout-ms timeout-ms}
          (fn [pkt]
            ;; キュー満杯なら待つ（キャンセル時は take されないと詰まる想定だが
            ;; デフォルト上限と既定の停止条件でリスクは低い）
            (.put q pkt)))
        (finally
          ;; キャプチャ終了通知とクローズ
          (.put q sentinel)
          (close! h))))
    ;; lazy-seq を返す
    (letfn [(drain []
              (lazy-seq
                (let [x (.take q)]
                  (if (identical? x sentinel)
                    ;; sentinelは消費。以降は空のseq
                    '()
                    (cons x (drain))))))]
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
           stopped (if (>= @cnt n) :n :idle-or-eof)]
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
